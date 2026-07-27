package dnsmsg

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// --- テスト用のクエリ組み立て ---------------------------------------------------

// qopt は組み立てるクエリのパラメータ。ゼロ値は「ID=0 の A/IN 問い合わせ 1 問」。
type qopt struct {
	id       uint16
	name     string
	qtype    Type
	class    Class
	rd       bool
	qr       bool   // 応答メッセージとして組み立てる（QR=1）
	opcode   uint8  // 既定 0（QUERY）
	qdcount  uint16 // 0 のときは 1 として書き込む（明示的に 0/2 を試すため -1 相当は noQD で表す）
	noQD     bool   // QDCOUNT=0 を書き込む
	rawName  []byte // 指定時は name の符号化に代えてそのまま埋め込む
	truncate int    // >0 なら末尾を削ってその長さにする
}

func buildQuery(o qopt) []byte {
	if o.qtype == 0 {
		o.qtype = TypeA
	}
	if o.class == 0 {
		o.class = ClassIN
	}
	qd := uint16(1)
	switch {
	case o.noQD:
		qd = 0
	case o.qdcount != 0:
		qd = o.qdcount
	}
	flags := uint16(o.opcode) << 11
	if o.qr {
		flags |= 0x8000
	}
	if o.rd {
		flags |= 0x0100
	}

	msg := make([]byte, 0, 32)
	msg = binary.BigEndian.AppendUint16(msg, o.id)
	msg = binary.BigEndian.AppendUint16(msg, flags)
	msg = binary.BigEndian.AppendUint16(msg, qd)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	if o.rawName != nil {
		msg = append(msg, o.rawName...)
	} else {
		msg = append(msg, encodeName(o.name)...)
	}
	msg = binary.BigEndian.AppendUint16(msg, uint16(o.qtype))
	msg = binary.BigEndian.AppendUint16(msg, uint16(o.class))
	if o.truncate > 0 && o.truncate < len(msg) {
		msg = msg[:o.truncate]
	}
	return msg
}

func encodeName(name string) []byte {
	var out []byte
	if name != "" {
		for _, l := range strings.Split(name, ".") {
			out = append(out, byte(len(l)))
			out = append(out, l...)
		}
	}
	return append(out, 0)
}

// fakeResolver は `.mesh` のみ権威を持つテスト用リゾルバ。
type fakeResolver struct{ zone map[string]netip.Addr }

func (f fakeResolver) Authoritative(name string) bool {
	return strings.HasSuffix(strings.ToLower(name), ".mesh")
}

func (f fakeResolver) Lookup(name string) (netip.Addr, bool) {
	a, ok := f.zone[strings.ToLower(name)]
	return a, ok
}

func testResolver() fakeResolver {
	return fakeResolver{zone: map[string]netip.Addr{
		"ollama.tanaka.mesh": netip.MustParseAddr("10.0.0.1"),
		"v6.tanaka.mesh":     netip.MustParseAddr("fd00::1"),
	}}
}

// --- ヘッダ検証ヘルパ -----------------------------------------------------------

type header struct {
	id                                 uint16
	qr, aa, tc, rd, ra                 bool
	opcode                             uint8
	rcode                              RCode
	qdcount, ancount, nscount, arcount uint16
}

func parseHeader(t *testing.T, msg []byte) header {
	t.Helper()
	if len(msg) < HeaderLen {
		t.Fatalf("応答がヘッダ長未満: %d バイト", len(msg))
	}
	f := binary.BigEndian.Uint16(msg[2:4])
	return header{
		id:      binary.BigEndian.Uint16(msg[0:2]),
		qr:      f&0x8000 != 0,
		opcode:  uint8((f >> 11) & 0x0F),
		aa:      f&0x0400 != 0,
		tc:      f&0x0200 != 0,
		rd:      f&0x0100 != 0,
		ra:      f&0x0080 != 0,
		rcode:   RCode(f & 0x000F),
		qdcount: binary.BigEndian.Uint16(msg[4:6]),
		ancount: binary.BigEndian.Uint16(msg[6:8]),
		nscount: binary.BigEndian.Uint16(msg[8:10]),
		arcount: binary.BigEndian.Uint16(msg[10:12]),
	}
}

// --- ParseQuery -----------------------------------------------------------------

func TestParseQuery(t *testing.T) {
	q, err := ParseQuery(buildQuery(qopt{id: 0xABCD, name: "Ollama.Tanaka.mesh", rd: true}))
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if q.ID != 0xABCD || !q.RD {
		t.Errorf("ID/RD = %#x/%v, want 0xABCD/true", q.ID, q.RD)
	}
	// 大文字小文字はクエリのまま保つ（DNS 0x20 対策でそのまま echo するため）。
	if q.Name != "Ollama.Tanaka.mesh" {
		t.Errorf("Name = %q", q.Name)
	}
	if q.Type != TypeA || q.Class != ClassIN {
		t.Errorf("Type/Class = %d/%d", q.Type, q.Class)
	}
	if want := len(encodeName("Ollama.Tanaka.mesh")) + 4; len(q.question) != want {
		t.Errorf("question = %d バイト, want %d", len(q.question), want)
	}
}

// TestParseQueryCopiesQuestion は入力バッファを再利用しても質問セクションが壊れないことを確かめる
// （cmd 側は読み取りバッファを使い回すため）。
func TestParseQueryCopiesQuestion(t *testing.T) {
	buf := buildQuery(qopt{name: "a.mesh"})
	q, err := ParseQuery(buf)
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	before := string(q.question)
	for i := range buf {
		buf[i] = 0xFF
	}
	if string(q.question) != before {
		t.Errorf("入力バッファの上書きで question が変化した")
	}
}

func TestParseQueryRootName(t *testing.T) {
	q, err := ParseQuery(buildQuery(qopt{name: ""}))
	if err != nil {
		t.Fatalf("ParseQuery: %v", err)
	}
	if q.Name != "" {
		t.Errorf("Name = %q, want 空（ルート）", q.Name)
	}
}

func TestParseQueryErrors(t *testing.T) {
	longLabel := strings.Repeat("a", 63)
	longName := strings.Join([]string{longLabel, longLabel, longLabel, longLabel}, ".") // 255 バイト超

	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"ヘッダ長未満", make([]byte, HeaderLen-1), ErrShort},
		{"応答メッセージ", buildQuery(qopt{qr: true}), ErrNotQuery},
		{"未対応 opcode", buildQuery(qopt{opcode: 5}), ErrUnsupportedOpcode},
		{"QDCOUNT=0", buildQuery(qopt{noQD: true}), ErrMalformed},
		{"QDCOUNT=2", buildQuery(qopt{qdcount: 2}), ErrMalformed},
		{"圧縮ポインタ", buildQuery(qopt{rawName: []byte{0xC0, 0x0C}}), ErrCompressedName},
		{"予約ラベル種別", buildQuery(qopt{rawName: []byte{0x80, 0x00}}), ErrMalformed},
		{"ラベル長がバッファ超過", buildQuery(qopt{rawName: []byte{0x10, 'a'}}), ErrMalformed},
		{"名前終端なし", buildQuery(qopt{name: "a.mesh", truncate: HeaderLen + 2}), ErrMalformed},
		{"名前が長すぎる", buildQuery(qopt{name: longName}), ErrMalformed},
		{"QTYPE/QCLASS 欠落", buildQuery(qopt{name: "a.mesh", truncate: HeaderLen + len(encodeName("a.mesh")) + 2}), ErrMalformed},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := ParseQuery(c.in); !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// --- Respond --------------------------------------------------------------------

func TestRespondA(t *testing.T) {
	in := buildQuery(qopt{id: 0x1234, name: "ollama.tanaka.mesh", rd: true})
	msg, err := Respond(in, testResolver(), 30)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	h := parseHeader(t, msg)
	if h.id != 0x1234 || !h.qr || !h.aa || h.ra || !h.rd || h.rcode != RCodeSuccess {
		t.Errorf("ヘッダ = %+v", h)
	}
	if h.qdcount != 1 || h.ancount != 1 || h.nscount != 0 || h.arcount != 0 {
		t.Errorf("カウント = %+v", h)
	}
	// 質問セクションはクエリのバイト列と一致する。
	q := in[HeaderLen:]
	if got := msg[HeaderLen : HeaderLen+len(q)]; string(got) != string(q) {
		t.Errorf("質問セクションがエコーされていない")
	}
	// 回答: 圧縮ポインタ + A/IN + TTL + RDLENGTH=4 + IPv4。
	rr := msg[HeaderLen+len(q):]
	if len(rr) != 16 {
		t.Fatalf("回答長 = %d, want 16", len(rr))
	}
	if rr[0] != 0xC0 || rr[1] != 0x0C {
		t.Errorf("NAME が圧縮ポインタでない: %#x %#x", rr[0], rr[1])
	}
	if Type(binary.BigEndian.Uint16(rr[2:4])) != TypeA || Class(binary.BigEndian.Uint16(rr[4:6])) != ClassIN {
		t.Errorf("TYPE/CLASS 不正")
	}
	if ttl := binary.BigEndian.Uint32(rr[6:10]); ttl != 30 {
		t.Errorf("TTL = %d, want 30", ttl)
	}
	if rdlen := binary.BigEndian.Uint16(rr[10:12]); rdlen != 4 {
		t.Errorf("RDLENGTH = %d, want 4", rdlen)
	}
	if addr, _ := netip.AddrFromSlice(rr[12:16]); addr != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("RDATA = %v", addr)
	}
}

// TestRespondCasePreserved は DNS 0x20 で大文字小文字を混ぜたクエリにも、同一バイト列の
// 質問をエコーして応答することを確かめる。
func TestRespondCasePreserved(t *testing.T) {
	in := buildQuery(qopt{name: "OlLaMa.TaNaKa.MeSh"})
	msg, err := Respond(in, testResolver(), 30)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if h := parseHeader(t, msg); h.ancount != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", h.ancount)
	}
	q := in[HeaderLen:]
	if string(msg[HeaderLen:HeaderLen+len(q)]) != string(q) {
		t.Errorf("大文字小文字が保たれていない")
	}
}

func TestRespondAAAA(t *testing.T) {
	msg, err := Respond(buildQuery(qopt{name: "v6.tanaka.mesh", qtype: TypeAAAA}), testResolver(), 30)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	h := parseHeader(t, msg)
	if h.rcode != RCodeSuccess || h.ancount != 1 {
		t.Fatalf("ヘッダ = %+v", h)
	}
	rr := msg[len(msg)-16:]
	if addr, _ := netip.AddrFromSlice(rr); addr != netip.MustParseAddr("fd00::1") {
		t.Errorf("RDATA = %v", addr)
	}
}

func TestRespondRCodes(t *testing.T) {
	cases := []struct {
		name    string
		in      []byte
		rcode   RCode
		aa      bool
		ancount uint16
		qdcount uint16
	}{
		{"未知の名前は NXDOMAIN", buildQuery(qopt{name: "nope.tanaka.mesh"}), RCodeNameError, true, 0, 1},
		{"IPv4 のみのピアへの AAAA は NODATA", buildQuery(qopt{name: "ollama.tanaka.mesh", qtype: TypeAAAA}), RCodeSuccess, true, 0, 1},
		{"IPv6 のみのピアへの A は NODATA", buildQuery(qopt{name: "v6.tanaka.mesh", qtype: TypeA}), RCodeSuccess, true, 0, 1},
		{"未対応種別（MX）は NODATA", buildQuery(qopt{name: "ollama.tanaka.mesh", qtype: 15}), RCodeSuccess, true, 0, 1},
		{"権威外は REFUSED", buildQuery(qopt{name: "example.com"}), RCodeRefused, false, 0, 1},
		{"IN 以外のクラスは NOTIMP", buildQuery(qopt{name: "ollama.tanaka.mesh", class: 3}), RCodeNotImplemented, false, 0, 1},
		{"未対応 opcode は NOTIMP（質問なし）", buildQuery(qopt{opcode: 4}), RCodeNotImplemented, false, 0, 0},
		{"解析不能は FORMERR（質問なし）", buildQuery(qopt{rawName: []byte{0xC0, 0x0C}}), RCodeFormatError, false, 0, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg, err := Respond(c.in, testResolver(), 30)
			if err != nil {
				t.Fatalf("Respond: %v", err)
			}
			h := parseHeader(t, msg)
			if h.rcode != c.rcode || h.aa != c.aa || h.ancount != c.ancount || h.qdcount != c.qdcount {
				t.Errorf("rcode=%d aa=%v an=%d qd=%d, want rcode=%d aa=%v an=%d qd=%d",
					h.rcode, h.aa, h.ancount, h.qdcount, c.rcode, c.aa, c.ancount, c.qdcount)
			}
			if !h.qr || h.ra || h.tc {
				t.Errorf("QR/RA/TC = %v/%v/%v, want true/false/false", h.qr, h.ra, h.tc)
			}
		})
	}
}

// TestRespondDropped は応答してはいけない入力で nil が返ることを確かめる。
func TestRespondDropped(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"ヘッダ長未満", []byte{0x00}, ErrShort},
		{"応答メッセージ", buildQuery(qopt{qr: true}), ErrNotQuery},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg, err := Respond(c.in, testResolver(), 30)
			if msg != nil {
				t.Errorf("msg = %v, want nil", msg)
			}
			if !errors.Is(err, c.want) {
				t.Errorf("err = %v, want %v", err, c.want)
			}
		})
	}
}

// TestRespondRDEcho は RD ビットをエコーしつつ RA を立てない（再帰しない）ことを確かめる。
func TestRespondRDEcho(t *testing.T) {
	for _, rd := range []bool{true, false} {
		msg, err := Respond(buildQuery(qopt{name: "ollama.tanaka.mesh", rd: rd}), testResolver(), 30)
		if err != nil {
			t.Fatalf("Respond: %v", err)
		}
		if h := parseHeader(t, msg); h.rd != rd || h.ra {
			t.Errorf("rd=%v ra=%v, want rd=%v ra=false", h.rd, h.ra, rd)
		}
	}
}

// TestRespondHeaderOnlyRDEcho は質問をエコーできない応答でも RD を引き継ぐことを確かめる。
func TestRespondHeaderOnlyRDEcho(t *testing.T) {
	msg, err := Respond(buildQuery(qopt{opcode: 2, rd: true}), testResolver(), 30)
	if err != nil {
		t.Fatalf("Respond: %v", err)
	}
	if h := parseHeader(t, msg); !h.rd || h.qdcount != 0 {
		t.Errorf("rd=%v qd=%d, want rd=true qd=0", h.rd, h.qdcount)
	}
}

func TestRdataFor(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.1")
	v6 := netip.MustParseAddr("fd00::1")
	v4in6 := netip.MustParseAddr("::ffff:10.0.0.1")

	cases := []struct {
		name string
		t    Type
		addr netip.Addr
		len  int
		ok   bool
	}{
		{"A/IPv4", TypeA, v4, 4, true},
		{"AAAA/IPv6", TypeAAAA, v6, 16, true},
		{"A/IPv6 は不一致", TypeA, v6, 0, false},
		{"AAAA/IPv4 は不一致", TypeAAAA, v4, 0, false},
		{"AAAA/IPv4射影は不一致", TypeAAAA, v4in6, 0, false},
		{"未対応種別", Type(33), v4, 0, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rdata, ok := rdataFor(c.t, c.addr)
			if ok != c.ok || len(rdata) != c.len {
				t.Errorf("rdata=%d バイト ok=%v, want %d バイト ok=%v", len(rdata), ok, c.len, c.ok)
			}
		})
	}
}
