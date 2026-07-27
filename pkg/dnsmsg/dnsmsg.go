// Package dnsmsg は DNS メッセージ（RFC 1035）の解析と応答組み立てを行う純粋ロジック。
//
// メッシュ名前空間のローカルレスポンダ（要件定義書 §4.6.3）の中核で、pkg/stun と同じ分割に従う
// ——メッセージのバイト列を扱うのは本パッケージ、UDP ソケットと OS への split DNS 注入は
// cmd/client（§4.6.5）。名前と解決先の対応は Resolver 越しに与えられるため、本パッケージは
// メッシュや製品固有の知識を持たない。
//
// 対応範囲は「権威サーバーとして自ゾーンの A / AAAA に答える」ことに絞る。再帰は行わず（RA=0）、
// 権威外の名前は REFUSED を返す。EDNS(0) は解釈せず OPT も返さない（RFC 6891 のとおり、
// 問い合わせ側は「レスポンダが EDNS 非対応」として扱う）。応答は常に 512 バイト未満に収まるため
// 切り詰め（TC）も発生しない。DNS over TCP は扱わない（stub リゾルバは UDP を先に使う）。
package dnsmsg

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// メッセージ構造の定数。
const (
	// HeaderLen は DNS ヘッダの長さ。
	HeaderLen = 12
	// maxLabelLen / maxNameLen は名前の長さ制限（RFC 1035）。
	maxLabelLen = 63
	maxNameLen  = 253
	// questionOffset は質問セクションの開始オフセット。回答の NAME はここへの圧縮ポインタで表す。
	questionOffset = HeaderLen
)

// Type は RR 種別（QTYPE）。
type Type uint16

// 扱う RR 種別。
const (
	// TypeA は IPv4 アドレス。
	TypeA Type = 1
	// TypeAAAA は IPv6 アドレス。
	TypeAAAA Type = 28
)

// Class は RR クラス（QCLASS）。
type Class uint16

// ClassIN はインターネットクラス。これ以外は扱わない。
const ClassIN Class = 1

// RCode は応答コード。
type RCode uint8

// 応答コード（RFC 1035 §4.1.1）。
const (
	// RCodeSuccess は正常応答（回答が 0 件でも名前自体は存在する）。
	RCodeSuccess RCode = 0
	// RCodeFormatError はクエリの書式が解釈できない。
	RCodeFormatError RCode = 1
	// RCodeNameError は名前が存在しない（NXDOMAIN）。
	RCodeNameError RCode = 3
	// RCodeNotImplemented は未対応のクエリ種別（OPCODE / CLASS）。
	RCodeNotImplemented RCode = 4
	// RCodeRefused は権威外のため応答を拒否した。
	RCodeRefused RCode = 5
)

// エラー。ErrShort / ErrNotQuery は「応答を返してはいけない」入力を表し、それ以外は
// 相応の RCODE を持つ応答を組み立てられる。
var (
	// ErrShort はヘッダ長に満たない入力。
	ErrShort = errors.New("dnsmsg: message shorter than header")
	// ErrNotQuery は QR=1（応答メッセージ）。応答に応答を返すと増幅の踏み台になるため破棄する。
	ErrNotQuery = errors.New("dnsmsg: not a query")
	// ErrUnsupportedOpcode は QUERY 以外の OPCODE。
	ErrUnsupportedOpcode = errors.New("dnsmsg: unsupported opcode")
	// ErrMalformed は質問セクションが解釈できない。
	ErrMalformed = errors.New("dnsmsg: malformed question")
	// ErrCompressedName は質問セクションに圧縮ポインタが含まれる。クエリ側に圧縮の必要は無く、
	// ポインタは無限ループの原因になりうるため受け付けない。
	ErrCompressedName = errors.New("dnsmsg: compression pointer in question")
)

// Query は解析済みのクエリ 1 件（質問は 1 問に限る）。
type Query struct {
	// ID はトランザクション ID。応答でそのまま返す。
	ID uint16
	// RD は再帰要求ビット。応答へエコーする（RA=0 なので実際に再帰はしない）。
	RD bool
	// Name は問い合わせ名（末尾ドット無し・クエリの大文字小文字のまま）。
	Name string
	// Type / Class は QTYPE / QCLASS。
	Type  Type
	Class Class

	// question は質問セクションの生バイト。応答へは再符号化せずこれをそのまま echo する。
	// DNS 0x20（大文字小文字をランダム化して応答の一致を検証する手法）を使うリゾルバに対し、
	// 問い合わせと 1 バイトも違わない質問を返すため。入力バッファの再利用に備えてコピー済み。
	question []byte
}

// Resolver は名前に対する権威判定と解決を与える（実装例: pkg/meshname.Zone）。
type Resolver interface {
	// Authoritative は当該名前について自身が権威かを返す。false なら REFUSED を返す。
	Authoritative(name string) bool
	// Lookup は名前に対応するアドレスを返す。未登録は ok=false（NXDOMAIN）。
	Lookup(name string) (netip.Addr, bool)
}

// ParseQuery は受信したバイト列を 1 問のクエリとして解析する。
func ParseQuery(b []byte) (Query, error) {
	if len(b) < HeaderLen {
		return Query{}, ErrShort
	}
	flags := binary.BigEndian.Uint16(b[2:4])
	if flags&0x8000 != 0 {
		return Query{}, ErrNotQuery
	}
	if opcode := (flags >> 11) & 0x0F; opcode != 0 {
		return Query{}, fmt.Errorf("dnsmsg: opcode %d: %w", opcode, ErrUnsupportedOpcode)
	}
	if qdcount := binary.BigEndian.Uint16(b[4:6]); qdcount != 1 {
		return Query{}, fmt.Errorf("dnsmsg: qdcount %d: %w", qdcount, ErrMalformed)
	}
	name, off, err := parseName(b, questionOffset)
	if err != nil {
		return Query{}, err
	}
	if off+4 > len(b) {
		return Query{}, ErrMalformed
	}
	question := make([]byte, off+4-questionOffset)
	copy(question, b[questionOffset:off+4])
	return Query{
		ID:       binary.BigEndian.Uint16(b[0:2]),
		RD:       flags&0x0100 != 0,
		Name:     name,
		Type:     Type(binary.BigEndian.Uint16(b[off : off+2])),
		Class:    Class(binary.BigEndian.Uint16(b[off+2 : off+4])),
		question: question,
	}, nil
}

// parseName は off から始まる QNAME を読み、ドット区切りの名前（末尾ドット無し）と
// 次のオフセットを返す。ルート（`.`）は空文字になる。
func parseName(b []byte, off int) (string, int, error) {
	var sb strings.Builder
	for {
		if off >= len(b) {
			return "", 0, ErrMalformed
		}
		n := int(b[off])
		off++
		if n == 0 {
			return sb.String(), off, nil
		}
		switch n & 0xC0 {
		case 0x00: // 通常ラベル
		case 0xC0:
			return "", 0, ErrCompressedName
		default: // 0x40 / 0x80 は予約済み
			return "", 0, ErrMalformed
		}
		if off+n > len(b) || sb.Len()+n+1 > maxNameLen {
			return "", 0, ErrMalformed
		}
		if sb.Len() > 0 {
			sb.WriteByte('.')
		}
		sb.Write(b[off : off+n])
		off += n
	}
}

// Respond はクエリのバイト列から応答のバイト列を組み立てる。ttl は回答に載せる TTL（秒）。
//
// 応答を返してはいけない入力（ヘッダ長未満・QR=1）では nil とエラーを返すので、呼び出し側は
// 黙って破棄する。それ以外の不正なクエリには FORMERR / NOTIMP を返す。
func Respond(query []byte, r Resolver, ttl uint32) ([]byte, error) {
	q, err := ParseQuery(query)
	if err != nil {
		switch {
		case errors.Is(err, ErrShort), errors.Is(err, ErrNotQuery):
			return nil, err
		case errors.Is(err, ErrUnsupportedOpcode):
			return headerOnly(query, RCodeNotImplemented), nil
		default:
			// 質問セクションを解釈できないので QDCOUNT=0 のヘッダのみで書式エラーを返す。
			return headerOnly(query, RCodeFormatError), nil
		}
	}
	switch {
	case q.Class != ClassIN:
		return q.reply(RCodeNotImplemented, false, nil), nil
	case !r.Authoritative(q.Name):
		// 権威外。オープンリゾルバとして振る舞わないため、転送も再帰もせず拒否する。
		return q.reply(RCodeRefused, false, nil), nil
	}
	addr, ok := r.Lookup(q.Name)
	if !ok {
		return q.reply(RCodeNameError, true, nil), nil
	}
	rdata, ok := rdataFor(q.Type, addr)
	if !ok {
		// 名前は存在するが当該種別の記録が無い（例: IPv4 のみのピアへの AAAA 問い合わせ）。
		// NXDOMAIN ではなく回答 0 件の NOERROR を返すのが正しい（RFC 2308 の NODATA）。
		return q.reply(RCodeSuccess, true, nil), nil
	}
	return q.reply(RCodeSuccess, true, answerRR(q.Type, ttl, rdata)), nil
}

// rdataFor は問い合わせ種別とアドレスの組から RDATA を返す。種別とアドレス族が食い違う場合は ok=false。
func rdataFor(t Type, addr netip.Addr) ([]byte, bool) {
	switch {
	case t == TypeA && addr.Is4():
		a := addr.As4()
		return a[:], true
	case t == TypeAAAA && addr.Is6() && !addr.Is4In6():
		a := addr.As16()
		return a[:], true
	}
	return nil, false
}

// answerRR は回答レコード 1 件を組み立てる。NAME は質問セクション先頭への圧縮ポインタで表す
// （質問は必ずヘッダ直後に置かれるためオフセットは常に 12）。
func answerRR(t Type, ttl uint32, rdata []byte) []byte {
	rr := make([]byte, 0, 12+len(rdata))
	rr = append(rr, 0xC0, byte(questionOffset))
	rr = binary.BigEndian.AppendUint16(rr, uint16(t))
	rr = binary.BigEndian.AppendUint16(rr, uint16(ClassIN))
	rr = binary.BigEndian.AppendUint32(rr, ttl)
	rr = binary.BigEndian.AppendUint16(rr, uint16(len(rdata)))
	return append(rr, rdata...)
}

// reply は質問をエコーした応答を組み立てる。aa は権威応答フラグ（権威外の拒否では下ろす）。
func (q Query) reply(rcode RCode, aa bool, answer []byte) []byte {
	return buildMessage(q.ID, q.RD, aa, rcode, q.question, answer)
}

// headerOnly は質問をエコーできない場合（解析不能なクエリ）の応答を組み立てる。
// 呼び出し時点で len(query) >= HeaderLen が保証されている。
func headerOnly(query []byte, rcode RCode) []byte {
	id := binary.BigEndian.Uint16(query[0:2])
	rd := binary.BigEndian.Uint16(query[2:4])&0x0100 != 0
	return buildMessage(id, rd, false, rcode, nil, nil)
}

// buildMessage はヘッダ・質問・回答を連結した応答メッセージを返す。RA は常に 0（再帰しない）。
func buildMessage(id uint16, rd, aa bool, rcode RCode, question, answer []byte) []byte {
	flags := uint16(0x8000) // QR=1
	if aa {
		flags |= 0x0400
	}
	if rd {
		flags |= 0x0100
	}
	flags |= uint16(rcode) & 0x000F

	var qdcount, ancount uint16
	if len(question) > 0 {
		qdcount = 1
	}
	if len(answer) > 0 {
		ancount = 1
	}

	msg := make([]byte, 0, HeaderLen+len(question)+len(answer))
	msg = binary.BigEndian.AppendUint16(msg, id)
	msg = binary.BigEndian.AppendUint16(msg, flags)
	msg = binary.BigEndian.AppendUint16(msg, qdcount)
	msg = binary.BigEndian.AppendUint16(msg, ancount)
	msg = binary.BigEndian.AppendUint16(msg, 0) // NSCOUNT
	msg = binary.BigEndian.AppendUint16(msg, 0) // ARCOUNT（OPT を返さない）
	msg = append(msg, question...)
	return append(msg, answer...)
}
