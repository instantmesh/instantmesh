package stun

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"
)

var zeroTx TxID

// buildResponse は指定種別・cookie・txID・属性列でメッセージを組み立てる。
func buildResponse(typ uint16, cookie uint32, tx TxID, attrs []byte) []byte {
	buf := make([]byte, headerLen+len(attrs))
	binary.BigEndian.PutUint16(buf[0:2], typ)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(attrs)))
	binary.BigEndian.PutUint32(buf[4:8], cookie)
	copy(buf[8:20], tx[:])
	copy(buf[20:], attrs)
	return buf
}

// attr は 1 属性（TLV、値を 4 バイト境界へパディング）を組み立てる。
func attr(atype uint16, val []byte) []byte {
	out := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(out[0:2], atype)
	binary.BigEndian.PutUint16(out[2:4], uint16(len(val)))
	copy(out[4:], val)
	for len(out)%4 != 0 {
		out = append(out, 0)
	}
	return out
}

// ipv4XorValue は 192.0.2.1:32853 を手計算した XOR-MAPPED-ADDRESS 値（cookie=0x2112A442）。
//
//	X-Port    = 0x8055(32853) ^ 0x2112 = 0xA147
//	X-Address = 0xC0000201 ^ 0x2112A442 = 0xE112A643
var ipv4XorValue = []byte{0x00, familyIPv4, 0xA1, 0x47, 0xE1, 0x12, 0xA6, 0x43}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func TestNewRequest(t *testing.T) {
	data, tx, err := NewRequest()
	if err != nil {
		t.Fatalf("NewRequest エラー: %v", err)
	}
	if len(data) != headerLen {
		t.Fatalf("長さ = %d, want %d", len(data), headerLen)
	}
	if binary.BigEndian.Uint16(data[0:2]) != bindingRequest {
		t.Error("種別は Binding Request であるべき")
	}
	if binary.BigEndian.Uint16(data[2:4]) != 0 {
		t.Error("属性なしのため長さは 0 であるべき")
	}
	if binary.BigEndian.Uint32(data[4:8]) != magicCookie {
		t.Error("magic cookie が不正")
	}
	if !bytes.Equal(data[8:20], tx[:]) {
		t.Error("ヘッダの txID が返り値と一致すべき")
	}
}

func TestNewRequestEntropyFailure(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = errReader{}
	if _, _, err := NewRequest(); err == nil {
		t.Error("乱数源の失敗はエラーになるべき")
	}
}

func TestParseResponseIPv4(t *testing.T) {
	resp := buildResponse(bindingSuccess, magicCookie, zeroTx, attr(attrXorMappedAddress, ipv4XorValue))
	got, err := ParseResponse(resp, zeroTx)
	if err != nil {
		t.Fatalf("ParseResponse エラー: %v", err)
	}
	if want := netip.MustParseAddrPort("192.0.2.1:32853"); got != want {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestParseResponseIPv6(t *testing.T) {
	// 2001:db8::1 を zeroTx で XOR（先頭4バイトのみ cookie と XOR、残りは不変）。
	xaddr := []byte{0x01, 0x13, 0xa9, 0xfa, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01}
	val := append([]byte{0x00, familyIPv6, 0xA1, 0x47}, xaddr...)
	resp := buildResponse(bindingSuccess, magicCookie, zeroTx, attr(attrXorMappedAddress, val))
	got, err := ParseResponse(resp, zeroTx)
	if err != nil {
		t.Fatalf("ParseResponse エラー: %v", err)
	}
	if want := netip.MustParseAddrPort("[2001:db8::1]:32853"); got != want {
		t.Errorf("got %v want %v", got, want)
	}
}

func TestParseResponseSkipsAttrsWithPadding(t *testing.T) {
	// XOR-MAPPED-ADDRESS の前にパディングを要する属性（3バイト）を置く。
	software := attr(0x8022, []byte("abc"))
	xm := attr(attrXorMappedAddress, ipv4XorValue)
	resp := buildResponse(bindingSuccess, magicCookie, zeroTx, append(software, xm...))
	got, err := ParseResponse(resp, zeroTx)
	if err != nil {
		t.Fatalf("ParseResponse エラー: %v", err)
	}
	if got != netip.MustParseAddrPort("192.0.2.1:32853") {
		t.Errorf("got %v", got)
	}
}

func TestParseResponseUnpaddedTail(t *testing.T) {
	// 末尾属性が 4 バイト境界に満たない（パディング欠落）→ 走査を打ち切り ErrNoAddress。
	bad := []byte{0x80, 0x22, 0x00, 0x03, 'a', 'b', 'c'}
	resp := buildResponse(bindingSuccess, magicCookie, zeroTx, bad)
	if _, err := ParseResponse(resp, zeroTx); !errors.Is(err, ErrNoAddress) {
		t.Errorf("got %v want ErrNoAddress", err)
	}
}

func TestParseResponseErrors(t *testing.T) {
	valid := attr(attrXorMappedAddress, ipv4XorValue)

	declaredTooLong := buildResponse(bindingSuccess, magicCookie, zeroTx, nil)
	binary.BigEndian.PutUint16(declaredTooLong[2:4], 100) // 実データより長い属性長を宣言

	attrOverflow := buildResponse(bindingSuccess, magicCookie, zeroTx, []byte{0x00, 0x20, 0x00, 0x08, 0xAA, 0xBB}) // len=8 宣言・値2バイト

	tests := []struct {
		name string
		data []byte
		want error
	}{
		{"short header", make([]byte, 10), ErrShort},
		{"not success", buildResponse(bindingRequest, magicCookie, zeroTx, valid), ErrNotSuccess},
		{"bad cookie", buildResponse(bindingSuccess, 0xdeadbeef, zeroTx, valid), ErrBadCookie},
		{"tx mismatch", buildResponse(bindingSuccess, magicCookie, TxID{1, 2, 3}, valid), ErrTxMismatch},
		{"declared len too long", declaredTooLong, ErrShort},
		{"attr len overflow", attrOverflow, ErrShort},
		{"no xor-mapped", buildResponse(bindingSuccess, magicCookie, zeroTx, attr(0x8022, []byte("soft"))), ErrNoAddress},
		{"bad family", buildResponse(bindingSuccess, magicCookie, zeroTx, attr(attrXorMappedAddress, []byte{0x00, 0x09, 0x00, 0x00})), ErrBadFamily},
		{"xor value short", buildResponse(bindingSuccess, magicCookie, zeroTx, attr(attrXorMappedAddress, []byte{0x00, familyIPv4})), ErrShort},
		{"ipv4 addr short", buildResponse(bindingSuccess, magicCookie, zeroTx, attr(attrXorMappedAddress, []byte{0x00, familyIPv4, 0x00, 0x00, 0x01})), ErrShort},
		{"ipv6 addr short", buildResponse(bindingSuccess, magicCookie, zeroTx, attr(attrXorMappedAddress, []byte{0x00, familyIPv6, 0x00, 0x00, 0x01})), ErrShort},
	}
	for _, tt := range tests {
		if _, err := ParseResponse(tt.data, zeroTx); !errors.Is(err, tt.want) {
			t.Errorf("%s: got %v want %v", tt.name, err, tt.want)
		}
	}
}

func TestIsMessage(t *testing.T) {
	valid := buildResponse(bindingSuccess, magicCookie, zeroTx, nil)
	req, _, _ := NewRequest()
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"binding success", valid, true},
		{"binding request", req, true},
		{"too short", make([]byte, 10), false},
		{"bad cookie", buildResponse(bindingSuccess, 0xdeadbeef, zeroTx, nil), false},
		{"high bits set", func() []byte { b := append([]byte(nil), valid...); b[0] |= 0x80; return b }(), false},
		{"wireguard data packet", append([]byte{0x04, 0x00, 0x00, 0x00}, make([]byte, 20)...), false},
	}
	for _, tt := range tests {
		if got := IsMessage(tt.data); got != tt.want {
			t.Errorf("%s: IsMessage = %v want %v", tt.name, got, tt.want)
		}
	}
}

func TestMessageTxID(t *testing.T) {
	want := TxID{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	msg := buildResponse(bindingSuccess, magicCookie, want, nil)
	got, ok := MessageTxID(msg)
	if !ok {
		t.Fatal("STUN メッセージは ok=true を返すべき")
	}
	if got != want {
		t.Errorf("TxID = %v want %v", got, want)
	}
	if _, ok := MessageTxID(make([]byte, 8)); ok {
		t.Error("STUN でないパケットは ok=false を返すべき")
	}
}

// fakePacketConn は PacketConn のテスト実装。
type fakePacketConn struct {
	written  []byte
	writeErr error
	readErr  error
	respFn   func(req []byte) []byte
}

func (c *fakePacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if c.writeErr != nil {
		return 0, c.writeErr
	}
	c.written = append([]byte(nil), p...)
	return len(p), nil
}

func (c *fakePacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if c.readErr != nil {
		return 0, nil, c.readErr
	}
	return copy(p, c.respFn(c.written)), nil, nil
}

func (c *fakePacketConn) SetReadDeadline(time.Time) error { return nil }

func TestDiscover(t *testing.T) {
	fc := &fakePacketConn{respFn: func(req []byte) []byte {
		var tx TxID
		copy(tx[:], req[8:20]) // 要求の txID をエコー
		return buildResponse(bindingSuccess, magicCookie, tx, attr(attrXorMappedAddress, ipv4XorValue))
	}}
	got, err := Discover(fc, &net.UDPAddr{IP: net.IPv4(203, 0, 113, 1), Port: 3478}, time.Second)
	if err != nil {
		t.Fatalf("Discover エラー: %v", err)
	}
	if got != netip.MustParseAddrPort("192.0.2.1:32853") {
		t.Errorf("got %v", got)
	}
	if len(fc.written) != headerLen || binary.BigEndian.Uint16(fc.written[0:2]) != bindingRequest {
		t.Error("Binding Request が送信されるべき")
	}
}

func TestDiscoverErrors(t *testing.T) {
	if _, err := Discover(&fakePacketConn{writeErr: errors.New("no route")}, &net.UDPAddr{}, time.Second); err == nil {
		t.Error("書き込み失敗はエラーになるべき")
	}
	if _, err := Discover(&fakePacketConn{readErr: errors.New("timeout")}, &net.UDPAddr{}, time.Second); err == nil {
		t.Error("読み取り失敗はエラーになるべき")
	}
	garbage := &fakePacketConn{respFn: func([]byte) []byte { return []byte{0, 0, 0} }}
	if _, err := Discover(garbage, &net.UDPAddr{}, time.Second); err == nil {
		t.Error("不正な応答はパースエラーになるべき")
	}
}

func TestDiscoverRequestError(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = errReader{}
	if _, err := Discover(&fakePacketConn{}, &net.UDPAddr{}, time.Second); err == nil {
		t.Error("リクエスト生成失敗はエラーになるべき")
	}
}
