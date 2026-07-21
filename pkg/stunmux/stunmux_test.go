package stunmux

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/stun"
)

const (
	magicCookie   uint32 = 0x2112A442
	bindingResp   uint16 = 0x0101
	attrXorMapped uint16 = 0x0020
	familyIPv4    byte   = 0x01
)

// buildSuccess は tx・addr（IPv4）に対応する Binding Success Response を組み立てる。
func buildSuccess(tx stun.TxID, addr netip.AddrPort) []byte {
	ip := addr.Addr().As4()
	val := make([]byte, 8)
	val[1] = familyIPv4
	binary.BigEndian.PutUint16(val[2:4], addr.Port()^uint16(magicCookie>>16))
	binary.BigEndian.PutUint32(val[4:8], binary.BigEndian.Uint32(ip[:])^magicCookie)

	attr := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(attr[0:2], attrXorMapped)
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(val)))
	copy(attr[4:], val)

	return append(buildHeader(tx, len(attr)), attr...)
}

// buildHeader は属性長 attrLen の Binding Success ヘッダ（20 バイト）を組み立てる。
func buildHeader(tx stun.TxID, attrLen int) []byte {
	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], bindingResp)
	binary.BigEndian.PutUint16(buf[2:4], uint16(attrLen))
	binary.BigEndian.PutUint32(buf[4:8], magicCookie)
	copy(buf[8:20], tx[:])
	return buf
}

func txOf(t *testing.T, req []byte) stun.TxID {
	t.Helper()
	tx, ok := stun.MessageTxID(req)
	if !ok {
		t.Fatal("生成した Binding Request は STUN メッセージであるべき")
	}
	return tx
}

func TestConsumeDeliversResponse(t *testing.T) {
	m := New()
	req, resp, cancel, err := m.Begin()
	if err != nil {
		t.Fatalf("Begin エラー: %v", err)
	}
	defer cancel()

	want := netip.MustParseAddrPort("192.0.2.1:32853")
	if !m.Consume(buildSuccess(txOf(t, req), want)) {
		t.Fatal("進行中トランザクション宛の STUN 応答は消費(true)されるべき")
	}
	select {
	case got := <-resp:
		if got != want {
			t.Errorf("配送アドレス = %v want %v", got, want)
		}
	default:
		t.Fatal("応答がチャネルへ配送されるべき")
	}
}

func TestConsumePassesThroughNonSTUN(t *testing.T) {
	m := New()
	// WireGuard データパケット風（先頭バイト 0x04）は STUN でないため false（パススルー）。
	if m.Consume([]byte{0x04, 0x00, 0x00, 0x00}) {
		t.Error("非 STUN パケットは false（WireGuard へパススルー）を返すべき")
	}
}

func TestConsumeUnknownTransaction(t *testing.T) {
	m := New()
	// Begin していない TxID 宛の応答。STUN なので消費(true)するが配送先は無い。
	if !m.Consume(buildSuccess(stun.TxID{9, 9, 9}, netip.MustParseAddrPort("192.0.2.1:1"))) {
		t.Error("進行中でない STUN 応答も消費(true)されるべき")
	}
}

func TestConsumeMalformedResponse(t *testing.T) {
	m := New()
	req, resp, cancel, err := m.Begin()
	if err != nil {
		t.Fatalf("Begin エラー: %v", err)
	}
	defer cancel()

	// 正しい TxID・cookie の Binding Success だが XOR-MAPPED-ADDRESS を含まない → 解析失敗。
	if !m.Consume(buildHeader(txOf(t, req), 0)) {
		t.Fatal("壊れた STUN 応答も消費(true)されるべき")
	}
	select {
	case <-resp:
		t.Error("解析に失敗した応答は配送されるべきでない")
	default:
	}
}

func TestCancelUnregisters(t *testing.T) {
	m := New()
	req, resp, cancel, err := m.Begin()
	if err != nil {
		t.Fatalf("Begin エラー: %v", err)
	}
	cancel()

	// cancel 後に応答が来ても配送されない（トランザクション登録が解除済み）。
	if !m.Consume(buildSuccess(txOf(t, req), netip.MustParseAddrPort("192.0.2.1:32853"))) {
		t.Fatal("STUN 応答は消費(true)されるべき")
	}
	select {
	case <-resp:
		t.Error("cancel 後は配送されるべきでない")
	default:
	}
}

func TestBeginRequestError(t *testing.T) {
	orig := newRequest
	t.Cleanup(func() { newRequest = orig })
	newRequest = func() ([]byte, stun.TxID, error) {
		return nil, stun.TxID{}, errors.New("no entropy")
	}
	if _, _, _, err := New().Begin(); err == nil {
		t.Error("リクエスト生成失敗はエラーになるべき")
	}
}
