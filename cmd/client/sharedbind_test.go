package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/instantmesh/instantmesh/pkg/stun"
	"github.com/instantmesh/instantmesh/pkg/stunmux"
)

// fakeEndpoint は conn.Endpoint の最小実装。
type fakeEndpoint struct{}

func (fakeEndpoint) ClearSrc()           {}
func (fakeEndpoint) SrcToString() string { return "" }
func (fakeEndpoint) DstToString() string { return "" }
func (fakeEndpoint) DstToBytes() []byte  { return nil }
func (fakeEndpoint) DstIP() netip.Addr   { return netip.Addr{} }
func (fakeEndpoint) SrcIP() netip.Addr   { return netip.Addr{} }

// fakeBind は conn.Bind のテスト実装。
type fakeBind struct {
	fns      []conn.ReceiveFunc
	openErr  error
	sendErr  error
	parseErr error
	sent     [][]byte
	onSend   func(bufs [][]byte)
}

func (f *fakeBind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	if f.openErr != nil {
		return nil, 0, f.openErr
	}
	return f.fns, 51820, nil
}

func (f *fakeBind) Close() error         { return nil }
func (f *fakeBind) SetMark(uint32) error { return nil }

func (f *fakeBind) Send(bufs [][]byte, _ conn.Endpoint) error {
	if f.sendErr != nil {
		return f.sendErr
	}
	for _, b := range bufs {
		f.sent = append(f.sent, append([]byte(nil), b...))
	}
	if f.onSend != nil {
		f.onSend(bufs)
	}
	return nil
}

func (f *fakeBind) ParseEndpoint(string) (conn.Endpoint, error) {
	if f.parseErr != nil {
		return nil, f.parseErr
	}
	return fakeEndpoint{}, nil
}

func (f *fakeBind) BatchSize() int { return 1 }

// buildSuccess は tx・addr（IPv4）に対応する STUN Binding Success Response を組み立てる。
func buildSuccess(tx stun.TxID, addr netip.AddrPort) []byte {
	const magic = 0x2112A442
	ip := addr.Addr().As4()
	val := make([]byte, 8)
	val[1] = 0x01 // IPv4
	binary.BigEndian.PutUint16(val[2:4], addr.Port()^uint16(magic>>16))
	binary.BigEndian.PutUint32(val[4:8], binary.BigEndian.Uint32(ip[:])^magic)

	attr := make([]byte, 4+len(val))
	binary.BigEndian.PutUint16(attr[0:2], 0x0020) // XOR-MAPPED-ADDRESS
	binary.BigEndian.PutUint16(attr[2:4], uint16(len(val)))
	copy(attr[4:], val)

	buf := make([]byte, 20)
	binary.BigEndian.PutUint16(buf[0:2], 0x0101) // Binding Success
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(attr)))
	binary.BigEndian.PutUint32(buf[4:8], magic)
	copy(buf[8:20], tx[:])
	return append(buf, attr...)
}

func TestSharedBindOpenFiltersSTUN(t *testing.T) {
	wgPkt := []byte{0x04, 0x00, 0x00, 0x00, 0xde, 0xad}
	stunReq, _, err := stun.NewRequest() // STUN メッセージ（進行中トランザクションなし → 消費される）
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	// 元の受信関数: [STUN, WG] の 2 パケットを返す。
	src := func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		sizes[0] = copy(packets[0], stunReq)
		sizes[1] = copy(packets[1], wgPkt)
		eps[0], eps[1] = fakeEndpoint{}, fakeEndpoint{}
		return 2, nil
	}
	sb := &sharedBind{Bind: &fakeBind{fns: []conn.ReceiveFunc{src}}, mux: stunmux.New()}
	fns, port, err := sb.Open(0)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if port != 51820 {
		t.Errorf("actualPort = %d want 51820", port)
	}

	packets := [][]byte{make([]byte, 1500), make([]byte, 1500)}
	sizes := make([]int, 2)
	eps := make([]conn.Endpoint, 2)
	n, err := fns[0](packets, sizes, eps)
	if err != nil {
		t.Fatalf("receive: %v", err)
	}
	if n != 1 {
		t.Fatalf("WireGuard へ渡す件数 = %d want 1（STUN は除外）", n)
	}
	if !bytes.Equal(packets[0][:sizes[0]], wgPkt) {
		t.Errorf("残ったパケット = %x want %x", packets[0][:sizes[0]], wgPkt)
	}
}

func TestSharedBindOpenError(t *testing.T) {
	sb := &sharedBind{Bind: &fakeBind{openErr: errors.New("bind failed")}, mux: stunmux.New()}
	if _, _, err := sb.Open(0); err == nil {
		t.Error("基底 Bind の Open 失敗はエラーになるべき")
	}
}

func TestDiscoverWANSuccess(t *testing.T) {
	want := netip.MustParseAddrPort("203.0.113.5:41641")
	fb := &fakeBind{}
	sb := &sharedBind{Bind: fb, mux: stunmux.New()}
	// Send されたら、そのリクエストの TxID で応答を作り受信をシミュレートする。
	fb.onSend = func(bufs [][]byte) {
		tx, ok := stun.MessageTxID(bufs[0])
		if !ok {
			t.Error("送信されたのは STUN Binding Request であるべき")
			return
		}
		go sb.mux.Consume(buildSuccess(tx, want))
	}
	got, err := sb.DiscoverWAN("192.0.2.1:3478", time.Second)
	if err != nil {
		t.Fatalf("DiscoverWAN: %v", err)
	}
	if got != want {
		t.Errorf("WAN = %v want %v", got, want)
	}
}

func TestDiscoverWANTimeout(t *testing.T) {
	sb := &sharedBind{Bind: &fakeBind{}, mux: stunmux.New()}
	if _, err := sb.DiscoverWAN("192.0.2.1:3478", 10*time.Millisecond); !errors.Is(err, errSTUNTimeout) {
		t.Errorf("応答が無ければタイムアウトすべき: got %v", err)
	}
}

func TestDiscoverWANErrors(t *testing.T) {
	// STUN サーバーアドレスがポート欠落で解決不能。
	sb := &sharedBind{Bind: &fakeBind{}, mux: stunmux.New()}
	if _, err := sb.DiscoverWAN("no-port", time.Second); err == nil {
		t.Error("解決不能なアドレスはエラーになるべき")
	}

	// ParseEndpoint 失敗。
	sbParse := &sharedBind{Bind: &fakeBind{parseErr: errors.New("bad ep")}, mux: stunmux.New()}
	if _, err := sbParse.DiscoverWAN("192.0.2.1:3478", time.Second); err == nil {
		t.Error("ParseEndpoint 失敗はエラーになるべき")
	}

	// Send 失敗。
	sbSend := &sharedBind{Bind: &fakeBind{sendErr: errors.New("no route")}, mux: stunmux.New()}
	if _, err := sbSend.DiscoverWAN("192.0.2.1:3478", time.Second); err == nil {
		t.Error("Send 失敗はエラーになるべき")
	}
}
