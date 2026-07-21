package main

import (
	"net"
	"sync"
	"testing"
	"time"
)

// fakeRelayTransport は relayTransport のテスト実装。送出フレームをチャネルへ流し、Close を記録する。
type fakeRelayTransport struct {
	sent   chan sentFrame
	mu     sync.Mutex
	closed bool
}

type sentFrame struct {
	dst     string
	payload []byte
}

func newFakeRelayTransport() *fakeRelayTransport {
	return &fakeRelayTransport{sent: make(chan sentFrame, 8)}
}

func (f *fakeRelayTransport) Send(dst string, payload []byte) error {
	f.sent <- sentFrame{dst: dst, payload: append([]byte(nil), payload...)}
	return nil
}

func (f *fakeRelayTransport) Close() error {
	f.mu.Lock()
	f.closed = true
	f.mu.Unlock()
	return nil
}

func (f *fakeRelayTransport) isClosed() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.closed
}

// newFakeWG はループバック UDP ソケット（WG の待受を模す）を返す。
func newFakeWG(t *testing.T) (*net.UDPConn, uint16) {
	t.Helper()
	wg, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("fake WG socket: %v", err)
	}
	return wg, uint16(wg.LocalAddr().(*net.UDPAddr).Port)
}

func TestRelayProxyBridgesBothDirections(t *testing.T) {
	wg, wgPort := newFakeWG(t)
	defer wg.Close()
	ft := newFakeRelayTransport()
	p := newRelayProxy(ft, wgPort)
	defer p.Close()

	epStr, err := p.Endpoint("peerX")
	if err != nil {
		t.Fatalf("Endpoint: %v", err)
	}
	epAddr, err := net.ResolveUDPAddr("udp4", epStr)
	if err != nil {
		t.Fatalf("resolve ep: %v", err)
	}

	// WG→relay: WG がループバックエンドポイントへ送ったパケットはリレーへ転送される。
	if _, err := wg.WriteToUDP([]byte("from-wg"), epAddr); err != nil {
		t.Fatalf("wg write: %v", err)
	}
	select {
	case f := <-ft.sent:
		if f.dst != "peerX" || string(f.payload) != "from-wg" {
			t.Fatalf("転送フレーム不正: dst=%q payload=%q", f.dst, f.payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WG→relay の転送が届かない")
	}

	// relay→WG: リレー受信は同ソケットから WG 待受へ書き戻され、送信元はループバックエンドポイント。
	p.Deliver("peerX", []byte("to-wg"))
	buf := make([]byte, 1500)
	_ = wg.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, src, err := wg.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("wg read: %v", err)
	}
	if string(buf[:n]) != "to-wg" {
		t.Errorf("WG 受信 = %q want to-wg", buf[:n])
	}
	if src.String() != epStr {
		t.Errorf("WG 受信の送信元 = %v want %v（ループバックエンドポイント）", src, epStr)
	}
}

func TestRelayProxyEndpointIdempotent(t *testing.T) {
	_, wgPort := newFakeWG(t)
	p := newRelayProxy(newFakeRelayTransport(), wgPort)
	defer p.Close()
	ep1, err := p.Endpoint("peerX")
	if err != nil {
		t.Fatal(err)
	}
	ep2, err := p.Endpoint("peerX")
	if err != nil {
		t.Fatal(err)
	}
	if ep1 != ep2 {
		t.Errorf("同一ピアの Endpoint は同じアドレスを返すべき: %q != %q", ep1, ep2)
	}
}

func TestRelayProxyDeliverUnknownPeer(t *testing.T) {
	_, wgPort := newFakeWG(t)
	p := newRelayProxy(newFakeRelayTransport(), wgPort)
	defer p.Close()
	// リンク未登録のピアへの Deliver はパニックせず捨てられる。
	p.Deliver("unknown", []byte("dropped"))
}

func TestRelayProxyRemove(t *testing.T) {
	_, wgPort := newFakeWG(t)
	p := newRelayProxy(newFakeRelayTransport(), wgPort)
	defer p.Close()
	if _, err := p.Endpoint("peerX"); err != nil {
		t.Fatal(err)
	}
	p.Remove("peerX")   // ソケットを閉じ readLoop を終了させる。
	p.Remove("peerX")   // 冪等（不在でもパニックしない）。
	// Remove 後は新規リンクとして再作成される（別アドレスになり得るがエラーにならないこと）。
	if _, err := p.Endpoint("peerX"); err != nil {
		t.Fatalf("Remove 後の Endpoint 再作成: %v", err)
	}
}

func TestRelayProxyClose(t *testing.T) {
	_, wgPort := newFakeWG(t)
	ft := newFakeRelayTransport()
	p := newRelayProxy(ft, wgPort)
	if _, err := p.Endpoint("peerX"); err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !ft.isClosed() {
		t.Error("Close はトランスポートも閉じるべき")
	}
	if err := p.Close(); err != nil {
		t.Errorf("Close は冪等であるべき: %v", err)
	}
	// クローズ後の Endpoint はエラー。
	if _, err := p.Endpoint("peerY"); err != errRelayProxyClosed {
		t.Errorf("クローズ後の Endpoint は errRelayProxyClosed, got %v", err)
	}
}
