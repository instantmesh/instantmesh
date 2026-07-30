package main

import (
	"context"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/accesskey"
	"github.com/instantmesh/instantmesh/pkg/usage"
)

// echoService は転送先に見立てたローカルサービス（受け取った行をそのまま返す）。
func echoService(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				_, _ = io.Copy(c, c)
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln
}

// TestForwarderRelays は待受→転送先の双方向中継が成立することを確かめる
// （ホスト側の「メッシュIP:ポート → 127.0.0.1:ポート」と同じ経路。要件 §4.6.2 の前提）。
func TestForwarderRelays(t *testing.T) {
	svc := echoService(t)
	f, err := startForwarder(netip.MustParseAddrPort("127.0.0.1:0"), svc.Addr().String(), net.Dial)
	if err != nil {
		t.Fatalf("startForwarder: %v", err)
	}
	defer f.close()

	c, err := net.Dial("tcp", f.addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))

	if _, err := io.WriteString(c, "ping\n"); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 5)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "ping\n" {
		t.Errorf("受信 = %q, want %q", buf, "ping\n")
	}
}

// TestForwarderCloseReleasesPort は共有停止で待受ポートが直ちに解放されることを確かめる
// （ホストが元ポートを占有し続けないこと・要件 §4.6.4 の即時解放）。
func TestForwarderCloseReleasesPort(t *testing.T) {
	svc := echoService(t)
	f, err := startForwarder(netip.MustParseAddrPort("127.0.0.1:0"), svc.Addr().String(), net.Dial)
	if err != nil {
		t.Fatalf("startForwarder: %v", err)
	}
	addr := f.addr().String()
	// 確立済み接続がある状態で閉じても、リスナーと接続の双方が解放される。
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	f.close()

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		t.Fatalf("解放後に同じアドレスを bind できない: %v", err)
	}
	_ = ln.Close()
}

// TestForwarderTargetUnreachable は転送先へ繋がらない場合に受け側を閉じることを確かめる。
func TestForwarderTargetUnreachable(t *testing.T) {
	// 誰も待ち受けていないアドレスを転送先にする。
	dead := echoService(t)
	target := dead.Addr().String()
	_ = dead.Close()

	f, err := startForwarder(netip.MustParseAddrPort("127.0.0.1:0"), target, net.Dial)
	if err != nil {
		t.Fatalf("startForwarder: %v", err)
	}
	defer f.close()

	c, err := net.Dial("tcp", f.addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer c.Close()
	_ = c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadAll(c); err != nil {
		t.Errorf("転送先へ繋がらない場合は EOF で閉じるべき: %v", err)
	}
}

// TestServiceForwarderApply は共有ポート集合の差分適用（開始・停止）を確かめる。
func TestServiceForwarderApply(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := echoService(t)
	sf := newServiceForwarder(ctx, netip.MustParseAddr("127.0.0.1"))
	// 転送先はテスト用のエコーサービスへ固定する（実運用は localhost:<同じポート>）。
	sf.targetFor = func(int) string { return svc.Addr().String() }

	port := freePort(t)
	sf.apply([]int{port})
	assertReachable(t, port, true)

	// 共有から外すと直ちに解放される。
	sf.apply(nil)
	assertReachable(t, port, false)

	// 再共有できる。
	sf.apply([]int{port})
	assertReachable(t, port, true)

	// ctx 終了で全解放（closeAll 経由）。
	cancel()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ln, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port))); err == nil {
			_ = ln.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("ctx 終了後も待受が解放されていない")
}

// TestServiceForwarderSkipsBoundPort は、サービス自身が既に待ち受けていて bind できない場合に
// 転送を諦めて先へ進むことを確かめる（その場合は直接到達できるため転送は不要）。
func TestServiceForwarderSkipsBoundPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 対象ポートを別プロセス相当（同一アドレス）で占有しておく。
	occupied := echoService(t)
	port := occupied.Addr().(*net.TCPAddr).Port

	sf := newServiceForwarder(ctx, netip.MustParseAddr("127.0.0.1"))
	sf.targetFor = func(int) string { return occupied.Addr().String() }
	sf.apply([]int{port})

	if _, ok := sf.set.listenerFor(port); ok {
		t.Error("bind できないポートを転送対象にした")
	}
}

// TestServiceForwarderSetGate は待受の性質が変わるとき（生 TCP 転送 ⇄ HTTP プロキシ）だけ
// 張り替え、同じ性質のままなら継続中の待受を切らないことを確かめる。
//
// ゲートの設定変更（キー要求の切替）でここを通らないのは、l7Gate が長命な 1 個で各リクエストが
// 現在値を読むため（張り替え不要）。その挙動は TestHTTPProxyRequireKeyTakesEffectLive が見る。
func TestServiceForwarderSetGate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	svc := echoService(t)
	sf := newServiceForwarder(ctx, netip.MustParseAddr("127.0.0.1"))
	sf.targetFor = func(int) string { return svc.Addr().String() }

	port := freePort(t)
	sf.apply([]int{port})
	first, ok := sf.set.listenerFor(port)
	if !ok {
		t.Fatal("待受が開いていない")
	}

	// 生 TCP 転送 → HTTP プロキシ。待受は閉じ、次の apply で開き直る。
	gate := &l7Gate{keys: accesskey.New(), rec: usage.New(), now: time.Now}
	sf.setGate(gate)
	if _, ok := sf.set.listenerFor(port); ok {
		t.Error("ゲート切替で待受が閉じていない")
	}
	sf.apply([]int{port})
	second, ok := sf.set.listenerFor(port)
	if !ok {
		t.Fatal("張り替え後に待受が開いていない")
	}
	if second == first {
		t.Error("HTTP プロキシへ張り替わっていない")
	}

	// 同じゲートを再設定しても張り替えない（継続中の接続を切らない）。
	sf.setGate(gate)
	again, ok := sf.set.listenerFor(port)
	if !ok || again != second {
		t.Error("性質が変わらないのに張り替えた")
	}
}

// TestServiceForwarderNilSafe は転送無効（-tunnel 無効）時に nil レシーバで呼んでも安全なことを確かめる。
func TestServiceForwarderNilSafe(t *testing.T) {
	var sf *serviceForwarder
	sf.apply([]int{11434})
	sf.setGate(nil)
	sf.closeAll()
}

// freePort は誰も使っていないポート番号を返す。
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	_ = ln.Close()
	return port
}

// assertReachable は 127.0.0.1:port へ接続できるか（＝転送が動いているか）を検査する。
func assertReachable(t *testing.T, port int, want bool) {
	t.Helper()
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), time.Second)
	if err == nil {
		_ = c.Close()
	}
	if got := err == nil; got != want {
		t.Errorf("到達性 = %v, want %v (err=%v)", got, want, err)
	}
}
