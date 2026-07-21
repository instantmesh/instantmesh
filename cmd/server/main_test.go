package main

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

func testConfig() config {
	return config{
		addr:                "127.0.0.1:0",
		path:                "/ws",
		relayPath:           "/relay",
		maintenanceInterval: time.Hour, // テスト中は発火させない
		shutdownGrace:       time.Second,
		pool:                netip.MustParsePrefix("10.0.0.0/8"),
	}
}

func TestParseFlags(t *testing.T) {
	cfg, err := parseFlags([]string{
		"-addr", "127.0.0.1:9999", "-path", "/sig",
		"-pool", "10.1.0.0/16", "-maintenance-interval", "10s", "-shutdown-grace", "2s",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.addr != "127.0.0.1:9999" || cfg.path != "/sig" {
		t.Errorf("addr/path 不正: %+v", cfg)
	}
	if cfg.maintenanceInterval != 10*time.Second || cfg.shutdownGrace != 2*time.Second {
		t.Errorf("duration 不正: %+v", cfg)
	}
	if cfg.pool.String() != "10.1.0.0/16" {
		t.Errorf("pool = %s, want 10.1.0.0/16", cfg.pool)
	}
}

func TestParseFlagsDefaults(t *testing.T) {
	cfg, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.addr != ":8080" || cfg.path != "/ws" || cfg.pool.String() != "10.0.0.0/8" {
		t.Fatalf("既定値が不正: %+v", cfg)
	}
}

func TestParseFlagsInvalidPool(t *testing.T) {
	if _, err := parseFlags([]string{"-pool", "not-a-prefix"}); err == nil {
		t.Fatal("不正な -pool はエラーになるべき")
	}
}

func TestParseFlagsInvalidFlag(t *testing.T) {
	if _, err := parseFlags([]string{"-nonexistent"}); err == nil {
		t.Fatal("未知フラグはエラーになるべき")
	}
}

func TestBuildServer(t *testing.T) {
	b, err := buildServer(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if b == nil || b.http == nil || b.maint == nil || len(b.closers) != 2 {
		t.Fatalf("builtServer が不完全: %+v", b)
	}
}

func TestBuildServerInvalidPool(t *testing.T) {
	cfg := testConfig()
	cfg.pool = netip.MustParsePrefix("2001:db8::/32") // IPv6 は manager が拒否
	if _, err := buildServer(cfg); err == nil {
		t.Fatal("不正な pool は buildServer エラーになるべき")
	}
}

func TestServeGracefulShutdown(t *testing.T) {
	cfg := testConfig()
	b, err := buildServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serve(ctx, cfg, ln, b) }()

	// 実接続でハンドラが動作することを確認。
	wsURL := "ws://" + ln.Addr().String() + cfg.path
	c, _, err := websocket.DefaultDialer.Dial(wsURL+"?role=host&pubkey="+testHostKey, http.Header{"Authorization": {"Bearer acc-1"}})
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	data, _ := signaling.Encode(signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: 1800})
	if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
		t.Fatal(err)
	}
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, resp, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	env, _ := signaling.Decode(resp)
	if env.Type != signaling.TypeRoomCreated {
		t.Fatalf("room_created を期待, got %s", env.Type)
	}
	_ = c.Close()

	// ctx キャンセル → グレースフルシャットダウンで serve が nil を返す。
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("グレースフルシャットダウンは nil を返すべき: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("serve が終了しない")
	}
}

func TestServeListenerError(t *testing.T) {
	cfg := testConfig()
	b, err := buildServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	_ = ln.Close() // 先に閉じる → Serve が即エラー。

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // メンテナンスゴルーチンを確実に停止。
	if err := serve(ctx, cfg, ln, b); err == nil {
		t.Fatal("閉じたリスナーでは serve がエラーを返すべき")
	}
}

func TestRunGracefulShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- run(ctx, testConfig()) }()

	time.Sleep(50 * time.Millisecond) // listen/serve 起動の猶予。
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run はグレースフルに nil を返すべき: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run が終了しない")
	}
}

func TestRunBuildError(t *testing.T) {
	cfg := testConfig()
	cfg.pool = netip.MustParsePrefix("2001:db8::/32")
	if err := run(context.Background(), cfg); err == nil {
		t.Fatal("buildServer 失敗時 run はエラーを返すべき")
	}
}

func TestRunListenError(t *testing.T) {
	cfg := testConfig()
	cfg.addr = "not-an-address"
	if err := run(context.Background(), cfg); err == nil {
		t.Fatal("net.Listen 失敗時 run はエラーを返すべき")
	}
}
