package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/instantmesh/instantmesh/pkg/manager"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/relayframe"
	"github.com/instantmesh/instantmesh/pkg/relayhub"
	"github.com/instantmesh/instantmesh/pkg/room"
)

// relayAuthorizerFunc はテスト用の関数アダプタ。
type relayAuthorizerFunc func(roomID, pubKey string) (string, plan.Spec, error)

func (f relayAuthorizerFunc) Authorize(roomID, pubKey string) (string, plan.Spec, error) {
	return f(roomID, pubKey)
}

func permissiveRelayAuth() RelayAuthorizer {
	return relayAuthorizerFunc(func(roomID, _ string) (string, plan.Spec, error) {
		if roomID == "" {
			return "", plan.Spec{}, ErrRelayUnauthorized
		}
		return roomID, plan.MustLookup(plan.Free), nil // ルームIDをそのままルームキーに
	})
}

func newTestRelay(t *testing.T, auth RelayAuthorizer) (*RelayServer, string) {
	t.Helper()
	rs := NewRelayServer(relayhub.New(), auth)
	ts := httptest.NewServer(http.HandlerFunc(rs.ServeRelay))
	t.Cleanup(ts.Close)
	return rs, "ws" + strings.TrimPrefix(ts.URL, "http")
}

func dialRelay(t *testing.T, wsURL, roomID, pubKey string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial(wsURL+"?room="+roomID+"&pubkey="+pubKey, nil)
	if err != nil {
		t.Fatalf("relay dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func waitRelayPeers(t *testing.T, rs *RelayServer, roomKey string, want int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if rs.hub.PeerCount(roomKey) == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("リレーpeer数が %d にならない", want)
}

func TestManagerAuthorizer(t *testing.T) {
	mgr, err := manager.New(manager.Config{})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	r, err := mgr.Create(manager.CreateParams{HostAccountID: "acc", HostPubKey: "hostPK", Tier: plan.Free}, now)
	if err != nil {
		t.Fatal(err)
	}
	a := managerAuthorizer{mgr: mgr}

	// ホストは許可。
	roomKey, spec, err := a.Authorize(r.ID, "hostPK")
	if err != nil || roomKey != r.ID || spec.Tier != plan.Free {
		t.Fatalf("host は許可されるべき: err=%v roomKey=%q spec=%+v", err, roomKey, spec)
	}

	// 未知ルームIDは拒否。
	if _, _, err := a.Authorize("bogus", "hostPK"); err != ErrRelayUnauthorized {
		t.Errorf("未知ルームIDは拒否, got %v", err)
	}

	// 未申請の公開鍵は拒否。
	if _, _, err := a.Authorize(r.ID, "strangerPK"); err != ErrRelayUnauthorized {
		t.Errorf("未申請は拒否, got %v", err)
	}

	// 申請中（未承認）は拒否。
	if err := mgr.WithRoom(r.ID, func(rm *room.Room) error {
		_, e := rm.RequestJoin("guestPK", "g", "203.0.113.5", now)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Authorize(r.ID, "guestPK"); err != ErrRelayUnauthorized {
		t.Errorf("Pending は拒否, got %v", err)
	}

	// 承認済みは許可。
	if err := mgr.WithRoom(r.ID, func(rm *room.Room) error {
		_, e := rm.Approve("guestPK", now)
		return e
	}); err != nil {
		t.Fatal(err)
	}
	if roomKey, _, err := a.Authorize(r.ID, "guestPK"); err != nil || roomKey != r.ID {
		t.Errorf("承認済みゲストは許可されるべき: err=%v roomKey=%q", err, roomKey)
	}
}

func TestRelayIntegration(t *testing.T) {
	rs, wsURL := newTestRelay(t, permissiveRelayAuth())
	a := dialRelay(t, wsURL, "room-1", "pkA")
	b := dialRelay(t, wsURL, "room-1", "pkB")
	waitRelayPeers(t, rs, "room-1", 2)

	// 非バイナリフレームは無視される。
	if err := a.WriteMessage(websocket.TextMessage, []byte("ignored")); err != nil {
		t.Fatal(err)
	}
	// 不正な短いフレームも無視される。
	if err := a.WriteMessage(websocket.BinaryMessage, []byte{0x00}); err != nil {
		t.Fatal(err)
	}
	// 正常フレーム: A → B。
	frameAB, err := relayframe.Encode("pkB", []byte("secret-packet"))
	if err != nil {
		t.Fatal(err)
	}
	if err := a.WriteMessage(websocket.BinaryMessage, frameAB); err != nil {
		t.Fatal(err)
	}

	// B は正常フレームのみ、src=pkA で受信する。
	_ = b.SetReadDeadline(time.Now().Add(2 * time.Second))
	mt, data, err := b.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if mt != websocket.BinaryMessage {
		t.Fatalf("binary フレームを期待, got %d", mt)
	}
	src, payload, err := relayframe.Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if src != "pkA" || string(payload) != "secret-packet" {
		t.Fatalf("中継内容が不正: src=%q payload=%q", src, payload)
	}
}

func TestServeRelayAuthError(t *testing.T) {
	rejecting := relayAuthorizerFunc(func(_, _ string) (string, plan.Spec, error) {
		return "", plan.Spec{}, ErrRelayUnauthorized
	})
	_, wsURL := newTestRelay(t, rejecting)
	_, resp, err := websocket.DefaultDialer.Dial(wsURL+"?room=x&pubkey=y", nil)
	if err == nil {
		t.Fatal("認証失敗時はダイヤルが失敗すべき")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("401 を期待, got %v", resp)
	}
}

func TestServeRelayUpgradeError(t *testing.T) {
	rs := NewRelayServer(relayhub.New(), permissiveRelayAuth())
	ts := httptest.NewServer(http.HandlerFunc(rs.ServeRelay))
	t.Cleanup(ts.Close)

	// WebSocket ヘッダの無い通常 GET → アップグレード失敗。
	resp, err := http.Get(ts.URL + "?room=room-1&pubkey=pkA")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("非 WebSocket リクエストはアップグレードされないべき")
	}
}

func TestRelayServerCloseConns(t *testing.T) {
	rs, wsURL := newTestRelay(t, permissiveRelayAuth())
	a := dialRelay(t, wsURL, "room-1", "pkA")
	waitRelayPeers(t, rs, "room-1", 1)

	rs.CloseConns()
	_ = a.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := a.ReadMessage(); err == nil {
		t.Fatal("CloseConns 後は読み取りがエラーになるべき")
	}

	// シャットダウン後の新規接続は即クローズ（addConn=false 経路）。
	c, _, err := websocket.DefaultDialer.Dial(wsURL+"?room=room-1&pubkey=pkC", nil)
	if err != nil {
		return
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("シャットダウン中の新規接続は即クローズされるべき")
	}
}
