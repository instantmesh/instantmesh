package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gorilla/websocket"
	"github.com/instantmesh/instantmesh/pkg/auditlog"
	"github.com/instantmesh/instantmesh/pkg/hub"
	"github.com/instantmesh/instantmesh/pkg/manager"
	"github.com/instantmesh/instantmesh/pkg/room"
	"github.com/instantmesh/instantmesh/pkg/session"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

// テスト用の正規 Curve25519 公開鍵（base64・32バイト）。入口検証（M-05(a)）を通す。
const (
	testHostKey  = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	testGuestKey = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	testLateKey  = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
	testBobKey   = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
)

func newTestServer(t *testing.T) (*Server, string) {
	t.Helper()
	mgr, err := manager.New(manager.Config{})
	if err != nil {
		t.Fatalf("manager.New: %v", err)
	}
	s := NewServer(hub.New(session.New(mgr)), DevAuthenticator{}, NopAuditLogger{})
	ts := httptest.NewServer(http.HandlerFunc(s.ServeWS))
	t.Cleanup(ts.Close)
	return s, "ws" + strings.TrimPrefix(ts.URL, "http")
}

func dialHost(t *testing.T, wsURL, account, pubKey string) *websocket.Conn {
	t.Helper()
	h := http.Header{"Authorization": {"Bearer " + account}}
	c, _, err := websocket.DefaultDialer.Dial(wsURL+"?role=host&pubkey="+url.QueryEscape(pubKey), h)
	if err != nil {
		t.Fatalf("host dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func dialGuest(t *testing.T, wsURL string) *websocket.Conn {
	t.Helper()
	c, _, err := websocket.DefaultDialer.Dial(wsURL+"?role=guest", nil)
	if err != nil {
		t.Fatalf("guest dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func send(t *testing.T, c *websocket.Conn, mt signaling.MessageType, payload any) {
	t.Helper()
	data, err := signaling.Encode(mt, payload)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := c.WriteMessage(websocket.TextMessage, data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func recv(t *testing.T, c *websocket.Conn) signaling.Envelope {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	_, data, err := c.ReadMessage()
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	env, err := signaling.Decode(data)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return env
}

// waitConns はサーバーに登録された接続数が want になるまで待つ（登録は接続ごとの goroutine 内）。
func waitConns(t *testing.T, s *Server, want int) {
	t.Helper()
	for i := 0; i < 200; i++ {
		s.mu.Lock()
		n := len(s.conns)
		s.mu.Unlock()
		if n == want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("接続数が %d にならない", want)
}

// TestServerIntegration は実 WebSocket 上で作成→参加→承認→交換→解散のシーケンスを検証する。
func TestServerIntegration(t *testing.T) {
	_, wsURL := newTestServer(t)

	// 1. ルーム作成
	host := dialHost(t, wsURL, "acc-1", testHostKey)
	send(t, host, signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: 1800})
	env := recv(t, host)
	if env.Type != signaling.TypeRoomCreated {
		t.Fatalf("room_created を期待, got %s", env.Type)
	}
	var rc signaling.RoomCreated
	if err := env.Unmarshal(&rc); err != nil {
		t.Fatal(err)
	}
	if rc.RoomID == "" || rc.Token == "" || rc.HostIP != "10.0.0.1" {
		t.Fatalf("room_created 不正: %+v", rc)
	}

	// 2. ゲスト参加 → host に join_pending
	guest := dialGuest(t, wsURL)
	send(t, guest, signaling.TypeJoinRequest, signaling.JoinRequest{Token: rc.Token, Nickname: "Alice", GuestPubKey: testGuestKey})
	env = recv(t, host)
	if env.Type != signaling.TypeJoinPending {
		t.Fatalf("join_pending を期待, got %s", env.Type)
	}
	var jp signaling.JoinPending
	_ = env.Unmarshal(&jp)
	if jp.GuestPubKey != testGuestKey || jp.SAS == "" {
		t.Fatalf("join_pending 不正: %+v", jp)
	}

	// 3. 承認 → guest に join_approved、host に guest_joined
	send(t, host, signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestKey, Approve: true})
	env = recv(t, guest)
	if env.Type != signaling.TypeJoinApproved {
		t.Fatalf("join_approved を期待, got %s", env.Type)
	}
	var ja signaling.JoinApproved
	_ = env.Unmarshal(&ja)
	if ja.AssignedIP != "10.0.0.2" || ja.HostPubKey != testHostKey || ja.HostIP != "10.0.0.1" || ja.RoomID != rc.RoomID {
		t.Fatalf("join_approved 不正: %+v", ja)
	}
	// ホストはゲスト参加通知（IP付き）を受信する。
	if env = recv(t, host); env.Type != signaling.TypeGuestJoined {
		t.Fatalf("host は guest_joined を期待, got %s", env.Type)
	}
	var gj signaling.GuestJoined
	_ = env.Unmarshal(&gj)
	if gj.GuestPubKey != testGuestKey || gj.AssignedIP != "10.0.0.2" {
		t.Fatalf("guest_joined 不正: %+v", gj)
	}

	// 4. peer_info 交換（host→guest, guest→host）
	send(t, host, signaling.TypePeerInfo, signaling.PeerInfo{PubKey: testHostKey, WANEndpoint: "198.51.100.1:51820"})
	if env = recv(t, guest); env.Type != signaling.TypePeerInfo {
		t.Fatalf("guest は host peer_info を受信すべき, got %s", env.Type)
	}
	send(t, guest, signaling.TypePeerInfo, signaling.PeerInfo{PubKey: testGuestKey, WANEndpoint: "203.0.113.5:51820"})
	if env = recv(t, host); env.Type != signaling.TypePeerInfo {
		t.Fatalf("host は guest peer_info を受信すべき, got %s", env.Type)
	}

	// 5. 解散 → 双方 room_closed
	send(t, host, signaling.TypeCloseRoom, signaling.CloseRoom{})
	if env = recv(t, host); env.Type != signaling.TypeRoomClosed {
		t.Fatalf("host は room_closed を期待, got %s", env.Type)
	}
	if env = recv(t, guest); env.Type != signaling.TypeRoomClosed {
		t.Fatalf("guest は room_closed を期待, got %s", env.Type)
	}
}

// TestServerInviteReissue は実 WebSocket 上で招待リンク再発行を検証する:
// rotate_token → invite_reissued（新トークン）、旧トークンの新規参加拒否、新トークンでの参加受理。
func TestServerInviteReissue(t *testing.T) {
	_, wsURL := newTestServer(t)

	// ルーム作成。
	host := dialHost(t, wsURL, "acc-1", testHostKey)
	send(t, host, signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: 1800})
	var rc signaling.RoomCreated
	_ = recv(t, host).Unmarshal(&rc)
	oldTok := rc.Token

	// ゲストを承認済みにする（再発行後も維持されることの前提）。
	guest := dialGuest(t, wsURL)
	send(t, guest, signaling.TypeJoinRequest, signaling.JoinRequest{Token: oldTok, Nickname: "Alice", GuestPubKey: testGuestKey})
	_ = recv(t, host) // join_pending
	send(t, host, signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestKey, Approve: true})
	_ = recv(t, guest) // join_approved
	_ = recv(t, host)  // guest_joined

	// 再発行 → host に invite_reissued（新トークン）。
	send(t, host, signaling.TypeRotateToken, signaling.RotateToken{})
	env := recv(t, host)
	if env.Type != signaling.TypeInviteReissued {
		t.Fatalf("invite_reissued を期待, got %s", env.Type)
	}
	var ir signaling.InviteReissued
	_ = env.Unmarshal(&ir)
	if ir.Token == "" || ir.Token == oldTok {
		t.Fatalf("新トークンは旧と異なるべき: old=%q new=%q", oldTok, ir.Token)
	}

	// 旧トークンでの新規参加は失効により拒否される。
	late := dialGuest(t, wsURL)
	send(t, late, signaling.TypeJoinRequest, signaling.JoinRequest{Token: oldTok, Nickname: "Late", GuestPubKey: testLateKey})
	if env = recv(t, late); env.Type != signaling.TypeError {
		t.Fatalf("旧トークンは error を返すべき, got %s", env.Type)
	}

	// 新トークンでの参加はホストへ join_pending として届く（承認済みゲストは維持）。
	fresh := dialGuest(t, wsURL)
	send(t, fresh, signaling.TypeJoinRequest, signaling.JoinRequest{Token: ir.Token, Nickname: "Bob", GuestPubKey: testBobKey})
	if env = recv(t, host); env.Type != signaling.TypeJoinPending {
		t.Fatalf("新トークン参加は join_pending を期待, got %s", env.Type)
	}
}

func TestServeWSAuthError(t *testing.T) {
	_, wsURL := newTestServer(t)
	// host なのに Bearer / pubkey が無い → 401 でハンドシェイク失敗。
	_, resp, err := websocket.DefaultDialer.Dial(wsURL+"?role=host", nil)
	if err == nil {
		t.Fatal("認証失敗時はダイヤルが失敗すべき")
	}
	if resp == nil || resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("401 を期待, got %v", resp)
	}
}

func TestServeWSUpgradeError(t *testing.T) {
	mgr, _ := manager.New(manager.Config{})
	s := NewServer(hub.New(session.New(mgr)), DevAuthenticator{}, NopAuditLogger{})
	ts := httptest.NewServer(http.HandlerFunc(s.ServeWS))
	t.Cleanup(ts.Close)

	// WebSocket ヘッダの無い通常 GET → アップグレード失敗（400）。
	resp, err := http.Get(ts.URL + "?role=guest")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusSwitchingProtocols {
		t.Fatal("非 WebSocket リクエストはアップグレードされないべき")
	}
}

func TestServeWSMalformedMessage(t *testing.T) {
	_, wsURL := newTestServer(t)
	guest := dialGuest(t, wsURL)

	// 不正な JSON → error エンベロープが返り、接続は維持される。
	if err := guest.WriteMessage(websocket.TextMessage, []byte("not-json")); err != nil {
		t.Fatal(err)
	}
	env := recv(t, guest)
	if env.Type != signaling.TypeError {
		t.Fatalf("不正メッセージには error を返すべき, got %s", env.Type)
	}
	var e signaling.Error
	_ = env.Unmarshal(&e)
	if e.Code != "bad_request" {
		t.Errorf("code = %q, want bad_request", e.Code)
	}
}

// recordingAudit は AuditLogger のテスト実装。記録したイベントを保持する。
type recordingAudit struct {
	mu     sync.Mutex
	events []auditlog.Event
}

func (r *recordingAudit) Log(ev auditlog.Event) {
	r.mu.Lock()
	r.events = append(r.events, ev)
	r.mu.Unlock()
}

func (r *recordingAudit) find(kind string) (auditlog.Event, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.events {
		if e.Kind == kind {
			return e, true
		}
	}
	return auditlog.Event{}, false
}

// waitAudit は指定種別の監査イベントが記録されるまで待つ（Handle は接続ごとの goroutine 内で非同期）。
func waitAudit(t *testing.T, rec *recordingAudit, kind string) auditlog.Event {
	t.Helper()
	for i := 0; i < 200; i++ {
		if e, ok := rec.find(kind); ok {
			return e
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("監査イベント %q が記録されない", kind)
	return auditlog.Event{}
}

// TestServerAudit は接続メタデータ（ルーム作成・ゲスト参加）が監査記録されることを検証する（要件 §監査ログ）。
func TestServerAudit(t *testing.T) {
	mgr, err := manager.New(manager.Config{})
	if err != nil {
		t.Fatal(err)
	}
	rec := &recordingAudit{}
	s := NewServer(hub.New(session.New(mgr)), DevAuthenticator{}, rec)
	ts := httptest.NewServer(http.HandlerFunc(s.ServeWS))
	t.Cleanup(ts.Close)
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http")

	// ホストがルーム作成 → room_create 監査。
	host := dialHost(t, wsURL, "acc-1", testHostKey)
	send(t, host, signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: 1800})
	env := recv(t, host)
	var rc signaling.RoomCreated
	_ = env.Unmarshal(&rc)

	rce := waitAudit(t, rec, auditlog.KindRoomCreate)
	if rce.AccountID != "acc-1" || rce.RoomID == "" || rce.RoomID != rc.RoomID {
		t.Errorf("room_create 監査が不正: %+v (want account=acc-1 room=%s)", rce, rc.RoomID)
	}

	// ゲスト参加 → guest_join 監査（IP・ルームID）。
	guest := dialGuest(t, wsURL)
	send(t, guest, signaling.TypeJoinRequest, signaling.JoinRequest{Token: rc.Token, Nickname: "Alice", GuestPubKey: testGuestKey})

	gje := waitAudit(t, rec, auditlog.KindGuestJoin)
	if gje.RoomID != rc.RoomID || gje.RemoteIP == "" {
		t.Errorf("guest_join 監査が不正: %+v", gje)
	}

	// 接続イベントも記録される（通信内容は含めない）。
	if _, ok := rec.find(auditlog.KindConnect); !ok {
		t.Error("connect 監査が記録されるべき")
	}
}

// TestHostDisconnectClosesRoom はホスト切断でルームが解散し、承認済みゲストへ room_closed が
// 配送されることを検証する（エフェメラル）。
func TestHostDisconnectClosesRoom(t *testing.T) {
	_, wsURL := newTestServer(t)

	host := dialHost(t, wsURL, "acc-1", testHostKey)
	send(t, host, signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: 1800})
	env := recv(t, host)
	var rc signaling.RoomCreated
	_ = env.Unmarshal(&rc)

	guest := dialGuest(t, wsURL)
	send(t, guest, signaling.TypeJoinRequest, signaling.JoinRequest{Token: rc.Token, Nickname: "Alice", GuestPubKey: testGuestKey})
	if env = recv(t, host); env.Type != signaling.TypeJoinPending {
		t.Fatalf("join_pending を期待, got %s", env.Type)
	}
	send(t, host, signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestKey, Approve: true})
	if env = recv(t, guest); env.Type != signaling.TypeJoinApproved {
		t.Fatalf("join_approved を期待, got %s", env.Type)
	}
	if env = recv(t, host); env.Type != signaling.TypeGuestJoined { // guest_joined を消化
		t.Fatalf("guest_joined を期待, got %s", env.Type)
	}

	// ホスト切断 → ルーム解散 → ゲストへ room_closed(host)。
	_ = host.Close()
	env = recv(t, guest)
	if env.Type != signaling.TypeRoomClosed {
		t.Fatalf("host 切断でゲストは room_closed を受けるべき, got %s", env.Type)
	}
	var closed signaling.RoomClosed
	_ = env.Unmarshal(&closed)
	if closed.Reason != string(room.CloseHost) {
		t.Errorf("解散理由 = %q, want %q", closed.Reason, room.CloseHost)
	}
}

// TestGuestDisconnectNotifiesHost はゲスト切断でホストへ guest_left が配送されることを検証する。
func TestGuestDisconnectNotifiesHost(t *testing.T) {
	_, wsURL := newTestServer(t)

	host := dialHost(t, wsURL, "acc-1", testHostKey)
	send(t, host, signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: 1800})
	env := recv(t, host)
	var rc signaling.RoomCreated
	_ = env.Unmarshal(&rc)

	guest := dialGuest(t, wsURL)
	send(t, guest, signaling.TypeJoinRequest, signaling.JoinRequest{Token: rc.Token, Nickname: "Alice", GuestPubKey: testGuestKey})
	if env = recv(t, host); env.Type != signaling.TypeJoinPending {
		t.Fatalf("join_pending を期待, got %s", env.Type)
	}
	send(t, host, signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestKey, Approve: true})
	if env = recv(t, guest); env.Type != signaling.TypeJoinApproved {
		t.Fatalf("join_approved を期待, got %s", env.Type)
	}
	if env = recv(t, host); env.Type != signaling.TypeGuestJoined { // guest_joined を消化
		t.Fatalf("guest_joined を期待, got %s", env.Type)
	}

	// ゲスト切断 → ホストへ guest_left（ピア除去用）。
	_ = guest.Close()
	env = recv(t, host)
	if env.Type != signaling.TypeGuestLeft {
		t.Fatalf("guest 切断でホストは guest_left を受けるべき, got %s", env.Type)
	}
	var gl signaling.GuestLeft
	_ = env.Unmarshal(&gl)
	if gl.GuestPubKey != testGuestKey {
		t.Errorf("guest_left の公開鍵が不正: %+v", gl)
	}
}

func TestServerCloseConns(t *testing.T) {
	s, wsURL := newTestServer(t)
	guest := dialGuest(t, wsURL)
	waitConns(t, s, 1)

	// 全接続をクローズ → クライアント側の読み取りが解除される。
	s.CloseConns()
	_ = guest.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := guest.ReadMessage(); err == nil {
		t.Fatal("CloseConns 後は読み取りがエラーになるべき")
	}

	// シャットダウン後の新規接続はサーバー側で即クローズされる（addConn=false 経路）。
	c, _, err := websocket.DefaultDialer.Dial(wsURL+"?role=guest", nil)
	if err != nil {
		return // ハンドシェイク前に閉じられた場合も許容（サーバー側 addConn=false は実行済み）。
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, _, err := c.ReadMessage(); err == nil {
		t.Fatal("シャットダウン中の新規接続は即クローズされるべき")
	}
}
