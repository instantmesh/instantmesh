package appstate

import (
	"errors"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/invite"
)

// validLink はテスト用の正しい招待リンクとその Invite を返す。
func validLink(t *testing.T) (string, invite.Invite) {
	t.Helper()
	inv := invite.Invite{Server: "ws://s/ws", Token: "tok", HostPubKey: "hostkey"}
	link, err := inv.URL()
	if err != nil {
		t.Fatalf("URL: %v", err)
	}
	return link, inv
}

// hosting は Hosting フェーズまで進めた Model を返す。
func hosting(t *testing.T) *Model {
	t.Helper()
	m := New()
	if err := m.StartHosting(); err != nil {
		t.Fatalf("StartHosting: %v", err)
	}
	if err := m.RoomCreated("room1", "instantmesh://join?x=1", "HOSTSAS"); err != nil {
		t.Fatalf("RoomCreated: %v", err)
	}
	return m
}

// waiting は Waiting フェーズまで進めたゲスト Model を返す。
func waiting(t *testing.T) *Model {
	t.Helper()
	m := New()
	link, _ := validLink(t)
	if err := m.StartJoining(link, "alice"); err != nil {
		t.Fatalf("StartJoining: %v", err)
	}
	if err := m.MarkRequested(); err != nil {
		t.Fatalf("MarkRequested: %v", err)
	}
	return m
}

func TestNew(t *testing.T) {
	m := New()
	if m.Role != RoleNone || m.Phase != PhaseIdle {
		t.Fatalf("New = {%d,%d}, want {RoleNone,PhaseIdle}", m.Role, m.Phase)
	}
}

func TestHostHappyPath(t *testing.T) {
	m := hosting(t)
	if m.Role != RoleHost || m.Phase != PhaseHosting {
		t.Fatalf("phase=%d role=%d, want Hosting/Host", m.Phase, m.Role)
	}
	if m.RoomID != "room1" || m.InviteLink == "" || m.SAS != "HOSTSAS" {
		t.Fatalf("room fields not set: %+v", m)
	}
	// 再発行で招待リンクが差し替わる。
	if err := m.ReissueInvite("instantmesh://join?x=2"); err != nil {
		t.Fatalf("ReissueInvite: %v", err)
	}
	if m.InviteLink != "instantmesh://join?x=2" {
		t.Fatalf("InviteLink=%q, want reissued", m.InviteLink)
	}
	// 待合室 → 承認 → 参加確定 → 接続 → 離脱。
	if err := m.AddPending("g1", "bob", "SAS1"); err != nil {
		t.Fatalf("AddPending: %v", err)
	}
	// 同じ公開鍵の再申請は情報更新（重複追加しない）。
	if err := m.AddPending("g1", "bob2", "SAS1b"); err != nil {
		t.Fatalf("AddPending(re): %v", err)
	}
	if len(m.Guests) != 1 || m.Guests[0].Nickname != "bob2" {
		t.Fatalf("re-request should update in place: %+v", m.Guests)
	}
	if err := m.Approve("g1"); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if m.Guests[0].State != GuestApproved {
		t.Fatalf("guest not approved")
	}
	if err := m.GuestJoined("g1", "10.9.0.2"); err != nil {
		t.Fatalf("GuestJoined: %v", err)
	}
	if m.Guests[0].AssignedIP != "10.9.0.2" {
		t.Fatalf("assigned ip not set")
	}
	if err := m.PeerUp("g1", RouteDirect); err != nil {
		t.Fatalf("PeerUp: %v", err)
	}
	if err := m.PeerUp("g1", RouteRelay); err != nil { // 既存ピアの経路更新
		t.Fatalf("PeerUp(update): %v", err)
	}
	if len(m.Peers) != 1 || m.Peers[0].Route != RouteRelay {
		t.Fatalf("peer route not updated: %+v", m.Peers)
	}
	if err := m.GuestLeft("g1"); err != nil {
		t.Fatalf("GuestLeft: %v", err)
	}
	if len(m.Guests) != 0 || len(m.Peers) != 0 {
		t.Fatalf("guest/peer not removed: %+v", m)
	}
}

func TestReject(t *testing.T) {
	m := hosting(t)
	if err := m.AddPending("g1", "bob", "SAS1"); err != nil {
		t.Fatal(err)
	}
	if err := m.Reject("g1"); err != nil {
		t.Fatalf("Reject: %v", err)
	}
	if len(m.Guests) != 0 {
		t.Fatalf("rejected guest not removed")
	}
}

// TestGuestLeftWithoutPeer は接続前（ピア未確立）に離脱したゲストの除去で
// removePeer の「見つからない」経路を通す。
func TestGuestLeftWithoutPeer(t *testing.T) {
	m := hosting(t)
	_ = m.AddPending("g1", "bob", "SAS1")
	_ = m.Approve("g1")
	if err := m.GuestLeft("g1"); err != nil {
		t.Fatalf("GuestLeft: %v", err)
	}
	if len(m.Guests) != 0 {
		t.Fatalf("guest not removed")
	}
}

func TestGuestHappyPath(t *testing.T) {
	m := waiting(t)
	if m.Role != RoleGuest || m.Phase != PhaseWaiting {
		t.Fatalf("phase=%d role=%d, want Waiting/Guest", m.Phase, m.Role)
	}
	_, inv := validLink(t)
	if m.Server != inv.Server || m.Token != inv.Token || m.HostPubKey != inv.HostPubKey || m.SAS != inv.SAS() || m.Nickname != "alice" {
		t.Fatalf("guest fields from invite not set: %+v", m)
	}
	if err := m.Approved("10.9.0.2", "10.9.0.1"); err != nil {
		t.Fatalf("Approved: %v", err)
	}
	if m.Phase != PhaseActive || m.AssignedIP != "10.9.0.2" || m.HostIP != "10.9.0.1" {
		t.Fatalf("not active: %+v", m)
	}
	// 接続後にピアが立つ（Active フェーズでの PeerUp）。
	if err := m.PeerUp("hostkey", RouteDirect); err != nil {
		t.Fatalf("PeerUp: %v", err)
	}
	if len(m.Peers) != 1 {
		t.Fatalf("peer not added")
	}
}

func TestGuestRejectedByHost(t *testing.T) {
	m := waiting(t)
	if err := m.RejectedByHost("full"); err != nil {
		t.Fatalf("RejectedByHost: %v", err)
	}
	if m.Phase != PhaseClosed || m.Reason != "full" {
		t.Fatalf("not closed with reason: %+v", m)
	}
}

func TestStartJoiningInvalidLink(t *testing.T) {
	m := New()
	err := m.StartJoining("http://example.com", "alice")
	if !errors.Is(err, invite.ErrScheme) {
		t.Fatalf("StartJoining(bad) err=%v, want ErrScheme", err)
	}
	// 状態は変わらない。
	if m.Phase != PhaseIdle || m.Role != RoleNone {
		t.Fatalf("state changed on invalid link: %+v", m)
	}
}

// TestApproveRejectNotFound は承認/拒否対象が居ない・既に承認済みの経路を通す。
func TestApproveRejectNotFound(t *testing.T) {
	m := hosting(t)
	if err := m.Approve("nope"); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("Approve(missing)=%v, want ErrGuestNotFound", err)
	}
	if err := m.Reject("nope"); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("Reject(missing)=%v, want ErrGuestNotFound", err)
	}
	// 既に承認済み → Pending でないため Approve/Reject は not found 扱い。
	_ = m.AddPending("g1", "bob", "SAS1")
	_ = m.Approve("g1")
	if err := m.Approve("g1"); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("Approve(approved)=%v, want ErrGuestNotFound", err)
	}
	if err := m.Reject("g1"); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("Reject(approved)=%v, want ErrGuestNotFound", err)
	}
}

func TestGuestJoinedNotFound(t *testing.T) {
	m := hosting(t)
	if err := m.GuestJoined("nope", "10.9.0.2"); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("GuestJoined(missing)=%v, want ErrGuestNotFound", err)
	}
}

func TestGuestLeftNotFound(t *testing.T) {
	m := hosting(t)
	if err := m.GuestLeft("nope"); !errors.Is(err, ErrGuestNotFound) {
		t.Fatalf("GuestLeft(missing)=%v, want ErrGuestNotFound", err)
	}
}

func TestCloseAndSetError(t *testing.T) {
	m := hosting(t)
	m.SetError("transient")
	if m.ErrMsg != "transient" {
		t.Fatalf("SetError not applied")
	}
	// ClearError で回復時に文言を消せる（バナー永続化防止）。
	m.ClearError()
	if m.ErrMsg != "" {
		t.Fatalf("ClearError not applied: %q", m.ErrMsg)
	}
	m.Close("host_disconnected")
	if m.Phase != PhaseClosed || m.Reason != "host_disconnected" {
		t.Fatalf("Close not applied: %+v", m)
	}
}

func TestStartJoiningInvite(t *testing.T) {
	_, inv := validLink(t)

	// 解析済み招待から Idle→Connecting へ遷移する（二重パースを避ける経路）。
	m := New()
	if err := m.StartJoiningInvite(inv, "alice"); err != nil {
		t.Fatalf("StartJoiningInvite: %v", err)
	}
	if m.Role != RoleGuest || m.Phase != PhaseConnecting ||
		m.Server != inv.Server || m.Token != inv.Token ||
		m.HostPubKey != inv.HostPubKey || m.SAS != inv.SAS() || m.Nickname != "alice" {
		t.Fatalf("StartJoiningInvite state = %+v", m)
	}

	// 非 Idle からは ErrInvalidState。
	if err := hosting(t).StartJoiningInvite(inv, "a"); !errors.Is(err, ErrInvalidState) {
		t.Errorf("StartJoiningInvite on non-idle err=%v, want ErrInvalidState", err)
	}
}

func TestVerifyHostKey(t *testing.T) {
	m := waiting(t) // HostPubKey は validLink の "hostkey"
	if !m.VerifyHostKey("hostkey") {
		t.Error("一致するホスト鍵は照合成功すべき")
	}
	if m.VerifyHostKey("wrongkey") {
		t.Error("不一致のホスト鍵は照合失敗すべき")
	}
}

func TestGuestIP(t *testing.T) {
	m := hosting(t)
	_ = m.AddPending("g1", "bob", "SAS1")
	if _, ok := m.GuestIP("g1"); ok {
		t.Error("参加確定前（IP 未割当）は GuestIP=false であるべき")
	}
	if _, ok := m.GuestIP("nope"); ok {
		t.Error("不在ゲストの GuestIP は false であるべき")
	}
	_ = m.Approve("g1")
	_ = m.GuestJoined("g1", "10.9.0.5")
	if ip, ok := m.GuestIP("g1"); !ok || ip != "10.9.0.5" {
		t.Errorf("GuestIP=(%q,%v), want (10.9.0.5,true)", ip, ok)
	}
}

// TestInvalidTransitions は各操作が誤ったロール/フェーズで ErrInvalidState を返すことを、
// `||` 条件の両オペランド（ロール側・フェーズ側）を含めて網羅する。
func TestInvalidTransitions(t *testing.T) {
	// StartHosting: 非 Idle。
	if m := hosting(t); !errors.Is(m.StartHosting(), ErrInvalidState) {
		t.Error("StartHosting on non-idle should fail")
	}
	// StartJoining: 非 Idle。
	if m := hosting(t); !errors.Is(m.StartJoining("instantmesh://join?x=1", "a"), ErrInvalidState) {
		t.Error("StartJoining on non-idle should fail")
	}

	// RoomCreated: ロール不正（New）／フェーズ不正（Hosting で再実行）。
	if err := New().RoomCreated("r", "l", "s"); !errors.Is(err, ErrInvalidState) {
		t.Error("RoomCreated without host role should fail")
	}
	if m := hosting(t); !errors.Is(m.RoomCreated("r", "l", "s"), ErrInvalidState) {
		t.Error("RoomCreated in Hosting should fail (phase operand)")
	}

	// ReissueInvite: ロール不正／フェーズ不正（Connecting）。
	if err := New().ReissueInvite("l"); !errors.Is(err, ErrInvalidState) {
		t.Error("ReissueInvite without host role should fail")
	}
	mc := New()
	_ = mc.StartHosting() // Connecting
	if !errors.Is(mc.ReissueInvite("l"), ErrInvalidState) {
		t.Error("ReissueInvite in Connecting should fail (phase operand)")
	}

	// AddPending: ロール不正／フェーズ不正（Connecting）。
	if err := New().AddPending("g", "n", "s"); !errors.Is(err, ErrInvalidState) {
		t.Error("AddPending without host role should fail")
	}
	if !errors.Is(mc.AddPending("g", "n", "s"), ErrInvalidState) {
		t.Error("AddPending in Connecting should fail (phase operand)")
	}

	// Approve/Reject/GuestJoined/GuestLeft: ロール不正（ゲスト）。
	g := waiting(t)
	for name, err := range map[string]error{
		"Approve":     g.Approve("x"),
		"Reject":      g.Reject("x"),
		"GuestJoined": g.GuestJoined("x", "ip"),
		"GuestLeft":   g.GuestLeft("x"),
	} {
		if !errors.Is(err, ErrInvalidState) {
			t.Errorf("%s as guest should be ErrInvalidState, got %v", name, err)
		}
	}

	// MarkRequested: ロール不正（New）／フェーズ不正（Waiting で再実行）。
	if err := New().MarkRequested(); !errors.Is(err, ErrInvalidState) {
		t.Error("MarkRequested without guest role should fail")
	}
	if m := waiting(t); !errors.Is(m.MarkRequested(), ErrInvalidState) {
		t.Error("MarkRequested in Waiting should fail (phase operand)")
	}

	// Approved/RejectedByHost: ロール不正（New）／フェーズ不正（Connecting）。
	if err := New().Approved("a", "h"); !errors.Is(err, ErrInvalidState) {
		t.Error("Approved without guest role should fail")
	}
	if err := New().RejectedByHost("r"); !errors.Is(err, ErrInvalidState) {
		t.Error("RejectedByHost without guest role should fail")
	}
	gc := New()
	link, _ := validLink(t)
	_ = gc.StartJoining(link, "a") // Connecting（未 MarkRequested）
	if !errors.Is(gc.Approved("a", "h"), ErrInvalidState) {
		t.Error("Approved in Connecting should fail (phase operand)")
	}
	if !errors.Is(gc.RejectedByHost("r"), ErrInvalidState) {
		t.Error("RejectedByHost in Connecting should fail (phase operand)")
	}

	// PeerUp: 接続段階外（Idle）。
	if err := New().PeerUp("p", RouteDirect); !errors.Is(err, ErrInvalidState) {
		t.Error("PeerUp in Idle should fail")
	}
}

func TestEnumStrings(t *testing.T) {
	if RoleNone.String() != "none" || RoleHost.String() != "host" || RoleGuest.String() != "guest" {
		t.Errorf("Role.String: none=%q host=%q guest=%q", RoleNone, RoleHost, RoleGuest)
	}
	if PhaseIdle.String() != "idle" || PhaseConnecting.String() != "connecting" ||
		PhaseHosting.String() != "hosting" || PhaseWaiting.String() != "waiting" ||
		PhaseActive.String() != "active" || PhaseClosed.String() != "closed" {
		t.Error("Phase.String に想定外の値")
	}
	if RouteDirect.String() != "direct" || RouteRelay.String() != "relay" {
		t.Error("Route.String に想定外の値")
	}
	if GuestPending.String() != "pending" || GuestApproved.String() != "approved" {
		t.Error("GuestState.String に想定外の値")
	}
}

func TestView(t *testing.T) {
	// ホスト: ゲスト・ピアありのスナップショット。
	m := hosting(t)
	_ = m.AddPending("g1", "bob", "SAS1")
	_ = m.Approve("g1")
	_ = m.GuestJoined("g1", "10.9.0.2")
	_ = m.PeerUp("g1", RouteRelay)
	s := m.View()
	if s.Role != "host" || s.Phase != "hosting" || s.InviteLink == "" {
		t.Fatalf("host view: %+v", s)
	}
	if len(s.Guests) != 1 || s.Guests[0].State != "approved" || s.Guests[0].AssignedIP != "10.9.0.2" {
		t.Fatalf("host view guests: %+v", s.Guests)
	}
	if len(s.Peers) != 1 || s.Peers[0].Route != "relay" {
		t.Fatalf("host view peers: %+v", s.Peers)
	}

	// ゲスト: ゲスト/ピアが空でも JSON で [] になるよう非 nil スライス。
	gs := waiting(t).View()
	if gs.Role != "guest" || gs.Phase != "waiting" {
		t.Fatalf("guest view: %+v", gs)
	}
	if gs.Guests == nil || gs.Peers == nil {
		t.Fatal("空スライスは非 nil であるべき（JSON []）")
	}
}
