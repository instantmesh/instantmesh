package hub

import (
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/manager"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/room"
	"github.com/instantmesh/instantmesh/pkg/session"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

const (
	// hostPK は hub 層では検証されない（形式検証は cmd/server の認証入口）。guest 公開鍵は
	// session.handleJoinRequest の入口で正規の Curve25519 鍵として検証されるため、join_request に
	// 使う鍵は base64・32バイトの正規形式にする（M-05(a)）。
	hostPK   = "host-public-key"
	guestPK  = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	guestPK2 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
	guestPK3 = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ="
)

// fakeConn は Conn のテスト実装。送出されたエンベロープを記録する。
type fakeConn struct {
	id   string
	mu   sync.Mutex
	sent []signaling.Envelope
	fail bool // true の場合 Send がエラーを返す（送出は記録しない）
}

func (c *fakeConn) ID() string { return c.id }

func (c *fakeConn) Send(env signaling.Envelope) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail {
		return errors.New("send failed")
	}
	c.sent = append(c.sent, env)
	return nil
}

// msgs は記録済みエンベロープのコピーを返す。
func (c *fakeConn) msgs() []signaling.Envelope {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]signaling.Envelope(nil), c.sent...)
}

// types は記録済みエンベロープの種別列を返す。
func (c *fakeConn) types() []signaling.MessageType {
	out := make([]signaling.MessageType, 0)
	for _, e := range c.msgs() {
		out = append(out, e.Type)
	}
	return out
}

func newTestHub(t *testing.T) *Hub {
	t.Helper()
	m, err := manager.New(manager.Config{})
	if err != nil {
		t.Fatalf("manager.New: %v", err)
	}
	return New(session.New(m))
}

// mkEnv は種別とペイロードから受信エンベロープを組み立てる。
func mkEnv(t *testing.T, mt signaling.MessageType, payload any) signaling.Envelope {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return signaling.Envelope{Type: mt, Payload: raw}
}

// lastType は接続が最後に受け取ったエンベロープの種別を返す。
func lastType(t *testing.T, c *fakeConn) signaling.MessageType {
	t.Helper()
	m := c.msgs()
	if len(m) == 0 {
		t.Fatalf("接続 %s はまだ何も受け取っていない", c.id)
	}
	return m[len(m)-1].Type
}

// createRoom はホスト接続を登録して create_room を処理し、ルームIDとトークンを返す。
func createRoom(t *testing.T, h *Hub, host *fakeConn, now time.Time) (roomID, tok string) {
	t.Helper()
	h.Register(host, Auth{Role: session.RoleHost, AccountID: "acc-1", PubKey: hostPK})
	h.Handle(host.id, mkEnv(t, signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: 1800}), now)
	m := host.msgs()
	if len(m) != 1 || m[0].Type != signaling.TypeRoomCreated {
		t.Fatalf("host は room_created を受け取るべき: %v", host.types())
	}
	var rc signaling.RoomCreated
	if err := m[0].Unmarshal(&rc); err != nil {
		t.Fatalf("room_created decode: %v", err)
	}
	return rc.RoomID, rc.Token
}

func TestHubFullFlow(t *testing.T) {
	h := newTestHub(t)
	now := time.Now()
	host := &fakeConn{id: "c-host"}
	guest := &fakeConn{id: "c-guest"}

	// 1. ルーム作成 → host に room_created
	_, tok := createRoom(t, h, host, now)

	// 2. ゲスト参加 → host に join_pending、guest はまだ何も受け取らない
	h.Register(guest, Auth{Role: session.RoleGuest, RemoteIP: "203.0.113.5"})
	h.Handle(guest.id, mkEnv(t, signaling.TypeJoinRequest,
		signaling.JoinRequest{Token: tok, Nickname: "Alice", GuestPubKey: guestPK}), now)
	if got := host.types(); len(got) != 2 || got[1] != signaling.TypeJoinPending {
		t.Fatalf("host は join_pending を受け取るべき: %v", got)
	}
	if len(guest.msgs()) != 0 {
		t.Fatalf("guest は承認前に何も受け取らない: %v", guest.types())
	}

	// 3. 承認 → guest に join_approved
	h.Handle(host.id, mkEnv(t, signaling.TypeDecision,
		signaling.Decision{GuestPubKey: guestPK, Approve: true}), now)
	if lastType(t, guest) != signaling.TypeJoinApproved {
		t.Fatalf("guest は join_approved を受け取るべき: %v", guest.types())
	}

	// 4. ホストのエンドポイントを承認済みゲストへ中継
	h.Handle(host.id, mkEnv(t, signaling.TypePeerInfo,
		signaling.PeerInfo{PubKey: hostPK, WANEndpoint: "198.51.100.1:51820"}), now)
	if lastType(t, guest) != signaling.TypePeerInfo {
		t.Fatalf("guest は host の peer_info を受け取るべき: %v", guest.types())
	}

	// 5. ゲストのエンドポイントをホストへ中継
	h.Handle(guest.id, mkEnv(t, signaling.TypePeerInfo,
		signaling.PeerInfo{PubKey: guestPK, WANEndpoint: "203.0.113.5:51820"}), now)
	if lastType(t, host) != signaling.TypePeerInfo {
		t.Fatalf("host は guest の peer_info を受け取るべき: %v", host.types())
	}

	// 6. 解散 → host・guest 双方に room_closed
	h.Handle(host.id, mkEnv(t, signaling.TypeCloseRoom, signaling.CloseRoom{}), now)
	if lastType(t, host) != signaling.TypeRoomClosed {
		t.Fatalf("host は room_closed を受け取るべき: %v", host.types())
	}
	if lastType(t, guest) != signaling.TypeRoomClosed {
		t.Fatalf("guest は room_closed を受け取るべき: %v", guest.types())
	}
}

// joinGuest はゲスト接続を登録して join_request を処理する。
func joinGuest(t *testing.T, h *Hub, c *fakeConn, tok, pk, nick string, now time.Time) {
	t.Helper()
	h.Register(c, Auth{Role: session.RoleGuest, RemoteIP: "203.0.113.5"})
	h.Handle(c.id, mkEnv(t, signaling.TypeJoinRequest,
		signaling.JoinRequest{Token: tok, Nickname: nick, GuestPubKey: pk}), now)
}

// approveGuest はホストとしてゲストを承認する。
func approveGuest(t *testing.T, h *Hub, hostID, pk string, now time.Time) {
	t.Helper()
	h.Handle(hostID, mkEnv(t, signaling.TypeDecision,
		signaling.Decision{GuestPubKey: pk, Approve: true}), now)
}

func TestHandleUnknownConn(t *testing.T) {
	h := newTestHub(t)
	// 未知の接続からの受信はパニックせず黙って捨てる。
	h.Handle("nope", mkEnv(t, signaling.TypeCreateRoom, signaling.CreateRoom{}), time.Now())
}

func TestUnregisterUnknownAndUnbound(t *testing.T) {
	h := newTestHub(t)

	// 未知IDの解除は冪等（何も起きない）。
	h.Unregister("nope")

	// 登録のみでバインドされていない接続の解除。
	c := &fakeConn{id: "c1"}
	h.Register(c, Auth{Role: session.RoleGuest})
	h.Unregister(c.id)
	// 二重解除も安全。
	h.Unregister(c.id)
}

func TestUnregisterHostDropsRouting(t *testing.T) {
	h := newTestHub(t)
	now := time.Now()
	host := &fakeConn{id: "c-host"}
	_, tok := createRoom(t, h, host, now)

	// ホストを解除 → ルームのホスト索引が消える。
	h.Unregister(host.id)

	// ゲストが参加しても join_pending は消えたホストへ向かうため破棄される。
	guest := &fakeConn{id: "c-guest"}
	joinGuest(t, h, guest, tok, guestPK, "Bob", now)

	if len(host.msgs()) != 1 { // room_created の 1 件のみ
		t.Fatalf("解除後のホストへは配送されない: %v", host.types())
	}
	if len(guest.msgs()) != 0 {
		t.Fatalf("guest は待合室で待機（通知なし）: %v", guest.types())
	}
}

func TestUnregisterGuestSingleAndMulti(t *testing.T) {
	h := newTestHub(t)
	now := time.Now()
	host := &fakeConn{id: "c-host"}
	_, tok := createRoom(t, h, host, now)

	g1 := &fakeConn{id: "g1"}
	g2 := &fakeConn{id: "g2"}
	joinGuest(t, h, g1, tok, guestPK2, "G1", now) // guestByRoom[room] を新規作成
	joinGuest(t, h, g2, tok, guestPK3, "G2", now) // 既存マップへ追加
	approveGuest(t, h, host.id, guestPK2, now)
	approveGuest(t, h, host.id, guestPK3, now)

	// g1 を解除（マップから削除、他ゲストが残るためマップは保持）。
	h.Unregister(g1.id)

	// ホストの peer_info は承認済みゲスト全員へ。解除済み g1 は届かず g2 のみ受信。
	g1before := len(g1.msgs())
	h.Handle(host.id, mkEnv(t, signaling.TypePeerInfo,
		signaling.PeerInfo{PubKey: hostPK, WANEndpoint: "198.51.100.1:51820"}), now)
	if len(g1.msgs()) != g1before {
		t.Errorf("解除済み g1 へは配送されない: %v", g1.types())
	}
	if lastType(t, g2) != signaling.TypePeerInfo {
		t.Errorf("g2 は peer_info を受信すべき: %v", g2.types())
	}

	// g2 も解除（最後のゲストなのでマップごと除去）。
	h.Unregister(g2.id)
}

func TestUnregisterRejoinGuardPreservesNewConn(t *testing.T) {
	h := newTestHub(t)
	now := time.Now()
	host := &fakeConn{id: "c-host"}
	_, tok := createRoom(t, h, host, now)

	// conn1 が pk=X で申請（Pending）。
	c1 := &fakeConn{id: "c1"}
	joinGuest(t, h, c1, tok, guestPK, "X1", now)

	// 無応答タイムアウトで失効（ドメイン上 Expired、hub 索引は c1 のまま）。
	h.ExpirePending(now.Add(plan.JoinRequestTimeout + time.Second))
	if lastType(t, c1) != signaling.TypeJoinRejected {
		t.Fatalf("c1 は失効通知を受けるべき: %v", c1.types())
	}

	// 同一鍵 pk=X で conn2 が再申請（失効済みは許可）→ hub 索引は c2 へ更新。
	later := now.Add(plan.JoinRequestTimeout + 2*time.Second)
	c2 := &fakeConn{id: "c2"}
	joinGuest(t, h, c2, tok, guestPK, "X2", later)

	// c1 を解除。索引は c2 を指すため、ガードにより c2 のルーティングは保持される。
	h.Unregister(c1.id)

	// 承認 → 再参加した c2 が join_approved を受信できる（索引が壊れていない証左）。
	approveGuest(t, h, host.id, guestPK, later)
	if lastType(t, c2) != signaling.TypeJoinApproved {
		t.Fatalf("再参加した c2 のルーティングが保持されるべき: %v", c2.types())
	}
}

func TestHubSweep(t *testing.T) {
	h := newTestHub(t)
	now := time.Now()
	host := &fakeConn{id: "c-host"}
	_, tok := createRoom(t, h, host, now)
	guest := &fakeConn{id: "c-guest"}
	joinGuest(t, h, guest, tok, guestPK, "S", now)
	approveGuest(t, h, host.id, guestPK, now)

	hostBefore, guestBefore := len(host.msgs()), len(guest.msgs())

	// 掃除対象なし → 配送なし。
	h.Sweep(now)
	if len(host.msgs()) != hostBefore || len(guest.msgs()) != guestBefore {
		t.Fatalf("掃除対象なしなら配送されない")
	}

	// 制限時間超過 → 双方へ room_closed。
	h.Sweep(now.Add(time.Hour + time.Minute))
	if lastType(t, host) != signaling.TypeRoomClosed {
		t.Fatalf("host は room_closed を受けるべき: %v", host.types())
	}
	if lastType(t, guest) != signaling.TypeRoomClosed {
		t.Fatalf("guest は room_closed を受けるべき: %v", guest.types())
	}
}

func TestHubCloseRoom(t *testing.T) {
	h := newTestHub(t)
	now := time.Now()
	host := &fakeConn{id: "c-host"}
	roomID, tok := createRoom(t, h, host, now)
	guest := &fakeConn{id: "c-guest"}
	joinGuest(t, h, guest, tok, guestPK, "G", now)
	approveGuest(t, h, host.id, guestPK, now)

	// ルーム解散 → 承認済みゲストへ room_closed。
	h.CloseRoom(roomID, room.CloseHost, now)
	if lastType(t, guest) != signaling.TypeRoomClosed {
		t.Fatalf("guest は room_closed を受けるべき: %v", guest.types())
	}

	// 冪等: 既に解散済みなら配送なし。
	before := len(guest.msgs())
	h.CloseRoom(roomID, room.CloseHost, now)
	if len(guest.msgs()) != before {
		t.Error("解散済みルームの再解散では配送されない")
	}
}

func TestHubNotifyGuestLeft(t *testing.T) {
	h := newTestHub(t)
	now := time.Now()
	host := &fakeConn{id: "c-host"}
	roomID, tok := createRoom(t, h, host, now)
	guest := &fakeConn{id: "c-guest"}
	joinGuest(t, h, guest, tok, guestPK, "G", now)
	approveGuest(t, h, host.id, guestPK, now)

	hostBefore := len(host.msgs())
	// ゲスト離脱 → ホストへ guest_left。
	h.NotifyGuestLeft(roomID, guestPK, now)
	if lastType(t, host) != signaling.TypeGuestLeft {
		t.Fatalf("host は guest_left を受けるべき: %v", host.types())
	}
	if len(host.msgs()) != hostBefore+1 {
		t.Errorf("guest_left は 1 件のみ配送: %v", host.types())
	}

	// 離脱済み（もう居ない）なら配送なし。
	before := len(host.msgs())
	h.NotifyGuestLeft(roomID, guestPK, now)
	if len(host.msgs()) != before {
		t.Error("不在ゲストの再離脱では配送されない")
	}
}

func TestHubExpirePending(t *testing.T) {
	h := newTestHub(t)
	now := time.Now()
	host := &fakeConn{id: "c-host"}
	_, tok := createRoom(t, h, host, now)
	guest := &fakeConn{id: "c-guest"}
	joinGuest(t, h, guest, tok, guestPK, "P", now)

	// 失効対象なし → 配送なし。
	h.ExpirePending(now)
	if len(guest.msgs()) != 0 {
		t.Fatalf("失効対象なしなら配送されない: %v", guest.types())
	}

	// タイムアウト超過 → guest に join_rejected。
	h.ExpirePending(now.Add(plan.JoinRequestTimeout + time.Second))
	if lastType(t, guest) != signaling.TypeJoinRejected {
		t.Fatalf("guest は失効通知を受けるべき: %v", guest.types())
	}
}

func TestSendFailureIgnored(t *testing.T) {
	h := newTestHub(t)
	now := time.Now()
	host := &fakeConn{id: "c-host", fail: true}
	h.Register(host, Auth{Role: session.RoleHost, AccountID: "acc-1", PubKey: hostPK})

	// Send がエラーを返しても Handle はパニックせず完了する（ベストエフォート配送）。
	h.Handle(host.id, mkEnv(t, signaling.TypeCreateRoom, signaling.CreateRoom{}), now)
	if len(host.msgs()) != 0 {
		t.Fatalf("送出失敗時は記録されない: %v", host.types())
	}
}
