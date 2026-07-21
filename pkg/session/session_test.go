package session

import (
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/manager"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/room"
	"github.com/instantmesh/instantmesh/pkg/signaling"
	"github.com/instantmesh/instantmesh/pkg/token"
)

const (
	// 公開鍵は正規の Curve25519 鍵（base64・32バイト）。join_request 入口で検証される（M-05(a)）。
	testHostPK   = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
	testGuestPK  = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
	testGuestPK2 = "AwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwM="
	testGuestPK3 = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU="
	testAccount  = "acc-1"
)

func newDispatcher(t *testing.T) *Dispatcher {
	t.Helper()
	m, err := manager.New(manager.Config{})
	if err != nil {
		t.Fatalf("manager.New: %v", err)
	}
	return New(m)
}

// mustDecode はエンベロープのペイロードを目的構造体へ展開する。
func mustDecode(t *testing.T, env signaling.Envelope, v any) {
	t.Helper()
	if err := env.Unmarshal(v); err != nil {
		t.Fatalf("payload decode: %v", err)
	}
}

// wantErr は Result が送信元宛ての error 1 件（指定コード・Bind なし）であることを検証する。
func wantErr(t *testing.T, res Result, code string) {
	t.Helper()
	if res.Bind != nil {
		t.Errorf("エラー時は Bind なしのはず: %+v", res.Bind)
	}
	if len(res.Out) != 1 {
		t.Fatalf("error 応答は 1 件のはず: %+v", res.Out)
	}
	om := res.Out[0]
	if om.To.Kind != TargetOrigin || om.Env.Type != signaling.TypeError {
		t.Fatalf("送信元宛ての error を期待: %+v", om)
	}
	var e signaling.Error
	mustDecode(t, om.Env, &e)
	if e.Code != code {
		t.Errorf("code = %q, want %q (message=%q)", e.Code, code, e.Message)
	}
	if e.Message == "" {
		t.Error("error メッセージは空であってはならない")
	}
}

// hostCreate は create_room を通してルームを作成し、ルームIDと招待トークンを返す。
func hostCreate(t *testing.T, d *Dispatcher, now time.Time) (roomID, tok string) {
	t.Helper()
	res := d.Dispatch(
		Origin{Role: RoleHost, AccountID: testAccount, PubKey: testHostPK},
		envelope(signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: 1800}),
		now,
	)
	if res.Bind == nil {
		t.Fatalf("create_room は Bind を返すべき: %+v", res)
	}
	var rc signaling.RoomCreated
	mustDecode(t, res.Out[0].Env, &rc)
	return rc.RoomID, rc.Token
}

// guestJoin は join_request を通してゲストを待合室へ登録する。
func guestJoin(t *testing.T, d *Dispatcher, tok, pubKey, nick string, now time.Time) {
	t.Helper()
	res := d.Dispatch(
		Origin{Role: RoleGuest, RemoteIP: "203.0.113.5", PubKey: pubKey},
		envelope(signaling.TypeJoinRequest, signaling.JoinRequest{Token: tok, Nickname: nick, GuestPubKey: pubKey}),
		now,
	)
	if res.Bind == nil || res.Bind.Role != RoleGuest {
		t.Fatalf("join_request は guest Bind を返すべき: %+v", res)
	}
}

// approve はホストとしてゲストを承認する（join_approved→ゲスト、guest_joined→ホストの2通）。
func approve(t *testing.T, d *Dispatcher, roomID, guestPK string, now time.Time) {
	t.Helper()
	res := d.Dispatch(
		Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK, AccountID: testAccount},
		envelope(signaling.TypeDecision, signaling.Decision{GuestPubKey: guestPK, Approve: true}),
		now,
	)
	if len(res.Out) != 2 || res.Out[0].Env.Type != signaling.TypeJoinApproved || res.Out[1].Env.Type != signaling.TypeGuestJoined {
		t.Fatalf("承認は join_approved と guest_joined を返すべき: %+v", res.Out)
	}
}

// TestFullFlow は作成→参加→承認→エンドポイント交換→解散の一連を検証する（アーキ §3）。
func TestFullFlow(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()

	// 1. ルーム作成
	res := d.Dispatch(
		Origin{Role: RoleHost, AccountID: testAccount, PubKey: testHostPK},
		envelope(signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: 1800}),
		now,
	)
	if res.Bind == nil || res.Bind.Role != RoleHost || res.Bind.PubKey != testHostPK {
		t.Fatalf("create は host バインドを返すべき: %+v", res.Bind)
	}
	if len(res.Out) != 1 || res.Out[0].To.Kind != TargetOrigin || res.Out[0].Env.Type != signaling.TypeRoomCreated {
		t.Fatalf("room_created を送信元へ返すべき: %+v", res.Out)
	}
	var rc signaling.RoomCreated
	mustDecode(t, res.Out[0].Env, &rc)
	if rc.RoomID == "" || rc.Token == "" || rc.HostIP != "10.0.0.1" {
		t.Fatalf("room_created 内容が不正: %+v", rc)
	}
	if rc.Tier != string(plan.Free) {
		t.Errorf("room_created Tier = %q, want %q", rc.Tier, plan.Free)
	}
	roomID := rc.RoomID
	if res.Bind.RoomID != roomID {
		t.Errorf("bind RoomID = %q, want %q", res.Bind.RoomID, roomID)
	}

	// 2. ゲスト参加申請 → 待合室通知（SAS付き）をホストへ
	res = d.Dispatch(
		Origin{Role: RoleGuest, RemoteIP: "203.0.113.5", PubKey: testGuestPK},
		envelope(signaling.TypeJoinRequest, signaling.JoinRequest{Token: rc.Token, Nickname: "Alice", GuestPubKey: testGuestPK}),
		now,
	)
	if res.Bind == nil || res.Bind.Role != RoleGuest || res.Bind.RoomID != roomID || res.Bind.PubKey != testGuestPK {
		t.Fatalf("join は guest バインドを返すべき: %+v", res.Bind)
	}
	if len(res.Out) != 1 || res.Out[0].To.Kind != TargetHost || res.Out[0].To.RoomID != roomID {
		t.Fatalf("join_pending をホストへ返すべき: %+v", res.Out)
	}
	var jp signaling.JoinPending
	mustDecode(t, res.Out[0].Env, &jp)
	if jp.GuestPubKey != testGuestPK || jp.Nickname != "Alice" {
		t.Fatalf("join_pending 内容が不正: %+v", jp)
	}
	if jp.SAS != token.SAS([]byte(testGuestPK)) {
		t.Errorf("SAS はゲスト公開鍵から導出されるべき: got %q", jp.SAS)
	}

	// 3. 承認 → join_approved をゲストへ、guest_joined をホストへ
	hostOrigin := Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK, AccountID: testAccount}
	res = d.Dispatch(hostOrigin, envelope(signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestPK, Approve: true}), now)
	if len(res.Out) != 2 {
		t.Fatalf("承認は 2 件（ゲスト・ホスト）返すべき: %+v", res.Out)
	}
	if res.Out[0].To.Kind != TargetGuest || res.Out[0].To.PubKey != testGuestPK {
		t.Fatalf("1 件目は join_approved をゲストへ: %+v", res.Out[0])
	}
	var ja signaling.JoinApproved
	mustDecode(t, res.Out[0].Env, &ja)
	if ja.AssignedIP != "10.0.0.2" || ja.HostPubKey != testHostPK || ja.HostIP != "10.0.0.1" {
		t.Fatalf("join_approved 内容が不正: %+v", ja)
	}
	if ja.RoomID != roomID {
		t.Errorf("join_approved RoomID = %q, want %q（リレー認可に使う）", ja.RoomID, roomID)
	}
	if ja.Tier != string(plan.Free) {
		t.Errorf("join_approved Tier = %q, want %q", ja.Tier, plan.Free)
	}
	if res.Out[1].To.Kind != TargetHost || res.Out[1].Env.Type != signaling.TypeGuestJoined {
		t.Fatalf("2 件目は guest_joined をホストへ: %+v", res.Out[1])
	}
	var gj signaling.GuestJoined
	mustDecode(t, res.Out[1].Env, &gj)
	if gj.GuestPubKey != testGuestPK || gj.AssignedIP != "10.0.0.2" || gj.Nickname != "Alice" {
		t.Fatalf("guest_joined 内容が不正: %+v", gj)
	}

	// 4. ホストのエンドポイントを承認済みゲストへ中継
	res = d.Dispatch(hostOrigin, envelope(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: testHostPK, WANEndpoint: "198.51.100.1:51820"}), now)
	if len(res.Out) != 1 || res.Out[0].To.Kind != TargetGuest || res.Out[0].To.PubKey != testGuestPK || res.Out[0].Env.Type != signaling.TypePeerInfo {
		t.Fatalf("host peer_info を承認済みゲストへ中継すべき: %+v", res.Out)
	}

	// 5. ゲストのエンドポイントをホストへ中継
	guestOrigin := Origin{Role: RoleGuest, RoomID: roomID, PubKey: testGuestPK}
	res = d.Dispatch(guestOrigin, envelope(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: testGuestPK, WANEndpoint: "203.0.113.5:51820"}), now)
	if len(res.Out) != 1 || res.Out[0].To.Kind != TargetHost || res.Out[0].To.RoomID != roomID || res.Out[0].Env.Type != signaling.TypePeerInfo {
		t.Fatalf("guest peer_info をホストへ中継すべき: %+v", res.Out)
	}

	// 6. 解散 → ホスト＋承認済みゲストへ room_closed
	res = d.Dispatch(hostOrigin, envelope(signaling.TypeCloseRoom, signaling.CloseRoom{}), now)
	if len(res.Out) != 2 {
		t.Fatalf("解散通知はホスト＋ゲストの 2 件のはず: %+v", res.Out)
	}
	if res.Out[0].To.Kind != TargetHost || res.Out[1].To.Kind != TargetGuest || res.Out[1].To.PubKey != testGuestPK {
		t.Fatalf("解散通知の宛先が不正: %+v", res.Out)
	}
	var closed signaling.RoomClosed
	mustDecode(t, res.Out[1].Env, &closed)
	if closed.Reason != reasonHost {
		t.Errorf("解散理由 = %q, want %q", closed.Reason, reasonHost)
	}
	if _, ok := d.mgr.Get(roomID); ok {
		t.Error("解散後はルームが取得できてはならない")
	}
}

// TestRejectFlow はホストによる拒否で join_rejected(rejected) がゲストへ返ることを検証する。
func TestRejectFlow(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	roomID, tok := hostCreate(t, d, now)
	guestJoin(t, d, tok, testGuestPK, "Bob", now)

	res := d.Dispatch(
		Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK, AccountID: testAccount},
		envelope(signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestPK, Approve: false}),
		now,
	)
	if len(res.Out) != 1 || res.Out[0].To.Kind != TargetGuest || res.Out[0].Env.Type != signaling.TypeJoinRejected {
		t.Fatalf("拒否は join_rejected をゲストへ返すべき: %+v", res.Out)
	}
	var jr signaling.JoinRejected
	mustDecode(t, res.Out[0].Env, &jr)
	if jr.Reason != reasonRejected {
		t.Errorf("拒否理由 = %q, want %q", jr.Reason, reasonRejected)
	}
}

// TestKickFlow はキックで room_closed(kicked) が対象ゲストへ返ることを検証する。
func TestKickFlow(t *testing.T) {
	d := newDispatcher(t)
	now := time.Now()
	roomID, tok := hostCreate(t, d, now)
	guestJoin(t, d, tok, testGuestPK, "Carol", now)
	approve(t, d, roomID, testGuestPK, now)

	res := d.Dispatch(
		Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK, AccountID: testAccount},
		envelope(signaling.TypeKick, signaling.Kick{GuestPubKey: testGuestPK}),
		now,
	)
	if len(res.Out) != 1 || res.Out[0].To.Kind != TargetGuest || res.Out[0].To.PubKey != testGuestPK {
		t.Fatalf("キックは対象ゲストへ通知すべき: %+v", res.Out)
	}
	var closed signaling.RoomClosed
	mustDecode(t, res.Out[0].Env, &closed)
	if closed.Reason != reasonKicked {
		t.Errorf("キック理由 = %q, want %q", closed.Reason, reasonKicked)
	}
}

// badPayload は目的構造体へ展開できない不正ペイロードのエンベロープを返す。
func badPayload(t signaling.MessageType) signaling.Envelope {
	return signaling.Envelope{Type: t, Payload: json.RawMessage("{")}
}

func TestDispatchUnknownType(t *testing.T) {
	d := newDispatcher(t)
	// クライアントが送るべきでないサーバー→クライアント種別も default で弾く。
	res := d.Dispatch(Origin{Role: RoleHost}, signaling.Envelope{Type: signaling.TypeRoomCreated}, time.Now())
	wantErr(t, res, ErrCodeBadRequest)
}

func TestCreateRoomErrors(t *testing.T) {
	now := time.Now()

	// 役割不一致（ゲストが作成）。
	d := newDispatcher(t)
	res := d.Dispatch(Origin{Role: RoleGuest, AccountID: "a", PubKey: "p"},
		envelope(signaling.TypeCreateRoom, signaling.CreateRoom{}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// 認証情報欠如（AccountID / PubKey が空）。
	res = d.Dispatch(Origin{Role: RoleHost}, envelope(signaling.TypeCreateRoom, signaling.CreateRoom{}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// ペイロード不正。
	res = d.Dispatch(Origin{Role: RoleHost, AccountID: "a", PubKey: "p"}, badPayload(signaling.TypeCreateRoom), now)
	wantErr(t, res, ErrCodeBadRequest)
}

func TestCreateRoomRateLimited(t *testing.T) {
	now := time.Now()
	m, err := manager.New(manager.Config{CreateRate: 0, CreateBurst: 1})
	if err != nil {
		t.Fatal(err)
	}
	d := New(m)
	o := Origin{Role: RoleHost, AccountID: testAccount, PubKey: testHostPK}

	if res := d.Dispatch(o, envelope(signaling.TypeCreateRoom, signaling.CreateRoom{}), now); res.Bind == nil {
		t.Fatalf("1 回目は成功すべき: %+v", res)
	}
	res := d.Dispatch(o, envelope(signaling.TypeCreateRoom, signaling.CreateRoom{}), now)
	wantErr(t, res, ErrCodeRateLimited)
}

// TestCreateRoomEmptyPayloadAndTier は空ペイロード（duration 未指定）とプラン反映を検証する。
func TestCreateRoomEmptyPayloadAndTier(t *testing.T) {
	now := time.Now()

	// 空ペイロード → Free の上限（1h）へクランプ。
	d := newDispatcher(t)
	res := d.Dispatch(Origin{Role: RoleHost, AccountID: testAccount, PubKey: testHostPK},
		signaling.Envelope{Type: signaling.TypeCreateRoom}, now)
	if res.Bind == nil {
		t.Fatalf("空ペイロードでも作成できるべき: %+v", res)
	}
	r, ok := d.mgr.Get(res.Bind.RoomID)
	if !ok {
		t.Fatal("作成ルームを取得できるべき")
	}
	if got := r.ExpiresAt.Sub(now); got != time.Hour {
		t.Errorf("Free の既定制限時間 = %v, want 1h", got)
	}

	// Pro プラン + 5h → 5h（Free 上限を超える指定が通る）。
	d2 := newDispatcher(t)
	res = d2.Dispatch(Origin{Role: RoleHost, AccountID: testAccount, PubKey: testHostPK, Tier: plan.Pro},
		envelope(signaling.TypeCreateRoom, signaling.CreateRoom{DurationSeconds: int64((5 * time.Hour).Seconds())}), now)
	if res.Bind == nil {
		t.Fatalf("Pro 作成は成功すべき: %+v", res)
	}
	var rcPro signaling.RoomCreated
	mustDecode(t, res.Out[0].Env, &rcPro)
	if rcPro.Tier != string(plan.Pro) {
		t.Errorf("Pro の room_created Tier = %q, want %q", rcPro.Tier, plan.Pro)
	}
	r2, _ := d2.mgr.Get(res.Bind.RoomID)
	if got := r2.ExpiresAt.Sub(now); got != 5*time.Hour {
		t.Errorf("Pro の制限時間 = %v, want 5h", got)
	}
}

func TestJoinRequestErrors(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	_, tok := hostCreate(t, d, now)

	// 役割不一致（ホストが参加申請）。
	res := d.Dispatch(Origin{Role: RoleHost},
		envelope(signaling.TypeJoinRequest, signaling.JoinRequest{Token: tok, GuestPubKey: "g"}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// ペイロード不正。
	res = d.Dispatch(Origin{Role: RoleGuest}, badPayload(signaling.TypeJoinRequest), now)
	wantErr(t, res, ErrCodeBadRequest)

	// 必須フィールド欠如（トークンなし）。
	res = d.Dispatch(Origin{Role: RoleGuest},
		envelope(signaling.TypeJoinRequest, signaling.JoinRequest{GuestPubKey: "g"}), now)
	wantErr(t, res, ErrCodeBadRequest)

	// 未知トークン（公開鍵は正規形式で、トークン検証まで到達させる）。
	res = d.Dispatch(Origin{Role: RoleGuest},
		envelope(signaling.TypeJoinRequest, signaling.JoinRequest{Token: "bogus", GuestPubKey: testGuestPK}), now)
	wantErr(t, res, ErrCodeNotFound)

	// 公開鍵が不正形式（base64・32バイトでない）→ bad_request（入口検証・M-05(a)）。
	res = d.Dispatch(Origin{Role: RoleGuest},
		envelope(signaling.TypeJoinRequest, signaling.JoinRequest{Token: tok, Nickname: "x", GuestPubKey: "not-a-valid-key"}), now)
	wantErr(t, res, ErrCodeBadRequest)

	// 重複申請（同一鍵で二重申請）。
	guestJoin(t, d, tok, testGuestPK, "Dave", now)
	res = d.Dispatch(Origin{Role: RoleGuest, RemoteIP: "203.0.113.5", PubKey: testGuestPK},
		envelope(signaling.TypeJoinRequest, signaling.JoinRequest{Token: tok, Nickname: "Dave", GuestPubKey: testGuestPK}), now)
	wantErr(t, res, ErrCodeConflict)
}

func TestDecisionErrors(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, tok := hostCreate(t, d, now)
	guestJoin(t, d, tok, testGuestPK, "Eve", now)

	// 役割不一致 / ルーム未確立。
	res := d.Dispatch(Origin{Role: RoleGuest},
		envelope(signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestPK}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// ペイロード不正。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		badPayload(signaling.TypeDecision), now)
	wantErr(t, res, ErrCodeBadRequest)

	// 必須フィールド欠如。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypeDecision, signaling.Decision{}), now)
	wantErr(t, res, ErrCodeBadRequest)

	// 承認: ホスト鍵不一致。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: "impostor"},
		envelope(signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestPK, Approve: true}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// 承認: 未知ゲスト。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypeDecision, signaling.Decision{GuestPubKey: "no-such-guest", Approve: true}), now)
	wantErr(t, res, ErrCodeNotFound)

	// 承認: ルーム不明（o.RoomID が実在しない）。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: "ghost", PubKey: testHostPK},
		envelope(signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestPK, Approve: true}), now)
	wantErr(t, res, ErrCodeNotFound)

	// 拒否: ホスト鍵不一致。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: "impostor"},
		envelope(signaling.TypeDecision, signaling.Decision{GuestPubKey: testGuestPK, Approve: false}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// 拒否: 未知ゲスト。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypeDecision, signaling.Decision{GuestPubKey: "no-such-guest", Approve: false}), now)
	wantErr(t, res, ErrCodeNotFound)
}

func TestKickErrors(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, _ := hostCreate(t, d, now)

	// 役割不一致 / ルーム未確立。
	res := d.Dispatch(Origin{Role: RoleGuest},
		envelope(signaling.TypeKick, signaling.Kick{GuestPubKey: "g"}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// ペイロード不正。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK}, badPayload(signaling.TypeKick), now)
	wantErr(t, res, ErrCodeBadRequest)

	// 必須フィールド欠如。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypeKick, signaling.Kick{}), now)
	wantErr(t, res, ErrCodeBadRequest)

	// ホスト鍵不一致。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: "impostor"},
		envelope(signaling.TypeKick, signaling.Kick{GuestPubKey: "g"}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// 未知ゲスト。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypeKick, signaling.Kick{GuestPubKey: "no-such-guest"}), now)
	wantErr(t, res, ErrCodeNotFound)
}

func TestCloseRoomErrors(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, _ := hostCreate(t, d, now)

	// 役割不一致 / ルーム未確立。
	res := d.Dispatch(Origin{Role: RoleGuest}, envelope(signaling.TypeCloseRoom, signaling.CloseRoom{}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// ホスト鍵不一致。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: "impostor"},
		envelope(signaling.TypeCloseRoom, signaling.CloseRoom{}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// ルーム不明。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: "ghost", PubKey: testHostPK},
		envelope(signaling.TypeCloseRoom, signaling.CloseRoom{}), now)
	wantErr(t, res, ErrCodeNotFound)
}

// TestCloseRoomNoGuests はゲスト不在での解散が host 宛て 1 件のみになることを検証する。
func TestCloseRoomNoGuests(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, _ := hostCreate(t, d, now)

	res := d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypeCloseRoom, signaling.CloseRoom{}), now)
	if len(res.Out) != 1 || res.Out[0].To.Kind != TargetHost {
		t.Fatalf("ゲスト不在の解散は host 宛て 1 件のはず: %+v", res.Out)
	}
	var closed signaling.RoomClosed
	mustDecode(t, res.Out[0].Env, &closed)
	if closed.Reason != reasonHost {
		t.Errorf("理由 = %q, want %q", closed.Reason, reasonHost)
	}
}

func TestPeerInfoErrors(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, tok := hostCreate(t, d, now)

	// ルーム未確立。
	res := d.Dispatch(Origin{Role: RoleHost, PubKey: testHostPK},
		envelope(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: testHostPK, WANEndpoint: "e"}), now)
	wantErr(t, res, ErrCodeBadRequest)

	// ペイロード不正。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK}, badPayload(signaling.TypePeerInfo), now)
	wantErr(t, res, ErrCodeBadRequest)

	// 必須フィールド欠如。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: testHostPK}), now)
	wantErr(t, res, ErrCodeBadRequest)

	// 送信者と公開鍵が不一致（なりすまし）。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: "other", WANEndpoint: "e"}), now)
	wantErr(t, res, ErrCodeBadRequest)

	// ホスト鍵不一致（別ルームのホストを騙る等）。
	res = d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: "impostor"},
		envelope(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: "impostor", WANEndpoint: "e"}), now)
	wantErr(t, res, ErrCodeUnauthorized)

	// ゲスト（未承認）が中継しようとする。
	guestJoin(t, d, tok, testGuestPK, "Frank", now)
	res = d.Dispatch(Origin{Role: RoleGuest, RoomID: roomID, PubKey: testGuestPK},
		envelope(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: testGuestPK, WANEndpoint: "e"}), now)
	wantErr(t, res, ErrCodeConflict)

	// 未知の役割。
	res = d.Dispatch(Origin{Role: Role("weird"), RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: testHostPK, WANEndpoint: "e"}), now)
	wantErr(t, res, ErrCodeUnauthorized)
}

// TestPeerInfoHostNoGuests はホストの peer_info が承認済みゲスト不在なら空を返すことを検証する。
func TestPeerInfoHostNoGuests(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, _ := hostCreate(t, d, now)

	res := d.Dispatch(Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK},
		envelope(signaling.TypePeerInfo, signaling.PeerInfo{PubKey: testHostPK, WANEndpoint: "198.51.100.1:51820"}), now)
	if len(res.Out) != 0 || res.Bind != nil {
		t.Fatalf("承認済みゲスト不在なら中継先なし: %+v", res)
	}
}

func TestSweep(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, tok := hostCreate(t, d, now)
	guestJoin(t, d, tok, testGuestPK, "Grace", now)
	approve(t, d, roomID, testGuestPK, now)

	// 掃除対象なし。
	if out := d.Sweep(now); out != nil {
		t.Errorf("対象なしなら nil のはず: %+v", out)
	}

	// 制限時間超過（Free: 1h）で解散 → host + 承認済みゲストへ room_closed(expired)。
	out := d.Sweep(now.Add(time.Hour + time.Minute))
	if len(out) != 2 {
		t.Fatalf("解散通知はホスト＋ゲストの 2 件のはず: %+v", out)
	}
	if out[0].To.Kind != TargetHost || out[1].To.Kind != TargetGuest || out[1].To.PubKey != testGuestPK {
		t.Fatalf("宛先が不正: %+v", out)
	}
	var closed signaling.RoomClosed
	mustDecode(t, out[1].Env, &closed)
	if closed.Reason != string(room.CloseExpired) {
		t.Errorf("理由 = %q, want %q", closed.Reason, room.CloseExpired)
	}
	if d.mgr.Count() != 0 {
		t.Errorf("掃除後 Count = %d, want 0", d.mgr.Count())
	}
}

func TestExpirePending(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	_, tok := hostCreate(t, d, now)

	// 対象なし。
	if out := d.ExpirePending(now); out != nil {
		t.Errorf("Pending なしなら nil のはず: %+v", out)
	}

	// Pending 申請 → タイムアウト超過で失効通知。
	guestJoin(t, d, tok, testGuestPK, "Heidi", now)
	out := d.ExpirePending(now.Add(plan.JoinRequestTimeout + time.Second))
	if len(out) != 1 || out[0].To.Kind != TargetGuest || out[0].To.PubKey != testGuestPK {
		t.Fatalf("失効通知はゲスト宛て 1 件のはず: %+v", out)
	}
	var jr signaling.JoinRejected
	mustDecode(t, out[0].Env, &jr)
	if jr.Reason != reasonTimeout {
		t.Errorf("失効理由 = %q, want %q", jr.Reason, reasonTimeout)
	}
}

func TestCloseRoomMethod(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, tok := hostCreate(t, d, now)
	guestJoin(t, d, tok, testGuestPK, "Zoe", now)
	approve(t, d, roomID, testGuestPK, now)

	// 解散 → ホスト＋承認済みゲストへ room_closed。
	out := d.CloseRoom(roomID, room.CloseHost, now)
	if len(out) != 2 {
		t.Fatalf("解散通知はホスト＋ゲストの 2 件のはず: %+v", out)
	}
	if out[0].To.Kind != TargetHost || out[1].To.Kind != TargetGuest || out[1].To.PubKey != testGuestPK {
		t.Fatalf("宛先が不正: %+v", out)
	}
	var closed signaling.RoomClosed
	mustDecode(t, out[1].Env, &closed)
	if closed.Reason != string(room.CloseHost) {
		t.Errorf("理由 = %q, want %q", closed.Reason, room.CloseHost)
	}
	if _, ok := d.mgr.Get(roomID); ok {
		t.Error("解散後はルームが取得できてはならない")
	}

	// 冪等: 既に解散済みなら nil。
	if again := d.CloseRoom(roomID, room.CloseHost, now); again != nil {
		t.Errorf("解散済みルームは nil を返すべき: %+v", again)
	}
}

func TestGuestLeft(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, tok := hostCreate(t, d, now)
	guestJoin(t, d, tok, testGuestPK, "Ivy", now)
	approve(t, d, roomID, testGuestPK, now)

	// 離脱 → ホストへ guest_left（ピア除去用）。
	out := d.GuestLeft(roomID, testGuestPK, now)
	if len(out) != 1 || out[0].To.Kind != TargetHost || out[0].Env.Type != signaling.TypeGuestLeft {
		t.Fatalf("guest_left をホストへ返すべき: %+v", out)
	}
	var gl signaling.GuestLeft
	mustDecode(t, out[0].Env, &gl)
	if gl.GuestPubKey != testGuestPK {
		t.Errorf("guest_left の公開鍵が不正: %+v", gl)
	}

	// 離脱済み（もう居ない）なら nil。
	if again := d.GuestLeft(roomID, testGuestPK, now); again != nil {
		t.Errorf("不在ゲストの GuestLeft は nil を返すべき: %+v", again)
	}
	// 未知ルームも nil。
	if out := d.GuestLeft("ghost", testGuestPK, now); out != nil {
		t.Errorf("未知ルームの GuestLeft は nil を返すべき: %+v", out)
	}
}

// TestRotateToken は招待リンク再発行の正常系: 新トークン発行・旧トークン失効・承認済みピア維持。
func TestRotateToken(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, tok := hostCreate(t, d, now)

	// 承認済みゲストを 1 名用意（再発行後も維持されることの確認用）。
	guestJoin(t, d, tok, testGuestPK, "Alice", now)
	approve(t, d, roomID, testGuestPK, now)

	host := Origin{Role: RoleHost, RoomID: roomID, PubKey: testHostPK, AccountID: testAccount}

	// 再発行 → invite_reissued（新トークン）を送信元へ返す。
	res := d.Dispatch(host, envelope(signaling.TypeRotateToken, signaling.RotateToken{}), now)
	if len(res.Out) != 1 || res.Out[0].To.Kind != TargetOrigin || res.Out[0].Env.Type != signaling.TypeInviteReissued {
		t.Fatalf("invite_reissued を送信元へ返すべき: %+v", res.Out)
	}
	var ir signaling.InviteReissued
	mustDecode(t, res.Out[0].Env, &ir)
	if ir.Token == "" || ir.Token == tok {
		t.Errorf("新トークンは旧トークンと異なるべき: old=%q new=%q", tok, ir.Token)
	}

	// 旧トークンは失効（新規参加に使えない）。
	res = d.Dispatch(
		Origin{Role: RoleGuest, RemoteIP: "203.0.113.9", PubKey: testGuestPK2},
		envelope(signaling.TypeJoinRequest, signaling.JoinRequest{Token: tok, Nickname: "Late", GuestPubKey: testGuestPK2}),
		now,
	)
	wantErr(t, res, ErrCodeNotFound)

	// 承認済みゲスト・ルームは維持される（再発行はメンバーを変えない）。
	if _, ok := d.mgr.Get(roomID); !ok {
		t.Fatal("ルームは維持されるべき")
	}

	// 新トークンでの参加は受理される。
	guestJoin(t, d, ir.Token, testGuestPK3, "New", now)
}

// TestRotateTokenAuthErrors は再発行の権限エラー（非ホスト・ルーム未確立・ホスト不一致）を検証する。
func TestRotateTokenAuthErrors(t *testing.T) {
	now := time.Now()
	d := newDispatcher(t)
	roomID, _ := hostCreate(t, d, now)

	rotate := func(o Origin) Result {
		return d.Dispatch(o, envelope(signaling.TypeRotateToken, signaling.RotateToken{}), now)
	}

	// 非ホストは不可。
	wantErr(t, rotate(Origin{Role: RoleGuest, RoomID: roomID, PubKey: testGuestPK}), ErrCodeUnauthorized)
	// ルーム未確立（RoomID 空）は不可。
	wantErr(t, rotate(Origin{Role: RoleHost, PubKey: testHostPK}), ErrCodeUnauthorized)
	// 当該ルームのホストでない公開鍵は不可（ErrNotRoomHost）。
	wantErr(t, rotate(Origin{Role: RoleHost, RoomID: roomID, PubKey: "not-the-host"}), ErrCodeUnauthorized)
}

func TestClassify(t *testing.T) {
	cases := []struct {
		err  error
		code string
	}{
		{manager.ErrRoomNotFound, ErrCodeNotFound},
		{manager.ErrCreateRateLimited, ErrCodeRateLimited},
		{manager.ErrPrefixExhausted, ErrCodeUnavailable},
		{manager.ErrTokenCollision, ErrCodeInternal},
		{manager.ErrNotRoomHost, ErrCodeUnauthorized},
		{room.ErrRateLimited, ErrCodeRateLimited},
		{room.ErrDenied, ErrCodeDenied},
		{room.ErrDuplicate, ErrCodeConflict},
		{room.ErrRoomFull, ErrCodeRoomFull},
		{room.ErrWaitingRoomFull, ErrCodeRoomFull},
		{room.ErrNotPending, ErrCodeConflict},
		{room.ErrUnknownGuest, ErrCodeNotFound},
		{room.ErrRoomClosed, ErrCodeRoomClosed},
		{room.ErrRoomExpired, ErrCodeRoomClosed},
		{room.ErrEmptyPubKey, ErrCodeBadRequest},
		{errNotRoomHost, ErrCodeUnauthorized},
		{errNotApproved, ErrCodeConflict},
		{errors.New("unclassified"), ErrCodeBadRequest},
	}
	for _, c := range cases {
		code, msg := classify(c.err)
		if code != c.code {
			t.Errorf("classify(%v) code = %q, want %q", c.err, code, c.code)
		}
		if msg == "" {
			t.Errorf("classify(%v) message は空であってはならない", c.err)
		}
	}
}
