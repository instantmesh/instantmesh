package room

import (
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/ipam"
	"github.com/instantmesh/instantmesh/pkg/nickname"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/ratelimit"
)

func newRoom(t *testing.T, tier plan.Tier, now time.Time) *Room {
	t.Helper()
	return newRoomWithLimiter(t, tier, nil, now)
}

func newRoomWithLimiter(t *testing.T, tier plan.Tier, lim *ratelimit.Limiter, now time.Time) *Room {
	t.Helper()
	r, err := Create(CreateParams{
		ID:            "room-1",
		HostAccountID: "host-acct",
		HostPubKey:    "host-pubkey",
		Tier:          tier,
		Token:         "invite-token",
		Prefix:        netip.MustParsePrefix("10.0.0.0/24"),
		JoinLimiter:   lim,
	}, now)
	if err != nil {
		t.Fatalf("Create エラー: %v", err)
	}
	return r
}

func TestCreateAndToken(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if r.State != Active {
		t.Errorf("State = %s, want active", r.State)
	}
	if !r.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("ExpiresAt = %v, want +1h (Free 上限)", r.ExpiresAt)
	}
	if !r.VerifyToken("invite-token") {
		t.Error("正しいトークンは検証を通るべき")
	}
	if r.VerifyToken("wrong") {
		t.Error("誤ったトークンは検証を通ってはならない")
	}
	if got := r.HostIP().String(); got != "10.0.0.1" {
		t.Errorf("HostIP = %s, want 10.0.0.1", got)
	}
}

func TestDurationClamp(t *testing.T) {
	now := time.Now()
	r, err := Create(CreateParams{
		ID: "r", HostAccountID: "h", HostPubKey: "hk", Tier: plan.Free,
		Token: "tk", Prefix: netip.MustParsePrefix("10.0.0.0/24"),
		Duration: 10 * time.Hour, // Free 上限(1h)超 → クランプ
	}, now)
	if err != nil {
		t.Fatal(err)
	}
	if !r.ExpiresAt.Equal(now.Add(time.Hour)) {
		t.Errorf("上限超過の Duration はクランプされるべき: ExpiresAt=%v", r.ExpiresAt)
	}
}

func TestWaitingRoomHappyPath(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	g, err := r.RequestJoin("guest-pk", "Alice", "203.0.113.9", now)
	if err != nil {
		t.Fatalf("RequestJoin エラー: %v", err)
	}
	if g.State != Pending {
		t.Errorf("申請直後の State = %s, want pending", g.State)
	}
	if g.IP.IsValid() {
		t.Error("承認前ネットワーク隔離: Pending は IP 未割当であるべき")
	}

	approved, err := r.Approve("guest-pk", now)
	if err != nil {
		t.Fatalf("Approve エラー: %v", err)
	}
	if approved.State != Approved {
		t.Errorf("State = %s, want approved", approved.State)
	}
	if approved.IP.String() != "10.0.0.2" {
		t.Errorf("承認後 IP = %s, want 10.0.0.2", approved.IP)
	}
	if len(r.ActiveGuests()) != 1 {
		t.Errorf("ActiveGuests = %d, want 1", len(r.ActiveGuests()))
	}
}

func TestApproveRespectsGuestCap(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now) // MaxGuests=5

	for i := 0; i < 5; i++ {
		pk := fmt.Sprintf("pk%d", i)
		if _, err := r.RequestJoin(pk, fmt.Sprintf("g%d", i), "10.1.1.1", now); err != nil {
			t.Fatalf("RequestJoin[%d] エラー: %v", i, err)
		}
		if _, err := r.Approve(pk, now); err != nil {
			t.Fatalf("Approve[%d] エラー: %v", i, err)
		}
	}

	if _, err := r.RequestJoin("pk5", "g5", "10.1.1.1", now); err != nil {
		t.Fatalf("6 人目の申請自体は可能なはず: %v", err)
	}
	if _, err := r.Approve("pk5", now); err != ErrRoomFull {
		t.Errorf("6 人目の承認は ErrRoomFull を返すべき, got %v", err)
	}
}

func TestRejectBlocksRejoin(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if _, err := r.RequestJoin("pk", "Bob", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}
	if err := r.Reject("pk", now); err != nil {
		t.Fatalf("Reject エラー: %v", err)
	}
	if _, err := r.RequestJoin("pk", "Bob", "10.0.0.9", now); err != ErrDenied {
		t.Errorf("拒否後の再申請は ErrDenied を返すべき, got %v", err)
	}
}

func TestKickReclaimsIPAndBlocksRejoin(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if _, err := r.RequestJoin("pk", "Carol", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve("pk", now); err != nil {
		t.Fatal(err)
	}
	if err := r.Kick("pk", now); err != nil {
		t.Fatalf("Kick エラー: %v", err)
	}

	g, _ := r.Guest("pk")
	if g.State != Kicked {
		t.Errorf("State = %s, want kicked", g.State)
	}
	if g.IP.IsValid() {
		t.Error("キック後は IP が回収されるべき")
	}
	if _, err := r.RequestJoin("pk", "Carol", "10.0.0.9", now); err != ErrDenied {
		t.Errorf("キック後の再参加は ErrDenied を返すべき, got %v", err)
	}

	// Kick は冪等。
	if err := r.Kick("pk", now); err != nil {
		t.Errorf("再キックはエラーにならないべき, got %v", err)
	}
}

func TestExpirePendingThenAllowRejoin(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if _, err := r.RequestJoin("pk", "Dan", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}

	// タイムアウト未満では失効しない。
	if got := r.ExpirePending(now.Add(plan.JoinRequestTimeout - time.Second)); len(got) != 0 {
		t.Errorf("タイムアウト前に失効した: %d 件", len(got))
	}
	// タイムアウト到達で失効。
	expired := r.ExpirePending(now.Add(plan.JoinRequestTimeout))
	if len(expired) != 1 {
		t.Fatalf("失効件数 = %d, want 1", len(expired))
	}
	if expired[0].State != Expired {
		t.Errorf("返却された失効ゲストの State = %s, want expired", expired[0].State)
	}
	// 失効エントリは r.guests から実削除される（メモリ累積防止・M-04）。
	if _, ok := r.Guest("pk"); ok {
		t.Error("失効した申請は実削除されるべき")
	}

	// 失効した鍵は再申請できる。
	later := now.Add(plan.JoinRequestTimeout + time.Second)
	g, err := r.RequestJoin("pk", "Dan", "10.0.0.9", later)
	if err != nil {
		t.Fatalf("失効後の再申請は許可されるべき: %v", err)
	}
	if g.State != Pending {
		t.Errorf("再申請後の State = %s, want pending", g.State)
	}
}

func TestDuplicateRequest(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if _, err := r.RequestJoin("pk", "Eve", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.RequestJoin("pk", "Eve", "10.0.0.9", now); err != ErrDuplicate {
		t.Errorf("申請中の重複申請は ErrDuplicate を返すべき, got %v", err)
	}
}

func TestNicknameDeduplication(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	g1, err := r.RequestJoin("pk1", "dev", "10.0.0.9", now)
	if err != nil {
		t.Fatal(err)
	}
	g2, err := r.RequestJoin("pk2", "dev", "10.0.0.9", now)
	if err != nil {
		t.Fatal(err)
	}
	if g1.Nickname != "dev" {
		t.Errorf("1 人目の表示名 = %q, want %q", g1.Nickname, "dev")
	}
	if g2.Nickname != "dev#2" {
		t.Errorf("重複時の表示名 = %q, want %q", g2.Nickname, "dev#2")
	}
}

// TestNicknameSuffixCollision はユーザ申告名が生成サフィックスと衝突するケース（保険ループの前進）を検証する。
func TestNicknameSuffixCollision(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if _, err := r.RequestJoin("pk1", "dev", "10.0.0.9", now); err != nil { // "dev"
		t.Fatal(err)
	}
	if _, err := r.RequestJoin("pk2", "dev#2", "10.0.0.9", now); err != nil { // ユーザ申告の "dev#2" を先取り
		t.Fatal(err)
	}
	// 3 人目の "dev" は nameSeq の開始位置 "dev#2" が使用中のため前進し "dev#3" になる。
	g3, err := r.RequestJoin("pk3", "dev", "10.0.0.9", now)
	if err != nil {
		t.Fatal(err)
	}
	if g3.Nickname != "dev#3" {
		t.Errorf("衝突回避後の表示名 = %q, want %q", g3.Nickname, "dev#3")
	}
}

// TestWaitingRoomCapacity は待合室(Pending)の同時申請数が上限に達すると ErrWaitingRoomFull を返すことを検証する（M-04）。
func TestWaitingRoomCapacity(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	for i := 0; i < MaxPendingGuests; i++ {
		pk := fmt.Sprintf("pk%d", i)
		if _, err := r.RequestJoin(pk, fmt.Sprintf("g%d", i), "10.1.1.1", now); err != nil {
			t.Fatalf("RequestJoin[%d] は上限内で成功すべき: %v", i, err)
		}
	}
	if _, err := r.RequestJoin("overflow", "of", "10.1.1.1", now); err != ErrWaitingRoomFull {
		t.Errorf("上限超過の申請は ErrWaitingRoomFull を返すべき, got %v", err)
	}

	// 失効で枠が空けば再び申請できる（実削除でカウントが減る）。
	expired := r.ExpirePending(now.Add(plan.JoinRequestTimeout))
	if len(expired) != MaxPendingGuests {
		t.Fatalf("失効件数 = %d, want %d", len(expired), MaxPendingGuests)
	}
	if _, err := r.RequestJoin("after", "af", "10.1.1.1", now.Add(plan.JoinRequestTimeout)); err != nil {
		t.Errorf("失効後は再び申請可能であるべき: %v", err)
	}
}

func TestJoinRateLimited(t *testing.T) {
	now := time.Now()
	// burst=1, rate=0 → 同一IPからは 1 回のみ許可。
	r := newRoomWithLimiter(t, plan.Free, ratelimit.New(0, 1), now)

	if _, err := r.RequestJoin("pk1", "a", "10.9.9.9", now); err != nil {
		t.Fatalf("1 回目は許可されるべき: %v", err)
	}
	if _, err := r.RequestJoin("pk2", "b", "10.9.9.9", now); err != ErrRateLimited {
		t.Errorf("同一IPの連続申請は ErrRateLimited を返すべき, got %v", err)
	}
}

func TestExpiredRoomRejectsJoin(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now) // 上限 1h

	after := now.Add(time.Hour + time.Minute)
	if _, err := r.RequestJoin("pk", "late", "10.0.0.9", after); err != ErrRoomExpired {
		t.Errorf("期限切れルームへの申請は ErrRoomExpired を返すべき, got %v", err)
	}
}

func TestIdleDetection(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if r.IsIdle(now.Add(plan.IdleTimeout - time.Minute)) {
		t.Error("アイドル未満で IsIdle=true になった")
	}
	if !r.IsIdle(now.Add(plan.IdleTimeout)) {
		t.Error("純アイドル 30 分で IsIdle=true になるべき")
	}
}

func TestClosedRoomRejectsJoin(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)
	r.Close(CloseHost, now)

	if r.State != Closed {
		t.Errorf("State = %s, want closed", r.State)
	}
	if _, err := r.RequestJoin("pk", "x", "10.0.0.9", now); err != ErrRoomClosed {
		t.Errorf("解散済みルームへの申請は ErrRoomClosed を返すべき, got %v", err)
	}
}

func TestLeaveApproved(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)
	if _, err := r.RequestJoin("pkA", "alice", "1.1.1.1", now); err != nil {
		t.Fatal(err)
	}
	ga, err := r.Approve("pkA", now)
	if err != nil {
		t.Fatal(err)
	}
	if !ga.IP.IsValid() {
		t.Fatal("承認で仮想IPが割り当たるべき")
	}

	// 正常離脱: 除去され、再参加は許可され、表示名も解放される。
	if err := r.Leave("pkA", now); err != nil {
		t.Fatalf("Leave エラー: %v", err)
	}
	if _, ok := r.Guest("pkA"); ok {
		t.Error("離脱後はゲストが存在しないべき")
	}
	g2, err := r.RequestJoin("pkA", "alice", "1.1.1.1", now)
	if err != nil {
		t.Fatalf("離脱後の再参加は許可されるべき（denied でない）: %v", err)
	}
	if g2.Nickname != "alice" {
		t.Errorf("表示名が解放され再取得できるべき: got %q", g2.Nickname)
	}
}

func TestLeavePendingAndUnknown(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	// Pending（IP 未割当）の離脱。
	if _, err := r.RequestJoin("pkB", "bob", "2.2.2.2", now); err != nil {
		t.Fatal(err)
	}
	if err := r.Leave("pkB", now); err != nil {
		t.Fatalf("Pending の Leave エラー: %v", err)
	}
	if _, ok := r.Guest("pkB"); ok {
		t.Error("離脱後はゲストが存在しないべき")
	}

	// 未知ゲスト。
	if err := r.Leave("nope", now); err != ErrUnknownGuest {
		t.Errorf("未知ゲストの Leave は ErrUnknownGuest, got %v", err)
	}
}

func TestCreateErrors(t *testing.T) {
	now := time.Now()
	prefix := netip.MustParsePrefix("10.0.0.0/24")

	// 未知プラン。
	if _, err := Create(CreateParams{
		ID: "r", HostAccountID: "h", HostPubKey: "hk",
		Tier: plan.Tier("enterprise"), Token: "t", Prefix: prefix,
	}, now); err == nil {
		t.Error("未知プランはエラーになるべき")
	}

	// 必須フィールド欠落（Token 空）。
	if _, err := Create(CreateParams{
		ID: "r", HostAccountID: "h", HostPubKey: "hk",
		Tier: plan.Free, Token: "", Prefix: prefix,
	}, now); err == nil {
		t.Error("必須フィールド欠落はエラーになるべき")
	}

	// 不正な Prefix（/24 でない）。
	if _, err := Create(CreateParams{
		ID: "r", HostAccountID: "h", HostPubKey: "hk",
		Tier: plan.Free, Token: "t", Prefix: netip.MustParsePrefix("10.0.0.0/16"),
	}, now); err == nil {
		t.Error("/24 でない Prefix はエラーになるべき")
	}
}

func TestRequestJoinEmptyPubKey(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)
	if _, err := r.RequestJoin("", "nick", "10.0.0.9", now); err != ErrEmptyPubKey {
		t.Errorf("空公開鍵は ErrEmptyPubKey を返すべき, got %v", err)
	}
}

func TestApproveErrors(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	// 未知ゲスト。
	if _, err := r.Approve("nope", now); err != ErrUnknownGuest {
		t.Errorf("未知ゲストの承認は ErrUnknownGuest, got %v", err)
	}

	// 二重承認は ErrNotPending。
	if _, err := r.RequestJoin("pk", "a", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve("pk", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve("pk", now); err != ErrNotPending {
		t.Errorf("承認済みの再承認は ErrNotPending, got %v", err)
	}

	// 解散後の承認は ErrRoomClosed。
	r.Close(CloseHost, now)
	if _, err := r.Approve("pk", now); err != ErrRoomClosed {
		t.Errorf("解散後の承認は ErrRoomClosed, got %v", err)
	}
}

func TestRejectErrors(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if err := r.Reject("nope", now); err != ErrUnknownGuest {
		t.Errorf("未知ゲストの拒否は ErrUnknownGuest, got %v", err)
	}

	if _, err := r.RequestJoin("pk", "a", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Approve("pk", now); err != nil {
		t.Fatal(err)
	}
	if err := r.Reject("pk", now); err != ErrNotPending {
		t.Errorf("承認済みの拒否は ErrNotPending, got %v", err)
	}

	// 解散後の拒否は ErrRoomClosed（ensureOpen 経由）。
	r.Close(CloseHost, now)
	if err := r.Reject("pk", now); err != ErrRoomClosed {
		t.Errorf("解散後の拒否は ErrRoomClosed, got %v", err)
	}
}

func TestKickPendingAndUnknown(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if err := r.Kick("nope", now); err != ErrUnknownGuest {
		t.Errorf("未知ゲストのキックは ErrUnknownGuest, got %v", err)
	}

	// Pending（IP 未割当）のキックは Release を呼ばず Kicked にする。
	if _, err := r.RequestJoin("pk", "a", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}
	if err := r.Kick("pk", now); err != nil {
		t.Fatalf("Pending のキックでエラー: %v", err)
	}
	g, _ := r.Guest("pk")
	if g.State != Kicked {
		t.Errorf("State = %s, want kicked", g.State)
	}
	if g.IP.IsValid() {
		t.Error("Pending キック後も IP は無効のままであるべき")
	}
}

func TestGuestNotFound(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)
	if _, ok := r.Guest("nope"); ok {
		t.Error("存在しないゲストは ok=false を返すべき")
	}
}

func TestCloseIdempotent(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	r.Close(CloseHost, now)
	r.Close(CloseIdle, now.Add(time.Minute)) // 2 回目は無視される

	if r.CloseReason != CloseHost {
		t.Errorf("CloseReason = %s, 最初の理由(host)が保持されるべき", r.CloseReason)
	}
	if !r.ClosedAt.Equal(now) {
		t.Error("ClosedAt は最初の解散時刻が保持されるべき")
	}
}

func TestIsExpired(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now) // 上限 1h

	if r.IsExpired(now.Add(59 * time.Minute)) {
		t.Error("期限内で IsExpired=true になった")
	}
	if !r.IsExpired(now.Add(time.Hour + time.Second)) {
		t.Error("期限超過で IsExpired=true になるべき")
	}
}

func TestSetTokenRotation(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	if !r.VerifyToken("invite-token") {
		t.Fatal("初期トークンで検証が通るべき")
	}
	r.SetToken("rotated-token")
	if r.VerifyToken("invite-token") {
		t.Error("ローテーション後は旧トークンで検証が通ってはならない")
	}
	if !r.VerifyToken("rotated-token") {
		t.Error("ローテーション後は新トークンで検証が通るべき")
	}
}

func TestTouchUpdatesActivity(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	// Touch でアイドル基準時刻が前進する。
	later := now.Add(20 * time.Minute)
	r.Touch(later)

	if r.IsIdle(later.Add(plan.IdleTimeout - time.Minute)) {
		t.Error("Touch 後はアイドル基準が更新され、IdleTimeout 未満では IsIdle=false のはず")
	}
	if !r.IsIdle(later.Add(plan.IdleTimeout)) {
		t.Error("Touch 基準から IdleTimeout 経過で IsIdle=true になるべき")
	}
}

func TestRequestJoinInvalidNickname(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	// 正規化後に空となるニックネームは nickname.Clean のエラーが伝播する。
	if _, err := r.RequestJoin("pk", "   ", "10.0.0.9", now); err != nickname.ErrEmpty {
		t.Errorf("空ニックネームは nickname.ErrEmpty を伝播すべき, got %v", err)
	}
}

func TestRequestJoinDeniedStateFallthrough(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	// 防御的分岐: 通常 Rejected/Kicked は denied に載るが、
	// 何らかの理由で denied 未登録のまま denied 状態のゲストが居た場合も再申請を拒否する。
	if _, err := r.RequestJoin("pk", "a", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}
	// denied を経由せず Rejected 状態へ直接遷移させる（白箱）。
	r.guests["pk"].State = Rejected

	if _, err := r.RequestJoin("pk", "a", "10.0.0.9", now); err != ErrDenied {
		t.Errorf("denied 未登録でも denied 状態の鍵は ErrDenied を返すべき, got %v", err)
	}
}

func TestApproveAllocatorExhausted(t *testing.T) {
	now := time.Now()
	r := newRoom(t, plan.Free, now)

	// アロケータの .2..254 を全消費して枯渇させる（白箱）。
	for i := 0; i < 253; i++ {
		if _, err := r.alloc.Allocate(now); err != nil {
			break
		}
	}

	if _, err := r.RequestJoin("pk", "a", "10.0.0.9", now); err != nil {
		t.Fatal(err)
	}
	// approvedCount=0 < MaxGuests だが IP 枯渇で Approve は失敗する。
	if _, err := r.Approve("pk", now); err != ipam.ErrExhausted {
		t.Errorf("IP 枯渇時の承認は ipam.ErrExhausted を返すべき, got %v", err)
	}
}
