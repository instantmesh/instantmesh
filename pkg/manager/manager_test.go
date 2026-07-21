package manager

import (
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/room"
	"github.com/instantmesh/instantmesh/pkg/token"
)

func newManager(t *testing.T) *Manager {
	t.Helper()
	m, err := New(Config{})
	if err != nil {
		t.Fatalf("New エラー: %v", err)
	}
	return m
}

func mustCreate(t *testing.T, m *Manager, host string, now time.Time) *room.Room {
	t.Helper()
	r, err := m.Create(CreateParams{
		HostAccountID: host,
		HostPubKey:    "host-pk",
		Tier:          plan.Free,
	}, now)
	if err != nil {
		t.Fatalf("Create エラー: %v", err)
	}
	return r
}

func TestCreateAssignsPrefixAndIndexes(t *testing.T) {
	now := time.Now()
	m := newManager(t)

	r := mustCreate(t, m, "host-1", now)

	if r.State != room.Active {
		t.Errorf("State = %s, want active", r.State)
	}
	// 既定プール 10.0.0.0/8 の先頭 /24 が割り当てられる。
	if got := r.HostIP().String(); got != "10.0.0.1" {
		t.Errorf("HostIP = %s, want 10.0.0.1", got)
	}
	if m.Count() != 1 {
		t.Errorf("Count = %d, want 1", m.Count())
	}

	// ID 索引で取得できる。
	if got, ok := m.Get(r.ID); !ok || got != r {
		t.Error("Get(ID) で同一ルームが取得できるべき")
	}
	if _, ok := m.Get("no-such-room"); ok {
		t.Error("未知IDは ok=false を返すべき")
	}
}

func TestCreateSequentialPrefixes(t *testing.T) {
	now := time.Now()
	m, err := New(Config{Pool: netip.MustParsePrefix("10.9.0.0/16")})
	if err != nil {
		t.Fatal(err)
	}

	r1 := mustCreate(t, m, "h", now)
	r2 := mustCreate(t, m, "h", now)
	if r1.HostIP().String() != "10.9.0.1" {
		t.Errorf("1 室目 HostIP = %s, want 10.9.0.1", r1.HostIP())
	}
	if r2.HostIP().String() != "10.9.1.1" {
		t.Errorf("2 室目 HostIP = %s, want 10.9.1.1", r2.HostIP())
	}
}

func TestLookupByToken(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	r := mustCreate(t, m, "h", now)

	// 生成トークンは room.VerifyToken を通る値であり、そのトークンで解決できる。
	// トークン値は Manager 内部管理なので、ローテーション経由で既知値にして検証する。
	tok, err := m.RotateToken(r.ID)
	if err != nil {
		t.Fatalf("RotateToken エラー: %v", err)
	}

	got, ok := m.LookupByToken(tok)
	if !ok || got != r {
		t.Error("有効トークンでルームを解決できるべき")
	}
	if !got.VerifyToken(tok) {
		t.Error("解決したルームは当該トークンで検証を通るべき")
	}
	if _, ok := m.LookupByToken("bogus"); ok {
		t.Error("未知トークンは ok=false を返すべき")
	}
}

func TestRotateTokenInvalidatesOld(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	r := mustCreate(t, m, "h", now)

	first, err := m.RotateToken(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	second, err := m.RotateToken(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("ローテーションで新トークンが変わるべき")
	}

	// 旧トークンは無効、新トークンは有効。
	if _, ok := m.LookupByToken(first); ok {
		t.Error("ローテーション後、旧トークンでは解決できてはならない")
	}
	if got, ok := m.LookupByToken(second); !ok || got != r {
		t.Error("新トークンで解決できるべき")
	}
	if r.VerifyToken(first) {
		t.Error("旧トークンは VerifyToken を通ってはならない")
	}
}

func TestCloseRemovesRoom(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	r := mustCreate(t, m, "h", now)
	tok, _ := m.RotateToken(r.ID)

	if err := m.Close(r.ID, room.CloseHost, now); err != nil {
		t.Fatalf("Close エラー: %v", err)
	}
	if r.State != room.Closed || r.CloseReason != room.CloseHost {
		t.Errorf("解散状態が反映されるべき: state=%s reason=%s", r.State, r.CloseReason)
	}
	if _, ok := m.Get(r.ID); ok {
		t.Error("解散後は Get で取得できてはならない")
	}
	if _, ok := m.LookupByToken(tok); ok {
		t.Error("解散後はトークン索引からも消えるべき")
	}
	if m.Count() != 0 {
		t.Errorf("Count = %d, want 0", m.Count())
	}
}

func TestSweepIdle(t *testing.T) {
	base := time.Now()
	m := newManager(t)

	idle := mustCreate(t, m, "h1", base)
	active := mustCreate(t, m, "h2", base)

	sweepAt := base.Add(31 * time.Minute) // アイドル(30分)超・制限時間(1h)内
	// active は掃除直前に通信活動を記録して生存させる。
	if err := m.WithRoom(active.ID, func(r *room.Room) error {
		r.Touch(sweepAt)
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	swept := m.Sweep(sweepAt)
	if len(swept) != 1 || swept[0].ID != idle.ID || swept[0].CloseReason != room.CloseIdle {
		t.Fatalf("アイドル室のみが idle 理由で解散されるべき: %+v", swept)
	}
	if _, ok := m.Get(active.ID); !ok {
		t.Error("Touch した室は掃除で生存すべき")
	}
	if m.Count() != 1 {
		t.Errorf("掃除後 Count = %d, want 1", m.Count())
	}
}

func TestSweepExpiredTakesPrecedence(t *testing.T) {
	base := time.Now()
	m := newManager(t)
	r := mustCreate(t, m, "h", base) // Free: 上限 1h

	// 制限時間超（かつアイドルでもある）。IsExpired が優先され expired 理由になる。
	swept := m.Sweep(base.Add(time.Hour + time.Minute))
	if len(swept) != 1 || swept[0].ID != r.ID || swept[0].CloseReason != room.CloseExpired {
		t.Fatalf("制限時間超は expired 理由で解散されるべき: %+v", swept)
	}
	if m.Count() != 0 {
		t.Errorf("掃除後 Count = %d, want 0", m.Count())
	}
}

func TestSweepNothing(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	mustCreate(t, m, "h", now)

	if swept := m.Sweep(now); swept != nil {
		t.Errorf("解散対象なしなら nil を返すべき, got %v", swept)
	}
}

func TestSweepEvictsCreateLimiter(t *testing.T) {
	base := time.Now()
	m, err := New(Config{CreateRate: 1, CreateBurst: 2}) // createLimiter 有り
	if err != nil {
		t.Fatalf("New エラー: %v", err)
	}
	// 作成でホストアカウントのバケットが生成される。
	if _, err := m.Create(CreateParams{HostAccountID: "acct", HostPubKey: "pk", Tier: plan.Free}, base); err != nil {
		t.Fatalf("Create エラー: %v", err)
	}
	// Sweep は createLimiter.Evict を通る（満タン回復済みバケットを破棄。挙動は不変）。
	m.Sweep(base.Add(time.Hour))
	// エビクション後も作成できる（満タン＝未生成と等価）。
	if _, err := m.Create(CreateParams{HostAccountID: "acct", HostPubKey: "pk2", Tier: plan.Free}, base.Add(time.Hour)); err != nil {
		t.Errorf("エビクション後も作成できるべき: %v", err)
	}
}

func TestWithRoomMutatesUnderLock(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	r := mustCreate(t, m, "h", now)

	err := m.WithRoom(r.ID, func(rm *room.Room) error {
		_, err := rm.RequestJoin("guest-pk", "Alice", "203.0.113.9", now)
		return err
	})
	if err != nil {
		t.Fatalf("WithRoom 内の RequestJoin エラー: %v", err)
	}
	if g, ok := r.Guest("guest-pk"); !ok || g.State != room.Pending {
		t.Error("WithRoom 経由の変更が反映されるべき")
	}
}

func TestNewInvalidPool(t *testing.T) {
	// IPv6 は非対応。
	if _, err := New(Config{Pool: netip.MustParsePrefix("2001:db8::/32")}); err == nil {
		t.Error("IPv6 プールはエラーになるべき")
	}
	// /24 より狭い（/25）は /24 を内包できずエラー。
	if _, err := New(Config{Pool: netip.MustParsePrefix("10.0.0.0/25")}); err == nil {
		t.Error("/25 プールはエラーになるべき")
	}
}

func TestCreateRateLimited(t *testing.T) {
	now := time.Now()
	// burst=1, rate=0 → 同一アカウントからは 1 回のみ許可。
	m, err := New(Config{CreateRate: 0, CreateBurst: 1})
	if err != nil {
		t.Fatal(err)
	}

	if _, err := m.Create(CreateParams{HostAccountID: "h", HostPubKey: "pk", Tier: plan.Free}, now); err != nil {
		t.Fatalf("1 回目は許可されるべき: %v", err)
	}
	if _, err := m.Create(CreateParams{HostAccountID: "h", HostPubKey: "pk", Tier: plan.Free}, now); err != ErrCreateRateLimited {
		t.Errorf("同一アカウントの連続作成は ErrCreateRateLimited を返すべき, got %v", err)
	}
	// 別アカウントは独立に許可される。
	if _, err := m.Create(CreateParams{HostAccountID: "other", HostPubKey: "pk", Tier: plan.Free}, now); err != nil {
		t.Errorf("別アカウントは許可されるべき: %v", err)
	}
}

func TestCreatePrefixExhaustedThenReuse(t *testing.T) {
	now := time.Now()
	// /24 プール → 払い出せる /24 は 1 つだけ。
	m, err := New(Config{Pool: netip.MustParsePrefix("10.7.7.0/24")})
	if err != nil {
		t.Fatal(err)
	}

	r1 := mustCreate(t, m, "h", now)
	if r1.HostIP().String() != "10.7.7.1" {
		t.Errorf("HostIP = %s, want 10.7.7.1", r1.HostIP())
	}

	// 2 室目は枯渇。
	if _, err := m.Create(CreateParams{HostAccountID: "h", HostPubKey: "pk", Tier: plan.Free}, now); err != ErrPrefixExhausted {
		t.Errorf("枯渇時は ErrPrefixExhausted を返すべき, got %v", err)
	}

	// 1 室目を解散すると /24 が再利用可能になる。
	if err := m.Close(r1.ID, room.CloseHost, now); err != nil {
		t.Fatal(err)
	}
	r2 := mustCreate(t, m, "h", now)
	if r2.HostIP().String() != "10.7.7.1" {
		t.Errorf("解放後は同じ /24 を再利用すべき: HostIP = %s", r2.HostIP())
	}
}

func TestCreateIDGenError(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	m.newID = func() (string, error) { return "", errors.New("id boom") }

	if _, err := m.Create(CreateParams{HostAccountID: "h", HostPubKey: "pk", Tier: plan.Free}, now); err == nil {
		t.Fatal("ID 生成失敗はエラーになるべき")
	}
	if m.Count() != 0 {
		t.Errorf("失敗時はルームが登録されないべき: Count=%d", m.Count())
	}
	// 割り当てた /24 は解放され、次回作成で再利用される。
	m.newID = token.NewRoomToken
	r := mustCreate(t, m, "h", now)
	if r.HostIP().String() != "10.0.0.1" {
		t.Errorf("解放された /24 が再利用されるべき: HostIP=%s", r.HostIP())
	}
}

func TestCreateTokenGenError(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	m.newToken = func() (string, error) { return "", errors.New("token boom") }

	if _, err := m.Create(CreateParams{HostAccountID: "h", HostPubKey: "pk", Tier: plan.Free}, now); err == nil {
		t.Fatal("トークン生成失敗はエラーになるべき")
	}
	if m.Count() != 0 {
		t.Errorf("失敗時はルームが登録されないべき: Count=%d", m.Count())
	}
}

func TestCreateIDCollision(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	m.newID = func() (string, error) { return "same-id", nil }

	mustCreate(t, m, "h", now)
	if _, err := m.Create(CreateParams{HostAccountID: "h", HostPubKey: "pk", Tier: plan.Free}, now); err != ErrTokenCollision {
		t.Errorf("ID 衝突は ErrTokenCollision を返すべき, got %v", err)
	}
}

func TestCreateTokenCollision(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	m.newToken = func() (string, error) { return "same-token", nil } // ID は既定でユニーク

	mustCreate(t, m, "h", now)
	if _, err := m.Create(CreateParams{HostAccountID: "h", HostPubKey: "pk", Tier: plan.Free}, now); err != ErrTokenCollision {
		t.Errorf("トークン衝突は ErrTokenCollision を返すべき, got %v", err)
	}
}

func TestCreateRoomError(t *testing.T) {
	now := time.Now()
	m := newManager(t)

	// 未知プランは room.Create でエラーになり、割り当てた /24 は解放される。
	if _, err := m.Create(CreateParams{HostAccountID: "h", HostPubKey: "pk", Tier: plan.Tier("enterprise")}, now); err == nil {
		t.Fatal("未知プランはエラーになるべき")
	}
	if m.Count() != 0 {
		t.Errorf("失敗時はルームが登録されないべき: Count=%d", m.Count())
	}
	r := mustCreate(t, m, "h", now)
	if r.HostIP().String() != "10.0.0.1" {
		t.Errorf("解放された /24 が再利用されるべき: HostIP=%s", r.HostIP())
	}
}

func TestRotateTokenErrors(t *testing.T) {
	now := time.Now()
	m := newManager(t)

	// 未知ルーム。
	if _, err := m.RotateToken("nope"); err != ErrRoomNotFound {
		t.Errorf("未知ルームの再発行は ErrRoomNotFound, got %v", err)
	}

	r := mustCreate(t, m, "h", now)

	// 生成失敗。
	m.newToken = func() (string, error) { return "", errors.New("boom") }
	if _, err := m.RotateToken(r.ID); err == nil {
		t.Error("トークン生成失敗はエラーになるべき")
	}

	// 衝突（既存トークンと同値を生成）。まず既知の有効トークンへ再発行し、
	// 次にそれと同値を生成させると索引衝突する。
	m.newToken = token.NewRoomToken
	known, err := m.RotateToken(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	m.newToken = func() (string, error) { return known, nil }
	if _, err := m.RotateToken(r.ID); err != ErrTokenCollision {
		t.Errorf("トークン衝突は ErrTokenCollision, got %v", err)
	}
}

func TestRotateTokenForHost(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	r := mustCreate(t, m, "h", now) // HostPubKey = "host-pk"
	old, _ := m.Token(r.ID)

	// 未知ルーム。
	if _, err := m.RotateTokenForHost("nope", "host-pk"); err != ErrRoomNotFound {
		t.Errorf("未知ルームは ErrRoomNotFound, got %v", err)
	}
	// ホスト公開鍵不一致。
	if _, err := m.RotateTokenForHost(r.ID, "someone-else"); err != ErrNotRoomHost {
		t.Errorf("ホスト不一致は ErrNotRoomHost, got %v", err)
	}
	// 所有ホストによる再発行は成功し、旧トークンは失効する。
	nt, err := m.RotateTokenForHost(r.ID, "host-pk")
	if err != nil {
		t.Fatalf("RotateTokenForHost エラー: %v", err)
	}
	if nt == old {
		t.Error("再発行で新トークンになるべき")
	}
	if _, ok := m.LookupByToken(old); ok {
		t.Error("旧トークンは索引から失効しているべき")
	}
	if rm, ok := m.LookupByToken(nt); !ok || rm.ID != r.ID {
		t.Errorf("新トークンは当該ルームを解決すべき: ok=%v", ok)
	}
}

func TestCloseNotFound(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	if err := m.Close("nope", room.CloseHost, now); err != ErrRoomNotFound {
		t.Errorf("未知ルームの解散は ErrRoomNotFound, got %v", err)
	}
}

func TestWithRoomErrors(t *testing.T) {
	now := time.Now()
	m := newManager(t)

	// 未知ルーム。
	if err := m.WithRoom("nope", func(*room.Room) error { return nil }); err != ErrRoomNotFound {
		t.Errorf("未知ルームの WithRoom は ErrRoomNotFound, got %v", err)
	}

	// fn のエラーは伝播する。
	r := mustCreate(t, m, "h", now)
	sentinel := errors.New("fn failed")
	if err := m.WithRoom(r.ID, func(*room.Room) error { return sentinel }); err != sentinel {
		t.Errorf("fn のエラーが伝播すべき, got %v", err)
	}
}

func TestToken(t *testing.T) {
	now := time.Now()
	m := newManager(t)
	r := mustCreate(t, m, "h", now)

	// 作成直後のトークンで当該ルームを検証できる。
	tok, ok := m.Token(r.ID)
	if !ok || tok == "" {
		t.Fatalf("作成済みルームのトークンを取得できるべき: tok=%q ok=%v", tok, ok)
	}
	if !r.VerifyToken(tok) {
		t.Error("取得したトークンは VerifyToken を通るべき")
	}

	// ローテーション後は新トークンを返す。
	rotated, err := m.RotateToken(r.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Token(r.ID); got != rotated {
		t.Errorf("ローテーション後は新トークンを返すべき: got %q want %q", got, rotated)
	}

	// 未知ルームは ok=false。
	if _, ok := m.Token("nope"); ok {
		t.Error("未知ルームは ok=false を返すべき")
	}
}

func TestRoomIDs(t *testing.T) {
	now := time.Now()
	m := newManager(t)

	if ids := m.RoomIDs(); len(ids) != 0 {
		t.Errorf("空の Manager は空スライスを返すべき, got %v", ids)
	}

	r1 := mustCreate(t, m, "h1", now)
	r2 := mustCreate(t, m, "h2", now)

	ids := m.RoomIDs()
	if len(ids) != 2 {
		t.Fatalf("ルーム数 = %d, want 2", len(ids))
	}
	set := map[string]bool{ids[0]: true, ids[1]: true}
	if !set[r1.ID] || !set[r2.ID] {
		t.Errorf("両ルームのIDが含まれるべき: got %v", ids)
	}

	// 解散したルームは一覧から除外される。
	if err := m.Close(r1.ID, room.CloseHost, now); err != nil {
		t.Fatal(err)
	}
	ids = m.RoomIDs()
	if len(ids) != 1 || ids[0] != r2.ID {
		t.Errorf("解散後は残存ルームのみ: got %v", ids)
	}
}

func TestPerRoomJoinLimiterIsIndependent(t *testing.T) {
	now := time.Now()
	m, err := New(Config{JoinRate: 0, JoinBurst: 1}) // 1 ルーム 1 IP あたり 1 回
	if err != nil {
		t.Fatal(err)
	}
	r1 := mustCreate(t, m, "h1", now)
	r2 := mustCreate(t, m, "h2", now)

	join := func(r *room.Room, pk string) error {
		return m.WithRoom(r.ID, func(rm *room.Room) error {
			_, err := rm.RequestJoin(pk, "n", "203.0.113.9", now)
			return err
		})
	}

	if err := join(r1, "pk1"); err != nil {
		t.Fatalf("r1 の 1 回目は許可されるべき: %v", err)
	}
	if err := join(r1, "pk2"); err != room.ErrRateLimited {
		t.Errorf("r1 の同一IP連続は ErrRateLimited, got %v", err)
	}
	// r2 は独立したリミッタを持つため、同一IPでも許可される。
	if err := join(r2, "pk3"); err != nil {
		t.Errorf("r2 は独立リミッタで許可されるべき: %v", err)
	}
}
