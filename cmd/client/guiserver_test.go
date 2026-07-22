package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

// fakeConn は signalclient.Conn を満たすテスト用接続。送出メッセージを記録し、
// ReadMessage は Close されるまでブロックする（テストは受信ループを回さない）。
type fakeConn struct {
	mu      sync.Mutex
	written [][]byte
	done    chan struct{}
	once    sync.Once
}

func newFakeConn() *fakeConn { return &fakeConn{done: make(chan struct{})} }

func (f *fakeConn) WriteMessage(data []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.written = append(f.written, append([]byte(nil), data...))
	return nil
}
func (f *fakeConn) ReadMessage() ([]byte, error) { <-f.done; return nil, io.EOF }
func (f *fakeConn) Close() error {
	f.once.Do(func() { close(f.done) })
	return nil
}
func (f *fakeConn) sent() [][]byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.written
}

// testServer は baseCtx とフェイク起動関数を差し替えた guiServer を返す。
func testServer(t *testing.T) (*guiServer, context.CancelFunc) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	gs := newGUIServer(ctx, guiOptions{server: "ws://localhost:8080/ws", account: "dev", duration: 3600})
	return gs, cancel
}

// do はルーター経由でリクエストを実行し記録機を返す。originguard を通すため Host はループバック
// に固定する（httptest.NewRequest の既定 "example.com" は非ブラウザ扱いで許可されない）。
func do(t *testing.T, gs *guiServer, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Host = "127.0.0.1:8088"
	rec := httptest.NewRecorder()
	gs.handler().ServeHTTP(rec, req)
	return rec
}

// waitFor は cond が真になるまで最大 2 秒待つ（セッション起動ゴルーチンの反映待ち）。
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("条件が時間内に満たされませんでした")
}

// TestGUIServerOriginGuard は悪意サイトからのクロスオリジン要求・DNS リバインディングが
// 全 /api/* で 403 に弾かれ、正規の同一オリジン要求（Sec-Fetch-Site: same-origin）は通ることを検証する。
func TestGUIServerOriginGuard(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	// リクエストを組み立てて実行するローカルヘルパ（Host/Origin/Sec-Fetch-Site を指定）。
	req := func(method, path, host, origin, secFetch string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(""))
		r.Host = host
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		if secFetch != "" {
			r.Header.Set("Sec-Fetch-Site", secFetch)
		}
		rec := httptest.NewRecorder()
		gs.handler().ServeHTTP(rec, r)
		return rec
	}

	const loop = "127.0.0.1:8088"
	// 各 /api/* エンドポイントで防御が効くこと（状態変更 POST と機密メタデータ GET の両方）。
	for _, ep := range []struct{ method, path string }{
		{"POST", "/api/host"}, {"POST", "/api/join"}, {"POST", "/api/approve"},
		{"POST", "/api/reject"}, {"POST", "/api/rotate"}, {"POST", "/api/leave"},
		{"POST", "/api/reset"}, {"GET", "/api/state"}, {"GET", "/api/qr"},
	} {
		// 悪意サイトからの直接クロスオリジン fetch（Sec-Fetch-Site: cross-site）は 403。
		if rec := req(ep.method, ep.path, loop, "https://evil.example", "cross-site"); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s cross-site: status=%d, want 403", ep.method, ep.path, rec.Code)
		}
		// DNS リバインディング（攻撃者ドメインが Host に残る）は 403。
		if rec := req(ep.method, ep.path, "evil.example:8088", "http://evil.example:8088", "same-origin"); rec.Code != http.StatusForbidden {
			t.Errorf("%s %s rebinding: status=%d, want 403", ep.method, ep.path, rec.Code)
		}
	}

	// 正規の同一オリジン GET は 403 にならない（state は 200 で通る）。
	if rec := req("GET", "/api/state", loop, "http://127.0.0.1:8088", "same-origin"); rec.Code == http.StatusForbidden {
		t.Errorf("same-origin state: status=%d, should not be 403", rec.Code)
	}
	// 索引ページ("/")はガード対象外で、クロスオリジン扱いのヘッダでも到達できる。
	if rec := req("GET", "/", loop, "https://evil.example", "cross-site"); rec.Code != http.StatusOK {
		t.Errorf("index status=%d, want 200 (unguarded)", rec.Code)
	}
}

func TestGUIServerState(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	rec := do(t, gs, "GET", "/api/state", "")
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Errorf("Content-Type=%q, want json", ct)
	}
	var snap appstate.Snapshot
	if err := json.NewDecoder(rec.Body).Decode(&snap); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if snap.Phase != "idle" || snap.Role != "none" {
		t.Fatalf("initial snapshot = %+v, want idle/none", snap)
	}
}

func TestGUIServerIndex(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	rec := do(t, gs, "GET", "/", "")
	if !strings.Contains(rec.Body.String(), "InstantMesh") {
		t.Error("index HTML に InstantMesh が含まれない")
	}
	rec2 := do(t, gs, "GET", "/does-not-exist", "")
	if rec2.Code != http.StatusNotFound {
		t.Errorf("status=%d, want 404", rec2.Code)
	}
}

func TestGUIServerQR(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	// 招待リンク未確定なら 404。
	if rec := do(t, gs, "GET", "/api/qr", ""); rec.Code != http.StatusNotFound {
		t.Errorf("QR without invite: status=%d, want 404", rec.Code)
	}

	// 招待リンクを設定すると SVG を返す。
	gs.store.update(func(m *appstate.Model) {
		_ = m.StartHosting()
		_ = m.RoomCreated("room-1", "instantmesh://join?server=ws%3A%2F%2Fx%2Fws&token=t&host=h", "SAS")
	})
	rec := do(t, gs, "GET", "/api/qr", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("QR status=%d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.Contains(ct, "image/svg+xml") {
		t.Errorf("Content-Type=%q, want svg", ct)
	}
	if !strings.Contains(rec.Body.String(), "<svg") {
		t.Error("QR レスポンスに <svg が含まれない")
	}
}

func TestGUIServerHostStart(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	var gotCfg hostConfig
	fc := newFakeConn()
	gs.startHost = func(ctx context.Context, cfg hostConfig, store *viewStore, onClient func(*signalclient.Client)) error {
		gotCfg = cfg
		onClient(signalclient.New(fc))
		store.update(func(m *appstate.Model) {
			_ = m.StartHosting()
			_ = m.RoomCreated("room-1", "link", "SAS")
		})
		<-ctx.Done()
		return nil
	}

	rec := do(t, gs, "POST", "/api/host", `{"duration":1200}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("host start status=%d, want 202", rec.Code)
	}
	waitFor(t, func() bool { return gs.store.snapshot().Phase == "hosting" })
	if gotCfg.durationSec != 1200 || gotCfg.auto {
		t.Errorf("cfg = %+v, want duration 1200 / auto false", gotCfg)
	}

	// 稼働中の二重開始は 409。
	if rec2 := do(t, gs, "POST", "/api/host", "{}"); rec2.Code != http.StatusConflict {
		t.Errorf("double start status=%d, want 409", rec2.Code)
	}
}

func TestGUIServerHostDefaultDuration(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	var gotCfg hostConfig
	gs.startHost = func(ctx context.Context, cfg hostConfig, store *viewStore, onClient func(*signalclient.Client)) error {
		gotCfg = cfg
		onClient(signalclient.New(newFakeConn()))
		store.update(func(m *appstate.Model) { _ = m.StartHosting() })
		<-ctx.Done()
		return nil
	}
	// body 無し（duration 未指定）は opts の既定値へフォールバックする。
	rec := do(t, gs, "POST", "/api/host", "")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status=%d, want 202", rec.Code)
	}
	waitFor(t, func() bool { return gs.getClient() != nil })
	if gotCfg.durationSec != 3600 {
		t.Errorf("duration=%d, want 3600 (既定)", gotCfg.durationSec)
	}
}

func TestGUIServerJoin(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	// invite 欠落は 400。
	if rec := do(t, gs, "POST", "/api/join", `{"nick":"a"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("join without invite: status=%d, want 400", rec.Code)
	}

	var gotCfg guestConfig
	gs.startGuest = func(ctx context.Context, cfg guestConfig, store *viewStore, onClient func(*signalclient.Client)) error {
		gotCfg = cfg
		onClient(signalclient.New(newFakeConn()))
		store.update(func(m *appstate.Model) { _ = m.StartJoining(cfg.inviteURL, cfg.nick) })
		<-ctx.Done()
		return nil
	}
	link := "instantmesh://join?server=ws%3A%2F%2Fx%2Fws&token=t&host=h"
	rec := do(t, gs, "POST", "/api/join", `{"invite":"`+link+`","nick":"alice"}`)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("join status=%d, want 202", rec.Code)
	}
	waitFor(t, func() bool { return gs.store.snapshot().Role == "guest" })
	if gotCfg.inviteURL != link || gotCfg.nick != "alice" {
		t.Errorf("cfg = %+v, want invite/alice", gotCfg)
	}
}

func TestGUIServerJoinDefaultNick(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()
	var gotNick string
	gs.startGuest = func(ctx context.Context, cfg guestConfig, store *viewStore, onClient func(*signalclient.Client)) error {
		gotNick = cfg.nick
		onClient(signalclient.New(newFakeConn()))
		store.update(func(m *appstate.Model) { _ = m.StartJoining(cfg.inviteURL, cfg.nick) })
		<-ctx.Done()
		return nil
	}
	link := "instantmesh://join?server=ws%3A%2F%2Fx%2Fws&token=t&host=h"
	do(t, gs, "POST", "/api/join", `{"invite":"`+link+`"}`)
	waitFor(t, func() bool { return gs.getClient() != nil })
	if gotNick != "guest" {
		t.Errorf("nick=%q, want guest (既定)", gotNick)
	}
}

// startFakeHost はフェイクのホストセッションを開始し、fakeConn（送出観測用）を返す。
func startFakeHost(t *testing.T, gs *guiServer) *fakeConn {
	t.Helper()
	fc := newFakeConn()
	gs.startHost = func(ctx context.Context, cfg hostConfig, store *viewStore, onClient func(*signalclient.Client)) error {
		onClient(signalclient.New(fc))
		store.update(func(m *appstate.Model) {
			_ = m.StartHosting()
			_ = m.RoomCreated("room-1", "link", "SAS")
			_ = m.AddPending("guest-pub", "alice", "GG-HH")
		})
		<-ctx.Done()
		return nil
	}
	if rec := do(t, gs, "POST", "/api/host", "{}"); rec.Code != http.StatusAccepted {
		t.Fatalf("host start status=%d, want 202", rec.Code)
	}
	waitFor(t, func() bool { return gs.getClient() != nil })
	return fc
}

// decodeLast は fakeConn が最後に送出したエンベロープを復号する。
func decodeLast(t *testing.T, fc *fakeConn) signaling.Envelope {
	t.Helper()
	sent := fc.sent()
	if len(sent) == 0 {
		t.Fatal("送出メッセージがありません")
	}
	env, err := signaling.Decode(sent[len(sent)-1])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	return env
}

func TestGUIServerApproveReject(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()
	fc := startFakeHost(t, gs)

	// 承認 → decision(approve=true, pubKey) が送出される。
	if rec := do(t, gs, "POST", "/api/approve", `{"pubKey":"guest-pub"}`); rec.Code != http.StatusNoContent {
		t.Fatalf("approve status=%d, want 204", rec.Code)
	}
	env := decodeLast(t, fc)
	if env.Type != signaling.TypeDecision {
		t.Fatalf("type=%s, want decision", env.Type)
	}
	var d signaling.Decision
	_ = env.Unmarshal(&d)
	if d.GuestPubKey != "guest-pub" || !d.Approve {
		t.Errorf("decision = %+v, want guest-pub/approve", d)
	}

	// 拒否 → decision(approve=false)。
	do(t, gs, "POST", "/api/reject", `{"pubKey":"guest-pub"}`)
	env = decodeLast(t, fc)
	_ = env.Unmarshal(&d)
	if d.Approve {
		t.Error("reject should send approve=false")
	}

	// pubKey 欠落は 400。
	if rec := do(t, gs, "POST", "/api/approve", `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("approve without pubKey: status=%d, want 400", rec.Code)
	}
}

func TestGUIServerRotate(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()
	fc := startFakeHost(t, gs)

	if rec := do(t, gs, "POST", "/api/rotate", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("rotate status=%d, want 204", rec.Code)
	}
	if env := decodeLast(t, fc); env.Type != signaling.TypeRotateToken {
		t.Errorf("type=%s, want rotate_token", env.Type)
	}
}

func TestGUIServerOperationsNoSession(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	// セッション未稼働では操作は 409。
	for _, tc := range []struct{ path, body string }{
		{"/api/approve", `{"pubKey":"x"}`},
		{"/api/reject", `{"pubKey":"x"}`},
		{"/api/rotate", ""},
		{"/api/leave", ""},
	} {
		if rec := do(t, gs, "POST", tc.path, tc.body); rec.Code != http.StatusConflict {
			t.Errorf("%s without session: status=%d, want 409", tc.path, rec.Code)
		}
	}
}

func TestGUIServerLeave(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()
	startFakeHost(t, gs)

	if rec := do(t, gs, "POST", "/api/leave", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("leave status=%d, want 204", rec.Code)
	}
	// 表示状態は Closed へ落ち、セッションは解放される（client が nil に戻る）。
	waitFor(t, func() bool { return gs.getClient() == nil })
	if snap := gs.store.snapshot(); snap.Phase != "closed" {
		t.Errorf("phase=%s, want closed", snap.Phase)
	}

	// 解放後は新しいセッションを開始できる。
	startFakeHost(t, gs)
	if gs.getClient() == nil {
		t.Error("leave 後に再開できていない")
	}
}

// TestGUIServerSessionFailure は接続/認証失敗（run がエラーを返す）が GUI へ通知され、
// SPA が無言で idle へ戻らず終了理由を表示できることを検証する（指摘: 失敗の無言 idle 復帰）。
func TestGUIServerSessionFailure(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	gs.startHost = func(ctx context.Context, cfg hostConfig, store *viewStore, onClient func(*signalclient.Client)) error {
		return errors.New("dial refused")
	}
	if rec := do(t, gs, "POST", "/api/host", "{}"); rec.Code != http.StatusAccepted {
		t.Fatalf("host start status=%d, want 202", rec.Code)
	}
	// run 失敗で表示は closed へ落ち、理由にエラー文言を含む。
	waitFor(t, func() bool { return gs.store.snapshot().Phase == "closed" })
	if reason := gs.store.snapshot().Reason; !strings.Contains(reason, "dial refused") {
		t.Errorf("reason=%q, want to contain 'dial refused'", reason)
	}
	// 後始末済みなので新しいセッションを開始できる。
	waitFor(t, func() bool {
		gs.mu.Lock()
		defer gs.mu.Unlock()
		return !gs.started
	})
	startFakeHost(t, gs)
}

// TestFinishSessionClosedNotOverwritten は、退出/解散で既に Closed の表示を finishSession の
// 異常終了通知が上書きしないこと、かつ現行世代の後始末（started クリア）が行われることを検証する。
func TestFinishSessionClosedNotOverwritten(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	gs.mu.Lock()
	gs.started, gs.gen = true, 1
	gs.mu.Unlock()
	gs.store.update(func(m *appstate.Model) { m.Close("退出しました") })

	// 現行世代でエラー終了 → 既に closed なので理由は上書きしない。
	gs.finishSession(1, errors.New("connection reset"))
	if r := gs.store.snapshot().Reason; r != "退出しました" {
		t.Errorf("reason=%q, want '退出しました'（上書きされないこと）", r)
	}
	gs.mu.Lock()
	st := gs.started
	gs.mu.Unlock()
	if st {
		t.Error("現行世代の finishSession は started をクリアすべき")
	}
}

// TestFinishSessionStaleGeneration は、古い世代の後始末が現行セッションを壊さない（started を
// 落とさない・store を閉じない）ことを検証する（退出→リセット→新セッション開始のレース対策）。
func TestFinishSessionStaleGeneration(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	gs.mu.Lock()
	gs.started, gs.gen = true, 2 // 現行世代 = 2
	gs.mu.Unlock()

	gs.finishSession(1, errors.New("late error")) // 旧世代 1 の後始末
	gs.mu.Lock()
	st := gs.started
	gs.mu.Unlock()
	if !st {
		t.Error("古い世代の finishSession は現行セッションの started を落としてはならない")
	}
	if ph := gs.store.snapshot().Phase; ph == "closed" {
		t.Error("古い世代の finishSession は store を閉じてはならない")
	}
}

// TestGUIServerHeartbeatTimeout は、ブラウザの生存信号（/api/state ポーリング）が timeout を超えて
// 途絶えたら稼働中セッションが閉じられ（ブラウザを閉じた＝VPN もクローズ）、途絶前や更新後は
// 維持されることを検証する。時刻は now 注入で決定的に進める。
func TestGUIServerHeartbeatTimeout(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	// 制御可能な擬似クロック（UnixNano を atomic で進める）。
	var nowNano atomic.Int64
	base := time.Unix(1000, 0)
	nowNano.Store(base.UnixNano())
	gs.now = func() time.Time { return time.Unix(0, nowNano.Load()) }

	startFakeHost(t, gs)
	gs.touchHeartbeat() // 直近ハートビートを現在時刻に合わせる

	wctx, wcancel := context.WithCancel(context.Background())
	defer wcancel()
	go gs.watchHeartbeat(wctx, 2*time.Millisecond, 30*time.Second)

	// 途絶していない間はセッションを維持する。
	time.Sleep(20 * time.Millisecond)
	if gs.getClient() == nil {
		t.Fatal("途絶前にセッションが閉じられた")
	}

	// 時刻を timeout 超へ進める → ブラウザが閉じられたとみなしてセッションを閉じる。
	nowNano.Store(base.Add(time.Minute).UnixNano())
	waitFor(t, func() bool { return gs.getClient() == nil })
	snap := gs.store.snapshot()
	if snap.Phase != "closed" {
		t.Errorf("phase=%s, want closed", snap.Phase)
	}
	if !strings.Contains(snap.Reason, "ブラウザ") {
		t.Errorf("reason=%q, want ブラウザ切断の理由", snap.Reason)
	}
}

// TestGUIServerHeartbeatIdleNoop は、セッション未稼働なら途絶を検知しても何もしない（無害）ことを
// 検証する（idle 放置でハートビートが来なくても閉じる対象がない）。
func TestGUIServerHeartbeatIdleNoop(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()
	// 稼働中でなければ closeActiveSession は false（no-op）。
	if gs.closeActiveSession("x") {
		t.Error("セッション未稼働で closeActiveSession が true を返した")
	}
	if ph := gs.store.snapshot().Phase; ph != "idle" {
		t.Errorf("phase=%s, want idle（変化しないこと）", ph)
	}
}

func TestGUIServerReset(t *testing.T) {
	gs, cancel := testServer(t)
	defer cancel()

	// 稼働中はリセット不可。
	startFakeHost(t, gs)
	if rec := do(t, gs, "POST", "/api/reset", ""); rec.Code != http.StatusConflict {
		t.Errorf("reset while active: status=%d, want 409", rec.Code)
	}

	// 退出して Closed にした後はリセットで Idle へ戻る。
	do(t, gs, "POST", "/api/leave", "")
	waitFor(t, func() bool { return gs.getClient() == nil })
	if rec := do(t, gs, "POST", "/api/reset", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("reset status=%d, want 204", rec.Code)
	}
	if snap := gs.store.snapshot(); snap.Phase != "idle" {
		t.Errorf("phase=%s, want idle", snap.Phase)
	}
}
