package main

// 本ファイルは GUI（Tailscale の LocalAPI 方式）の localhost HTTP サーバー。
// フロント（埋め込み SPA）は appstate.Snapshot を JSON で購読し、操作を POST する。
// コアロジックは pkg/appstate と runHost/runGuest の受信ループに閉じ、ここは状態の配信と
// ブラウザ操作 → signalclient 呼び出しの配線を担う薄い層（設計原則1: UI とコアの分離）。
//
// セキュリティ: 127.0.0.1 のみに bind し外部へ公開しない。E2E 暗号化の設計どおり WireGuard
// 秘密鍵などの復号鍵は API に一切載せない（配信するのは公開鍵・招待・表示メタデータのみ）。
// 招待リンク/QR に含むのはホスト公開鍵とルーム招待トークンで、いずれも復号鍵ではない。
// さらに全 /api/* を pkg/originguard で守り、悪意サイトからのクロスオリジン要求（CSRF）と
// DNS リバインディングを弾く（loopback bind だけでは JS の fetch が 127.0.0.1 へ到達しうるため）。

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/originguard"
	"github.com/instantmesh/instantmesh/pkg/qr"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
)

// errSessionActive は既にセッション（ホスト/参加）が稼働中に別セッション開始を要求したことを表す。
var errSessionActive = errors.New("gui: session already active")

// guiOptions は GUI から開始するセッションへ渡す既定オプション（CLI フラグ由来）。招待リンクや
// ニックネームなどブラウザ操作で決まる値は含めない。
type guiOptions struct {
	server    string // ホスト時のシグナリング URL（ゲストは招待リンク内の server を使う）
	account   string // ホスト認証トークン（Cognito 未設定時の Bearer）
	duration  int64  // ルーム制限時間（秒）の既定値
	useTunnel bool
	ifname    string
	stunAddr  string
	relay     bool
	cognito   cognitoConfig // 設定時はホスト開始時に PKCE サインインで ID トークンを取得
}

// guiServer は GUI 用の状態保持＋HTTP 配信＋セッション制御を担う。store は受信ループ（唯一の
// 書き手）と HTTP ハンドラ（読み手）が共有する表示状態。session 系フィールドは HTTP ハンドラ
// 間の同時アクセスを mu で保護する。
type guiServer struct {
	store *viewStore
	opts  guiOptions

	// baseCtx はサーバーのライフサイクル。開始したセッションはこれを親に持ち、
	// サーバー停止（グレースフルシャットダウン）で連鎖的にキャンセルされる。
	baseCtx context.Context

	// quit はアプリ全体を終了させる（ルート ctx のキャンセル）。GUI の「終了」操作と、ブラウザ
	// との接続途絶（ハートビート途絶）による自動終了の双方から呼ぶ。runGUI が設定する（テストや
	// 未設定時は nil で no-op）。
	quit func()
	// now は時刻源（決定的テスト用に注入可能）。既定は time.Now。
	now func() time.Time
	// heartbeatTimeout はブラウザからの生存確認（/api/state ポーリング）が途絶えてからアプリを
	// 自動終了するまでの猶予。runGUI で既定を設定する。
	heartbeatTimeout time.Duration

	mu        sync.Mutex
	started   bool                 // セッション稼働中か
	client    *signalclient.Client // セッション確立後の操作用（承認/拒否/再発行/退出）
	cancel    context.CancelFunc   // 稼働中セッションのキャンセル関数
	gen       uint64               // セッション世代。後始末ゴルーチンが自分の世代のみ触るための識別子
	lastSeen  time.Time            // ブラウザから最後に /api/state を受けた時刻（ハートビート）
	connected bool                 // ブラウザが一度でも接続したか（初回接続前は自動終了しない）

	// セッション起動関数（テストでフェイクへ差し替え可能）。既定は runHost/runGuest。
	startHost  func(ctx context.Context, cfg hostConfig, store *viewStore, onClient func(*signalclient.Client)) error
	startGuest func(ctx context.Context, cfg guestConfig, store *viewStore, onClient func(*signalclient.Client)) error
}

// newGUIServer は初期状態（Idle）の GUI サーバーを返す。baseCtx はサーバーのライフサイクル
// （開始セッションの親コンテキスト）。
func newGUIServer(baseCtx context.Context, opts guiOptions) *guiServer {
	return &guiServer{
		store:            newViewStore(),
		opts:             opts,
		baseCtx:          baseCtx,
		now:              time.Now,
		heartbeatTimeout: guiHeartbeatTimeout,
		startHost:        runHost,
		startGuest:       runGuest,
	}
}

// GUI ブラウザとの接続途絶を検知して自動終了する際のパラメータ。SPA は /api/state を約 1 秒周期で
// ポーリングするため、タブを閉じる/ブラウザ終了でポーリングが止まると lastSeen が更新されなくなる。
// 猶予を長め（90 秒）に取るのは、ブラウザがバックグラウンドのタブでタイマー（setInterval）を
// 大きく間引く（数分放置で最短 1 回/分程度）ため、単なるタブ切り替えで誤って終了しないようにする
// ため。即時の明示停止は「アプリを終了」ボタン（/api/quit）が担うので、ここは無人残留を防ぐ番人。
const (
	guiHeartbeatTimeout = 90 * time.Second // これ以上ポーリングが途絶えたら自動終了
	guiHeartbeatTick    = 15 * time.Second // 途絶チェックの周期
)

// handler は GUI サーバーの HTTP ルーティングを返す。全 /api/* は originguard で保護し、
// 悪意サイトからのクロスオリジン要求（CSRF）と DNS リバインディングを弾く。索引ページ("/")は
// 秘密を含まない静的シェルなので保護対象外（機密メタデータは /api/state・/api/qr 側にある）。
func (s *guiServer) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/state", s.guard(s.handleState))
	mux.HandleFunc("GET /api/qr", s.guard(s.handleQR))
	mux.HandleFunc("POST /api/host", s.guard(s.handleHost))
	mux.HandleFunc("POST /api/join", s.guard(s.handleJoin))
	mux.HandleFunc("POST /api/approve", s.guard(s.handleApprove))
	mux.HandleFunc("POST /api/reject", s.guard(s.handleReject))
	mux.HandleFunc("POST /api/rotate", s.guard(s.handleRotate))
	mux.HandleFunc("POST /api/leave", s.guard(s.handleLeave))
	mux.HandleFunc("POST /api/reset", s.guard(s.handleReset))
	mux.HandleFunc("POST /api/quit", s.guard(s.handleQuit))
	mux.HandleFunc("GET /", s.handleIndex)
	return mux
}

// guard は LocalAPI ハンドラを originguard で包み、同一オリジンと確認できない要求を 403 で弾く
// ミドルウェア。判定は純粋ロジック（pkg/originguard）で、ここは Host/Origin/Sec-Fetch-Site の
// 抽出と応答の配線のみを担う。
func (s *guiServer) guard(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !originguard.Allow(r.Host, r.Header.Get("Origin"), r.Header.Get("Sec-Fetch-Site")) {
			http.Error(w, "同一オリジン以外からの要求は拒否されました", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

// handleIndex は埋め込み SPA を返す（"/" 以外のパスは 404）。
func (s *guiServer) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(indexHTML))
}

// handleState は現在の Snapshot を JSON で返す（フロントがポーリング/購読する）。
// このポーリング自体をブラウザ生存のハートビートとして扱い、途絶時の自動終了に用いる。
func (s *guiServer) handleState(w http.ResponseWriter, r *http.Request) {
	s.markSeen()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(s.store.snapshot())
}

// handleQR は現在の招待リンクを QR コードの SVG 画像で返す（ホストの招待リンク表示用）。
// 招待リンク未確定なら 404。長いリンクは EC レベル Medium→Low の順で収まりを試みる。
func (s *guiServer) handleQR(w http.ResponseWriter, r *http.Request) {
	link := s.store.snapshot().InviteLink
	if link == "" {
		http.NotFound(w, r)
		return
	}
	code, err := qr.Encode([]byte(link), qr.Medium)
	if errors.Is(err, qr.ErrTooLong) {
		code, err = qr.Encode([]byte(link), qr.Low)
	}
	if err != nil {
		http.Error(w, "QR 生成に失敗しました", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	_, _ = w.Write([]byte(qrSVG(code)))
}

// handleHost はホストとしてセッションを開始する。body は任意で {"duration": 秒}。
func (s *guiServer) handleHost(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Duration int64 `json:"duration"`
	}
	_ = json.NewDecoder(r.Body).Decode(&req) // body は任意（無ければ既定値）
	dur := req.Duration
	if dur <= 0 {
		dur = s.opts.duration
	}
	cfg := hostConfig{
		server: s.opts.server, account: s.opts.account, durationSec: dur,
		auto:      false, // GUI では人が待合室で承認するため自動承認しない
		useTunnel: s.opts.useTunnel, ifname: s.opts.ifname, stunAddr: s.opts.stunAddr,
		relay: s.opts.relay, stdinConsole: false, cognito: s.opts.cognito,
	}
	err := s.startSession(func(ctx context.Context) error {
		return s.startHost(ctx, cfg, s.store, s.setClient)
	})
	s.writeSessionStart(w, err)
}

// handleJoin はゲストとしてセッションを開始する。body は {"invite": リンク, "nick": 表示名}。
func (s *guiServer) handleJoin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Invite string `json:"invite"`
		Nick   string `json:"nick"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Invite == "" {
		http.Error(w, "招待リンク（invite）が必要です", http.StatusBadRequest)
		return
	}
	nick := req.Nick
	if nick == "" {
		nick = "guest"
	}
	cfg := guestConfig{
		inviteURL: req.Invite, nick: nick, useTunnel: s.opts.useTunnel,
		ifname: s.opts.ifname, stunAddr: s.opts.stunAddr, relay: s.opts.relay,
	}
	err := s.startSession(func(ctx context.Context) error {
		return s.startGuest(ctx, cfg, s.store, s.setClient)
	})
	s.writeSessionStart(w, err)
}

// handleApprove は待合室のゲストを承認する。body は {"pubKey": ゲスト公開鍵}。
func (s *guiServer) handleApprove(w http.ResponseWriter, r *http.Request) {
	s.withGuestOp(w, r, func(c *signalclient.Client, pubKey string) error {
		return c.Approve(pubKey)
	})
}

// handleReject は待合室のゲストを拒否する。body は {"pubKey": ゲスト公開鍵}。
func (s *guiServer) handleReject(w http.ResponseWriter, r *http.Request) {
	s.withGuestOp(w, r, func(c *signalclient.Client, pubKey string) error {
		return c.Reject(pubKey)
	})
}

// handleRotate は招待リンク（トークン）の再発行を要求する。
func (s *guiServer) handleRotate(w http.ResponseWriter, r *http.Request) {
	c := s.getClient()
	if c == nil {
		http.Error(w, "セッションが稼働していません", http.StatusConflict)
		return
	}
	if err := c.RotateToken(); err != nil {
		http.Error(w, "再発行の送信に失敗しました", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleLeave は稼働中セッションを終了する（ルーム退出/解散）。接続クローズで受信ループが
// 抜け、サーバー側がIP/枠を回収する。表示状態も Closed へ落とす。
//
// セッション制御状態（started/client/cancel）は同期的にクリアしてから cancel する。これにより
// 退出直後に「最初に戻る」(reset)→「ルーム作成/参加」(host/join) を素早く操作しても、後始末
// ゴルーチンの完了を待たずに次のセッションを開始でき、started 残存による 409 レースを断つ。
// また Close はキャンセル前に反映し、finishSession の異常終了通知が「退出しました」を上書き
// しないようにする（cancel 後にしか finishSession は走らないため順序が保証される）。
func (s *guiServer) handleLeave(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	cancel := s.cancel
	active := s.started
	if active {
		s.clearSessionLocked()
	}
	s.mu.Unlock()
	if !active || cancel == nil {
		http.Error(w, "セッションが稼働していません", http.StatusConflict)
		return
	}
	s.store.update(func(m *appstate.Model) { m.Close("退出しました") })
	cancel()
	w.WriteHeader(http.StatusNoContent)
}

// handleReset は終了状態の表示を初期状態（Idle）へ戻す（新しいホスト/参加を始められるように）。
// 判定は started フラグではなく表示フェーズで行う（idle / closed 以外＝稼働中は拒否）。これにより
// 退出直後（後始末ゴルーチンが started を落とし切る前）でも 409 レースなくリセットできる。
func (s *guiServer) handleReset(w http.ResponseWriter, r *http.Request) {
	if ph := s.store.snapshot().Phase; ph != "idle" && ph != "closed" {
		http.Error(w, "セッション稼働中はリセットできません", http.StatusConflict)
		return
	}
	s.store.reset()
	w.WriteHeader(http.StatusNoContent)
}

// handleQuit はアプリ全体を終了する（ブラウザの「アプリを終了」操作）。応答を返してから
// ルート ctx をキャンセルし、runGUI のグレースフルシャットダウン（稼働中セッションも連鎖
// キャンセル）を経てプロセスを終える。コンソールを持たない GUI 起動での正規の停止手段。
func (s *guiServer) handleQuit(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusNoContent)
	s.quitApp()
}

// quitApp はアプリ終了（ルート ctx のキャンセル）を発火する。未設定（テスト等）なら no-op。
func (s *guiServer) quitApp() {
	if s.quit != nil {
		s.quit()
	}
}

// markSeen はブラウザからのポーリング受信時刻を記録し、初回接続済みとして印を付ける。
func (s *guiServer) markSeen() {
	s.mu.Lock()
	s.lastSeen = s.now()
	s.connected = true
	s.mu.Unlock()
}

// idleExpired はブラウザが一度接続した後、ポーリングが heartbeatTimeout を超えて途絶えたかを返す。
// 初回接続前（connected=false）は false（ブラウザ手動起動の遅延等で誤って終了しないため）。
func (s *guiServer) idleExpired() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.connected && s.now().Sub(s.lastSeen) > s.heartbeatTimeout
}

// watchHeartbeat はブラウザとの接続途絶を周期的に検査し、途絶していればアプリを自動終了する。
// ctx（アプリのライフサイクル）終了で抜ける。タブを閉じる/ブラウザ終了で無人プロセスが
// 残らないようにするための番人。
func (s *guiServer) watchHeartbeat(ctx context.Context) {
	t := time.NewTicker(guiHeartbeatTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if s.idleExpired() {
				slog.Info("ブラウザとの接続が途絶えたためアプリを終了します", "timeout", s.heartbeatTimeout)
				s.quitApp()
				return
			}
		}
	}
}

// withGuestOp は {"pubKey": ...} を要求するホスト操作（承認/拒否）の共通処理。
func (s *guiServer) withGuestOp(w http.ResponseWriter, r *http.Request, op func(*signalclient.Client, string) error) {
	var req struct {
		PubKey string `json:"pubKey"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.PubKey == "" {
		http.Error(w, "ゲスト公開鍵（pubKey）が必要です", http.StatusBadRequest)
		return
	}
	c := s.getClient()
	if c == nil {
		http.Error(w, "セッションが稼働していません", http.StatusConflict)
		return
	}
	if err := op(c, req.PubKey); err != nil {
		http.Error(w, "操作の送信に失敗しました", http.StatusBadGateway)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// startSession は稼働中でなければ run をゴルーチンで起動し、そのキャンセル関数と世代を記録する。
// 既に稼働中なら errSessionActive を返す。run 終了時に finishSession で後始末する。開始時に
// 表示状態を初期化して前回の終了状態を引きずらない。
func (s *guiServer) startSession(run func(ctx context.Context) error) error {
	s.mu.Lock()
	if s.started {
		s.mu.Unlock()
		return errSessionActive
	}
	s.started = true
	s.gen++
	gen := s.gen
	sctx, cancel := context.WithCancel(s.baseCtx)
	s.cancel = cancel
	s.mu.Unlock()

	s.store.reset()

	go func() {
		defer cancel()
		s.finishSession(gen, run(sctx))
	}()
	return nil
}

// finishSession はセッションゴルーチン終了時の後始末。gen が現行世代と一致するときのみ状態を
// クリアする（退出→リセット→新セッション開始後に、古いゴルーチンが新セッションを壊さないための
// 世代チェック）。異常終了（run が非 nil を返し、かつ表示がまだ終了状態でない）なら終了理由を
// store へ反映し、SPA が無言で idle へ戻らず失敗を表示できるようにする。退出/解散で既に Closed の
// 場合は上書きしない。
func (s *guiServer) finishSession(gen uint64, err error) {
	s.mu.Lock()
	current := s.gen == gen
	if current {
		s.clearSessionLocked()
	}
	s.mu.Unlock()
	if !current {
		return // 既に別セッションが開始済み。古い後始末は行わない。
	}
	if err != nil {
		slog.Warn("GUI セッションが終了しました", "err", err)
		s.store.update(func(m *appstate.Model) {
			if m.Phase != appstate.PhaseClosed {
				m.Close("セッションが終了しました: " + err.Error())
			}
		})
	}
}

// clearSessionLocked はセッション制御状態を初期化する（呼び出し側が s.mu を保持していること）。
func (s *guiServer) clearSessionLocked() {
	s.started = false
	s.client = nil
	s.cancel = nil
}

// writeSessionStart はセッション開始要求の結果を HTTP レスポンスへ写す。
func (s *guiServer) writeSessionStart(w http.ResponseWriter, err error) {
	if errors.Is(err, errSessionActive) {
		http.Error(w, "既にセッションが稼働しています", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// setClient は受信ループが接続確立後に signalclient を公開するフック。
func (s *guiServer) setClient(c *signalclient.Client) {
	s.mu.Lock()
	s.client = c
	s.mu.Unlock()
}

// getClient は現在の signalclient を返す（未確立なら nil）。
func (s *guiServer) getClient() *signalclient.Client {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.client
}

// runGUI は GUI モードのエントリポイント。addr（127.0.0.1 のみ）で HTTP サーバーを起動し、
// ブラウザからのホスト/参加操作でセッションを駆動する。ctx 終了でグレースフルシャットダウン
// （稼働中セッションも baseCtx 経由でキャンセルされる）。
func runGUI(ctx context.Context, addr string, opts guiOptions) error {
	// アプリのライフサイクル。シグナル（親 ctx）に加え、GUI の「終了」操作やブラウザ切断でも
	// キャンセルできるよう、キャンセル可能なコンテキストを重ねる。
	appCtx, appCancel := context.WithCancel(ctx)
	defer appCancel()

	gs := newGUIServer(appCtx, opts)
	gs.quit = appCancel // ブラウザからの終了・ハートビート途絶でアプリを止める
	srv := &http.Server{Handler: gs.handler()}

	// リスナーを先に確立してからブラウザを開く（Serve 前に開くと接続に失敗しうるため）。
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		<-appCtx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	// ブラウザとの接続途絶（タブ閉じ/ブラウザ終了）を監視し、無人プロセスの残留を防ぐ。
	go gs.watchHeartbeat(appCtx)

	url := "http://" + ln.Addr().String()
	slog.Info("GUI サーバー起動", "url", url)
	// 既定のブラウザで自動的に開く（ベストエフォート・失敗してもサーバーは継続）。
	if err := openBrowser(url); err != nil {
		slog.Warn("ブラウザの自動起動に失敗しました。上記 URL を手動で開いてください", "url", url, "err", err)
	}

	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
