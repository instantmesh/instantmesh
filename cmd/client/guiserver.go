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
	"sync/atomic"
	"time"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/originguard"
	"github.com/instantmesh/instantmesh/pkg/qr"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
)

// GUI ハートビートの既定値。ブラウザ SPA の /api/state ポーリング（1 秒間隔）を生存信号とみなし、
// timeout を超えて途絶えたらブラウザが閉じられたとみなして稼働中セッションを閉じる。別タブへの
// 移動でポーリングが間引かれても誤検知しないよう timeout に十分な余裕を持たせ、リロードは
// timeout 内に復帰するため切断しない。
const (
	guiHeartbeatInterval = 10 * time.Second
	guiHeartbeatTimeout  = 45 * time.Second
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

	// baseURL は GUI 自身の URL（例 http://127.0.0.1:8088）。runGUI が bind 確定後に設定する。
	// Cognito サインイン成功後、認証タブをこの URL（ルーム/QR 表示）へ戻すために使う。
	baseURL string

	mu      sync.Mutex
	started bool                 // セッション稼働中か
	client  *signalclient.Client // セッション確立後の操作用（承認/拒否/再発行/退出）
	cancel  context.CancelFunc   // 稼働中セッションのキャンセル関数
	gen     uint64               // セッション世代。後始末ゴルーチンが自分の世代のみ触るための識別子

	// lastBeat はブラウザから最後にハートビート（/api/state ポーリング）を受けた時刻（UnixNano）。
	// 監視ゴルーチン（読み手）と HTTP ハンドラ（書き手）が触れるため atomic で扱う。
	lastBeat atomic.Int64
	now      func() time.Time // 現在時刻（テストで固定時刻へ差し替え可能）

	// セッション起動関数（テストでフェイクへ差し替え可能）。既定は runHost/runGuest。
	startHost  func(ctx context.Context, cfg hostConfig, store *viewStore, onClient func(*signalclient.Client)) error
	startGuest func(ctx context.Context, cfg guestConfig, store *viewStore, onClient func(*signalclient.Client)) error
}

// newGUIServer は初期状態（Idle）の GUI サーバーを返す。baseCtx はサーバーのライフサイクル
// （開始セッションの親コンテキスト）。
func newGUIServer(baseCtx context.Context, opts guiOptions) *guiServer {
	s := &guiServer{
		store:      newViewStore(),
		opts:       opts,
		baseCtx:    baseCtx,
		now:        time.Now,
		startHost:  runHost,
		startGuest: runGuest,
	}
	s.touchHeartbeat()
	return s
}

// touchHeartbeat はブラウザからの生存信号を受けた時刻を記録する（監視ゴルーチンが途絶判定に使う）。
func (s *guiServer) touchHeartbeat() { s.lastBeat.Store(s.now().UnixNano()) }

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

// handleState は現在の Snapshot を JSON で返す（フロントがポーリング/購読する）。このポーリングを
// 生存信号（ハートビート）とみなして時刻を更新し、途絶＝ブラウザが閉じられたと監視ゴルーチンが判定する。
func (s *guiServer) handleState(w http.ResponseWriter, r *http.Request) {
	s.touchHeartbeat()
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
		guiURL: s.baseURL, // Cognito サインイン成功後に認証タブを GUI 画面へ戻す
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
	if !s.closeActiveSession("退出しました") {
		http.Error(w, "セッションが稼働していません", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// closeActiveSession は稼働中セッションを終了し、表示を reason で Closed へ落とす。稼働していなけ
// れば false を返す（handleLeave のユーザー操作と、ハートビート途絶によるブラウザ切断の両方が使う）。
// セッション制御状態は cancel 前に同期クリアし、finishSession の異常終了通知が reason を上書きしない
// 順序を保証する（詳細は handleLeave 由来の設計コメント参照）。
func (s *guiServer) closeActiveSession(reason string) bool {
	s.mu.Lock()
	cancel := s.cancel
	active := s.started
	if active {
		s.clearSessionLocked()
	}
	s.mu.Unlock()
	if !active || cancel == nil {
		return false
	}
	s.store.update(func(m *appstate.Model) { m.Close(reason) })
	cancel()
	return true
}

// watchHeartbeat はブラウザからの生存信号（/api/state ポーリング）が timeout を超えて途絶えたら
// 稼働中セッションを閉じる（ブラウザを閉じた＝VPN もクローズ。方針: セッションのみ終了しプロセスは
// 常駐継続するため、閉じた後も再度ブラウザを開けば新しいホスト/参加を始められる）。単一ゴルーチンで
// interval ごとに判定し ctx 終了で抜ける。now 注入で決定的にテストする。
func (s *guiServer) watchHeartbeat(ctx context.Context, interval, timeout time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.now().UnixNano()-s.lastBeat.Load() > int64(timeout) {
				// 稼働中でなければ closeActiveSession は no-op（idle 放置で誤って何かを閉じない）。
				if s.closeActiveSession("ブラウザが閉じられたため切断しました") {
					slog.Info("ブラウザのハートビート途絶によりセッションを終了しました")
				}
			}
		}
	}
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

	// 開始直後にブラウザからのポーリングがまだ届いていなくても即座に途絶と誤判定しないよう更新する。
	s.touchHeartbeat()
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
// GUI からのホスト/参加操作でセッションを駆動する。ctx 終了でグレースフルシャットダウン
// （稼働中セッションも baseCtx 経由でキャンセルされる）。
//
// GUI の表示方法は 2 通り:
//   - アプリ内ウィンドウ対応 OS（appWindowAvailable=true・現状 Windows）: OS 内蔵 WebView で
//     LocalAPI をアプリのウィンドウとして開き、その間 HTTP は別ゴルーチンで提供する。ウィンドウを
//     閉じたら ctx をキャンセルしてサーバーを畳みプロセスを終了する。ウィンドウ生成に失敗したら
//     既定ブラウザへフォールバックする。
//   - 非対応 OS: 従来どおり既定ブラウザで開き、HTTP をブロッキング提供する。
func runGUI(ctx context.Context, addr string, opts guiOptions) error {
	// runGUI 内で ctx を派生し、ウィンドウを閉じたとき（アプリ内ウィンドウ経路）に defer cancel で
	// 全ゴルーチン（Shutdown 監視・ハートビート監視・稼働中セッション）を停止できるようにする。
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	gs := newGUIServer(ctx, opts)
	srv := &http.Server{Handler: gs.handler()}

	// リスナーを先に確立してからウィンドウ/ブラウザを開く（Serve 前に開くと接続に失敗しうるため）。
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	go func() {
		<-ctx.Done()
		shutCtx, sc := context.WithTimeout(context.Background(), 5*time.Second)
		defer sc()
		_ = srv.Shutdown(shutCtx)
	}()

	// ブラウザ/ウィンドウを閉じた（ハートビート途絶）を検知して稼働中セッションを閉じる監視を起動する。
	go gs.watchHeartbeat(ctx, guiHeartbeatInterval, guiHeartbeatTimeout)

	url := "http://" + ln.Addr().String()
	gs.baseURL = url // Cognito サインイン成功後に認証タブを戻す先（Serve 前に設定＝要求受付前に確定）
	slog.Info("GUI サーバー起動", "url", url)

	// アプリ内ウィンドウ対応 OS では WebView をメインスレッドで表示する（openAppWindow がブロック）。
	// その間 HTTP は別ゴルーチンで提供する。
	if appWindowAvailable {
		serveErr := make(chan error, 1)
		go func() { serveErr <- serveGUI(srv, ln) }()

		if werr := openAppWindow(ctx, url); werr != nil {
			// ウィンドウ生成に失敗（WebView2 ランタイム未導入等）。既定ブラウザへフォールバックし、
			// ctx 終了まで HTTP を提供し続ける。
			slog.Warn("アプリ内ウィンドウを開けませんでした。既定ブラウザにフォールバックします", "err", werr)
			if berr := openBrowser(url); berr != nil {
				slog.Warn("ブラウザの自動起動にも失敗しました。上記 URL を手動で開いてください", "url", url, "err", berr)
			}
			return <-serveErr
		}
		// ウィンドウが閉じられた → 全ゴルーチンを停止（Shutdown 監視が Serve を終わらせる）。
		cancel()
		return <-serveErr
	}

	// 非対応 OS: 従来どおり既定ブラウザで自動的に開く（ベストエフォート・失敗してもサーバーは継続）。
	if err := openBrowser(url); err != nil {
		slog.Warn("ブラウザの自動起動に失敗しました。上記 URL を手動で開いてください", "url", url, "err", err)
	}
	return serveGUI(srv, ln)
}

// serveGUI は HTTP サーバーを起動し、正常なシャットダウン（ErrServerClosed）を nil に畳んで返す。
func serveGUI(srv *http.Server, ln net.Listener) error {
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
