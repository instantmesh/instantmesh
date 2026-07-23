package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/instantmesh/instantmesh/pkg/oauthpkce"
)

// Cognito PKCE サインインの既定値・上限。
const (
	cognitoTokenMaxBytes   = 1 << 20         // token 応答の読み取り上限（巨大応答による DoS 抑止）
	cognitoVerifierBytes   = 32              // code_verifier の乱数バイト数（RFC 7636 推奨帯）
	cognitoStateBytes      = 16              // state（CSRF 対策乱数）のバイト数
	cognitoCallbackTimeout = 3 * time.Minute // ブラウザ認証のコールバック待ちタイムアウト

	// defaultCognitoRedirect は PKCE 認可コードのループバック受け取り先。Cognito アプリクライアント
	// に登録した callback URL（infra 側 desktopCallbackPort=53682）と一致させる固定値。不一致だと
	// Cognito が redirect_uri_mismatch を返し、ユーザーが変更する余地もないためフラグにはしない。
	defaultCognitoRedirect = "http://localhost:53682/callback"
)

// サインインの失敗を表すセンチネルエラー。
var (
	errSignInTimeout = errors.New("cognito: サインインがタイムアウトしました")
	errStateMismatch = errors.New("cognito: state 不一致（CSRF の可能性）のためサインインを中止しました")
)

// cognitoConfig はクライアント側 Cognito PKCE サインインの設定（CLI フラグ由来）。
type cognitoConfig struct {
	domain      string   // Hosted UI ベース URL（例: https://<prefix>.auth.<region>.amazoncognito.com）
	clientID    string   // アプリクライアント ID（公開クライアント・シークレット無し）
	redirectURI string   // 認可コード受け取り先（例: http://localhost:53682/callback）
	scopes      []string // 要求スコープ（空なら openid）
}

// enabled は Cognito サインインに必要な最小設定（domain・clientID）が揃っているかを返す。
// 未設定なら従来どおり -account の Bearer をそのまま用いる（開発フロー互換）。
func (c cognitoConfig) enabled() bool {
	return c.domain != "" && c.clientID != ""
}

// cognitoLogin は OAuth2 Authorization Code + PKCE フローで Cognito の ID トークンを取得する
// I/O アダプタ。純粋ロジック（PKCE チャレンジ・URL 構築・応答解析）は pkg/oauthpkce に委ね、
// 本型はループバックコールバックサーバー・ブラウザ起動・token エンドポイントへの HTTP POST を担う。
// openURL / httpc / randSrc / tokenURL / timeout は差し替え可能でユニットテストのシームになる。
type cognitoLogin struct {
	cfg      oauthpkce.Config
	httpc    *http.Client
	openURL  func(string) error // ブラウザ起動（既定 openBrowser・テストはコールバックを模擬）
	randSrc  io.Reader          // 乱数源（既定 crypto/rand.Reader）
	tokenURL string             // 空なら cfg から導出（テストで httptest サーバーへ差し替え）
	timeout  time.Duration      // コールバック待ちタイムアウト（0 なら既定）

	// successRedirect が非空なら、サインイン成功時のコールバックを文言ページではなくこの URL へ
	// 302 リダイレクトする（GUI をブラウザで表示するモードで、認証タブをそのまま GUI 画面＝
	// ルーム/QR 表示へ戻すため）。空（ヘッドレス CLI・後述の successCloseTab）ならリダイレクトしない。
	successRedirect string

	// successCloseTab が真なら、サインイン成功時に「このタブは閉じてよい」旨の完了ページを表示し、
	// 可能なら window.close() で自動的に閉じる（GUI をアプリ内ウィンドウ＝WebView で表示するモード）。
	// ルーム情報はウィンドウ側に表示されるため、認証用に開いた外部ブラウザのタブは不要になる。
	// successRedirect が非空のときはそちらを優先する。
	successCloseTab bool
}

// newCognitoLogin は実運用の既定（crypto/rand・実ブラウザ起動・10 秒タイムアウトの HTTP
// クライアント）で cognitoLogin を構築する。
func newCognitoLogin(c cognitoConfig) *cognitoLogin {
	return &cognitoLogin{
		cfg: oauthpkce.Config{
			Domain:      c.domain,
			ClientID:    c.clientID,
			RedirectURI: c.redirectURI,
			Scopes:      c.scopes,
		},
		httpc:   &http.Client{Timeout: 10 * time.Second},
		openURL: openBrowser,
		randSrc: rand.Reader,
		timeout: cognitoCallbackTimeout,
	}
}

// signInDoneCloseTabHTML はアプリ内ウィンドウ（WebView）モードでのサインイン成功ページ。
// ルーム情報はアプリのウィンドウに表示されるため、認証用に開いた外部ブラウザのタブは不要。
// window.close() で自動的に閉じるのを試み（多くのブラウザはユーザーが URL で開いたタブの
// スクリプトクローズを拒否するため）、閉じられない場合は文言で手動クローズを促す。
const signInDoneCloseTabHTML = `<!doctype html><html lang="ja"><head><meta charset="utf-8">` +
	`<title>InstantMesh</title></head>` +
	`<body style="font-family:sans-serif;padding:2rem">` +
	`<p>サインインが完了しました。このタブは閉じて、InstantMesh のウィンドウに戻ってください。</p>` +
	`<script>window.close()</script></body></html>`

// callbackResult はコールバックハンドラからサインインループへ渡す結果。
type callbackResult struct {
	code string
	err  error
}

// signIn は PKCE フローを一巡実行し、取得した ID トークンを返す。
//
// 手順: (1) code_verifier / state を生成、(2) redirectURI のホスト:ポートでループバック
// コールバックサーバーを起動（ポート 0 なら OS 割当）、(3) 実 bind ポートで認可 URL を構築して
// ブラウザを開き、(4) コールバックで code を受け取り state を照合、(5) token エンドポイントへ
// 交換して id_token を得る。ID トークンは Bearer に用いる資格情報でありディスクへは保存しない。
func (l *cognitoLogin) signIn(ctx context.Context) (string, error) {
	verifier, err := oauthpkce.RandomURLSafe(l.randSrc, cognitoVerifierBytes)
	if err != nil {
		return "", fmt.Errorf("code_verifier 生成: %w", err)
	}
	state, err := oauthpkce.RandomURLSafe(l.randSrc, cognitoStateBytes)
	if err != nil {
		return "", fmt.Errorf("state 生成: %w", err)
	}

	ru, err := url.Parse(l.cfg.RedirectURI)
	if err != nil {
		return "", fmt.Errorf("redirect URI 解析: %w", err)
	}
	port := ru.Port()
	if port == "" {
		port = "0" // ポート未指定なら OS 割当（本番は固定ポートを Cognito に登録する）
	}
	ln, err := net.Listen("tcp", net.JoinHostPort(ru.Hostname(), port))
	if err != nil {
		return "", fmt.Errorf("コールバックサーバーの bind: %w", err)
	}
	defer ln.Close()

	// 実際に bind したポートで redirect URI を確定する（authorize と token 交換で同一にする）。
	cfg := l.cfg
	cfg.RedirectURI = rebindRedirect(ru, ln)

	authURL, err := oauthpkce.AuthorizeURL(cfg, state, oauthpkce.S256Challenge(verifier))
	if err != nil {
		return "", fmt.Errorf("認可 URL 構築: %w", err)
	}

	resCh := make(chan callbackResult, 1)
	srv := &http.Server{
		Handler:           l.callbackHandler(ru.Path, state, resCh),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() { _ = srv.Serve(ln) }()
	defer func() { _ = srv.Close() }()

	fmt.Println("ブラウザで Cognito にサインインしてください。開かない場合は次の URL を貼り付けてください:")
	fmt.Println(authURL)
	if err := l.openURL(authURL); err != nil {
		slog.Warn("ブラウザの起動に失敗しました。上記 URL を手動で開いてください", "err", err)
	}

	timeout := l.timeout
	if timeout <= 0 {
		timeout = cognitoCallbackTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case <-timer.C:
		return "", errSignInTimeout
	case res := <-resCh:
		if res.err != nil {
			return "", res.err
		}
		return l.exchange(ctx, cfg, res.code, verifier)
	}
}

// callbackHandler はリダイレクトを受け取り、code と state を解析・照合して結果を一度だけ
// resCh へ送るハンドラを返す。ブラウザには結果に応じた簡単な文言を返す（想定外のパスは 404）。
func (l *cognitoLogin) callbackHandler(expectPath, expectState string, resCh chan<- callbackResult) http.Handler {
	var once sync.Once
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if expectPath != "" && r.URL.Path != expectPath {
			http.NotFound(w, r) // favicon 等の無関係な要求は結果に影響させない
			return
		}
		code, state, err := oauthpkce.ParseCallback(r.URL.RawQuery)
		if err == nil && state != expectState {
			err = errStateMismatch
		}
		switch {
		case err != nil:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, "サインインに失敗しました。端末（ターミナル）に戻って確認してください。")
		case l.successRedirect != "":
			// GUI（ブラウザ表示）モード: 認証タブをそのまま GUI 画面（ルーム作成/QR 表示）へ遷移させる。
			http.Redirect(w, r, l.successRedirect, http.StatusFound)
		case l.successCloseTab:
			// GUI（アプリ内ウィンドウ表示）モード: ルーム情報はウィンドウ側に出るため、認証用に
			// 開いたこのタブは不要。閉じるよう促し、可能なら自動で閉じる（window.close はスクリプトで
			// 開いたタブ以外はブラウザが拒否しうるためベストエフォート・文言でフォールバックする）。
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			_, _ = io.WriteString(w, signInDoneCloseTabHTML)
		default:
			_, _ = io.WriteString(w, "サインインが完了しました。このタブを閉じて端末（ターミナル）に戻ってください。")
		}
		once.Do(func() { resCh <- callbackResult{code: code, err: err} })
	})
}

// exchange は認可コードを token エンドポイントで ID トークンへ交換する。
func (l *cognitoLogin) exchange(ctx context.Context, cfg oauthpkce.Config, code, verifier string) (string, error) {
	tokenURL := l.tokenURL
	if tokenURL == "" {
		var err error
		if tokenURL, err = oauthpkce.TokenEndpoint(cfg); err != nil {
			return "", fmt.Errorf("token エンドポイント導出: %w", err)
		}
	}
	form := oauthpkce.TokenForm(cfg, code, verifier)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return "", fmt.Errorf("token リクエスト生成: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := l.httpc.Do(req)
	if err != nil {
		return "", fmt.Errorf("token エンドポイント接続: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, cognitoTokenMaxBytes))
	if err != nil {
		return "", fmt.Errorf("token 応答の読み取り: %w", err)
	}
	tok, err := oauthpkce.ParseTokenResponse(body)
	if err != nil {
		return "", err
	}
	return tok.IDToken, nil
}

// rebindRedirect は redirect URI のホスト表記を保ちつつ、実際に bind したポートへ差し替えた
// URI 文字列を返す（設定ポートが固定なら実質そのまま・0 なら OS 割当ポートを反映）。
func rebindRedirect(ru *url.URL, ln net.Listener) string {
	_, port, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		return ru.String()
	}
	u := *ru
	u.Host = net.JoinHostPort(ru.Hostname(), port)
	return u.String()
}
