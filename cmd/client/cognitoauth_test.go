package main

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/oauthpkce"
)

// fakeBrowser は openURL のフェイク。実ブラウザ＋IdP の代わりに、認可 URL から redirect_uri と
// state を読み取り、コールバックへ GET してフローを進める。overrides で state/error/code を差し替える。
type fakeBrowser struct {
	code, stateOverride, errParam string
	sawURL                        string
}

func (f *fakeBrowser) open(rawAuthURL string) error {
	f.sawURL = rawAuthURL
	u, err := url.Parse(rawAuthURL)
	if err != nil {
		return err
	}
	redirect := u.Query().Get("redirect_uri")
	q := url.Values{}
	if f.errParam != "" {
		q.Set("error", f.errParam)
		q.Set("error_description", "denied")
	} else {
		q.Set("code", f.code)
		state := u.Query().Get("state")
		if f.stateOverride != "" {
			state = f.stateOverride
		}
		q.Set("state", state)
	}
	resp, err := http.Get(redirect + "?" + q.Encode())
	if err != nil {
		return err
	}
	_ = resp.Body.Close()
	return nil
}

// newTokenServer は id_token を返す token エンドポイントのフェイク。assert が非 nil ならフォーム検査する。
func newTokenServer(t *testing.T, body string, assert func(url.Values)) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if assert != nil {
			_ = r.ParseForm()
			assert(r.PostForm)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, body)
	}))
}

func testLogin(redirectURI string) *cognitoLogin {
	return newCognitoLogin(cognitoConfig{
		domain:      "https://demo.auth.example.com",
		clientID:    "cid-123",
		redirectURI: redirectURI,
		scopes:      []string{"openid"},
	})
}

func TestCognitoLoginSuccess(t *testing.T) {
	var gotForm url.Values
	tok := newTokenServer(t,
		`{"id_token":"ID_TOKEN_XYZ","token_type":"Bearer","expires_in":3600}`,
		func(f url.Values) { gotForm = f })
	defer tok.Close()

	l := testLogin("http://localhost:0/callback")
	fb := &fakeBrowser{code: "AUTH_CODE"}
	l.openURL = fb.open
	l.httpc = tok.Client()
	l.tokenURL = tok.URL

	got, err := l.signIn(context.Background())
	if err != nil {
		t.Fatalf("signIn: %v", err)
	}
	if got != "ID_TOKEN_XYZ" {
		t.Errorf("id_token = %q, want ID_TOKEN_XYZ", got)
	}
	// token 交換フォームが PKCE の必須項目を含むこと。
	if gotForm.Get("grant_type") != "authorization_code" || gotForm.Get("code") != "AUTH_CODE" ||
		gotForm.Get("code_verifier") == "" || gotForm.Get("client_id") != "cid-123" {
		t.Errorf("token フォーム不正: %v", gotForm)
	}
	// authorize URL は PKCE の S256 を宣言し、実 bind ポート付き redirect_uri を持つこと。
	au, _ := url.Parse(fb.sawURL)
	if au.Query().Get("code_challenge_method") != "S256" {
		t.Errorf("code_challenge_method = %q, want S256", au.Query().Get("code_challenge_method"))
	}
	if !strings.HasPrefix(au.Query().Get("redirect_uri"), "http://localhost:") ||
		strings.HasSuffix(au.Query().Get("redirect_uri"), ":0/callback") {
		t.Errorf("redirect_uri がポート再割当されていない: %q", au.Query().Get("redirect_uri"))
	}
}

// TestCognitoCallbackSuccessRedirect は、successRedirect 設定時に成功コールバックが GUI 画面へ
// 302 リダイレクトし（完了文言を表示しない）、code/state も正しく渡ることを検証する（GUI モード）。
func TestCognitoCallbackSuccessRedirect(t *testing.T) {
	l := testLogin("http://localhost:0/callback")
	l.successRedirect = "http://127.0.0.1:8088/"
	resCh := make(chan callbackResult, 1)
	h := l.callbackHandler("/callback", "st", resCh)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/callback?code=AC&state=st", nil))

	if rec.Code != http.StatusFound {
		t.Fatalf("status=%d, want 302", rec.Code)
	}
	if loc := rec.Header().Get("Location"); loc != "http://127.0.0.1:8088/" {
		t.Errorf("Location=%q, want GUI URL", loc)
	}
	if strings.Contains(rec.Body.String(), "このタブを閉じて") {
		t.Error("リダイレクト時は完了文言を表示しないこと")
	}
	res := <-resCh
	if res.err != nil || res.code != "AC" {
		t.Errorf("result = %+v, want code AC / no err", res)
	}
}

// TestCognitoCallbackSuccessMessage は、successRedirect 未設定（ヘッドレス CLI）では従来どおり
// 完了文言を 200 で返すことを検証する。
func TestCognitoCallbackSuccessMessage(t *testing.T) {
	l := testLogin("http://localhost:0/callback")
	resCh := make(chan callbackResult, 1)
	h := l.callbackHandler("/callback", "st", resCh)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/callback?code=AC&state=st", nil))

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "サインインが完了しました") {
		t.Errorf("body=%q, want 完了文言", rec.Body.String())
	}
	<-resCh
}

func TestCognitoLoginStateMismatch(t *testing.T) {
	tok := newTokenServer(t, `{"id_token":"x"}`, nil)
	defer tok.Close()

	l := testLogin("http://localhost:0/callback")
	l.openURL = (&fakeBrowser{code: "c", stateOverride: "attacker-state"}).open
	l.httpc = tok.Client()
	l.tokenURL = tok.URL

	if _, err := l.signIn(context.Background()); !errors.Is(err, errStateMismatch) {
		t.Errorf("signIn err = %v, want errStateMismatch", err)
	}
}

func TestCognitoLoginCallbackError(t *testing.T) {
	l := testLogin("http://localhost:0/callback")
	l.openURL = (&fakeBrowser{errParam: "access_denied"}).open

	if _, err := l.signIn(context.Background()); !errors.Is(err, oauthpkce.ErrCallbackError) {
		t.Errorf("signIn err = %v, want ErrCallbackError", err)
	}
}

func TestCognitoLoginTokenError(t *testing.T) {
	tok := newTokenServer(t, `{"error":"invalid_grant","error_description":"bad code"}`, nil)
	defer tok.Close()

	l := testLogin("http://localhost:0/callback")
	l.openURL = (&fakeBrowser{code: "c"}).open
	l.httpc = tok.Client()
	l.tokenURL = tok.URL

	if _, err := l.signIn(context.Background()); !errors.Is(err, oauthpkce.ErrTokenError) {
		t.Errorf("signIn err = %v, want ErrTokenError", err)
	}
}

func TestCognitoLoginTimeout(t *testing.T) {
	l := testLogin("http://localhost:0/callback")
	l.openURL = func(string) error { return nil } // コールバックを起こさない
	l.timeout = 50 * time.Millisecond

	if _, err := l.signIn(context.Background()); !errors.Is(err, errSignInTimeout) {
		t.Errorf("signIn err = %v, want errSignInTimeout", err)
	}
}

func TestCognitoLoginContextCancelled(t *testing.T) {
	l := testLogin("http://localhost:0/callback")
	l.openURL = func(string) error { return nil }
	l.timeout = 5 * time.Second

	ctx, cancel := context.WithCancel(context.Background())
	go func() { time.Sleep(30 * time.Millisecond); cancel() }()
	if _, err := l.signIn(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("signIn err = %v, want context.Canceled", err)
	}
}

// TestCognitoLoginBrowserOpenFailureContinues はブラウザ起動に失敗してもフロー自体は継続し、
// コールバック（手動貼り付け相当）で完了できることを確認する。
func TestCognitoLoginBrowserOpenFailureContinues(t *testing.T) {
	tok := newTokenServer(t, `{"id_token":"ID_OK"}`, nil)
	defer tok.Close()

	l := testLogin("http://localhost:0/callback")
	fb := &fakeBrowser{code: "c"}
	// openURL は「起動失敗」を返しつつ、裏でコールバックは起こす（ユーザーが手動で URL を開いた想定）。
	l.openURL = func(u string) error {
		go func() { _ = fb.open(u) }()
		return errors.New("no browser")
	}
	l.httpc = tok.Client()
	l.tokenURL = tok.URL

	got, err := l.signIn(context.Background())
	if err != nil || got != "ID_OK" {
		t.Fatalf("signIn = (%q, %v), want (ID_OK, nil)", got, err)
	}
}

// failingReader は必ず読み取りエラーを返す io.Reader（乱数生成失敗の経路を突く）。
type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

// TestCognitoLoginDerivedTokenURL は tokenURL 未設定時に Domain から token エンドポイントを
// 導出する経路（本番相当）を通す。httptest サーバーを Domain に見立て /oauth2/token を応答させる。
func TestCognitoLoginDerivedTokenURL(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"id_token":"DERIVED_OK"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	// Domain をサーバー URL にすると TokenEndpoint は "<url>/oauth2/token" を導出する。
	l := newCognitoLogin(cognitoConfig{
		domain: srv.URL, clientID: "cid", redirectURI: "http://localhost:0/callback", scopes: []string{"openid"},
	})
	l.openURL = (&fakeBrowser{code: "c"}).open
	l.httpc = srv.Client()
	// tokenURL は敢えて未設定（導出経路を通す）。

	got, err := l.signIn(context.Background())
	if err != nil || got != "DERIVED_OK" {
		t.Fatalf("signIn = (%q, %v), want (DERIVED_OK, nil)", got, err)
	}
}

func TestCognitoLoginTokenConnFailure(t *testing.T) {
	dead := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	deadURL := dead.URL
	dead.Close() // 接続を確実に失敗させる

	l := testLogin("http://localhost:0/callback")
	l.openURL = (&fakeBrowser{code: "c"}).open
	l.tokenURL = deadURL

	if _, err := l.signIn(context.Background()); err == nil {
		t.Error("token エンドポイント接続失敗でエラーを期待")
	}
}

func TestCognitoLoginRandFailure(t *testing.T) {
	l := testLogin("http://localhost:0/callback")
	l.randSrc = failingReader{}
	l.openURL = func(string) error { return nil }
	if _, err := l.signIn(context.Background()); err == nil {
		t.Error("乱数生成失敗でエラーを期待")
	}
}

func TestCognitoLoginBindError(t *testing.T) {
	l := testLogin("http://localhost:999999/callback") // 範囲外ポート → bind 失敗
	l.openURL = func(string) error { return nil }
	if _, err := l.signIn(context.Background()); err == nil {
		t.Error("範囲外ポートで bind エラーを期待")
	}
}

func TestCognitoConfigEnabled(t *testing.T) {
	if (cognitoConfig{}).enabled() {
		t.Error("空設定は enabled=false であるべき")
	}
	if !(cognitoConfig{domain: "d", clientID: "c"}).enabled() {
		t.Error("domain+clientID 設定時は enabled=true であるべき")
	}
	if (cognitoConfig{domain: "d"}).enabled() {
		t.Error("clientID 欠如は enabled=false であるべき")
	}
}

func TestSplitScopes(t *testing.T) {
	if got := splitScopes(""); got != nil {
		t.Errorf("空文字 = %v, want nil", got)
	}
	got := splitScopes(" openid , email ,, profile")
	want := []string{"openid", "email", "profile"}
	if len(got) != len(want) {
		t.Fatalf("splitScopes = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("splitScopes[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}
