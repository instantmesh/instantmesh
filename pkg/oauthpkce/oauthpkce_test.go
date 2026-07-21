package oauthpkce

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/url"
	"strings"
	"testing"
)

func testCfg() Config {
	return Config{
		Domain:      "https://demo.auth.ap-northeast-1.amazoncognito.com",
		ClientID:    "client-123",
		RedirectURI: "http://localhost:53682/callback",
		Scopes:      []string{"openid", "email"},
	}
}

// failReader は必ず読み取りエラーを返す io.Reader。
type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("boom") }

func TestRandomURLSafe(t *testing.T) {
	// 成功: 決定的な入力から既知の base64url を得る。
	src := bytes.Repeat([]byte{0xAB}, 16)
	got, err := RandomURLSafe(bytes.NewReader(src), 16)
	if err != nil {
		t.Fatalf("RandomURLSafe: %v", err)
	}
	want := base64.RawURLEncoding.EncodeToString(src)
	if got != want {
		t.Errorf("RandomURLSafe = %q, want %q", got, want)
	}

	// 非正のバイト数。
	if _, err := RandomURLSafe(bytes.NewReader(src), 0); !errors.Is(err, ErrNonPositiveLength) {
		t.Errorf("nBytes=0 err = %v, want ErrNonPositiveLength", err)
	}

	// 読み取りエラー（短い入力 → io.ReadFull が ErrUnexpectedEOF）。
	if _, err := RandomURLSafe(bytes.NewReader([]byte{0x01}), 16); err == nil {
		t.Error("短い入力でエラーを期待")
	}
	// 読み取りエラー（Reader 自体が失敗）。
	if _, err := RandomURLSafe(failReader{}, 8); err == nil {
		t.Error("failReader でエラーを期待")
	}
}

func TestS256Challenge(t *testing.T) {
	verifier := "test-verifier-abc"
	sum := sha256.Sum256([]byte(verifier))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := S256Challenge(verifier); got != want {
		t.Errorf("S256Challenge = %q, want %q", got, want)
	}
}

func TestAuthorizeURL(t *testing.T) {
	raw, err := AuthorizeURL(testCfg(), "state-xyz", "chal-abc")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("結果 URL が解析不能: %v", err)
	}
	if u.Path != "/oauth2/authorize" {
		t.Errorf("Path = %q, want /oauth2/authorize", u.Path)
	}
	q := u.Query()
	checks := map[string]string{
		"response_type":         "code",
		"client_id":             "client-123",
		"redirect_uri":          "http://localhost:53682/callback",
		"scope":                 "openid email",
		"state":                 "state-xyz",
		"code_challenge":        "chal-abc",
		"code_challenge_method": "S256",
	}
	for k, want := range checks {
		if got := q.Get(k); got != want {
			t.Errorf("query %q = %q, want %q", k, got, want)
		}
	}
}

// TestAuthorizeURLScopeDefault はスコープ未指定時に openid が既定になることを確認する。
func TestAuthorizeURLScopeDefault(t *testing.T) {
	cfg := testCfg()
	cfg.Scopes = nil
	raw, err := AuthorizeURL(cfg, "s", "c")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	u, _ := url.Parse(raw)
	if got := u.Query().Get("scope"); got != "openid" {
		t.Errorf("scope 既定 = %q, want openid", got)
	}
}

// TestAuthorizeURLPreservesDomainPath は Domain にパスが付いていても /oauth2/authorize を
// 末尾に連結する（末尾スラッシュは重複しない）ことを確認する。
func TestAuthorizeURLPreservesDomainPath(t *testing.T) {
	cfg := testCfg()
	cfg.Domain = "https://example.com/base/"
	raw, err := AuthorizeURL(cfg, "s", "c")
	if err != nil {
		t.Fatalf("AuthorizeURL: %v", err)
	}
	u, _ := url.Parse(raw)
	if u.Path != "/base/oauth2/authorize" {
		t.Errorf("Path = %q, want /base/oauth2/authorize", u.Path)
	}
}

func TestEndpointErrors(t *testing.T) {
	// 設定不足。
	for _, cfg := range []Config{
		{ClientID: "c", RedirectURI: "r"},       // Domain 欠如
		{Domain: "https://d", RedirectURI: "r"}, // ClientID 欠如
		{Domain: "https://d", ClientID: "c"},    // RedirectURI 欠如
	} {
		if _, err := AuthorizeURL(cfg, "s", "c"); !errors.Is(err, ErrIncompleteConfig) {
			t.Errorf("設定不足 err = %v, want ErrIncompleteConfig（cfg=%+v）", err, cfg)
		}
	}

	// Domain が絶対 URL でない（scheme/host 無し）。
	cfg := Config{Domain: "not-a-url", ClientID: "c", RedirectURI: "r"}
	if _, err := AuthorizeURL(cfg, "s", "c"); err == nil || errors.Is(err, ErrIncompleteConfig) {
		t.Errorf("相対 URL Domain err = %v, want 絶対 URL エラー", err)
	}
	if _, err := TokenEndpoint(cfg); err == nil {
		t.Error("TokenEndpoint: 相対 URL Domain でエラーを期待")
	}

	// Domain が url.Parse で失敗する（不正な IPv6 リテラル）。
	bad := Config{Domain: "http://[::1", ClientID: "c", RedirectURI: "r"}
	if _, err := AuthorizeURL(bad, "s", "c"); err == nil {
		t.Error("パース不能 Domain でエラーを期待")
	}
}

func TestTokenEndpoint(t *testing.T) {
	got, err := TokenEndpoint(testCfg())
	if err != nil {
		t.Fatalf("TokenEndpoint: %v", err)
	}
	want := "https://demo.auth.ap-northeast-1.amazoncognito.com/oauth2/token"
	if got != want {
		t.Errorf("TokenEndpoint = %q, want %q", got, want)
	}
}

func TestTokenForm(t *testing.T) {
	form := TokenForm(testCfg(), "the-code", "the-verifier")
	checks := map[string]string{
		"grant_type":    "authorization_code",
		"client_id":     "client-123",
		"code":          "the-code",
		"redirect_uri":  "http://localhost:53682/callback",
		"code_verifier": "the-verifier",
	}
	for k, want := range checks {
		if got := form.Get(k); got != want {
			t.Errorf("form %q = %q, want %q", k, got, want)
		}
	}
	if form.Has("client_secret") {
		t.Error("公開クライアントは client_secret を含めてはならない")
	}
}

func TestParseCallback(t *testing.T) {
	// 成功。
	code, state, err := ParseCallback("code=abc123&state=st1")
	if err != nil {
		t.Fatalf("ParseCallback: %v", err)
	}
	if code != "abc123" || state != "st1" {
		t.Errorf("ParseCallback = (%q, %q), want (abc123, st1)", code, state)
	}

	// 認可サーバーの error 応答。
	_, _, err = ParseCallback("error=access_denied&error_description=denied+by+user")
	if !errors.Is(err, ErrCallbackError) {
		t.Errorf("error 応答 = %v, want ErrCallbackError", err)
	}

	// code 欠如。
	if _, _, err := ParseCallback("state=only"); !errors.Is(err, ErrCallbackMissingCode) {
		t.Errorf("code 欠如 = %v, want ErrCallbackMissingCode", err)
	}

	// 不正なクエリ（パーセントエンコーディング破損）。
	if _, _, err := ParseCallback("code=%zz"); err == nil {
		t.Error("不正クエリでエラーを期待")
	}
}

func TestParseTokenResponse(t *testing.T) {
	// 成功。
	tok, err := ParseTokenResponse([]byte(`{"id_token":"idtok","access_token":"acc","token_type":"Bearer","expires_in":3600,"refresh_token":"ref"}`))
	if err != nil {
		t.Fatalf("ParseTokenResponse: %v", err)
	}
	if tok.IDToken != "idtok" || tok.AccessToken != "acc" || tok.TokenType != "Bearer" ||
		tok.ExpiresIn != 3600 || tok.RefreshToken != "ref" {
		t.Errorf("Token 不正: %+v", tok)
	}

	// 不正 JSON。
	if _, err := ParseTokenResponse([]byte("{")); err == nil {
		t.Error("不正 JSON でエラーを期待")
	}

	// error 応答。
	_, err = ParseTokenResponse([]byte(`{"error":"invalid_grant","error_description":"bad code"}`))
	if !errors.Is(err, ErrTokenError) {
		t.Errorf("error 応答 = %v, want ErrTokenError", err)
	}
	if err != nil && !strings.Contains(err.Error(), "invalid_grant") {
		t.Errorf("error 詳細が欠落: %v", err)
	}

	// id_token 欠如。
	if _, err := ParseTokenResponse([]byte(`{"access_token":"acc"}`)); !errors.Is(err, ErrNoIDToken) {
		t.Errorf("id_token 欠如 = %v, want ErrNoIDToken", err)
	}
}

// TestRoundTrip は generate → challenge → authorize → callback → token-form の一巡が
// 首尾一貫すること（state が URL 経由で往復し、code_challenge が verifier と対応すること）を確認する。
func TestRoundTrip(t *testing.T) {
	cfg := testCfg()
	verifier, err := RandomURLSafe(bytes.NewReader(bytes.Repeat([]byte{1}, 32)), 32)
	if err != nil {
		t.Fatal(err)
	}
	state, err := RandomURLSafe(bytes.NewReader(bytes.Repeat([]byte{2}, 16)), 16)
	if err != nil {
		t.Fatal(err)
	}
	authURL, err := AuthorizeURL(cfg, state, S256Challenge(verifier))
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(authURL)
	// 認可サーバーが state を返し code を発行したと仮定してコールバックを組み立てる。
	cb := url.Values{"code": {"ISSUED"}, "state": {u.Query().Get("state")}}.Encode()
	code, gotState, err := ParseCallback(cb)
	if err != nil {
		t.Fatal(err)
	}
	if gotState != state {
		t.Errorf("state 往復不一致: got %q want %q", gotState, state)
	}
	if form := TokenForm(cfg, code, verifier); form.Get("code") != "ISSUED" {
		t.Errorf("TokenForm code = %q, want ISSUED", form.Get("code"))
	}
}

var _ io.Reader = failReader{}
