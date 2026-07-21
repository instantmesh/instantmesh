package main

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/cognitojwt"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/session"
)

// makeJWT は kid/iss/aud/sub/exp を持つ RS256 署名済み ID トークンを組み立てる。
func makeJWT(t *testing.T, key *rsa.PrivateKey, kid, iss, aud, sub string, exp int64) string {
	return makeJWTGroups(t, key, kid, iss, aud, sub, exp, nil)
}

// makeJWTGroups は cognito:groups 付きの RS256 署名済み ID トークンを組み立てる（groups が
// nil なら当該クレームを含めない）。
func makeJWTGroups(t *testing.T, key *rsa.PrivateKey, kid, iss, aud, sub string, exp int64, groups []string) string {
	t.Helper()
	header := fmt.Sprintf(`{"alg":"RS256","kid":%q}`, kid)
	payload := fmt.Sprintf(`{"iss":%q,"aud":%q,"token_use":"id","sub":%q,"exp":%d`, iss, aud, sub, exp)
	if groups != nil {
		g, _ := json.Marshal(groups)
		payload += fmt.Sprintf(`,"cognito:groups":%s`, g)
	}
	payload += "}"
	signing := base64.RawURLEncoding.EncodeToString([]byte(header)) + "." +
		base64.RawURLEncoding.EncodeToString([]byte(payload))
	d := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// jwksJSON は key の公開鍵を含む JWKS JSON を返す。
func jwksJSON(key *rsa.PrivateKey, kid string) string {
	n := base64.RawURLEncoding.EncodeToString(key.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes())
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","kid":%q,"n":%q,"e":%q}]}`, kid, n, e)
}

// jwksServer は body を差し替え可能・アクセス回数を数える JWKS モックエンドポイント。
type jwksServer struct {
	*httptest.Server
	mu   sync.Mutex
	body string
	hits int
}

func newJWKSServer(body string) *jwksServer {
	js := &jwksServer{body: body}
	js.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		js.mu.Lock()
		js.hits++
		b := js.body
		js.mu.Unlock()
		_, _ = io.WriteString(w, b)
	}))
	return js
}

func (js *jwksServer) setBody(b string) {
	js.mu.Lock()
	js.body = b
	js.mu.Unlock()
}

func (js *jwksServer) hitCount() int {
	js.mu.Lock()
	defer js.mu.Unlock()
	return js.hits
}

func testCognitoCfg() cognitojwt.Config {
	return cognitojwt.Config{Issuer: "iss1", Audience: "aud1", TokenUse: "id"}
}

func hostReq(tok string) *http.Request {
	r := httptest.NewRequest("GET", "/ws?role=host&pubkey="+testHostKey, nil)
	r.Header.Set("Authorization", "Bearer "+tok)
	return r
}

func TestCognitoAuthenticatorGuest(t *testing.T) {
	a := NewCognitoAuthenticator(testCognitoCfg(), "http://unused", "pro", nil, time.Hour, time.Now)
	for _, role := range []string{"", "guest"} {
		auth, err := a.Authenticate(httptest.NewRequest("GET", "/ws?role="+role, nil))
		if err != nil {
			t.Fatalf("guest(role=%q): %v", role, err)
		}
		if auth.Role != session.RoleGuest || auth.PubKey != "" || auth.AccountID != "" {
			t.Errorf("guest Auth 不正: %+v", auth)
		}
	}
}

func TestCognitoAuthenticatorHostSuccess(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	js := newJWKSServer(jwksJSON(key, "k1"))
	defer js.Close()

	a := NewCognitoAuthenticator(testCognitoCfg(), js.URL, "pro", nil, time.Hour, func() time.Time { return now })
	// プランは cognito:groups から判定する（proGroup="pro" 所属なので Pro）。
	tok := makeJWTGroups(t, key, "k1", "iss1", "aud1", "user-9", now.Add(time.Hour).Unix(), []string{"pro"})

	auth, err := a.Authenticate(hostReq(tok))
	if err != nil {
		t.Fatalf("host: %v", err)
	}
	if auth.Role != session.RoleHost || auth.AccountID != "user-9" || auth.PubKey != testHostKey || auth.Tier != plan.Pro {
		t.Errorf("host Auth 不正: %+v", auth)
	}
}

// TestCognitoAuthenticatorTierFromGroups はプランがトークンの cognito:groups からのみ決まり、
// クエリ ?tier=pro では昇格できない（詐称防止）ことを確認する。
func TestCognitoAuthenticatorTierFromGroups(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	js := newJWKSServer(jwksJSON(key, "k1"))
	defer js.Close()
	a := NewCognitoAuthenticator(testCognitoCfg(), js.URL, "pro", nil, time.Hour, func() time.Time { return now })

	// グループ無し＋クエリ ?tier=pro でも Free のまま（クエリ由来の昇格を無効化）。
	noGroups := makeJWT(t, key, "k1", "iss1", "aud1", "u", now.Add(time.Hour).Unix())
	r := hostReq(noGroups)
	r.URL.RawQuery += "&tier=pro"
	auth, err := a.Authenticate(r)
	if err != nil {
		t.Fatalf("no-groups host: %v", err)
	}
	if auth.Tier != plan.Free {
		t.Errorf("Tier = %v, want Free（クエリ ?tier= では昇格しない）", auth.Tier)
	}

	// 別グループのみ所属 → Free。
	otherGroup := makeJWTGroups(t, key, "k1", "iss1", "aud1", "u", now.Add(time.Hour).Unix(), []string{"admins"})
	auth2, err := a.Authenticate(hostReq(otherGroup))
	if err != nil {
		t.Fatalf("other-group host: %v", err)
	}
	if auth2.Tier != plan.Free {
		t.Errorf("Tier = %v, want Free（pro グループ非所属）", auth2.Tier)
	}
}

func TestCognitoAuthenticatorHostErrors(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	js := newJWKSServer(jwksJSON(key, "k1"))
	defer js.Close()
	a := NewCognitoAuthenticator(testCognitoCfg(), js.URL, "pro", nil, time.Hour, func() time.Time { return now })

	// Bearer 欠如。
	r := httptest.NewRequest("GET", "/ws?role=host&pubkey="+testHostKey, nil)
	if _, err := a.Authenticate(r); err != ErrMissingCredentials {
		t.Errorf("Bearer 欠如 = %v, want ErrMissingCredentials", err)
	}
	// pubkey 欠如。
	r = httptest.NewRequest("GET", "/ws?role=host", nil)
	r.Header.Set("Authorization", "Bearer x")
	if _, err := a.Authenticate(r); err != ErrMissingCredentials {
		t.Errorf("pubkey 欠如 = %v, want ErrMissingCredentials", err)
	}
	// 不正な公開鍵。
	r = httptest.NewRequest("GET", "/ws?role=host&pubkey=not-valid", nil)
	r.Header.Set("Authorization", "Bearer x")
	if _, err := a.Authenticate(r); err != ErrInvalidPubKey {
		t.Errorf("不正 pubkey = %v, want ErrInvalidPubKey", err)
	}
	// 期限切れトークン → ErrInvalidToken。
	expired := makeJWT(t, key, "k1", "iss1", "aud1", "u", now.Add(-time.Hour).Unix())
	if _, err := a.Authenticate(hostReq(expired)); err != ErrInvalidToken {
		t.Errorf("期限切れ = %v, want ErrInvalidToken", err)
	}
	// 未知 role。
	if _, err := a.Authenticate(httptest.NewRequest("GET", "/ws?role=admin", nil)); err != ErrUnknownRole {
		t.Errorf("未知 role = %v, want ErrUnknownRole", err)
	}
}

// TestCognitoAuthenticatorKeyCacheAndRotation はキャッシュ命中で再取得しないこと、未知 kid
// （鍵ローテーション）で再取得すること、TTL 切れで再取得することを確認する。
func TestCognitoAuthenticatorKeyCacheAndRotation(t *testing.T) {
	base := time.Unix(1_000_000, 0)
	nowVal := base
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	js := newJWKSServer(jwksJSON(key1, "k1"))
	defer js.Close()

	ttl := time.Minute
	a := NewCognitoAuthenticator(testCognitoCfg(), js.URL, "pro", nil, ttl, func() time.Time { return nowVal })
	tok1 := makeJWT(t, key1, "k1", "iss1", "aud1", "u", base.Add(time.Hour).Unix())

	// 1 回目: 初回取得。
	if _, err := a.Authenticate(hostReq(tok1)); err != nil {
		t.Fatalf("1st: %v", err)
	}
	if js.hitCount() != 1 {
		t.Fatalf("hits after 1st = %d, want 1", js.hitCount())
	}
	// 2 回目: TTL 内・既知 kid → キャッシュ命中で再取得しない。
	if _, err := a.Authenticate(hostReq(tok1)); err != nil {
		t.Fatalf("2nd: %v", err)
	}
	if js.hitCount() != 1 {
		t.Fatalf("hits after cache hit = %d, want 1", js.hitCount())
	}
	// 鍵ローテーション: サーバを k2 に切替、未知 kid のトークン → 再取得。
	js.setBody(jwksJSON(key2, "k2"))
	tok2 := makeJWT(t, key2, "k2", "iss1", "aud1", "u", base.Add(time.Hour).Unix())
	if _, err := a.Authenticate(hostReq(tok2)); err != nil {
		t.Fatalf("rotation: %v", err)
	}
	if js.hitCount() != 2 {
		t.Fatalf("hits after rotation = %d, want 2", js.hitCount())
	}
	// TTL 切れ: 既知 kid でも再取得する。
	nowVal = base.Add(2 * time.Minute)
	if _, err := a.Authenticate(hostReq(tok2)); err != nil {
		t.Fatalf("ttl refresh: %v", err)
	}
	if js.hitCount() != 3 {
		t.Fatalf("hits after ttl expiry = %d, want 3", js.hitCount())
	}
}

func TestCognitoAuthenticatorFetchFailures(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	tok := makeJWT(t, key, "k1", "iss1", "aud1", "u", now.Add(time.Hour).Unix())

	// (1) 接続失敗: サーバを立ててすぐ閉じる。
	js := newJWKSServer(jwksJSON(key, "k1"))
	url := js.URL
	js.Close()
	a := NewCognitoAuthenticator(testCognitoCfg(), url, "pro", nil, time.Hour, func() time.Time { return now })
	if _, err := a.Authenticate(hostReq(tok)); err != ErrInvalidToken {
		t.Errorf("接続失敗 = %v, want ErrInvalidToken", err)
	}

	// (2) 非 200 応答。
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()
	a2 := NewCognitoAuthenticator(testCognitoCfg(), srv.URL, "pro", nil, time.Hour, func() time.Time { return now })
	if _, err := a2.Authenticate(hostReq(tok)); err != ErrInvalidToken {
		t.Errorf("500 応答 = %v, want ErrInvalidToken", err)
	}
}

func TestNewAuthenticatorSelectsImpl(t *testing.T) {
	// Cognito issuer/audience 設定あり → CognitoAuthenticator。
	cfg := testConfig()
	cfg.cognitoIssuer = "https://cognito-idp.ap-northeast-1.amazonaws.com/pool/"
	cfg.cognitoAudience = "app-client-1"
	cfg.cognitoJWKSTTL = time.Hour
	if _, ok := newAuthenticator(cfg).(*CognitoAuthenticator); !ok {
		t.Error("issuer/audience 設定時は CognitoAuthenticator を返すべき")
	}

	// 未設定 → DevAuthenticator。
	if _, ok := newAuthenticator(testConfig()).(DevAuthenticator); !ok {
		t.Error("未設定時は DevAuthenticator を返すべき")
	}
}

func TestParseFlagsCognito(t *testing.T) {
	cfg, err := parseFlags([]string{
		"-cognito-issuer", "https://iss", "-cognito-audience", "aud",
		"-cognito-pro-group", "premium", "-cognito-jwks-ttl", "30m",
	})
	if err != nil {
		t.Fatal(err)
	}
	if cfg.cognitoIssuer != "https://iss" || cfg.cognitoAudience != "aud" ||
		cfg.cognitoProGroup != "premium" || cfg.cognitoJWKSTTL != 30*time.Minute {
		t.Errorf("cognito フラグが反映されない: %+v", cfg)
	}

	// 既定の pro グループは "pro"。
	def, err := parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if def.cognitoProGroup != "pro" {
		t.Errorf("cognitoProGroup 既定 = %q, want pro", def.cognitoProGroup)
	}
}
