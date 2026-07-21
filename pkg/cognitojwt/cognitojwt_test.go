package cognitojwt

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"testing"
	"time"
)

// テスト全体で使い回す RSA 鍵。生成コストを避けるため一度だけ作る。
var (
	testKey  *rsa.PrivateKey
	otherKey *rsa.PrivateKey
)

func init() {
	var err error
	if testKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
	if otherKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		panic(err)
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// signRS256 は headerJSON / payloadJSON を base64url 連結し RS256 で署名したトークンを返す。
// headerJSON / payloadJSON は壊れた JSON でもよい（署名は生の base64 連結に対して行う）。
func signRS256(t *testing.T, key *rsa.PrivateKey, headerJSON, payloadJSON string) string {
	t.Helper()
	signing := b64([]byte(headerJSON)) + "." + b64([]byte(payloadJSON))
	d := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, d[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return signing + "." + b64(sig)
}

// keyFor は kid "k1" に testKey の公開鍵を対応させる KeyByID を返す。
func keyFor() KeyByID {
	return func(kid string) (*rsa.PublicKey, bool) {
		if kid == "k1" {
			return &testKey.PublicKey, true
		}
		return nil, false
	}
}

const validHeader = `{"alg":"RS256","kid":"k1"}`

// payloadJSON は指定クレームで有効なペイロード JSON を組み立てる。
func payloadJSON(iss, aud, use string, exp, iat int64) string {
	return fmt.Sprintf(`{"iss":%q,"aud":%q,"token_use":%q,"sub":"user-123","exp":%d,"iat":%d}`,
		iss, aud, use, exp, iat)
}

func TestVerify_Success(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	exp := now.Add(time.Hour).Unix()
	iat := now.Add(-time.Minute).Unix()
	tok := signRS256(t, testKey, validHeader, payloadJSON("iss1", "aud1", "id", exp, iat))
	cfg := Config{Issuer: "iss1", Audience: "aud1", TokenUse: "id"}

	c, err := Verify(tok, cfg, keyFor(), now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c.Subject != "user-123" {
		t.Errorf("Subject = %q, want user-123", c.Subject)
	}
	if !c.ExpiresAt.Equal(time.Unix(exp, 0)) {
		t.Errorf("ExpiresAt = %v, want %v", c.ExpiresAt, time.Unix(exp, 0))
	}
	if !c.IssuedAt.Equal(time.Unix(iat, 0)) {
		t.Errorf("IssuedAt = %v, want %v", c.IssuedAt, time.Unix(iat, 0))
	}
}

// TestVerify_Groups は cognito:groups クレームが Claims.Groups へ取り出されること、
// クレームが無い場合は nil になることを確認する（プラン判定の入力）。
func TestVerify_Groups(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	exp := now.Add(time.Hour).Unix()
	cfg := Config{Issuer: "iss1", Audience: "aud1", TokenUse: "id"}

	// cognito:groups あり。
	withGroups := fmt.Sprintf(
		`{"iss":"iss1","aud":"aud1","token_use":"id","sub":"s","exp":%d,"cognito:groups":["pro","admins"]}`, exp)
	c, err := Verify(signRS256(t, testKey, validHeader, withGroups), cfg, keyFor(), now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(c.Groups) != 2 || c.Groups[0] != "pro" || c.Groups[1] != "admins" {
		t.Errorf("Groups = %v, want [pro admins]", c.Groups)
	}

	// cognito:groups 無し → nil。
	c2, err := Verify(signRS256(t, testKey, validHeader, payloadJSON("iss1", "aud1", "id", exp, 0)), cfg, keyFor(), now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if c2.Groups != nil {
		t.Errorf("Groups = %v, want nil", c2.Groups)
	}
}

// TestVerify_EmptyConfigSkipsClaimChecks は Issuer/Audience/TokenUse 未設定時に
// それぞれの検証がスキップされること（空欄スキップ経路）を確認する。
func TestVerify_EmptyConfigSkipsClaimChecks(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	exp := now.Add(time.Hour).Unix()
	// iat=0（iat なし）で Claims.IssuedAt がゼロ値になる経路も同時にカバー。
	tok := signRS256(t, testKey, validHeader, payloadJSON("whatever", "whatever", "access", exp, 0))

	c, err := Verify(tok, Config{}, keyFor(), now)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if !c.IssuedAt.IsZero() {
		t.Errorf("IssuedAt = %v, want zero", c.IssuedAt)
	}
}

// TestVerify_LeewayCovers は exp 経過直後・nbf 未到達直前でも leeway 内なら通ることを確認する。
func TestVerify_LeewayCovers(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	leeway := 5 * time.Minute
	cfg := Config{Issuer: "iss1", Audience: "aud1", TokenUse: "id", Leeway: leeway}

	// exp は now の 1 分前（経過済み）だが leeway 5 分内。
	expPast := now.Add(-time.Minute).Unix()
	tok := signRS256(t, testKey, validHeader, payloadJSON("iss1", "aud1", "id", expPast, 0))
	if _, err := Verify(tok, cfg, keyFor(), now); err != nil {
		t.Errorf("expired-within-leeway: %v", err)
	}

	// nbf は now の 1 分後（未到達）だが leeway 5 分内。
	exp := now.Add(time.Hour).Unix()
	nbf := now.Add(time.Minute).Unix()
	pl := fmt.Sprintf(`{"iss":"iss1","aud":"aud1","token_use":"id","sub":"s","exp":%d,"nbf":%d}`, exp, nbf)
	tok2 := signRS256(t, testKey, validHeader, pl)
	if _, err := Verify(tok2, cfg, keyFor(), now); err != nil {
		t.Errorf("nbf-within-leeway: %v", err)
	}
}

func TestVerify_Errors(t *testing.T) {
	now := time.Unix(1_000_000, 0)
	exp := now.Add(time.Hour).Unix()
	cfg := Config{Issuer: "iss1", Audience: "aud1", TokenUse: "id"}

	// 署名バイトを 1 バイト反転させたトークン（base64 デコードは成功・検証は失敗）。末尾の
	// base64 文字を差し替える方式は RawURLEncoding の末尾パディングビットが破棄され同一バイトに
	// デコードされうる（＝検証が通ってしまう）ため、デコード後のバイトを直接反転して確実に壊す。
	signing := b64([]byte(validHeader)) + "." + b64([]byte(payloadJSON("iss1", "aud1", "id", exp, 0)))
	dGood := sha256.Sum256([]byte(signing))
	sigBytes, err := rsa.SignPKCS1v15(rand.Reader, testKey, crypto.SHA256, dGood[:])
	if err != nil {
		t.Fatal(err)
	}
	sigBytes[0] ^= 0xFF
	tamperedSig := signing + "." + b64(sigBytes)

	// header の base64 は正当だが payload 部を不正 base64 にし、その連結に正しく署名する。
	badPayloadB64 := func() string {
		signing := b64([]byte(validHeader)) + "." + "!!!not-base64"
		d := sha256.Sum256([]byte(signing))
		sig, err := rsa.SignPKCS1v15(rand.Reader, testKey, crypto.SHA256, d[:])
		if err != nil {
			t.Fatal(err)
		}
		return signing + "." + b64(sig)
	}()

	// header は RS256/k1 で正当、signature を不正 base64 に。
	badSigB64 := b64([]byte(validHeader)) + "." + b64([]byte(payloadJSON("iss1", "aud1", "id", exp, 0))) + ".!!!"

	tests := []struct {
		name  string
		token string
		want  error
	}{
		{"parts!=3", "a.b", ErrMalformed},
		{"header base64", "!!!." + b64([]byte(payloadJSON("iss1", "aud1", "id", exp, 0))) + ".AAAA", ErrMalformed},
		{"header json", signRS256(t, testKey, "not-json", payloadJSON("iss1", "aud1", "id", exp, 0)), ErrMalformed},
		{"alg not RS256", signRS256(t, testKey, `{"alg":"HS256","kid":"k1"}`, payloadJSON("iss1", "aud1", "id", exp, 0)), ErrUnsupportedAlg},
		{"unknown kid", signRS256(t, testKey, `{"alg":"RS256","kid":"nope"}`, payloadJSON("iss1", "aud1", "id", exp, 0)), ErrUnknownKey},
		{"sig base64", badSigB64, ErrMalformed},
		{"sig mismatch (tampered)", tamperedSig, ErrSignature},
		{"sig mismatch (other key)", signRS256(t, otherKey, validHeader, payloadJSON("iss1", "aud1", "id", exp, 0)), ErrSignature},
		{"payload base64", badPayloadB64, ErrMalformed},
		{"payload json", signRS256(t, testKey, validHeader, "not-json"), ErrMalformed},
		{"issuer mismatch", signRS256(t, testKey, validHeader, payloadJSON("wrong", "aud1", "id", exp, 0)), ErrIssuer},
		{"audience mismatch", signRS256(t, testKey, validHeader, payloadJSON("iss1", "wrong", "id", exp, 0)), ErrAudience},
		{"token_use mismatch", signRS256(t, testKey, validHeader, payloadJSON("iss1", "aud1", "access", exp, 0)), ErrTokenUse},
		{"exp missing", signRS256(t, testKey, validHeader, `{"iss":"iss1","aud":"aud1","token_use":"id","sub":"s"}`), ErrMalformed},
		{"expired", signRS256(t, testKey, validHeader, payloadJSON("iss1", "aud1", "id", now.Add(-time.Hour).Unix(), 0)), ErrExpired},
		{"not yet valid (nbf)", signRS256(t, testKey, validHeader,
			fmt.Sprintf(`{"iss":"iss1","aud":"aud1","token_use":"id","sub":"s","exp":%d,"nbf":%d}`, exp, now.Add(time.Hour).Unix())), ErrNotYetValid},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Verify(tt.token, cfg, keyFor(), now)
			if !errors.Is(err, tt.want) {
				t.Errorf("Verify err = %v, want %v", err, tt.want)
			}
		})
	}
}

// --- ParseJWKS ---

// jwkFor は key の公開鍵を kty=RSA の JWK JSON 断片にする。
func jwkFor(key *rsa.PrivateKey, kid string) string {
	n := b64(key.N.Bytes())
	e := b64(big.NewInt(int64(key.E)).Bytes())
	return fmt.Sprintf(`{"kty":"RSA","kid":%q,"n":%q,"e":%q}`, kid, n, e)
}

func TestParseJWKS_Success(t *testing.T) {
	// RSA 鍵 1 つ ＋ スキップ対象の EC 鍵を混在させる。
	data := []byte(fmt.Sprintf(`{"keys":[%s,{"kty":"EC","kid":"ec1","crv":"P-256","x":"a","y":"b"}]}`,
		jwkFor(testKey, "k1")))

	keys, err := ParseJWKS(data)
	if err != nil {
		t.Fatalf("ParseJWKS: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("len(keys) = %d, want 1", len(keys))
	}
	got, ok := keys["k1"]
	if !ok {
		t.Fatal("k1 not found")
	}
	if got.N.Cmp(testKey.N) != 0 || got.E != testKey.E {
		t.Errorf("parsed key mismatch: N eq=%v, E=%d want %d", got.N.Cmp(testKey.N) == 0, got.E, testKey.E)
	}
}

func TestParseJWKS_Errors(t *testing.T) {
	tests := []struct {
		name string
		data string
		want error
	}{
		{"invalid json", `{`, ErrMalformedJWKS},
		{"empty kid", `{"keys":[{"kty":"RSA","kid":"","n":"AQAB","e":"AQAB"}]}`, ErrMalformedJWKS},
		{"bad n base64", `{"keys":[{"kty":"RSA","kid":"k1","n":"!!!","e":"AQAB"}]}`, ErrMalformedJWKS},
		{"empty n", `{"keys":[{"kty":"RSA","kid":"k1","n":"","e":"AQAB"}]}`, ErrMalformedJWKS},
		{"bad e base64", `{"keys":[{"kty":"RSA","kid":"k1","n":"AQAB","e":"!!!"}]}`, ErrMalformedJWKS},
		{"empty e", `{"keys":[{"kty":"RSA","kid":"k1","n":"AQAB","e":""}]}`, ErrMalformedJWKS},
		{"no keys", `{"keys":[]}`, ErrNoKeys},
		{"only non-RSA", `{"keys":[{"kty":"EC","kid":"ec1"}]}`, ErrNoKeys},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseJWKS([]byte(tt.data))
			if !errors.Is(err, tt.want) {
				t.Errorf("ParseJWKS err = %v, want %v", err, tt.want)
			}
		})
	}
}
