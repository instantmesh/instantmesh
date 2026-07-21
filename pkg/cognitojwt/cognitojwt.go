// Package cognitojwt は Amazon Cognito が発行する JWT（ID トークン）を検証する純粋ロジックを提供する。
//
// 本パッケージはネットワーク I/O を持たない。署名検証に使う RSA 公開鍵（JWKS 由来）は
// KeyByID で、現在時刻は now 引数で注入する（決定的テストのため）。JWKS の HTTP 取得・
// キャッシュは cmd 側のアダプタが担い、取得した JSON の解析は ParseJWKS（jwks.go）で行う。
//
// 対象は RS256 署名の Cognito ID トークン。alg 混同攻撃（alg=none や、公開鍵を HMAC 鍵と
// して悪用する HS256 すり替え）を防ぐため RS256 以外は拒否し、aud は単一文字列（app client
// id）として扱う。検証は署名を通過するまでクレームを信用しない順序で行う。
package cognitojwt

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// 検証失敗を表すセンチネルエラー。呼び出し側は errors.Is で判定する。
var (
	// ErrMalformed はトークンの構造・エンコード・必須クレームが不正な場合に返る。
	ErrMalformed = errors.New("cognitojwt: malformed token")
	// ErrUnsupportedAlg はヘッダの alg が RS256 以外の場合に返る（alg 混同攻撃対策）。
	ErrUnsupportedAlg = errors.New("cognitojwt: unsupported signature algorithm")
	// ErrUnknownKey はヘッダの kid に対応する署名検証鍵が見つからない場合に返る。
	ErrUnknownKey = errors.New("cognitojwt: signing key not found")
	// ErrSignature は署名検証に失敗した場合に返る。
	ErrSignature = errors.New("cognitojwt: signature verification failed")
	// ErrIssuer は iss が期待値と一致しない場合に返る。
	ErrIssuer = errors.New("cognitojwt: issuer mismatch")
	// ErrAudience は aud が期待値と一致しない場合に返る。
	ErrAudience = errors.New("cognitojwt: audience mismatch")
	// ErrTokenUse は token_use が期待値と一致しない場合に返る。
	ErrTokenUse = errors.New("cognitojwt: token_use mismatch")
	// ErrExpired は exp を過ぎている場合に返る。
	ErrExpired = errors.New("cognitojwt: token expired")
	// ErrNotYetValid は nbf 未到達の場合に返る。
	ErrNotYetValid = errors.New("cognitojwt: token not yet valid")
)

// KeyByID は kid（JWT ヘッダの鍵ID）に対応する署名検証用 RSA 公開鍵を返す。
// 見つからなければ ok=false。実体は JWKS を取得・キャッシュする cmd 側アダプタが与える。
type KeyByID func(kid string) (*rsa.PublicKey, bool)

// Config は検証パラメータ（Cognito User Pool 固有）。空欄の項目は当該検証をスキップするが、
// 本番では Issuer と Audience を必ず設定すること（未設定は検証の無効化を意味する）。
type Config struct {
	// Issuer は期待する iss（例: https://cognito-idp.<region>.amazonaws.com/<poolId>）。
	Issuer string
	// Audience は期待する aud（app client id）。
	Audience string
	// TokenUse は期待する token_use（ID トークンは "id"）。
	TokenUse string
	// Leeway は時刻検証（exp/nbf）の許容クロックスキュー（>=0）。
	Leeway time.Duration
}

// Claims は検証に成功した ID トークンから取り出す確定値。
type Claims struct {
	// Subject は sub（Cognito ユーザーの一意 ID。AccountID に用いる）。
	Subject string
	// ExpiresAt は exp。
	ExpiresAt time.Time
	// IssuedAt は iat（トークンに iat が無い場合はゼロ値）。
	IssuedAt time.Time
	// Groups は cognito:groups（ユーザーが所属する Cognito グループ名の一覧）。プラン(tier)
	// 判定に用いる。クレームが無い / 空なら nil。署名検証を通過した ID トークン由来のため、
	// クエリ由来 tier と違いクライアントによる詐称ができない。
	Groups []string
}

// jwtHeader は JOSE ヘッダの検証に必要な項目。
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// jwtClaims はペイロードの検証に用いる項目（Cognito ID トークン想定・aud は単一文字列）。
type jwtClaims struct {
	Iss      string   `json:"iss"`
	Aud      string   `json:"aud"`
	TokenUse string   `json:"token_use"`
	Sub      string   `json:"sub"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	Nbf      *int64   `json:"nbf"`
	Groups   []string `json:"cognito:groups"`
}

// Verify は Cognito 発行の JWT を検証し、成功時に Claims を返す。検証は
// 「形式 → alg → 署名 → クレーム（iss/aud/token_use）→ 時刻（exp/nbf）」の順で行い、
// 署名検証を通過するまでペイロードのクレームを信用しない。
func Verify(token string, cfg Config, keyByID KeyByID, now time.Time) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrMalformed
	}

	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, ErrMalformed
	}
	var hdr jwtHeader
	if err := json.Unmarshal(headerBytes, &hdr); err != nil {
		return nil, ErrMalformed
	}
	if hdr.Alg != "RS256" {
		return nil, ErrUnsupportedAlg
	}

	pub, ok := keyByID(hdr.Kid)
	if !ok {
		return nil, ErrUnknownKey
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrMalformed
	}
	// 署名対象は "base64url(header).base64url(payload)" の ASCII 文字列。
	signingInput := parts[0] + "." + parts[1]
	digest := sha256.Sum256([]byte(signingInput))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], sig); err != nil {
		return nil, ErrSignature
	}

	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrMalformed
	}
	var c jwtClaims
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return nil, ErrMalformed
	}

	if cfg.Issuer != "" && c.Iss != cfg.Issuer {
		return nil, ErrIssuer
	}
	if cfg.Audience != "" && c.Aud != cfg.Audience {
		return nil, ErrAudience
	}
	if cfg.TokenUse != "" && c.TokenUse != cfg.TokenUse {
		return nil, ErrTokenUse
	}

	if c.Exp == 0 {
		return nil, ErrMalformed
	}
	exp := time.Unix(c.Exp, 0)
	// exp は「これ以降は受理しない」。leeway 分の猶予を与える。
	if !now.Before(exp.Add(cfg.Leeway)) {
		return nil, ErrExpired
	}
	if c.Nbf != nil {
		nbf := time.Unix(*c.Nbf, 0)
		if now.Before(nbf.Add(-cfg.Leeway)) {
			return nil, ErrNotYetValid
		}
	}

	claims := &Claims{Subject: c.Sub, ExpiresAt: exp, Groups: c.Groups}
	if c.Iat != 0 {
		claims.IssuedAt = time.Unix(c.Iat, 0)
	}
	return claims, nil
}
