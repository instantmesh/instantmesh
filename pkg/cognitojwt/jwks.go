package cognitojwt

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
)

// JWKS 解析の失敗を表すセンチネルエラー。
var (
	// ErrMalformedJWKS は JWKS の JSON もしくは鍵素材（n/e/kid）が不正な場合に返る。
	ErrMalformedJWKS = errors.New("cognitojwt: malformed JWKS")
	// ErrNoKeys は JWKS に使用可能な RSA 鍵が 1 つも無い場合に返る。
	ErrNoKeys = errors.New("cognitojwt: JWKS contains no usable RSA keys")
)

// ParseJWKS は Cognito の JWKS エンドポイント（<issuer>/.well-known/jwks.json）が返す JSON を
// 解析し、kid → RSA 公開鍵のマップを返す。RSA 以外の鍵種別（kty != "RSA"）はスキップする。
// 純粋変換のみで I/O は行わない（HTTP 取得は cmd 側アダプタの責務）。
func ParseJWKS(data []byte) (map[string]*rsa.PublicKey, error) {
	var set struct {
		Keys []struct {
			Kid string `json:"kid"`
			Kty string `json:"kty"`
			N   string `json:"n"`
			E   string `json:"e"`
		} `json:"keys"`
	}
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, ErrMalformedJWKS
	}

	keys := make(map[string]*rsa.PublicKey)
	for _, k := range set.Keys {
		if k.Kty != "RSA" {
			continue
		}
		if k.Kid == "" {
			return nil, ErrMalformedJWKS
		}
		nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
		if err != nil || len(nBytes) == 0 {
			return nil, ErrMalformedJWKS
		}
		eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
		if err != nil || len(eBytes) == 0 {
			return nil, ErrMalformedJWKS
		}
		e := 0
		for _, b := range eBytes {
			e = e<<8 | int(b)
		}
		keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(nBytes), E: e}
	}
	if len(keys) == 0 {
		return nil, ErrNoKeys
	}
	return keys, nil
}
