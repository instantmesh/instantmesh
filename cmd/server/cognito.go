package main

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/instantmesh/instantmesh/pkg/clientip"
	"github.com/instantmesh/instantmesh/pkg/cognitojwt"
	"github.com/instantmesh/instantmesh/pkg/hub"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/session"
	"github.com/instantmesh/instantmesh/pkg/wgkey"
)

// ErrInvalidToken はホストの JWT が検証（署名・発行元・失効等）に失敗した場合に返る。
var ErrInvalidToken = errors.New("server: invalid or expired token")

// jwksMaxBytes は JWKS レスポンスの読み取り上限（悪意ある巨大応答による DoS を抑止する）。
const jwksMaxBytes = 1 << 20 // 1 MiB

// CognitoAuthenticator は Amazon Cognito が発行する ID トークン（JWT）を検証する Authenticator。
// 純粋な検証ロジックは pkg/cognitojwt に委ね、本型は JWKS の HTTP 取得・キャッシュ・鍵ローテー
// ション追従という I/O を担う。ゲストは DevAuthenticator と同様に認証なしで受け入れる。
type CognitoAuthenticator struct {
	cfg      cognitojwt.Config
	jwksURL  string
	proGroup string // このグループに所属するホストを Pro とみなす（空なら常に Free）
	proxies  *clientip.Resolver
	httpc    *http.Client
	ttl      time.Duration
	now      func() time.Time

	mu      sync.Mutex
	keys    map[string]*rsa.PublicKey
	fetched time.Time
}

// NewCognitoAuthenticator は Cognito 認証器を構築する。jwksURL は
// <issuer>/.well-known/jwks.json、proGroup は Pro とみなす cognito:groups 名（空なら常に
// Free）、ttl は JWKS キャッシュの有効期間、now は時刻源。
func NewCognitoAuthenticator(cfg cognitojwt.Config, jwksURL, proGroup string, proxies *clientip.Resolver, ttl time.Duration, now func() time.Time) *CognitoAuthenticator {
	return &CognitoAuthenticator{
		cfg:      cfg,
		jwksURL:  jwksURL,
		proGroup: proGroup,
		proxies:  proxies,
		httpc:    &http.Client{Timeout: 10 * time.Second},
		ttl:      ttl,
		now:      now,
	}
}

// Authenticate は Authenticator を実装する。role=host のみ JWT を検証し、検証済み sub を
// アカウント ID に用いる。role=guest（既定・未指定含む）は認証なしで受け入れる。
func (c *CognitoAuthenticator) Authenticate(r *http.Request) (hub.Auth, error) {
	remoteIP := resolveClientIP(c.proxies, r)
	switch r.URL.Query().Get("role") {
	case "", "guest":
		return hub.Auth{Role: session.RoleGuest, RemoteIP: remoteIP}, nil
	case "host":
		raw := bearerToken(r)
		pubKey := r.URL.Query().Get("pubkey")
		if raw == "" || pubKey == "" {
			return hub.Auth{}, ErrMissingCredentials
		}
		// 公開鍵は識別子として全経路（リレー認可・meshpeer・監査等）に流れるため、入口で
		// 正規の Curve25519 公開鍵（base64・32バイト）であることを検証する（M-05(a)）。
		if err := wgkey.ValidatePublicKey(pubKey); err != nil {
			return hub.Auth{}, ErrInvalidPubKey
		}
		claims, err := cognitojwt.Verify(raw, c.cfg, c.keyByID, c.now())
		if err != nil {
			return hub.Auth{}, ErrInvalidToken
		}
		// プランは署名検証済みトークンの cognito:groups から判定する。クエリ ?tier= と違い
		// クライアントが詐称できない（proGroup 所属なら Pro・それ以外は fail-safe に Free）。
		tier := plan.TierForGroups(claims.Groups, c.proGroup)
		return hub.Auth{
			Role:      session.RoleHost,
			AccountID: claims.Subject,
			PubKey:    pubKey,
			Tier:      tier,
			RemoteIP:  remoteIP,
		}, nil
	default:
		return hub.Auth{}, ErrUnknownRole
	}
}

// keyByID は kid に対応する署名検証鍵を返す（cognitojwt.KeyByID として Verify に渡す）。
// キャッシュが有効（TTL 内）かつ命中すればそれを返し、TTL 切れまたは未知の kid（鍵ローテー
// ション）なら JWKS を再取得してから返す。再取得に失敗した場合は既存キャッシュへフォール
// バックする（一時的なネットワーク障害で全認証が落ちるのを避ける）。
func (c *CognitoAuthenticator) keyByID(kid string) (*rsa.PublicKey, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	now := c.now()
	if k, ok := c.keys[kid]; ok && now.Sub(c.fetched) < c.ttl {
		return k, true
	}
	if keys, err := c.fetchJWKS(); err == nil {
		c.keys = keys
		c.fetched = now
	}
	k, ok := c.keys[kid]
	return k, ok
}

// fetchJWKS は JWKS エンドポイントを取得し kid→RSA 公開鍵へ解析する。
func (c *CognitoAuthenticator) fetchJWKS() (map[string]*rsa.PublicKey, error) {
	resp, err := c.httpc.Get(c.jwksURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("cognito: jwks endpoint returned status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBytes))
	if err != nil {
		return nil, err
	}
	return cognitojwt.ParseJWKS(body)
}
