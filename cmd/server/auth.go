package main

import (
	"errors"
	"net/http"
	"strings"

	"github.com/instantmesh/instantmesh/pkg/clientip"
	"github.com/instantmesh/instantmesh/pkg/hub"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/session"
	"github.com/instantmesh/instantmesh/pkg/wgkey"
)

// Authenticator は WebSocket 接続確立時の HTTP リクエストから hub.Auth を導出する。
// 実運用では Cognito JWT 検証実装へ差し替える（インターフェースは不変）。
type Authenticator interface {
	Authenticate(r *http.Request) (hub.Auth, error)
}

// 認証エラー。
var (
	// ErrMissingCredentials はホスト接続に必要な資格情報が欠けている場合に返る。
	ErrMissingCredentials = errors.New("server: host requires bearer token and public key")
	// ErrUnknownRole は未知の role クエリが指定された場合に返る。
	ErrUnknownRole = errors.New("server: unknown role")
	// ErrInvalidPubKey はホスト公開鍵が正規の形式（base64・32バイト）でない場合に返る。
	ErrInvalidPubKey = errors.New("server: invalid public key")
)

// DevAuthenticator はフェーズ1の最小認証。実 Cognito JWT 検証に差し替える前提のモックであり、
// トークンの署名・失効・発行元は一切検証しない。接続時のクエリ / ヘッダから役割を判定する:
//   - role=guest（既定・未指定含む）: 認証なしで参加を許可。公開鍵は join_request で確定するため空。
//   - role=host: Authorization: Bearer <account> と ?pubkey=<wg-pub> を要求（トークンはアカウントID
//     とみなすだけの擬似検証）。プランは ?tier=free|pro（既定 free）。
type DevAuthenticator struct {
	// Proxies は信頼するリバースプロキシの CIDR に基づき実クライアント IP を解決する。
	// nil の場合は「信頼プロキシなし（直接公開）」として X-Forwarded-For を無視する（H-02）。
	Proxies *clientip.Resolver
}

// Authenticate は Authenticator を実装する。
func (d DevAuthenticator) Authenticate(r *http.Request) (hub.Auth, error) {
	remoteIP := d.clientIP(r)
	switch r.URL.Query().Get("role") {
	case "", "guest":
		return hub.Auth{Role: session.RoleGuest, RemoteIP: remoteIP}, nil
	case "host":
		token := bearerToken(r)
		pubKey := r.URL.Query().Get("pubkey")
		if token == "" || pubKey == "" {
			return hub.Auth{}, ErrMissingCredentials
		}
		// 公開鍵は識別子として全経路（リレー認可・meshpeer・監査等）に流れるため、入口で
		// 正規の Curve25519 公開鍵（base64・32バイト）であることを検証する（M-05(a)）。
		if err := wgkey.ValidatePublicKey(pubKey); err != nil {
			return hub.Auth{}, ErrInvalidPubKey
		}
		tier := plan.Free
		if r.URL.Query().Get("tier") == string(plan.Pro) {
			tier = plan.Pro
		}
		return hub.Auth{
			Role:      session.RoleHost,
			AccountID: token, // モック: JWT 検証の代わりにトークンをアカウントIDとみなす。
			PubKey:    pubKey,
			Tier:      tier,
			RemoteIP:  remoteIP,
		}, nil
	default:
		return hub.Auth{}, ErrUnknownRole
	}
}

// bearerToken は Authorization: Bearer <token> のトークン部を返す（無ければ空）。
func bearerToken(r *http.Request) string {
	const prefix = "Bearer "
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, prefix) {
		return strings.TrimSpace(h[len(prefix):])
	}
	return ""
}

// clientIP は接続元の実IPを推定する。信頼するリバースプロキシ（-trusted-proxies）を経由した
// 場合のみ X-Forwarded-For を右から遡って実クライアントを採り、それ以外は直接接続元を用いる。
// X-Forwarded-For の無条件信頼はレート制限バイパス・監査 IP 偽装を招くため行わない（H-02）。
func (d DevAuthenticator) clientIP(r *http.Request) string {
	return resolveClientIP(d.Proxies, r)
}

// resolveClientIP は信頼プロキシ設定に基づき接続元の実 IP を解決する。res が nil の場合は
// 「信頼プロキシなし（直接公開）」として X-Forwarded-For を無視する（H-02）。DevAuthenticator と
// CognitoAuthenticator の双方が用いる。
func resolveClientIP(res *clientip.Resolver, r *http.Request) string {
	if res == nil {
		res = clientip.NewResolver(nil)
	}
	return res.ClientIP(r.RemoteAddr, r.Header.Get("X-Forwarded-For"))
}
