// Package oauthpkce は OAuth 2.0 Authorization Code + PKCE フロー（RFC 7636）の純粋ロジックを
// 提供する。Amazon Cognito Hosted UI を対象に、PKCE チャレンジ生成・認可 URL 構築・トークン
// 交換リクエストの組み立て・コールバック / トークン応答の解析を行う。
//
// 本パッケージはネットワーク I/O・ブラウザ起動・ローカルコールバックサーバーを一切持たない
// （それらは cmd/client のアダプタが担う）。乱数源は io.Reader として、時刻は不要（純粋）。
// これにより決定的にテストでき、SDK 化の際も UI/トランスポート非依存を保てる。
//
// フロー: (1) code_verifier をランダム生成 → code_challenge=BASE64URL(SHA256(verifier))、
// (2) AuthorizeURL でブラウザを開かせ、(3) リダイレクトのクエリを ParseCallback で解析し
// code を得、(4) TokenForm を token エンドポイントへ POST し、(5) ParseTokenResponse で
// id_token を取り出す。公開クライアント（クライアントシークレット無し）＋ PKCE を前提とする。
package oauthpkce

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
)

// フロー上の失敗を表すセンチネルエラー。呼び出し側は errors.Is で判定する。
var (
	// ErrIncompleteConfig は Domain / ClientID / RedirectURI のいずれかが欠けている場合に返る。
	ErrIncompleteConfig = errors.New("oauthpkce: domain, client id, and redirect uri are required")
	// ErrCallbackError は認可サーバーがコールバックで error パラメータを返した場合に返る。
	ErrCallbackError = errors.New("oauthpkce: authorization server returned an error")
	// ErrCallbackMissingCode はコールバックに認可コードが含まれない場合に返る。
	ErrCallbackMissingCode = errors.New("oauthpkce: callback is missing the authorization code")
	// ErrTokenError は token エンドポイントが error 応答を返した場合に返る。
	ErrTokenError = errors.New("oauthpkce: token endpoint returned an error")
	// ErrNoIDToken は token 応答に id_token が含まれない場合に返る。
	ErrNoIDToken = errors.New("oauthpkce: token response has no id_token")
	// ErrNonPositiveLength は RandomURLSafe に非正のバイト数が渡された場合に返る。
	ErrNonPositiveLength = errors.New("oauthpkce: byte length must be positive")
)

// Config は 1 つの Cognito アプリクライアントに対する PKCE フロー設定。
type Config struct {
	// Domain は Cognito Hosted UI のベース URL（例: https://<prefix>.auth.<region>.amazoncognito.com）。
	Domain string
	// ClientID は Cognito アプリクライアント ID（公開クライアント・シークレット無し）。
	ClientID string
	// RedirectURI は認可コードの受け取り先（例: http://localhost:53682/callback）。
	// cmd 側は実際に bind したループバックポートをここへ設定してから各関数へ渡す。
	RedirectURI string
	// Scopes は要求スコープ。空なら "openid" を既定にする。
	Scopes []string
}

// Token は token エンドポイントの成功応答から取り出す値。
type Token struct {
	IDToken      string `json:"id_token"`
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// RandomURLSafe は r から nBytes バイト読み取り、base64url（パディング無し）文字列を返す。
// code_verifier と state（CSRF 対策の乱数）の生成に用いる。nBytes は正でなければならない。
func RandomURLSafe(r io.Reader, nBytes int) (string, error) {
	if nBytes <= 0 {
		return "", fmt.Errorf("%w: got %d", ErrNonPositiveLength, nBytes)
	}
	buf := make([]byte, nBytes)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", fmt.Errorf("oauthpkce: read random bytes: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// S256Challenge は PKCE の code_challenge（method=S256）= BASE64URL(SHA256(verifier)) を返す。
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthorizeURL は Hosted UI の認可エンドポイント URL（response_type=code・PKCE 付き）を構築する。
func AuthorizeURL(cfg Config, state, codeChallenge string) (string, error) {
	u, err := endpointURL(cfg, "/oauth2/authorize")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("response_type", "code")
	q.Set("client_id", cfg.ClientID)
	q.Set("redirect_uri", cfg.RedirectURI)
	q.Set("scope", scopeParam(cfg.Scopes))
	q.Set("state", state)
	q.Set("code_challenge", codeChallenge)
	q.Set("code_challenge_method", "S256")
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// TokenEndpoint は Hosted UI の token エンドポイント URL を返す。
func TokenEndpoint(cfg Config) (string, error) {
	u, err := endpointURL(cfg, "/oauth2/token")
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

// TokenForm は token エンドポイントへ POST する application/x-www-form-urlencoded ボディを組み立てる
// （公開クライアント＋PKCE のため client_secret は含めない）。
func TokenForm(cfg Config, code, verifier string) url.Values {
	return url.Values{
		"grant_type":    {"authorization_code"},
		"client_id":     {cfg.ClientID},
		"code":          {code},
		"redirect_uri":  {cfg.RedirectURI},
		"code_verifier": {verifier},
	}
}

// ParseCallback はリダイレクトのクエリ文字列（"?" を除く）から認可コードと state を取り出す。
// 認可サーバーが error を返していればそれをエラーにし、code が無ければ ErrCallbackMissingCode を返す。
func ParseCallback(rawQuery string) (code, state string, err error) {
	q, err := url.ParseQuery(rawQuery)
	if err != nil {
		return "", "", fmt.Errorf("oauthpkce: invalid callback query: %w", err)
	}
	if e := q.Get("error"); e != "" {
		return "", "", fmt.Errorf("%w: %s %s", ErrCallbackError, e, q.Get("error_description"))
	}
	code = q.Get("code")
	if code == "" {
		return "", "", ErrCallbackMissingCode
	}
	return code, q.Get("state"), nil
}

// ParseTokenResponse は token エンドポイントの JSON 応答を解析する。error 応答なら ErrTokenError、
// id_token が無ければ ErrNoIDToken を返す。
func ParseTokenResponse(body []byte) (*Token, error) {
	var raw struct {
		Token
		Error     string `json:"error"`
		ErrorDesc string `json:"error_description"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("oauthpkce: invalid token response: %w", err)
	}
	if raw.Error != "" {
		return nil, fmt.Errorf("%w: %s %s", ErrTokenError, raw.Error, raw.ErrorDesc)
	}
	if raw.IDToken == "" {
		return nil, ErrNoIDToken
	}
	t := raw.Token
	return &t, nil
}

// endpointURL は Domain の絶対 URL に suffix パスを付けた *url.URL を返す。Domain / ClientID /
// RedirectURI のいずれかが空、または Domain が絶対 URL でなければエラー。
func endpointURL(cfg Config, suffix string) (*url.URL, error) {
	if cfg.Domain == "" || cfg.ClientID == "" || cfg.RedirectURI == "" {
		return nil, ErrIncompleteConfig
	}
	u, err := url.Parse(cfg.Domain)
	if err != nil {
		return nil, fmt.Errorf("oauthpkce: invalid domain %q: %w", cfg.Domain, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("oauthpkce: domain %q must be an absolute URL", cfg.Domain)
	}
	u.Path = strings.TrimRight(u.Path, "/") + suffix
	return u, nil
}

// scopeParam はスコープ一覧を空白区切りの scope パラメータへ整形する（空なら openid）。
func scopeParam(scopes []string) string {
	if len(scopes) == 0 {
		return "openid"
	}
	return strings.Join(scopes, " ")
}
