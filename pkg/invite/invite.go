// Package invite は招待リンク / QR コードのペイロード（生成・解析・検証）を提供する。
//
// 招待にはシグナリングサーバー・ルームトークンに加え、ホストの WireGuard 公開鍵を埋め込む。
// ゲストはこれを帯域外（対面・信頼できるチャネル）で受け取り、シグナリング経由で得た
// ホスト公開鍵と照合することで中間者攻撃（MITM）を検知する（アーキテクチャ定義書 §4.2）。
// 照合の安全性は「リンクを安全な経路で共有すること」に依存する。
//
// 本パッケージはトランスポート / UI に依存しない純粋ロジックであり、QR エンコード自体
// （画像化）は利用側が URL 文字列から行う。
package invite

import (
	"errors"
	"fmt"
	"net/url"

	"github.com/instantmesh/instantmesh/pkg/token"
)

// Scheme は招待リンクの URI スキーム。デスクトップアプリが関連付けで開く想定。
const Scheme = "instantmesh"

// host は招待 URI のホスト部（instantmesh://join?...）。
const host = "join"

// エラー。
var (
	// ErrMissingField は必須フィールドが欠けている場合に返る。
	ErrMissingField = errors.New("invite: missing required field")
	// ErrScheme は URI スキームが想定外の場合に返る。
	ErrScheme = errors.New("invite: unrecognized scheme")
	// ErrServerScheme は埋め込まれたシグナリングサーバー URL が ws/wss 以外の場合に返る。
	ErrServerScheme = errors.New("invite: server url must use ws or wss scheme")
)

// Invite は 1 件の招待情報。
type Invite struct {
	// Server はシグナリングサーバーの WebSocket URL（例: wss://mesh.example.com/ws）。
	Server string
	// Token はルーム招待トークン。
	Token string
	// HostPubKey はホストの WireGuard 公開鍵（帯域外 MITM 照合用）。
	HostPubKey string
}

// Validate は必須フィールドの充足と、シグナリングサーバー URL のスキームを検証する。
// サーバー URL は多層防御として ws/wss のみを許可し、悪意ある招待リンクによる想定外
// スキームへの誘導を防ぐ（鍵すり替え MITM は SAS の帯域外照合で別途遮断される。L-07）。
func (i Invite) Validate() error {
	if i.Server == "" || i.Token == "" || i.HostPubKey == "" {
		return ErrMissingField
	}
	u, err := url.Parse(i.Server)
	if err != nil || (u.Scheme != "ws" && u.Scheme != "wss") {
		return ErrServerScheme
	}
	return nil
}

// URL は招待を URI 文字列へ符号化する（QR / リンク共有用）。
func (i Invite) URL() (string, error) {
	if err := i.Validate(); err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("server", i.Server)
	q.Set("token", i.Token)
	q.Set("host", i.HostPubKey)
	u := url.URL{Scheme: Scheme, Host: host, RawQuery: q.Encode()}
	return u.String(), nil
}

// Parse は招待 URI 文字列を Invite へ復元する。スキーム不一致・必須欠落は検証エラー。
func Parse(raw string) (Invite, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return Invite{}, fmt.Errorf("invite: parse url: %w", err)
	}
	if u.Scheme != Scheme {
		return Invite{}, ErrScheme
	}
	q := u.Query()
	inv := Invite{
		Server:     q.Get("server"),
		Token:      q.Get("token"),
		HostPubKey: q.Get("host"),
	}
	if err := inv.Validate(); err != nil {
		return Invite{}, err
	}
	return inv, nil
}

// SAS はホスト公開鍵の短縮フィンガープリント（人間が読み上げて照合する用）を返す。
func (i Invite) SAS() string {
	return token.SAS([]byte(i.HostPubKey))
}

// VerifyHostKey はシグナリング経由で受け取ったホスト公開鍵が、招待に埋め込まれた鍵と
// 一致するかを定数時間で検証する。不一致は MITM の疑いであり、接続を中止すべき。
func (i Invite) VerifyHostKey(received string) bool {
	return token.Equal(i.HostPubKey, received)
}
