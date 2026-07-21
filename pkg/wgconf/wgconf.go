// Package wgconf は wireguard-go を設定するための UAPI（ユーザースペース API）設定文字列を
// 組み立てる純粋ロジックを提供する。
//
// wireguard-go の device.IpcSet は "key=value" 行の連なりで構成される設定を受け取り、鍵は
// 16 進表現を要求する（WireGuard の設定ファイル/wg コマンドが用いる base64 とは異なる）。
// 本パッケージは base64 鍵の 16 進変換・エンドポイント/AllowedIPs の検証を行い、初期設定と
// 差分（ピア追加・削除）の双方に使える UAPI 文字列を生成する。
//
// ネットワーク I/O・OS 依存を持たない純粋ロジックであり、単体テスト可能。実デバイス生成は
// 利用側（cmd/client の wireguard-go アダプタ）が担う。
package wgconf

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/netip"
	"strings"
)

// Peer は WireGuard ピア 1 件の設定。
type Peer struct {
	// PublicKey はピアの公開鍵（base64）。
	PublicKey string
	// Remove が true の場合、このピアを削除する（他フィールドは無視）。
	Remove bool
	// Endpoint はピアの WAN エンドポイント "ip:port"（省略可）。
	Endpoint string
	// AllowedIPs はこのピア経由で許可する宛先 CIDR 一覧（例: "10.0.0.1/32"）。
	AllowedIPs []string
	// PersistentKeepaliveSec は NAT 維持のためのキープアライブ間隔（秒・0 は無効）。
	PersistentKeepaliveSec int
}

// Config は 1 回の UAPI set 操作の内容。PrivateKey が空なら鍵・待受ポートは変更せず、
// ピアの追加/更新/削除のみを行う（差分適用に使える）。
type Config struct {
	// PrivateKey は自デバイスの秘密鍵（base64・省略時はデバイス鍵を変更しない）。
	PrivateKey string
	// PrivateKeyRaw は自デバイスの秘密鍵（生の 32 バイト）。非空のとき PrivateKey より優先され、
	// 秘密鍵を base64 文字列として materialize せずに設定できる（ゼロ化・メモリロック可能な
	// バッファから直接渡す用途。[[secret]] / [[client-secret-management]]）。PrivateKey と
	// PrivateKeyRaw はどちらか一方のみ設定する。
	PrivateKeyRaw []byte
	// ListenPort は UDP 待受ポート（0 は変更しない）。
	ListenPort int
	// ReplacePeers が true の場合、既存ピアを全置換してから Peers を適用する。
	ReplacePeers bool
	// Peers は設定するピア群。
	Peers []Peer
}

// UAPI は設定を wireguard-go の IpcSet 用文字列へ組み立てる。
func (c Config) UAPI() (string, error) {
	var b strings.Builder

	switch {
	case len(c.PrivateKeyRaw) > 0:
		if len(c.PrivateKeyRaw) != 32 {
			return "", fmt.Errorf("wgconf: private key must be 32 bytes, got %d", len(c.PrivateKeyRaw))
		}
		fmt.Fprintf(&b, "private_key=%s\n", hex.EncodeToString(c.PrivateKeyRaw))
	case c.PrivateKey != "":
		privHex, err := keyToHex(c.PrivateKey)
		if err != nil {
			return "", fmt.Errorf("wgconf: private key: %w", err)
		}
		fmt.Fprintf(&b, "private_key=%s\n", privHex)
	}
	if c.ListenPort > 0 {
		fmt.Fprintf(&b, "listen_port=%d\n", c.ListenPort)
	}
	if c.ReplacePeers {
		b.WriteString("replace_peers=true\n")
	}

	for _, p := range c.Peers {
		pubHex, err := keyToHex(p.PublicKey)
		if err != nil {
			return "", fmt.Errorf("wgconf: peer public key: %w", err)
		}
		fmt.Fprintf(&b, "public_key=%s\n", pubHex)
		if p.Remove {
			b.WriteString("remove=true\n")
			continue
		}
		if p.Endpoint != "" {
			if _, err := netip.ParseAddrPort(p.Endpoint); err != nil {
				return "", fmt.Errorf("wgconf: peer endpoint %q: %w", p.Endpoint, err)
			}
			fmt.Fprintf(&b, "endpoint=%s\n", p.Endpoint)
		}
		if p.PersistentKeepaliveSec > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.PersistentKeepaliveSec)
		}
		if len(p.AllowedIPs) > 0 {
			b.WriteString("replace_allowed_ips=true\n")
			for _, cidr := range p.AllowedIPs {
				if _, err := netip.ParsePrefix(cidr); err != nil {
					return "", fmt.Errorf("wgconf: allowed ip %q: %w", cidr, err)
				}
				fmt.Fprintf(&b, "allowed_ip=%s\n", cidr)
			}
		}
	}
	return b.String(), nil
}

// keyToHex は base64（32 バイト）鍵を wireguard-go UAPI 用の 16 進表現へ変換する。
func keyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("decode base64: %w", err)
	}
	if len(raw) != 32 {
		return "", fmt.Errorf("key must be 32 bytes, got %d", len(raw))
	}
	return hex.EncodeToString(raw), nil
}
