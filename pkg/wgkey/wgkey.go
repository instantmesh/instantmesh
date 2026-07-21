// Package wgkey は WireGuard 互換の鍵ペア（Curve25519 / X25519）の生成と符号化を提供する。
//
// WireGuard の秘密鍵は 32 バイトの Curve25519 スカラ、公開鍵はその基点倍点であり、いずれも
// base64（標準エンコード）で表現する。本パッケージは crypto/ecdh（標準ライブラリの X25519、
// RFC 7748 準拠でクランプ込み）を用いるため外部依存を持たない。
//
// 注意（開発規約 §1.3）: 秘密鍵はディスクに保存してはならない。本パッケージは文字列として
// 鍵を返すのみで、メモリロック（mlock）・使用後ゼロ化・スワップ抑止は利用側（cmd/client）が
// 担う。本パッケージはトランスポート / OS / UI に依存しない純粋ロジックである。
package wgkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// randReader は鍵生成の乱数源（既定は crypto/rand.Reader）。テストでエントロピー障害の
// エラーパスを検証するためのシーム。
var randReader io.Reader = rand.Reader

// KeyPair は base64（標準エンコード）で表現した WireGuard 鍵ペア。
type KeyPair struct {
	// Private は秘密鍵（32 バイトの base64）。ディスクへ保存しないこと。
	Private string
	// Public は公開鍵（32 バイトの base64）。シグナリング / 招待リンクで共有してよい。
	Public string
}

// Generate は新しい WireGuard 鍵ペアを生成する。
func Generate() (KeyPair, error) {
	priv, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return KeyPair{}, fmt.Errorf("wgkey: generate: %w", err)
	}
	return KeyPair{
		Private: base64.StdEncoding.EncodeToString(priv.Bytes()),
		Public:  base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()),
	}, nil
}

// GenerateSecret は新しい WireGuard 鍵ペアを生成し、秘密鍵を生の 32 バイト（Curve25519
// スカラ）で、公開鍵を base64 で返す。Generate と異なり秘密鍵を（不変でゼロ化できない）
// base64 文字列として materialize しないため、呼び出し側はゼロ化・メモリロック可能なバッファ
// （[[secret]] の Value）で保持できる。返り値 priv の所有権は呼び出し側にあり、使用後に
// ゼロ化すること。
//
// 制約（ゼロ化保証の限界）: crypto/ecdh の GenerateKey が返す *ecdh.PrivateKey は内部に秘密
// スカラの第 2 コピーを保持する。本関数は key.Bytes()（別コピー）だけを返すため、呼び出し側が
// 返り値をゼロ化・mlock しても ecdh 内部コピーは munlock 対象外・非ゼロ化のまま GC 到達まで
// 平文でヒープに残る。したがって「秘密鍵のメモリ内保持・使用後ゼロ化・mlock」は部分的にしか
// 成立しない。根治には crypto/ecdh に依存しない自前 X25519 実装が要る（標準ライブラリの制約）。
// Generate() も同じ制約を持つ。
func GenerateSecret() (priv []byte, publicB64 string, err error) {
	key, err := ecdh.X25519().GenerateKey(randReader)
	if err != nil {
		return nil, "", fmt.Errorf("wgkey: generate: %w", err)
	}
	return key.Bytes(), base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()), nil
}

// ValidatePublicKey は s が WireGuard 公開鍵として妥当（base64 標準エンコードの 32 バイト）かを
// 検証する。シグナリング入口で guest / host の公開鍵を検証し、公開鍵を識別子に使う全経路
// （リレー認可・meshpeer 写像・hub 索引・room.guests キー・監査/端末出力）の頑健性を高める
// （M-05(a)）。妥当なら nil、そうでなければエラーを返す。
func ValidatePublicKey(s string) error {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return fmt.Errorf("wgkey: decode public key: %w", err)
	}
	if len(raw) != 32 {
		return fmt.Errorf("wgkey: public key must be 32 bytes, got %d", len(raw))
	}
	return nil
}

// PublicFromPrivate は base64 の秘密鍵から対応する公開鍵（base64）を導出する。
// 鍵の一致検証や、秘密鍵のみ保持する場合の公開鍵再導出に使う。
func PublicFromPrivate(privateB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(privateB64)
	if err != nil {
		return "", fmt.Errorf("wgkey: decode private key: %w", err)
	}
	priv, err := ecdh.X25519().NewPrivateKey(raw) // 長さ 32 でなければエラー
	if err != nil {
		return "", fmt.Errorf("wgkey: invalid private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(priv.PublicKey().Bytes()), nil
}
