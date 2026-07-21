// Package relayframe はリレー（データプレーン）のワイヤフレーム形式を定義する純粋パッケージ。
//
// リレーサーバー（cmd/server）とリレークライアント（cmd/client）は、宛先公開鍵と暗号化
// ペイロードを 1 本の WebSocket バイナリメッセージに載せてやり取りする。両者が同一の
// フレーム形式に依存するため、符号化 / 復号を本パッケージへ集約し、実装のズレを防ぐ。
//
// フレーム形式（ビッグエンディアン）:
//
//	[公開鍵長 (2B)] [公開鍵 (可変)] [ペイロード (可変)]
//
// 公開鍵は「送信側→サーバー」では宛先公開鍵、「サーバー→受信側」では送信元公開鍵を表す
// （方向で意味が変わるだけで形式は同一）。ペイロードは WireGuard の暗号化パケットであり、
// リレーは復号しない（E2E 暗号化。アーキテクチャ定義書 §3-5, §4.1）。
package relayframe

import (
	"encoding/binary"
	"errors"
)

// ErrShort はフレームが短すぎて（ヘッダ欠落・公開鍵長がデータ長超）復号できないことを表す。
var ErrShort = errors.New("relayframe: short frame")

// MaxKeyLen は公開鍵長フィールド（uint16）で表現できる最大バイト数。
const MaxKeyLen = 1<<16 - 1

// ErrKeyTooLong は公開鍵が MaxKeyLen を超えて符号化できないことを表す。
var ErrKeyTooLong = errors.New("relayframe: public key too long")

// Encode は公開鍵とペイロードを 1 フレームへ符号化する。公開鍵が MaxKeyLen を超える場合は
// ErrKeyTooLong を返す（実運用の base64 公開鍵は 44 バイト程度で超えることはない）。
func Encode(pubKey string, payload []byte) ([]byte, error) {
	k := []byte(pubKey)
	if len(k) > MaxKeyLen {
		return nil, ErrKeyTooLong
	}
	buf := make([]byte, 2+len(k)+len(payload))
	binary.BigEndian.PutUint16(buf[:2], uint16(len(k)))
	copy(buf[2:], k)
	copy(buf[2+len(k):], payload)
	return buf, nil
}

// Decode は Encode の逆。公開鍵とペイロードを取り出す。ペイロードは data の内部スライスを
// 指すため、呼び出し側が保持する場合はコピーすること。ヘッダ欠落・切り詰めは ErrShort。
func Decode(data []byte) (pubKey string, payload []byte, err error) {
	if len(data) < 2 {
		return "", nil, ErrShort
	}
	n := int(binary.BigEndian.Uint16(data[:2]))
	if len(data) < 2+n {
		return "", nil, ErrShort
	}
	return string(data[2 : 2+n]), data[2+n:], nil
}
