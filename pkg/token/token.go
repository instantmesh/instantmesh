// Package token は招待トークンの生成と、公開鍵の短縮フィンガープリント(SAS)生成を提供する。
//
//   - 招待トークン: 128bit(CSPRNG) のURLセーフ文字列（要件定義書 §4.1）。
//   - SAS (Short Authentication String): WireGuard 公開鍵から導出する人間可読な
//     フィンガープリント。ホストは承認画面で表示し、ゲストと帯域外で読み合わせて
//     中間者攻撃(MITM)を検知する（要件定義書 §4.2 / アーキ §4.2）。
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"
)

// TokenBytes は招待トークンのエントロピー長（バイト）。128bit = 16 バイト（要件 §4.1）。
const TokenBytes = 16

// randRead は乱数読み取り関数（既定は crypto/rand.Read）。テストで差し替えて
// エントロピー障害時のエラーパスを検証するためのシーム。
// なお Go 1.24 以降 crypto/rand.Read は失敗時にエラーを返さずプロセスを致命的終了
// させるため、この関数を通さないとエラー分岐は到達不能となる。
var randRead = rand.Read

// NewRoomToken は 128bit(CSPRNG) のURLセーフな招待トークンを生成する。
func NewRoomToken() (string, error) {
	b := make([]byte, TokenBytes)
	if _, err := randRead(b); err != nil {
		return "", fmt.Errorf("token: read random: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Equal はトークン比較を定数時間で行う（タイミング攻撃対策）。
func Equal(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

// sasEncoding は SAS 用の base32（パディングなし・A-Z2-7）。
var sasEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// SAS は公開鍵（WireGuard 公開鍵など任意バイト列）から短縮フィンガープリントを生成する。
// 出力は "XXXX-XXXX-XXXX-XXXX" 形式（4 文字 × 4 群、base32）。
func SAS(publicKey []byte) string {
	sum := sha256.Sum256(publicKey)
	// 先頭 10 バイト(80bit)を base32 化（16 文字）し、4 文字ごとにハイフンで区切る。
	enc := sasEncoding.EncodeToString(sum[:10])
	return groupBy(enc, 4, "-")
}

// groupBy は s を n 文字ごとに sep で区切った文字列を返す。
func groupBy(s string, n int, sep string) string {
	if n <= 0 || len(s) <= n {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i += n {
		if i > 0 {
			b.WriteString(sep)
		}
		end := i + n
		if end > len(s) {
			end = len(s)
		}
		b.WriteString(s[i:end])
	}
	return b.String()
}
