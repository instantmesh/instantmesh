// Package wgstat は wireguard-go の UAPI get 出力（device.IpcGet が返す設定/状態テキスト）を
// 解析し、ピアごとの状態を取り出す純粋パーサを提供する。
//
// NAT トラバーサルでは「直通（P2P）ハンドシェイクが実際に成立したか」を知る必要がある。
// WireGuard は各ピアの最終ハンドシェイク時刻を保持しており、UAPI get 出力の
// last_handshake_time_sec / _nsec に現れる。これを観測して直通の成否を判定し、失敗時は
// リレーへフォールバックする（pkg/connmon が状態遷移を担う）。
//
// UAPI get 出力は "key=value" 行の連なりで、public_key= 行を境に各ピアのセクションが始まる。
// public_key 以前のデバイス行（private_key / listen_port / fwmark）は本パッケージの対象外で無視する。
// 公開鍵は 16 進小文字。トランスポート / OS に依存しない純粋ロジックで単体テスト可能。
package wgstat

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Peer は 1 ピアの状態（本パッケージが関心を持つ範囲）。
type Peer struct {
	// PublicKeyHex はピアの公開鍵（16 進小文字）。UAPI は 16 進を用いる（base64 ではない）。
	PublicKeyHex string
	// Endpoint はピアの現在のエンドポイント "ip:port"（未確立なら空）。
	Endpoint string
	// LastHandshake は直近のハンドシェイク成立時刻。未成立なら zero value。
	LastHandshake time.Time
}

// ErrMalformed は "=" を含まない行など、UAPI として解釈できない行を検出したことを表す。
var ErrMalformed = errors.New("wgstat: malformed uapi line")

// Parse は UAPI get 出力を解析し、公開鍵（16 進小文字）をキーとするピア状態のマップを返す。
// 空行は無視する。public_key 以前のデバイス行は無視する。数値フィールドの解析失敗・"=" を
// 含まない行はエラーを返す。
func Parse(uapi string) (map[string]Peer, error) {
	peers := make(map[string]Peer)
	// curKey は現在解析中ピアの公開鍵（16 進小文字。空ならピア未開始）、cur はその蓄積先、
	// hsSec/hsNsec はハンドシェイク秒/ナノ秒（未設定は 0）。
	var curKey string
	var hsSec, hsNsec int64
	var cur Peer

	flush := func() {
		if curKey == "" {
			return
		}
		if hsSec != 0 || hsNsec != 0 {
			cur.LastHandshake = time.Unix(hsSec, hsNsec)
		}
		cur.PublicKeyHex = curKey
		peers[curKey] = cur
	}

	for _, line := range strings.Split(uapi, "\n") {
		if line == "" {
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%w: %q", ErrMalformed, line)
		}
		switch key {
		case "public_key":
			flush() // 直前ピアを確定してから次ピアを開始。
			curKey = strings.ToLower(val)
			cur = Peer{}
			hsSec, hsNsec = 0, 0
		case "endpoint":
			if curKey != "" {
				cur.Endpoint = val
			}
		case "last_handshake_time_sec":
			if curKey != "" {
				n, err := strconv.ParseInt(val, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("wgstat: last_handshake_time_sec %q: %w", val, err)
				}
				hsSec = n
			}
		case "last_handshake_time_nsec":
			if curKey != "" {
				n, err := strconv.ParseInt(val, 10, 64)
				if err != nil {
					return nil, fmt.Errorf("wgstat: last_handshake_time_nsec %q: %w", val, err)
				}
				hsNsec = n
			}
		default:
			// private_key / listen_port / fwmark / tx_bytes / rx_bytes / allowed_ip 等は無視。
		}
	}
	flush() // 最終ピアを確定。
	return peers, nil
}

// LastHandshake は UAPI 出力から公開鍵 pubKeyHex（16 進・大文字小文字不問）のピアの最終
// ハンドシェイク時刻を返す。ピアが存在しない、または解析に失敗した場合は ok=false。
// ハンドシェイク未成立（zero value）の場合も ok=false（＝直通未確立）とする。
func LastHandshake(uapi, pubKeyHex string) (t time.Time, ok bool) {
	peers, err := Parse(uapi)
	if err != nil {
		return time.Time{}, false
	}
	p, found := peers[strings.ToLower(pubKeyHex)]
	if !found || p.LastHandshake.IsZero() {
		return time.Time{}, false
	}
	return p.LastHandshake, true
}
