// Package portfilter は無料プランのポート制限（要件定義書 §4.5）の判定ロジックを提供する。
//
// 復号後の内部 IP パケット（IPv4 / IPv6）を解析し、L4 プロトコルと宛先ポートを取り出して、
// プラン仕様に基づき送出を許可するか判定する。ポート制限なし（Pro）は常に許可。制限あり（Free）
// は ICMP / ICMPv6 と許可 TCP ポート（plan.AllowedTCPPorts）のみ許可し、それ以外（UDP・許可外
// TCP・解析不能）は拒否する。
//
// これはクライアント側の既定フィルタ（緩和策）であり、改変によりバイパスされうる点はドキュメント
// と一致させること（強制はリレー量制限・レート制限・監査ログで担保）。本パッケージは純粋ロジック
// で、実際のパケット遮断（仮想NICのフック）は利用側が担う。
package portfilter

import (
	"encoding/binary"

	"github.com/instantmesh/instantmesh/pkg/plan"
)

// L4 プロトコル番号（IPv4 protocol / IPv6 next header）。
const (
	protoICMP   = 1  // ICMP (IPv4)
	protoTCP    = 6  // TCP
	protoUDP    = 17 // UDP
	protoICMPv6 = 58 // ICMPv6
)

// Allow は内部 IP パケットをプラン仕様に基づき送出許可するか判定する。
func Allow(packet []byte, spec plan.Spec) bool {
	if !spec.PortRestricted {
		return true
	}
	proto, dstPort, ok := parse(packet)
	if !ok {
		return false // 解析不能は安全側で拒否
	}
	switch proto {
	case protoICMP, protoICMPv6:
		return true
	case protoTCP:
		return spec.TCPPortAllowed(int(dstPort))
	default:
		return false // UDP・その他プロトコル
	}
}

// parse は IP パケットから L4 プロトコル番号と、TCP/UDP の宛先ポートを取り出す。
// ICMP 等ポートを持たないプロトコルは dstPort=0 を返す。
func parse(p []byte) (proto byte, dstPort uint16, ok bool) {
	if len(p) < 1 {
		return 0, 0, false
	}
	switch p[0] >> 4 { // IP バージョン
	case 4:
		return parseIPv4(p)
	case 6:
		return parseIPv6(p)
	default:
		return 0, 0, false
	}
}

func parseIPv4(p []byte) (byte, uint16, bool) {
	if len(p) < 20 {
		return 0, 0, false
	}
	ihl := int(p[0]&0x0f) * 4 // ヘッダ長（32bit ワード数 × 4）
	if ihl < 20 || len(p) < ihl {
		return 0, 0, false
	}
	proto := p[9]
	return withPort(proto, p[ihl:])
}

func parseIPv6(p []byte) (byte, uint16, bool) {
	if len(p) < 40 {
		return 0, 0, false
	}
	proto := p[6] // Next Header（拡張ヘッダは非対応・そのまま L4 とみなす）
	return withPort(proto, p[40:])
}

// withPort は L4 ヘッダ先頭 l4 から、TCP/UDP なら宛先ポートを読む。
func withPort(proto byte, l4 []byte) (byte, uint16, bool) {
	if proto == protoTCP || proto == protoUDP {
		if len(l4) < 4 {
			return 0, 0, false
		}
		return proto, binary.BigEndian.Uint16(l4[2:4]), true // 宛先ポートは L4 の 2〜4 バイト目
	}
	return proto, 0, true
}
