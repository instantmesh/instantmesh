// Package netcfg は割当メッシュIPから仮想NIC(WireGuard)に適用すべきアドレス設定と
// ルートを算出する純粋ロジックを提供する。
//
// フェーズ1は star トポロジ・IPv4 /24 メッシュ（pkg/ipam の払出・pkg/meshpeer の allowed_ip と整合）。
// ノードは自身の割当IPを /32 でインターフェースに付与し、メッシュ全体(/24)を当該インターフェース
// 経由でルーティングする。WireGuard の cryptokey routing（pkg/meshpeer の allowed_ip）が実際の
// 宛先ピアを解決するため、OS 側は「メッシュ宛はトンネルへ」という単一ルートだけを持てばよい。
// ホスト（.1）・ゲスト（.N）で計画は対称であり、いずれも自身の割当IPだけを渡せばよい。
//
// 実インターフェースへのアドレス/ルート適用（OS依存）は利用側（cmd/client）が担う純粋パッケージ。
package netcfg

import (
	"fmt"
	"net/netip"
)

// meshPrefixBits はルームのメッシュサブネットのプレフィックス長。ipam の /24 払出と一致させる。
const meshPrefixBits = 24

// Plan は仮想NICへ適用するアドレス設定とルートを表す。
type Plan struct {
	// Address はインターフェースに付与する自ノードのアドレス（ホストマスク /32）。
	Address netip.Prefix
	// Routes はインターフェース経由でルーティングするプレフィックス（メッシュ /24）。
	Routes []netip.Prefix
}

// For は割当メッシュIP assignedIP（例 "10.0.0.5"）から設定計画を返す。ホスト・ゲスト共通で、
// 自IPを /32 で付与し、同一 /24 全体をトンネル経由ルートに載せる（メンバー間通信は star の
// ホスト経由）。フェーズ1は IPv4 メッシュのみを対象とする。
func For(assignedIP string) (Plan, error) {
	addr, err := netip.ParseAddr(assignedIP)
	if err != nil {
		return Plan{}, fmt.Errorf("netcfg: 割当IP %q の解析: %w", assignedIP, err)
	}
	if !addr.Is4() {
		return Plan{}, fmt.Errorf("netcfg: 割当IP %q は IPv4 である必要があります（フェーズ1）", assignedIP)
	}
	mesh := netip.PrefixFrom(addr, meshPrefixBits).Masked() // 例: 10.0.0.5 → 10.0.0.0/24
	return Plan{
		Address: netip.PrefixFrom(addr, addr.BitLen()), // /32
		Routes:  []netip.Prefix{mesh},
	}, nil
}

// Conflicts は計画のメッシュルート（/24）と重複する既存プレフィックスを返す（空なら衝突なし）。
// existing は適用先ホストが既に接続しているオンリンクのサブネット（各インターフェースのアドレスから
// 導いたプレフィックス）を呼び出し側が列挙して渡す。
//
// メッシュ /24 と既存サブネットが重複すると、当該 /24 のルートが既存ネットワーク宛トラフィックを
// 奪う（あるいは奪われる）ため、呼び出し側は仮想NICへの適用を中止すべき。例えばクライアントの実LANが
// 10.0.0.0/24 で、ルームにも 10.0.0.0/24 が割り当たると、実LAN（実ルータ・NAS 等）への到達性が壊れる。
// 判定は netip.Prefix.Overlaps による包含判定。デフォルトルート等の広域プレフィックスは「オンリンクの
// サブネット」ではないため呼び出し側が列挙対象に含めない前提（含めると常に重複扱いになる）。
func (p Plan) Conflicts(existing []netip.Prefix) []netip.Prefix {
	var out []netip.Prefix
	for _, e := range existing {
		if !e.IsValid() {
			continue
		}
		for _, r := range p.Routes {
			if r.Overlaps(e) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}
