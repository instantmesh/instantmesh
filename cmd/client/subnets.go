package main

import (
	"net"
	"net/netip"
)

// localOnlinkPrefixes は excludeIfName 以外の、起動中かつ非ループバックなインターフェースが持つ
// オンリンクの IPv4 サブネット（ネットワークアドレスへ正規化済みのプレフィックス）を列挙する。
// メッシュ /24 と適用先ホストの既存 LAN の衝突検知（netcfg.Plan.Conflicts）へ渡す。
//
// excludeIfName（自身の仮想NIC）を除くのは、メッシュ /24 は本来この NIC に付与されるため、
// 自身を含めると常に自己衝突扱いになるからである。デフォルトルート等の広域プレフィックスは
// インターフェースのオンリンクアドレスには現れないため、自然と対象外となる。
func localOnlinkPrefixes(excludeIfName string) ([]netip.Prefix, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var out []netip.Prefix
	for _, ifc := range ifaces {
		if ifc.Name == excludeIfName {
			continue
		}
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue // ダウン・ループバックは「接続中の LAN」ではないため対象外
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			if pfx, ok := ipNetToIPv4Prefix(ipnet); ok {
				out = append(out, pfx)
			}
		}
	}
	return out, nil
}

// ipNetToIPv4Prefix は *net.IPNet を IPv4 の netip.Prefix（ネットワークアドレスへ正規化済み）へ
// 変換する。IPv4 以外・非連続マスクは ok=false。net.IPNet のマスクは IPv4 でも 16 バイト
// （IPv4-in-IPv6）で表現されることがあるため、その場合はビット数を補正する（フェーズ1は IPv4 のみ）。
func ipNetToIPv4Prefix(n *net.IPNet) (netip.Prefix, bool) {
	ip4 := n.IP.To4()
	if ip4 == nil {
		return netip.Prefix{}, false
	}
	ones, bits := n.Mask.Size()
	if bits == 0 {
		return netip.Prefix{}, false // 非連続マスク
	}
	if bits == 128 {
		ones -= 96 // ::ffff:0:0/96 分を差し引き IPv4 のビット数へ
	}
	if ones < 0 || ones > 32 {
		return netip.Prefix{}, false
	}
	addr, ok := netip.AddrFromSlice(ip4)
	if !ok {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(addr, ones).Masked(), true
}
