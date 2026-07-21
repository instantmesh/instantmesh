// Package meshpeer はシグナリングで得たピア情報（公開鍵・メッシュIP・WANエンドポイント）を
// WireGuard のピア設定（pkg/wgconf）へ写すメッシュ構成ポリシーを提供する。
//
// フェーズ1は star トポロジ: ゲストはメッシュ全体（ホストIP の /24）をホスト経由でルーティング
// し、ホストは各ゲストをその割当IP（/32）のみ許可する。全ピアを個別 allowed_ip で構成するため、
// 複数ゲスト時もルーティングが一意に定まる。
//
// 純粋ロジックであり、実デバイスへの適用は利用側（cmd/client の Tunnel.Apply）が担う。
package meshpeer

import (
	"fmt"
	"net/netip"

	"github.com/instantmesh/instantmesh/pkg/wgconf"
)

// keepaliveSec は NAT マッピング維持のためのキープアライブ間隔（秒）。
const keepaliveSec = 25

// HostPeer は承認済みゲストをホスト側 WireGuard へ追加する差分設定を返す。
// allowed_ip はゲストの割当IPのみ（/32・IPv6 なら /128）。endpoint は peer_info で得た WAN。
func HostPeer(guestPubKey, guestIP, endpoint string) (wgconf.Config, error) {
	addr, err := netip.ParseAddr(guestIP)
	if err != nil {
		return wgconf.Config{}, fmt.Errorf("meshpeer: guest ip %q: %w", guestIP, err)
	}
	return wgconf.Config{Peers: []wgconf.Peer{{
		PublicKey:              guestPubKey,
		Endpoint:               endpoint,
		AllowedIPs:             []string{netip.PrefixFrom(addr, addr.BitLen()).String()},
		PersistentKeepaliveSec: keepaliveSec,
	}}}, nil
}

// GuestPeer はホストをゲスト側 WireGuard へ追加する差分設定を返す。
// allowed_ip はメッシュ全体（ホストIP の /24）で、メンバー間通信をホスト経由でルーティングする。
func GuestPeer(hostPubKey, hostIP, endpoint string) (wgconf.Config, error) {
	addr, err := netip.ParseAddr(hostIP)
	if err != nil {
		return wgconf.Config{}, fmt.Errorf("meshpeer: host ip %q: %w", hostIP, err)
	}
	mesh := netip.PrefixFrom(addr, 24).Masked() // 例: 10.0.0.1 → 10.0.0.0/24
	return wgconf.Config{Peers: []wgconf.Peer{{
		PublicKey:              hostPubKey,
		Endpoint:               endpoint,
		AllowedIPs:             []string{mesh.String()},
		PersistentKeepaliveSec: keepaliveSec,
	}}}, nil
}

// RemovePeer は指定公開鍵のピアを WireGuard から除去する差分設定を返す。ゲスト離脱・キック時に使う。
func RemovePeer(pubKey string) wgconf.Config {
	return wgconf.Config{Peers: []wgconf.Peer{{PublicKey: pubKey, Remove: true}}}
}
