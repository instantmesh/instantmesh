//go:build linux

package main

import "github.com/instantmesh/instantmesh/pkg/netcfg"

// configureLink は Linux の iproute2(`ip`)で仮想NIC ifName にアドレスとルートを設定する。
// 要 root / CAP_NET_ADMIN。wireguard-go は WG レベルで up 済みだが、netlink リンクの up・
// アドレス付与・メッシュ経由ルート追加は別途必要。
func configureLink(ifName string, plan netcfg.Plan) error {
	if err := runCmd("ip", "address", "add", plan.Address.String(), "dev", ifName); err != nil {
		return err
	}
	if err := runCmd("ip", "link", "set", "dev", ifName, "up"); err != nil {
		return err
	}
	for _, r := range plan.Routes {
		if err := runCmd("ip", "route", "add", r.String(), "dev", ifName); err != nil {
			return err
		}
	}
	return nil
}
