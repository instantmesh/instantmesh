//go:build darwin

package main

import "github.com/instantmesh/instantmesh/pkg/netcfg"

// configureLink は macOS の仮想NIC(utun)ifName に ifconfig/route でアドレスとルートを設定する。
// 要 root。utun は point-to-point のため inet に local/peer を与え、メッシュ /24 を interface 経由に
// ルーティングする。
func configureLink(ifName string, plan netcfg.Plan) error {
	local := plan.Address.Addr().String()
	if err := runCmd("ifconfig", ifName, "inet", plan.Address.String(), local, "alias"); err != nil {
		return err
	}
	for _, r := range plan.Routes {
		if err := runCmd("route", "-q", "-n", "add", "-inet", r.String(), "-interface", ifName); err != nil {
			return err
		}
	}
	return nil
}
