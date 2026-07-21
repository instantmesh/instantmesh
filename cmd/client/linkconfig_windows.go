//go:build windows

package main

import "github.com/instantmesh/instantmesh/pkg/netcfg"

// configureLink は Windows(Wintun)の仮想NIC ifName に netsh でアドレスとルートを設定する。
// 要管理者権限。アドレス・ルートいずれも CIDR 表記（例 10.0.0.5/32・10.0.0.0/24）で与える。
func configureLink(ifName string, plan netcfg.Plan) error {
	if err := runCmd("netsh", "interface", "ipv4", "add", "address", ifName, plan.Address.String()); err != nil {
		return err
	}
	for _, r := range plan.Routes {
		if err := runCmd("netsh", "interface", "ipv4", "add", "route", r.String(), ifName); err != nil {
			return err
		}
	}
	return nil
}
