//go:build !linux && !windows && !darwin

package main

import (
	"fmt"

	"github.com/instantmesh/instantmesh/pkg/netcfg"
)

// configureLink は未対応 OS 向けのフォールバック。仮想NICのアドレス/ルート設定は行わず、
// 明示的に未対応エラーを返す（wireguard-go 自体は他BSD等でも動くが本コマンドの自動設定は
// linux/windows/darwin のみ対応）。
func configureLink(_ string, _ netcfg.Plan) error {
	return fmt.Errorf("仮想NICのアドレス/ルート設定は本OSでは未対応です（対応OS: linux/windows/darwin）")
}
