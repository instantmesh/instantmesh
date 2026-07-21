package main

import (
	"fmt"
	"os/exec"
	"strings"
)

// configureLink（各 OS 実装は linkconfig_<os>.go）は仮想NIC ifName に netcfg.Plan の
// アドレスを付与し、ルートを当該インターフェース経由に設定する。管理者/root 権限が必要で、
// wireguard-go が WG レベルで起動済みのデバイスに対し OS のネットワークスタック設定を行う。
//
// 実 OS のネットワーク設定を伴うため CI（Linux ランナー・非特権）では検証できない。実機検証は
// TODO.md の該当項目に従い別途行う。純粋な計画部分は pkg/netcfg（100%テスト）に分離している。

// runCmd は外部コマンドを実行し、失敗時は結合出力を添えてエラーを返す。OS 依存アプライヤが共有する。
func runCmd(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
