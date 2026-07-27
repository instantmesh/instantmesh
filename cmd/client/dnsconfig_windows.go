//go:build windows

package main

import "fmt"

// powershell は NRPT 操作に使う PowerShell の起動引数（プロファイル・対話入力を排して実行する）。
var powershell = []string{"powershell", "-NoProfile", "-NonInteractive", "-Command"}

// applySplitDNS は NRPT（Name Resolution Policy Table）へ当該サフィックス専用の規則を追加する。
// NRPT は名前空間単位のポリシーであり、指定した名前空間以外の解決経路には影響しない。
// 二重登録を避けるため、追加前に自分の残骸を回収する。要管理者権限。
func applySplitDNS(cfg splitDNS) error {
	if err := clearSplitDNS(cfg); err != nil {
		return err
	}
	// Namespace は先頭ドット付きでサフィックス一致（`.mesh` → `*.mesh`）を意味する。
	// Comment に目印を入れ、異常終了後も自分の規則だけを識別して消せるようにする。
	script := fmt.Sprintf(`Add-DnsClientNrptRule -Namespace '.%s' -NameServers '%s' -Comment '%s'`,
		cfg.Suffix, cfg.Server.String(), dnsMarker)
	return runCmd(powershell[0], append(powershell[1:], script)...)
}

// clearSplitDNS は自分が入れた NRPT 規則（Comment が目印と一致するもの）だけを削除する。
// 該当が無ければ何もしない（起動時の残骸回収でも同じ呼び出しを使う）。
func clearSplitDNS(cfg splitDNS) error {
	script := fmt.Sprintf(
		`Get-DnsClientNrptRule | Where-Object { $_.Comment -eq '%s' } | Remove-DnsClientNrptRule -Force`,
		dnsMarker)
	return runCmd(powershell[0], append(powershell[1:], script)...)
}
