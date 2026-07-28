//go:build linux

package main

import (
	"fmt"
	"os/exec"
)

// lookResolvectl は systemd-resolved の CLI 有無を調べる（テストで差し替え可能）。
var lookResolvectl = func() error {
	_, err := exec.LookPath("resolvectl")
	return err
}

// applySplitDNS は systemd-resolved にリンク単位の DNS を設定する。
//
//	resolvectl dns    <if> <server>   … このリンクで使う DNS サーバー
//	resolvectl domain <if> ~<suffix>  … 「~」付きはルーティング専用ドメイン指定で、
//	                                     当該サフィックスのクエリだけをこのリンクへ送る
//
// リンク単位のためグローバルの DNS 設定には触れず、仮想NIC が消えれば設定も一緒に消える
// （エフェメラル性と整合する）。`/etc/resolv.conf` の上書きは行わない。
// systemd-resolved が無い環境では errDNSUnsupported を返す（名前解決は使えないが、メッシュIP
// 直接での到達は可能）。
func applySplitDNS(cfg splitDNS) error {
	if cfg.IfName == "" {
		return fmt.Errorf("%w: インターフェース名が未指定です", errDNSUnsupported)
	}
	if err := lookResolvectl(); err != nil {
		return fmt.Errorf("%w: resolvectl が見つかりません: %v", errDNSUnsupported, err)
	}
	if err := runCmd("resolvectl", "dns", cfg.IfName, cfg.Server.String()); err != nil {
		return err
	}
	return runCmd("resolvectl", "domain", cfg.IfName, "~"+cfg.Suffix)
}

// clearSplitDNS はリンクの DNS 設定を既定へ戻す。仮想NIC が既に消えている場合（異常終了後の
// 起動時回収など）は設定も一緒に消えているため、失敗しても成功として扱う。
func clearSplitDNS(cfg splitDNS) error {
	if cfg.IfName == "" {
		return nil
	}
	if err := lookResolvectl(); err != nil {
		return nil // 何も注入していない
	}
	_ = runCmd("resolvectl", "revert", cfg.IfName)
	return nil
}
