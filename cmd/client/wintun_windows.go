//go:build windows

package main

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path/filepath"
)

// wintunDLL は wireguard-go が Windows で仮想NIC(Wintun)を作成する際に実行時ロードする
// wintun.dll（WireGuard LLC 署名済みのプリビルド・amd64・v0.14.1）を実行ファイルへ埋め込んだもの。
// これにより配布物が単一の exe で完結し、利用者が別途 wintun.dll を用意する必要がなくなる。
// 署名済みプリビルド DLL は再配布可能（同梱ライセンスは WINTUN-LICENSE.txt を参照）。
//
// 配布対象は現状 windows/amd64 のみ（CI のビルドマトリクスに準拠）。windows/arm64 を配布する
// 場合は GOARCH 別に埋め込みファイルを分ける（本ファイルの build 制約を windows && amd64 にし、
// arm64 用の埋め込みを別途用意する）。
//
//go:embed wintun.dll
var wintunDLL []byte

// ensureWintun は埋め込んだ wintun.dll を実行ファイルと同じディレクトリへ配置する。
//
// golang.zx2c4.com/wintun は DLL を LoadLibraryEx の
// LOAD_LIBRARY_SEARCH_APPLICATION_DIR|LOAD_LIBRARY_SEARCH_SYSTEM32 でロードするため、
// wintun.dll は実行ファイルと同じディレクトリ（APPLICATION_DIR）か System32 からしか探索されない
// （PATH・カレントディレクトリ・SetDllDirectory は検索対象外）。System32 を汚さないため、
// 実行ファイルと同じディレクトリへ配置する。OpenTunnel（CreateTUN）の前に呼ぶ。
//
// 既に同一内容の wintun.dll があれば書き直さない（別プロセスがロード中でも安全）。書き出しに
// 失敗しても既存の dll があればそれで続行し、存在しない場合のみエラーを返す（＝従来どおり
// CreateTUN が「DLL が見つからない」で失敗するのと同じ状態に留め、原因を分かりやすく報告する）。
func ensureWintun() error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("実行ファイルパス取得: %w", err)
	}
	dst := filepath.Join(filepath.Dir(exe), "wintun.dll")
	if existing, err := os.ReadFile(dst); err == nil && bytes.Equal(existing, wintunDLL) {
		return nil // 既に同一内容が配置済み（再書き込み不要）
	}
	if err := os.WriteFile(dst, wintunDLL, 0o644); err != nil {
		if _, statErr := os.Stat(dst); statErr == nil {
			return nil // 書けなかったが既存 dll がある（ロード中等）ので続行する
		}
		return fmt.Errorf("wintun.dll の配置に失敗しました（%s）: %w", dst, err)
	}
	return nil
}
