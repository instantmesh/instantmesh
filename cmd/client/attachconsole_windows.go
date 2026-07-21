//go:build windows

package main

// 本ファイルは Windows GUI サブシステム（リンク時 -H windowsgui）でビルドした exe を、
// 「ダブルクリック起動では無音（コンソールを開かない）／既存コンソールからの起動では
// その親コンソールへ入出力を接続」の両立させるためのアダプタ。GUI 既定モードの通常利用で
// コンソールウィンドウを出さないことが目的（設計原則1: UI とコアの分離に沿い、cmd/ 側の
// I/O 配線として実装する）。

import (
	"log"
	"log/slog"
	"os"
	"syscall"
)

// attachParentConsole は、親プロセスがコンソール（cmd.exe / PowerShell 等）を持つ場合だけ
// そのコンソールへアタッチし、標準出力・標準エラー・標準入力を貼り直す。
//
// エクスプローラからのダブルクリック起動では親コンソールが無いため AttachConsole は失敗し、
// 何もせず戻る（-H windowsgui によりコンソールは新規に開かれない）。これにより GUI 既定
// モードは無音で起動しつつ、-mode host / guest の CLI 利用は端末から従来どおり
// 入出力できる。main の先頭（フラグ解析や出力より前）で一度だけ呼ぶ。
func attachParentConsole() {
	// ATTACH_PARENT_PROCESS = (DWORD)-1。親プロセスのコンソールを共有する。
	const attachParentProcess = ^uintptr(0)
	proc := syscall.NewLazyDLL("kernel32.dll").NewProc("AttachConsole")
	if r, _, _ := proc.Call(attachParentProcess); r == 0 {
		return // 親コンソール無し（ダブルクリック起動等）。無音のまま GUI として起動する。
	}
	// 親コンソールの擬似ファイルへ標準ハンドルを貼り直す。fmt.Println 等は呼び出し時に
	// os.Stdout を参照するためこれで端末へ出力される。失敗しても致命ではない（無音に留める）。
	if out, err := os.OpenFile("CONOUT$", os.O_WRONLY, 0); err == nil {
		os.Stdout = out
		os.Stderr = out
	}
	if in, err := os.OpenFile("CONIN$", os.O_RDONLY, 0); err == nil {
		os.Stdin = in
	}
	// slog / 標準 log は生成時に os.Stderr を捕捉しており、上の再代入では追随しない。
	// 貼り直した os.Stderr を明示的に出力先に据え、診断ログも親端末へ届くようにする。
	log.SetOutput(os.Stderr)
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, nil)))
}
