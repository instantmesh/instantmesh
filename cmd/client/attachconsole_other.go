//go:build !windows

package main

// attachParentConsole は Windows 専用の親コンソール接続処理（attachconsole_windows.go）の
// 非 Windows 版 no-op。Linux/macOS はコンソール（サブシステム）の概念が無く、
// 端末から起動すれば標準入出力はそのまま親端末に繋がるため何もしない。
func attachParentConsole() {}
