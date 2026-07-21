//go:build !windows

package main

// ensureWintun は Windows 以外では何もしない。wintun.dll は Windows 専用（Wintun）であり、
// Linux/macOS の wireguard-go は wintun を使わないため準備は不要。
func ensureWintun() error { return nil }
