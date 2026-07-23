//go:build linux

package main

import (
	"errors"
	"strings"
	"testing"
)

// TestFindChromeBrowser は候補の探索順（先頭優先）と、どれも無い場合に空文字を返すことを検証する。
func TestFindChromeBrowser(t *testing.T) {
	// google-chrome-stable と chromium が両方あるとき、候補リスト先頭の google-chrome-stable を返す。
	look := func(name string) (string, error) {
		switch name {
		case "google-chrome-stable":
			return "/usr/bin/google-chrome-stable", nil
		case "chromium":
			return "/usr/bin/chromium", nil
		}
		return "", errors.New("not found")
	}
	if got, want := findChromeBrowser(look), "/usr/bin/google-chrome-stable"; got != want {
		t.Errorf("findChromeBrowser = %q, want %q（先頭候補を優先）", got, want)
	}

	// 後方の候補だけ存在するとき、それを返す。
	edgeOnly := func(name string) (string, error) {
		if name == "microsoft-edge" {
			return "/usr/bin/microsoft-edge", nil
		}
		return "", errors.New("not found")
	}
	if got, want := findChromeBrowser(edgeOnly), "/usr/bin/microsoft-edge"; got != want {
		t.Errorf("findChromeBrowser = %q, want %q", got, want)
	}

	// どれも無ければ空文字（runGUI が既定ブラウザへフォールバックする合図）。
	none := func(string) (string, error) { return "", errors.New("not found") }
	if got := findChromeBrowser(none); got != "" {
		t.Errorf("findChromeBrowser(none) = %q, want 空文字", got)
	}
}

// TestChromeAppArgs はアプリケーションモードの必須フラグ（--app / --user-data-dir）と初回ウィザード
// 抑止フラグが引数に含まれることを検証する。
func TestChromeAppArgs(t *testing.T) {
	args := chromeAppArgs("http://127.0.0.1:8088", "/tmp/prof")
	joined := strings.Join(args, " ")
	for _, want := range []string{
		"--app=http://127.0.0.1:8088",
		"--user-data-dir=/tmp/prof",
		"--no-first-run",
		"--no-default-browser-check",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("args=%v, want に %q を含む", args, want)
		}
	}
}
