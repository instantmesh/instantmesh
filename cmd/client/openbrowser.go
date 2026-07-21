package main

import (
	"os/exec"
	"runtime"
)

// openBrowser は既定のブラウザで url を開く（OS 依存・ベストエフォート）。Cognito Hosted UI での
// サインインに用いる。起動できなくてもフローは継続できるよう、呼び出し側は URL を端末にも表示し、
// 失敗は警告に留める。exec は起動のみ（Start）で完了を待たない。
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default: // linux / *bsd 等は xdg-open
		return exec.Command("xdg-open", url).Start()
	}
}
