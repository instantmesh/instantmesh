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
		// クライアントは -tunnel 既定 true のため UAC 昇格（高整合性）で起動する。
		// rundll32/FileProtocolHandler を高整合性プロセスから直接呼ぶと、中整合性で
		// 起動中の既定ブラウザとの整合性レベル不一致で無視され何も開かないことがある。
		// explorer.exe 経由ならシェルの整合性レベルに降格して既定ブラウザで開けるため、
		// 昇格・非昇格のどちらでも動く。explorer は成功時も終了コード 1 を返すが Start()
		// は完了を待たないため問題にならない。
		return exec.Command("explorer.exe", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default: // linux / *bsd 等は xdg-open
		return exec.Command("xdg-open", url).Start()
	}
}
