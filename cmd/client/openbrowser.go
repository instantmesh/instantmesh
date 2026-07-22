package main

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// openBrowser は既定のブラウザで url を開く（OS 依存・ベストエフォート）。Cognito Hosted UI での
// サインインや GUI 本体の表示に用いる。起動できなくてもフローは継続できるよう、呼び出し側は URL を
// 端末にも表示し、失敗は警告に留める。exec は起動のみ（Start）で完了を待たない。
func openBrowser(url string) error {
	switch runtime.GOOS {
	case "windows":
		return openBrowserWindows(url)
	case "darwin":
		return exec.Command("open", url).Start()
	default: // linux / *bsd 等は xdg-open
		return exec.Command("xdg-open", url).Start()
	}
}

// openBrowserWindows は Windows で既定ブラウザに url を開く。
//
// クライアントは -tunnel 既定 true のため UAC 昇格（高整合性）で起動する。rundll32/
// FileProtocolHandler を高整合性プロセスから直接呼ぶと、中整合性で起動中の既定ブラウザとの整合性
// レベル不一致で無視され何も開かないことがある。explorer.exe 経由ならシェルの整合性レベルに降格して
// 既定ブラウザで開けるため、昇格・非昇格のどちらでも動く（explorer は成功時も終了コード 1 を返すが
// Start() は完了を待たないため問題にならない）。
//
// ただし explorer.exe は "?a=b&c=d" のようなクエリ文字列付き URL を直接引数で渡すと、URL ではなく
// パスと誤認して既定フォルダ（ドキュメント）を開いてしまう。Cognito 認可 URL はクエリだらけのため
// これに該当し、サインイン画面が開かない。回避のため URL を一時 .url（インターネットショートカット）
// ファイルへ書き出し、そのファイルを explorer.exe に開かせる。.url はクエリを含む URL 全体を保持でき、
// 既定ブラウザで正しく開く。
func openBrowserWindows(url string) error {
	// .url は INI 風フォーマット。URL= の値は行末までがそのまま扱われるためクエリの & 等の
	// エスケープは不要。改行は Windows 規約の CRLF。
	f, err := os.CreateTemp("", "instantmesh-open-*.url")
	if err != nil {
		return err
	}
	name := f.Name()
	_, werr := f.WriteString("[InternetShortcut]\r\nURL=" + url + "\r\n")
	cerr := f.Close()
	if werr != nil {
		_ = os.Remove(name)
		return fmt.Errorf("ショートカット書き込み: %w", werr)
	}
	if cerr != nil {
		_ = os.Remove(name)
		return fmt.Errorf("ショートカットクローズ: %w", cerr)
	}
	if err := exec.Command("explorer.exe", name).Start(); err != nil {
		_ = os.Remove(name)
		return err
	}
	// explorer は非同期にファイルを読むため即削除できない。プロセスはサインイン待ち等で生存して
	// いるので、少し待ってから後始末する（招待リンク等の表示メタデータをディスクに残さない方針・
	// 設計原則3。認可 URL 自体は復号鍵ではないが、使い終われば消す）。
	go func() {
		time.Sleep(15 * time.Second)
		_ = os.Remove(name)
	}()
	return nil
}
