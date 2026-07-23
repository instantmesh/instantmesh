//go:build linux

package main

// 本ファイルは GUI（LocalAPI）を外部ブラウザのタブではなく「アプリ内ウィンドウ」で表示するための
// Linux 実装。Linux には cgo-free で使える埋め込み WebView が無い（WebKitGTK バインディングは
// いずれも CGO＋システム開発ライブラリ必須で、本プロジェクトの CGO_ENABLED=0 クロスビルド構成と
// 衝突する）。そこで Chromium 系ブラウザ（chromium/chrome/edge 等）を `--app=<URL>` のアプリケー
// ションモードで起動し、アドレスバーやタブのないクロームレスなウィンドウを開く。これにより CGO
// 非依存のまま Windows(WebView2) に近いアプリ体験を得る（appwindow_windows.go と対をなす）。
//
// 表示するのは既存の LocalAPI（http://127.0.0.1:<port>）そのもので、SPA・originguard・秘密の
// 非露出といったセキュリティ設計は一切変わらない（外殻がブラウザタブからアプリウィンドウに
// 変わるだけ）。専用の一時 user-data-dir を与えることで、(1) 既存ブラウザインスタンスへタブとして
// 吸収されず独立プロセスとしてウィンドウのライフサイクルを持たせ、(2) 履歴・キャッシュ等を
// プロファイルに残さずエフェメラルに保つ（設計原則3: 使い終われば消える）。
//
// Chromium 系が見つからない/起動に失敗した場合は openAppWindow が errAppWindowUnavailable を
// 返し、runGUI が従来どおり既定ブラウザ（xdg-open）へフォールバックする。

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"os/exec"
	"strconv"
)

// アプリ内ウィンドウの既定サイズ。SPA は縦長のルーム操作 UI のため縦長にする（Windows と同値）。
const (
	appWindowWidth  = 480
	appWindowHeight = 760
)

// appWindowAvailable は Linux では true（Chromium 系ブラウザがあればアプリ内ウィンドウを開ける）。
// 実際に開けるか（ブラウザの有無）は実行時に openAppWindow が判定し、不可なら errAppWindowUnavailable
// を返して runGUI が既定ブラウザへフォールバックする（Windows の WebView2 未導入時と同じ挙動）。
const appWindowAvailable = true

// errAppWindowUnavailable は Chromium 系ブラウザ未検出や起動失敗でアプリ内ウィンドウを開けなかった
// ことを表す。runGUI はこれを受けて既定ブラウザへフォールバックする。
var errAppWindowUnavailable = errors.New("アプリ内ウィンドウを起動できません（Chromium 系ブラウザ未検出）")

// linuxAppBrowserCandidates は --app モードで起動を試みる Chromium 系ブラウザの実行ファイル名
// （PATH 探索順）。いずれも Chromium 由来で --app/--user-data-dir を解釈する。
var linuxAppBrowserCandidates = []string{
	"google-chrome-stable", "google-chrome",
	"chromium", "chromium-browser",
	"microsoft-edge-stable", "microsoft-edge",
	"brave-browser",
}

// findChromeBrowser は候補のうち PATH 上で最初に見つかった Chromium 系ブラウザの絶対パスを返す。
// 見つからなければ空文字。look は exec.LookPath を注入するテストシーム（純粋にテストできる）。
func findChromeBrowser(look func(string) (string, error)) string {
	for _, name := range linuxAppBrowserCandidates {
		if p, err := look(name); err == nil {
			return p
		}
	}
	return ""
}

// chromeAppArgs は Chromium 系を「アプリケーションモード」で開くための引数を組み立てる（純粋関数）。
// --app でクロームレスなウィンドウ、--user-data-dir で独立・エフェメラルなプロファイル、
// --no-first-run/--no-default-browser-check で初回ウィザードや既定ブラウザ確認を抑止する。
func chromeAppArgs(url, dataDir string) []string {
	return []string{
		"--app=" + url,
		"--user-data-dir=" + dataDir,
		"--window-size=" + strconv.Itoa(appWindowWidth) + "," + strconv.Itoa(appWindowHeight),
		"--no-first-run",
		"--no-default-browser-check",
	}
}

// openAppWindow は url（GUI の LocalAPI）を Chromium 系のアプリケーションモードで開き、ウィンドウが
// 閉じられるまでブロックする。ctx が終了したらブラウザプロセスを終了して戻る（グレースフル
// シャットダウン）。ブラウザ未検出/一時プロファイル作成失敗/起動失敗の場合は errAppWindowUnavailable
// を返し、runGUI が既定ブラウザへフォールバックする。
//
// 注意: 専用 user-data-dir により通常は独立プロセスとなりウィンドウ生存中は Wait がブロックするが、
// snap/flatpak 等のラッパー経由だと起動直後に戻る（＝即シャットダウンに見える）ことがある。その
// 環境では -gui-addr を既定ブラウザで手動起動する運用に切り替えられる（PoC の既知の制約）。
func openAppWindow(ctx context.Context, url string) error {
	bin := findChromeBrowser(exec.LookPath)
	if bin == "" {
		return errAppWindowUnavailable
	}

	// 専用の一時 user-data-dir を用意する。独立インスタンス化（既存ブラウザへタブ吸収されない）と
	// エフェメラル化（招待リンク等の表示メタデータをプロファイルに残さない）の両方を担う。作成に
	// 失敗したら独立プロセスを保証できないため、既定ブラウザへフォールバックする。
	dataDir, err := os.MkdirTemp("", "instantmesh-appwindow-")
	if err != nil {
		slog.Warn("アプリ内ウィンドウ用の一時プロファイル作成に失敗、既定ブラウザにフォールバックします", "err", err)
		return errAppWindowUnavailable
	}
	defer func() {
		if err := os.RemoveAll(dataDir); err != nil {
			slog.Warn("アプリ内ウィンドウ用の一時プロファイル削除に失敗", "path", dataDir, "err", err)
		}
	}()

	cmd := exec.Command(bin, chromeAppArgs(url, dataDir)...)
	if err := cmd.Start(); err != nil {
		slog.Warn("アプリ内ウィンドウの起動に失敗、既定ブラウザにフォールバックします", "bin", bin, "err", err)
		return errAppWindowUnavailable
	}

	// ctx 終了（シグナル/グレースフルシャットダウン）でブラウザプロセスを終了させ、下の Wait を返す。
	// ウィンドウを手で閉じた場合は Wait が先に戻り、defer close(done) でこの監視ゴルーチンを即解放
	// してリークを防ぐ（設計原則5: goroutine はチャネル/ctx でキャンセルライフサイクルを持たせる）。
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = cmd.Process.Kill()
		case <-done:
		}
	}()

	// ウィンドウが閉じられる（または Kill）までブロックする。専用 user-data-dir により独立プロセス
	// となるため、Wait はウィンドウの生存期間を反映する。
	_ = cmd.Wait()
	return nil
}
