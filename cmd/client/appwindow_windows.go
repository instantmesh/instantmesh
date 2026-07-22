//go:build windows

package main

// 本ファイルは GUI（LocalAPI）を外部ブラウザではなく「アプリ内ウィンドウ」で表示するための
// Windows 実装（PoC）。OS 内蔵の WebView2（Edge・Win10/11 標準搭載）を jchv/go-webview2 で
// 埋め込む。go-webview2 は cgo-free（WebView2Loader を go-winloader でメモリ内ロード）のため、
// 既存の CGO_ENABLED=0 クロスビルド構成を崩さない。
//
// 表示するのは既存の LocalAPI（http://127.0.0.1:<port>）そのもの。SPA・originguard・秘密の
// 非露出といったセキュリティ設計は一切変わらない（外殻がブラウザタブからアプリウィンドウに
// 変わるだけ）。WebView2 からの fetch は Origin がこの LocalAPI と同一になるため originguard を
// 素通りする。
//
// wintun_windows.go と同じ build tag 分離パターンに従い、非 Windows は appwindow_other.go の
// スタブが担う（appWindowAvailable=false のため runGUI からは呼ばれない）。

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"runtime"

	webview2 "github.com/jchv/go-webview2"
)

// アプリ内ウィンドウの既定サイズ・タイトル。SPA は縦長のルーム操作 UI のため縦長ウィンドウにする。
const (
	appWindowTitle  = "InstantMesh"
	appWindowWidth  = 480
	appWindowHeight = 760
)

// appWindowAvailable はこのビルドでアプリ内ウィンドウ表示が可能かを表す（Windows のみ true）。
// runGUI はこれを見てウィンドウ優先フローか従来のブラウザ起動かを分岐する。
const appWindowAvailable = true

// errAppWindowUnavailable は WebView2 ランタイム未導入等でウィンドウを生成できなかったことを表す。
// runGUI はこれを受けて既定ブラウザへフォールバックする。
var errAppWindowUnavailable = errors.New("アプリ内ウィンドウを生成できません（WebView2 ランタイム未導入の可能性）")

// openAppWindow は url（GUI の LocalAPI）を OS 内蔵 WebView2 のウィンドウで開き、ウィンドウが
// 閉じられるまでブロックする。ctx が終了したらウィンドウを閉じて戻る（グレースフルシャットダウン）。
//
// WebView2 のウィンドウ生成（NewWithOptions）とメッセージループ（Run）は同一 OS スレッドで
// 動かす必要がある（NewWithOptions が現在スレッド ID を保持し、Run の GetMessage がそのスレッドの
// メッセージキューを回すため）。そのため呼び出しゴルーチンを起動スレッドへ固定する。runGUI は
// これをメインゴルーチンから同期的に呼ぶ。
func openAppWindow(ctx context.Context, url string) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	// WebView2 のユーザーデータ（キャッシュ/履歴等）を、終了時に消える専用の一時ディレクトリへ隔離する。
	// 既定パスはユーザープロファイル配下に永続するため、招待リンク等の表示メタデータが残りうる。
	// InstantMesh のエフェメラル思想（使い終われば消える／秘密をディスクに残さない・設計原則3）に
	// 沿わせるため専用一時領域を使い、ウィンドウ破棄後に削除する。作成に失敗しても既定パスで続行する
	// （ベストエフォート）。昇格起動（-tunnel 既定 true）でも一時領域なのでプロファイルを汚さない。
	dataPath := ""
	if tmp, err := os.MkdirTemp("", "instantmesh-webview-"); err != nil {
		slog.Warn("WebView 用一時データディレクトリの作成に失敗、既定パスで続行します", "err", err)
	} else {
		dataPath = tmp
		// defer は LIFO のため、下の w.Destroy() の後にこの削除が走る（ウィンドウ破棄後にフォルダ削除）。
		defer func() {
			if err := os.RemoveAll(tmp); err != nil {
				slog.Warn("WebView 用一時データディレクトリの削除に失敗", "path", tmp, "err", err)
			}
		}()
	}

	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:    false,
		DataPath: dataPath,
		WindowOptions: webview2.WindowOptions{
			Title:  appWindowTitle,
			Width:  appWindowWidth,
			Height: appWindowHeight,
			Center: true,
		},
	})
	if w == nil {
		return errAppWindowUnavailable
	}
	defer w.Destroy()

	// ctx 終了（シグナル/グレースフルシャットダウン）でウィンドウを閉じる。
	//
	// 注意: go-webview2 の Terminate は PostQuitMessage を「呼び出しスレッド」のメッセージキューへ
	// 積むだけで、別スレッドから呼んでも Run のメッセージループ（メインスレッド）は終了しない。
	// そのため必ず Dispatch でメインスレッドへ関数を渡し、そこで Terminate を実行させる
	// （Dispatch は PostThreadMessageW でメインスレッドのキューへ WM_APP を送り、Run 内で実行される）。
	//
	// ウィンドウを手で閉じた場合は Run が先に戻り、defer close(done) でこの監視ゴルーチンを即解放して
	// リークを防ぐ（設計原則5: goroutine はチャネル/ctx でキャンセルライフサイクルを持たせる）。
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			w.Dispatch(w.Terminate)
		case <-done:
		}
	}()

	w.Navigate(url)
	w.Run() // ウィンドウが閉じられる（または Terminate）まで戻らない
	return nil
}
