//go:build !windows && !linux

package main

// Windows(WebView2)・Linux(Chromium --app) 以外の OS 向けアプリ内ウィンドウ・スタブ（現状は
// macOS 等が該当）。appWindowAvailable が false のため runGUI は従来どおり既定ブラウザで GUI を
// 開く経路を通り、openAppWindow は呼ばれない。ビルド（およびクロスビルド）を通すためだけに定義を
// 置く。macOS(WKWebView) 対応を追加する際は appwindow_darwin.go に実装を分離して差し替える。

import (
	"context"
	"errors"
)

// appWindowAvailable は非 Windows では false（アプリ内ウィンドウ非対応）。
const appWindowAvailable = false

// openAppWindow は非対応 OS では常に失敗を返す（appWindowAvailable=false のため実際には呼ばれない）。
func openAppWindow(_ context.Context, _ string) error {
	return errors.New("アプリ内ウィンドウはこの OS では未対応です")
}
