//go:build !windows

package main

// 非 Windows 向けのアプリ内ウィンドウ・スタブ（PoC は Windows のみ対応）。appWindowAvailable が
// false のため runGUI は従来どおり既定ブラウザで GUI を開く経路を通り、openAppWindow は呼ばれない。
// ビルド（およびクロスビルド）を通すためだけに定義を置く。macOS(WKWebView)/Linux(WebKitGTK)
// 対応を追加する際は、本ファイルを OS 別に分割して実装へ差し替える。

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
