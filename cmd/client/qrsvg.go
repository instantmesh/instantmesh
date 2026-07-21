package main

// 本ファイルは QR モジュール行列を SVG 画像へ変換する I/O アダプタ（GUI の LocalAPI が配信）。
// 符号化（純粋ロジック）は pkg/qr が担い、ここではモジュール→ベクタ描画への写像のみを行う。
// 端末描画は qrterm.go（半角ブロック）、こちらはブラウザ表示用のスケーラブルな SVG を返す。

import (
	"fmt"
	"strings"

	"github.com/instantmesh/instantmesh/pkg/qr"
)

// qrSVG は QR モジュール行列を自己完結の SVG 文字列へ変換する。1 モジュール = viewBox の 1 単位
// とし、暗モジュールを 1 枚の path（各セルを M x y h1 v1 で塗る）で描く。周囲には規格推奨の
// クワイエットゾーン（qrQuietZone）を明で確保し、shape-rendering=crispEdges で境界を鮮明に保つ
// ことで、拡大表示・スキャンに耐える。色は明=白・暗=黒で固定し端末/ブラウザのテーマに依存しない。
func qrSVG(code *qr.Code) string {
	quiet := qrQuietZone
	dim := code.Size + 2*quiet
	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" viewBox="0 0 %d %d" shape-rendering="crispEdges" role="img" aria-label="招待リンクの QR コード">`,
		dim*8, dim*8, dim, dim)
	// 背景（クワイエットゾーン込みの全面）を白で塗る。
	b.WriteString(`<rect width="100%" height="100%" fill="#ffffff"/>`)
	// 暗モジュールを 1 枚の path にまとめて塗る（DOM ノード数を抑える）。
	b.WriteString(`<path fill="#000000" d="`)
	for y := 0; y < code.Size; y++ {
		for x := 0; x < code.Size; x++ {
			if code.Module(x, y) {
				fmt.Fprintf(&b, "M%d %dh1v1h-1z", x+quiet, y+quiet)
			}
		}
	}
	b.WriteString(`"/></svg>`)
	return b.String()
}
