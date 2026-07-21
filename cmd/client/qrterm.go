package main

// 本ファイルは招待リンクを端末上に QR コードとして描画する I/O アダプタ。
// QR の符号化（純粋ロジック）は pkg/qr が担い、ここではモジュール行列を端末文字へ変換する。

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/instantmesh/instantmesh/pkg/qr"
)

// qrQuietZone は QR コード周囲に設ける明モジュールの余白（クワイエットゾーン）。
// スキャナが境界を認識できるよう規格推奨の 4 モジュールを確保する。
const qrQuietZone = 4

// printInviteQR は招待リンクを QR コードとして w へ描画する。まず EC レベル Medium で
// 符号化し、リンクが長く対応バージョン（1〜10）に収まらない場合は容量の大きい Low で再試行する。
// それでも収まらない、または符号化に失敗した場合は QR を省略する（リンク文字列表示で代替）。
func printInviteQR(w io.Writer, link string) {
	code, err := qr.Encode([]byte(link), qr.Medium)
	if errors.Is(err, qr.ErrTooLong) {
		code, err = qr.Encode([]byte(link), qr.Low)
	}
	if err != nil {
		slog.Warn("QR コード生成を省略（リンク文字列で共有してください）", "err", err)
		return
	}
	fmt.Fprint(w, renderQR(code))
}

// renderQR は QR モジュール行列を端末向け文字列へ変換する（末尾改行付き）。
// 半角ブロック '▀' で縦 2 モジュールを 1 文字に圧縮し、上半分＝前景色・下半分＝背景色として
// 暗を黒・明を白で明示するため、端末の配色テーマに依存せず正しい明暗でスキャンできる。
func renderQR(code *qr.Code) string {
	dim := code.Size + 2*qrQuietZone
	var b strings.Builder
	for y := 0; y < dim; y += 2 {
		for x := 0; x < dim; x++ {
			// y+1 が範囲外（最終行）のときは下半分をクワイエットゾーン扱い（明）にする。
			b.WriteString(cellFor(qrDark(code, x, y), qrDark(code, x, y+1)))
		}
		b.WriteString("\x1b[0m\n") // 行末で属性リセット
	}
	return b.String()
}

// qrDark は QR 全体（クワイエットゾーン込み）座標 (x, y) が暗モジュールかを返す。
// クワイエットゾーンおよび範囲外は明（false）。
func qrDark(code *qr.Code, x, y int) bool {
	x -= qrQuietZone
	y -= qrQuietZone
	if x < 0 || y < 0 || x >= code.Size || y >= code.Size {
		return false
	}
	return code.Module(x, y)
}

// cellFor は上下 2 モジュールを 1 文字（▀）で表す ANSI シーケンスを返す。
// 前景色 = 上モジュール、背景色 = 下モジュール（暗=黒 30/40、明=白 37/47）。
func cellFor(top, bottom bool) string {
	fg := 37
	if top {
		fg = 30
	}
	bg := 47
	if bottom {
		bg = 40
	}
	return fmt.Sprintf("\x1b[%d;%dm▀", fg, bg)
}
