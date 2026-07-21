package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/qr"
)

func TestCellFor(t *testing.T) {
	cases := []struct {
		top, bottom bool
		want        string
	}{
		{false, false, "\x1b[37;47m▀"}, // 明/明
		{true, false, "\x1b[30;47m▀"},  // 暗/明
		{false, true, "\x1b[37;40m▀"},  // 明/暗
		{true, true, "\x1b[30;40m▀"},   // 暗/暗
	}
	for _, c := range cases {
		if got := cellFor(c.top, c.bottom); got != c.want {
			t.Errorf("cellFor(%v,%v)=%q, want %q", c.top, c.bottom, got, c.want)
		}
	}
}

func TestQRDarkQuietZone(t *testing.T) {
	code, err := qr.Encode([]byte("x"), qr.Low)
	if err != nil {
		t.Fatal(err)
	}
	if qrDark(code, 0, 0) {
		t.Error("クワイエットゾーン (0,0) は明であるべき")
	}
	if !qrDark(code, qrQuietZone, qrQuietZone) {
		t.Error("ファインダ左上角は暗であるべき")
	}
}

func TestRenderQR(t *testing.T) {
	code, err := qr.Encode([]byte("instantmesh://join?x=1"), qr.Medium)
	if err != nil {
		t.Fatal(err)
	}
	out := renderQR(code)
	dim := code.Size + 2*qrQuietZone
	if lines := strings.Count(out, "\n"); lines != (dim+1)/2 {
		t.Errorf("行数=%d, want %d", lines, (dim+1)/2)
	}
	if !strings.Contains(out, "\x1b[0m") {
		t.Error("行末のリセットシーケンスがない")
	}
}

func TestPrintInviteQR(t *testing.T) {
	var buf bytes.Buffer
	printInviteQR(&buf, "instantmesh://join?server=ws://h/ws&token=abc&host=key")
	if buf.Len() == 0 {
		t.Error("QR 出力が空")
	}
	// 対応バージョンに収まらない過大リンクは QR を省略し、出力しない。
	buf.Reset()
	printInviteQR(&buf, "instantmesh://join?x="+strings.Repeat("A", 400))
	if buf.Len() != 0 {
		t.Errorf("過大リンクでは QR 省略のはずが %d バイト出力", buf.Len())
	}
}
