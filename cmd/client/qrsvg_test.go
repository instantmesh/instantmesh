package main

import (
	"strings"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/qr"
)

func TestQRSVG(t *testing.T) {
	code, err := qr.Encode([]byte("instantmesh://join?server=ws%3A%2F%2Fx%2Fws&token=t&host=h"), qr.Medium)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	svg := qrSVG(code)

	for _, want := range []string{"<svg", "viewBox=", `fill="#000000"`, `fill="#ffffff"`, "<path", "</svg>"} {
		if !strings.Contains(svg, want) {
			t.Errorf("SVG に %q が含まれない", want)
		}
	}
	// 少なくとも 1 つの暗モジュール（path セグメント）が描かれる。
	if !strings.Contains(svg, "h1v1h-1z") {
		t.Error("暗モジュールの path セグメントが描かれていない")
	}
}
