package main

import (
	"net"
	"net/netip"
	"testing"
)

func TestIPNetToIPv4Prefix(t *testing.T) {
	tests := []struct {
		name string
		in   *net.IPNet
		want string // "" は ok=false を期待
	}{
		{
			name: "IPv4 4バイトマスク",
			in:   &net.IPNet{IP: net.IPv4(10, 0, 0, 5).To4(), Mask: net.CIDRMask(24, 32)},
			want: "10.0.0.0/24",
		},
		{
			name: "IPv4 16バイトマスク（IPv4-in-IPv6）",
			in:   &net.IPNet{IP: net.IPv4(192, 168, 1, 20), Mask: net.CIDRMask(96+24, 128)},
			want: "192.168.1.0/24",
		},
		{
			name: "ホストアドレス付き /16 もネットワークへ正規化",
			in:   &net.IPNet{IP: net.IPv4(172, 16, 5, 9).To4(), Mask: net.CIDRMask(16, 32)},
			want: "172.16.0.0/16",
		},
		{
			name: "IPv6 は対象外",
			in:   &net.IPNet{IP: net.ParseIP("fd00::1"), Mask: net.CIDRMask(64, 128)},
			want: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := ipNetToIPv4Prefix(tt.in)
			if tt.want == "" {
				if ok {
					t.Errorf("ok=true, got %v; want ok=false", got)
				}
				return
			}
			if !ok {
				t.Fatalf("ok=false; want %s", tt.want)
			}
			if got != netip.MustParsePrefix(tt.want) {
				t.Errorf("got %v; want %s", got, tt.want)
			}
		})
	}
}

// localOnlinkPrefixes は自インターフェースとループバックを除外して列挙する。実機の
// インターフェース構成には依存できないため、除外指定した名前が結果に現れないことと、
// ループバック(127.0.0.0/8)が含まれないことのみを検証する。
func TestLocalOnlinkPrefixesExcludesLoopback(t *testing.T) {
	prefixes, err := localOnlinkPrefixes("")
	if err != nil {
		t.Fatalf("localOnlinkPrefixes: %v", err)
	}
	loopback := netip.MustParsePrefix("127.0.0.0/8")
	for _, p := range prefixes {
		if p.Overlaps(loopback) {
			t.Errorf("ループバックは除外すべき: %v", p)
		}
		if !p.Addr().Is4() {
			t.Errorf("IPv4 のみ列挙すべき: %v", p)
		}
	}
}
