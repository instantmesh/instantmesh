package clientip

import (
	"net/netip"
	"testing"
)

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	var ps []netip.Prefix
	for _, c := range cidrs {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", c, err)
		}
		ps = append(ps, p)
	}
	return ps
}

func TestClientIP(t *testing.T) {
	trusted := mustPrefixes(t, "10.0.0.0/8", "192.168.0.0/16")

	cases := []struct {
		name       string
		trusted    []netip.Prefix
		remoteAddr string
		xff        string
		want       string
	}{
		// 信頼プロキシ未設定: XFF を無視し直接接続元を返す（安全既定）。
		{"no trusted, port stripped", nil, "203.0.113.9:5555", "198.51.100.7", "203.0.113.9"},
		{"no trusted, no port", nil, "203.0.113.9", "", "203.0.113.9"},
		// 直接接続元が信頼外: XFF を信頼しない。
		{"peer untrusted ignores xff", trusted, "203.0.113.9:1", "198.51.100.7", "203.0.113.9"},
		// 信頼プロキシ経由: 右から非信頼＝実クライアントを採る。
		{"trusted peer single hop", trusted, "10.0.0.1:80", "198.51.100.7", "198.51.100.7"},
		{"trusted peer strips trusted hops", trusted, "10.0.0.1:80", "198.51.100.7, 10.0.0.9, 192.168.1.1", "198.51.100.7"},
		// 全ホップが信頼プロキシ: 最左を採る。
		{"all hops trusted", trusted, "10.0.0.1:80", "10.0.0.2, 192.168.0.3", "10.0.0.2"},
		// 信頼プロキシだが XFF なし: 直接接続元を返す。
		{"trusted peer empty xff", trusted, "10.0.0.1:80", "", "10.0.0.1"},
		// 空要素・空白を含む XFF はトリム/除去される。
		{"xff with empty elements", trusted, "10.0.0.1:80", " , 198.51.100.7 , ", "198.51.100.7"},
		// パース不能なホップは非信頼扱い（実クライアント候補としてそのまま返す）。
		{"unparseable hop treated untrusted", trusted, "10.0.0.1:80", "not-an-ip", "not-an-ip"},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := NewResolver(c.trusted)
			if got := r.ClientIP(c.remoteAddr, c.xff); got != c.want {
				t.Errorf("ClientIP(%q, %q) = %q, want %q", c.remoteAddr, c.xff, got, c.want)
			}
		})
	}
}
