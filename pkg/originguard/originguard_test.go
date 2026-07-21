package originguard

import "testing"

func TestAllow(t *testing.T) {
	const host = "127.0.0.1:8088"
	tests := []struct {
		name         string
		host         string
		origin       string
		secFetchSite string
		want         bool
	}{
		// --- Host（DNS リバインディング）ゲート ---
		{"非ループバック Host は拒否", "evil.com:8088", "http://evil.com:8088", "same-origin", false},
		{"リバインド攻撃者ドメインは拒否", "attacker.example:8088", "", "", false},
		{"Host 空は拒否", "", "", "", false},
		{"localhost（ポート付き）は許可", "localhost:8088", "", "same-origin", true},
		{"localhost（ポート無し）は許可", "localhost", "", "same-origin", true},
		{"127.0.0.1 は許可", "127.0.0.1:8088", "", "same-origin", true},
		{"127.0.0.2（/8 内）は許可", "127.0.0.2:8088", "", "same-origin", true},
		{"IPv6 ループバックは許可", "[::1]:8088", "", "same-origin", true},
		{"IPv6 ループバック（ポート無し）は許可", "::1", "", "same-origin", true},
		{"非ループバック IP は拒否", "10.0.0.5:8088", "", "same-origin", false},

		// --- Sec-Fetch-Site 判定（Host はループバック固定） ---
		{"same-origin は許可", host, "http://127.0.0.1:8088", "same-origin", true},
		{"none は許可", host, "", "none", true},
		{"cross-site は拒否", host, "http://evil.com", "cross-site", false},
		{"same-site は拒否", host, "http://127.0.0.1:9999", "same-site", false},
		{"未知の Sec-Fetch-Site は拒否", host, "", "bogus", false},

		// --- Origin フォールバック（Sec-Fetch-Site 無し） ---
		{"Sec-Fetch/Origin ともに無し（非ブラウザ）は許可", host, "", "", true},
		{"Origin が Host と一致すれば許可", host, "http://127.0.0.1:8088", "", true},
		{"Origin が Host と不一致なら拒否", host, "http://127.0.0.1:9999", "", false},
		{"別オリジン（localhost 別名）でも authority 不一致は拒否", host, "http://localhost:8088", "", false},
		{"パース不能な Origin は拒否", host, "://bad", "", false},
		{"Origin: null は拒否", host, "null", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Allow(tc.host, tc.origin, tc.secFetchSite); got != tc.want {
				t.Errorf("Allow(%q, %q, %q) = %v, want %v",
					tc.host, tc.origin, tc.secFetchSite, got, tc.want)
			}
		})
	}
}
