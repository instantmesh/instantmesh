package wgconf

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

// key は指定バイトを 32 個並べた base64 鍵を返す（hex は "<bb>"×32）。
func key(b byte) string { return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32)) }

func TestUAPIFull(t *testing.T) {
	cfg := Config{
		PrivateKey:   key(0x01),
		ListenPort:   51820,
		ReplacePeers: true,
		Peers: []Peer{{
			PublicKey:              key(0x02),
			Endpoint:               "198.51.100.1:51820",
			AllowedIPs:             []string{"10.0.0.1/32", "10.0.0.0/24"},
			PersistentKeepaliveSec: 25,
		}},
	}
	out, err := cfg.UAPI()
	if err != nil {
		t.Fatalf("UAPI エラー: %v", err)
	}
	want := []string{
		"private_key=" + strings.Repeat("01", 32),
		"listen_port=51820",
		"replace_peers=true",
		"public_key=" + strings.Repeat("02", 32),
		"endpoint=198.51.100.1:51820",
		"persistent_keepalive_interval=25",
		"replace_allowed_ips=true",
		"allowed_ip=10.0.0.1/32",
		"allowed_ip=10.0.0.0/24",
	}
	for _, l := range want {
		if !strings.Contains(out, l+"\n") {
			t.Errorf("UAPI に %q 行が無い:\n%s", l, out)
		}
	}
}

func TestUAPIPrivateKeyRaw(t *testing.T) {
	// 生バイトの秘密鍵は base64 を経由せず直接 hex 化される。
	raw := bytes.Repeat([]byte{0x05}, 32)
	out, err := Config{PrivateKeyRaw: raw}.UAPI()
	if err != nil {
		t.Fatalf("UAPI エラー: %v", err)
	}
	if !strings.Contains(out, "private_key="+strings.Repeat("05", 32)+"\n") {
		t.Errorf("生バイト秘密鍵の hex 行が無い:\n%s", out)
	}
}

func TestUAPIPrivateKeyRawTakesPrecedence(t *testing.T) {
	// PrivateKeyRaw が非空なら PrivateKey より優先される。
	raw := bytes.Repeat([]byte{0x06}, 32)
	out, err := Config{PrivateKey: key(0x01), PrivateKeyRaw: raw}.UAPI()
	if err != nil {
		t.Fatalf("UAPI エラー: %v", err)
	}
	if !strings.Contains(out, "private_key="+strings.Repeat("06", 32)+"\n") {
		t.Errorf("PrivateKeyRaw が優先されるべき:\n%s", out)
	}
	if strings.Contains(out, strings.Repeat("01", 32)) {
		t.Error("PrivateKeyRaw 指定時は PrivateKey を使わない")
	}
}

func TestUAPIPrivateKeyRawWrongLength(t *testing.T) {
	if _, err := (Config{PrivateKeyRaw: []byte{1, 2, 3}}).UAPI(); err == nil {
		t.Error("32 バイトでない生秘密鍵はエラーになるべき")
	}
}

func TestUAPIPeerOnly(t *testing.T) {
	// 秘密鍵・ポート未指定＝デバイス設定は変えずにピア追加のみ。
	cfg := Config{Peers: []Peer{{PublicKey: key(0x03)}}}
	out, err := cfg.UAPI()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "private_key=") {
		t.Error("秘密鍵未指定なら private_key 行を出さない")
	}
	if strings.Contains(out, "listen_port=") {
		t.Error("ポート 0 なら listen_port 行を出さない")
	}
	if strings.Contains(out, "replace_peers=") {
		t.Error("ReplacePeers=false なら replace_peers 行を出さない")
	}
	if !strings.Contains(out, "public_key="+strings.Repeat("03", 32)+"\n") {
		t.Error("ピア公開鍵行が必要")
	}
	if strings.Contains(out, "endpoint=") || strings.Contains(out, "allowed_ip=") || strings.Contains(out, "persistent_keepalive") {
		t.Errorf("未指定の任意項目は出さない:\n%s", out)
	}
}

func TestUAPIPeerRemove(t *testing.T) {
	cfg := Config{Peers: []Peer{{PublicKey: key(0x04), Remove: true, Endpoint: "1.2.3.4:5"}}}
	out, err := cfg.UAPI()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "remove=true\n") {
		t.Error("remove=true 行が必要")
	}
	if strings.Contains(out, "endpoint=") {
		t.Error("削除時は他属性を出さない")
	}
}

func TestUAPIErrors(t *testing.T) {
	badB64 := "not base64!!!"
	shortKey := base64.StdEncoding.EncodeToString([]byte{1, 2, 3}) // 32 バイト未満
	cases := []struct {
		name string
		cfg  Config
	}{
		{"bad private base64", Config{PrivateKey: badB64}},
		{"short private key", Config{PrivateKey: shortKey}},
		{"bad peer public key", Config{Peers: []Peer{{PublicKey: badB64}}}},
		{"bad endpoint", Config{Peers: []Peer{{PublicKey: key(1), Endpoint: "not-an-endpoint"}}}},
		{"bad allowed ip", Config{Peers: []Peer{{PublicKey: key(1), AllowedIPs: []string{"not-a-cidr"}}}}},
	}
	for _, tt := range cases {
		if _, err := tt.cfg.UAPI(); err == nil {
			t.Errorf("%s: エラーになるべき", tt.name)
		}
	}
}
