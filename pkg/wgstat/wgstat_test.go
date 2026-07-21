package wgstat

import (
	"errors"
	"testing"
	"time"
)

// sampleUAPI は wireguard-go device.IpcGet() が返す典型的な出力（デバイス行＋2 ピア）。
// ピア A はハンドシェイク成立済み、ピア B は未成立（sec/nsec ともに 0）。
const sampleUAPI = "private_key=0000000000000000000000000000000000000000000000000000000000000001\n" +
	"listen_port=51820\n" +
	"fwmark=0\n" +
	"public_key=AAAA000000000000000000000000000000000000000000000000000000000001\n" +
	"protocol_version=1\n" +
	"endpoint=203.0.113.7:41641\n" +
	"last_handshake_time_sec=1600000000\n" +
	"last_handshake_time_nsec=250000000\n" +
	"tx_bytes=2048\n" +
	"rx_bytes=4096\n" +
	"persistent_keepalive_interval=25\n" +
	"allowed_ip=10.0.0.2/32\n" +
	"public_key=bbbb000000000000000000000000000000000000000000000000000000000002\n" +
	"protocol_version=1\n" +
	"endpoint=198.51.100.9:51820\n" +
	"last_handshake_time_sec=0\n" +
	"last_handshake_time_nsec=0\n" +
	"allowed_ip=10.0.0.3/32\n"

func TestParse(t *testing.T) {
	peers, err := Parse(sampleUAPI)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("ピア数 = %d want 2", len(peers))
	}

	// public_key は小文字化される（キー・PublicKeyHex 双方）。
	a, ok := peers["aaaa000000000000000000000000000000000000000000000000000000000001"]
	if !ok {
		t.Fatal("ピア A が見つからない（小文字化されているべき）")
	}
	if a.PublicKeyHex != "aaaa000000000000000000000000000000000000000000000000000000000001" {
		t.Errorf("PublicKeyHex = %q", a.PublicKeyHex)
	}
	if a.Endpoint != "203.0.113.7:41641" {
		t.Errorf("Endpoint = %q", a.Endpoint)
	}
	if want := time.Unix(1600000000, 250000000); !a.LastHandshake.Equal(want) {
		t.Errorf("LastHandshake = %v want %v", a.LastHandshake, want)
	}

	// ピア B はハンドシェイク未成立 → zero value。
	b := peers["bbbb000000000000000000000000000000000000000000000000000000000002"]
	if !b.LastHandshake.IsZero() {
		t.Errorf("未成立ピアの LastHandshake は zero であるべき: %v", b.LastHandshake)
	}
	if b.Endpoint != "198.51.100.9:51820" {
		t.Errorf("B.Endpoint = %q", b.Endpoint)
	}
}

func TestParseEmpty(t *testing.T) {
	peers, err := Parse("")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("空入力はピア 0 件であるべき: %d", len(peers))
	}
}

func TestParseNsecOnly(t *testing.T) {
	// sec=0 でも nsec が非 0 ならハンドシェイク時刻を設定する（両方 0 のときのみ zero）。
	peers, err := Parse("public_key=aa\nlast_handshake_time_nsec=500\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if peers["aa"].LastHandshake.IsZero() {
		t.Error("nsec 単独でも LastHandshake は設定されるべき")
	}
}

func TestParseMalformedLine(t *testing.T) {
	if _, err := Parse("public_key=aa\nnoequalsign\n"); !errors.Is(err, ErrMalformed) {
		t.Errorf("'=' を含まない行は ErrMalformed, got %v", err)
	}
}

func TestParseBadNumbers(t *testing.T) {
	if _, err := Parse("public_key=aa\nlast_handshake_time_sec=notint\n"); err == nil {
		t.Error("sec の数値解析失敗はエラーになるべき")
	}
	if _, err := Parse("public_key=aa\nlast_handshake_time_nsec=notint\n"); err == nil {
		t.Error("nsec の数値解析失敗はエラーになるべき")
	}
}

func TestParseIgnoresPeerFieldsBeforePublicKey(t *testing.T) {
	// public_key 以前に現れるピア相当フィールドは無視される（cur 未開始）。
	peers, err := Parse("endpoint=1.2.3.4:5\nlast_handshake_time_sec=1\nlast_handshake_time_nsec=1\nprivate_key=00\n")
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(peers) != 0 {
		t.Errorf("public_key 前の行はピアを生まないべき: %d", len(peers))
	}
}

func TestLastHandshake(t *testing.T) {
	// 成立済みピア（大文字指定でも小文字照合でヒット）。
	ts, ok := LastHandshake(sampleUAPI, "AAAA000000000000000000000000000000000000000000000000000000000001")
	if !ok {
		t.Fatal("成立済みピアは ok=true であるべき")
	}
	if want := time.Unix(1600000000, 250000000); !ts.Equal(want) {
		t.Errorf("LastHandshake = %v want %v", ts, want)
	}

	// 未成立ピアは ok=false。
	if _, ok := LastHandshake(sampleUAPI, "bbbb000000000000000000000000000000000000000000000000000000000002"); ok {
		t.Error("未成立ピアは ok=false であるべき")
	}

	// 不在ピアは ok=false。
	if _, ok := LastHandshake(sampleUAPI, "cccc"); ok {
		t.Error("不在ピアは ok=false であるべき")
	}

	// 解析エラー時も ok=false。
	if _, ok := LastHandshake("public_key=aa\nbroken", "aa"); ok {
		t.Error("解析エラー時は ok=false であるべき")
	}
}
