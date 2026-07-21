package relayframe

import (
	"bytes"
	"strings"
	"testing"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	pubKey := "pubKeyABC"
	payload := []byte("payload-bytes")
	frame, err := Encode(pubKey, payload)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	gotKey, gotPayload, err := Decode(frame)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if gotKey != pubKey {
		t.Errorf("pubKey = %q want %q", gotKey, pubKey)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Errorf("payload = %q want %q", gotPayload, payload)
	}
}

func TestEncodeDecodeEmptyPayload(t *testing.T) {
	frame, err := Encode("k", nil)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}
	gotKey, gotPayload, err := Decode(frame)
	if err != nil || gotKey != "k" || len(gotPayload) != 0 {
		t.Fatalf("空ペイロード round-trip 不正: key=%q payload=%v err=%v", gotKey, gotPayload, err)
	}
}

func TestEncodeKeyTooLong(t *testing.T) {
	long := strings.Repeat("a", MaxKeyLen+1)
	if _, err := Encode(long, nil); err != ErrKeyTooLong {
		t.Errorf("超過鍵は ErrKeyTooLong, got %v", err)
	}
	// 上限ちょうどは符号化できる。
	if _, err := Encode(strings.Repeat("a", MaxKeyLen), nil); err != nil {
		t.Errorf("上限長の鍵は符号化できるべき: %v", err)
	}
}

func TestDecodeShort(t *testing.T) {
	// 2 バイト未満（長さフィールド欠落）。
	if _, _, err := Decode([]byte{0x00}); err != ErrShort {
		t.Errorf("短すぎるフレームは ErrShort, got %v", err)
	}
	// 公開鍵長がデータ長を超える（切り詰め）。
	if _, _, err := Decode([]byte{0x00, 0x05, 'a', 'b'}); err != ErrShort {
		t.Errorf("切り詰めフレームは ErrShort, got %v", err)
	}
}
