package wgkey

import (
	"encoding/base64"
	"errors"
	"io"
	"testing"
)

func TestGenerate(t *testing.T) {
	kp, err := Generate()
	if err != nil {
		t.Fatalf("Generate エラー: %v", err)
	}

	// 秘密鍵・公開鍵はいずれも 32 バイトの base64。
	priv, err := base64.StdEncoding.DecodeString(kp.Private)
	if err != nil || len(priv) != 32 {
		t.Fatalf("秘密鍵が 32 バイトの base64 でない: len=%d err=%v", len(priv), err)
	}
	pub, err := base64.StdEncoding.DecodeString(kp.Public)
	if err != nil || len(pub) != 32 {
		t.Fatalf("公開鍵が 32 バイトの base64 でない: len=%d err=%v", len(pub), err)
	}

	// 公開鍵は秘密鍵から決定的に導出できる。
	derived, err := PublicFromPrivate(kp.Private)
	if err != nil {
		t.Fatalf("PublicFromPrivate エラー: %v", err)
	}
	if derived != kp.Public {
		t.Errorf("導出公開鍵が不一致: got %q want %q", derived, kp.Public)
	}
}

func TestGenerateUnique(t *testing.T) {
	a, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if a.Private == b.Private || a.Public == b.Public {
		t.Error("生成のたびに異なる鍵ペアになるべき")
	}
}

func TestGenerateEntropyFailure(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = errReader{}

	if _, err := Generate(); err == nil {
		t.Error("乱数源の失敗はエラーになるべき")
	}
}

func TestGenerateSecret(t *testing.T) {
	priv, pub, err := GenerateSecret()
	if err != nil {
		t.Fatalf("GenerateSecret エラー: %v", err)
	}
	// 秘密鍵は生の 32 バイト。
	if len(priv) != 32 {
		t.Fatalf("秘密鍵が 32 バイトでない: len=%d", len(priv))
	}
	// 公開鍵は 32 バイトの base64。
	rawPub, err := base64.StdEncoding.DecodeString(pub)
	if err != nil || len(rawPub) != 32 {
		t.Fatalf("公開鍵が 32 バイトの base64 でない: len=%d err=%v", len(rawPub), err)
	}
	// 公開鍵は秘密鍵から決定的に導出でき、返り値と一致する。
	derived, err := PublicFromPrivate(base64.StdEncoding.EncodeToString(priv))
	if err != nil {
		t.Fatalf("PublicFromPrivate エラー: %v", err)
	}
	if derived != pub {
		t.Errorf("導出公開鍵が不一致: got %q want %q", derived, pub)
	}
}

func TestGenerateSecretUnique(t *testing.T) {
	a, _, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	b, _, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) {
		t.Error("生成のたびに異なる秘密鍵になるべき")
	}
}

func TestGenerateSecretEntropyFailure(t *testing.T) {
	orig := randReader
	t.Cleanup(func() { randReader = orig })
	randReader = errReader{}

	if _, _, err := GenerateSecret(); err == nil {
		t.Error("乱数源の失敗はエラーになるべき")
	}
}

func TestPublicFromPrivateErrors(t *testing.T) {
	// 不正な base64。
	if _, err := PublicFromPrivate("!!!not-base64!!!"); err == nil {
		t.Error("不正な base64 はエラーになるべき")
	}
	// 長さが 32 でない（3 バイト）。
	short := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	if _, err := PublicFromPrivate(short); err == nil {
		t.Error("32 バイトでない秘密鍵はエラーになるべき")
	}
}

func TestValidatePublicKey(t *testing.T) {
	// 正規の 32 バイト公開鍵。
	kp, err := Generate()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidatePublicKey(kp.Public); err != nil {
		t.Errorf("正規の公開鍵は妥当であるべき: %v", err)
	}

	// 不正な base64。
	if err := ValidatePublicKey("!!!not-base64!!!"); err == nil {
		t.Error("不正な base64 はエラーになるべき")
	}
	// 長さが 32 でない（3 バイト）。
	short := base64.StdEncoding.EncodeToString([]byte{1, 2, 3})
	if err := ValidatePublicKey(short); err == nil {
		t.Error("32 バイトでない公開鍵はエラーになるべき")
	}
	// 空文字列。
	if err := ValidatePublicKey(""); err == nil {
		t.Error("空文字列はエラーになるべき")
	}
}

// errReader は常に失敗する io.Reader。
type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

var _ io.Reader = errReader{}
