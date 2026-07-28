package accesskey

import (
	"errors"
	"testing"
)

func TestIssueVerifyRevoke(t *testing.T) {
	r := New()
	key, err := r.Issue("guest-pk")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if key == "" {
		t.Fatal("空のキーを発行した")
	}
	if got, ok := r.Verify(key); !ok || got != "guest-pk" {
		t.Errorf("Verify = %q, %v", got, ok)
	}
	if got, ok := r.KeyFor("guest-pk"); !ok || got != key {
		t.Errorf("KeyFor = %q, %v", got, ok)
	}

	// 失効後は通らない（キックとは独立に呼べる）。
	r.Revoke("guest-pk")
	if _, ok := r.Verify(key); ok {
		t.Error("失効後のキーが通った")
	}
	if _, ok := r.KeyFor("guest-pk"); ok {
		t.Error("失効後も KeyFor が返る")
	}
}

// TestReissueInvalidatesOld は再発行で旧キーが直ちに失効することを確かめる（漏洩時の入れ替え）。
func TestReissueInvalidatesOld(t *testing.T) {
	r := New()
	old, err := r.Issue("guest-pk")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	fresh, err := r.Issue("guest-pk")
	if err != nil {
		t.Fatalf("Issue(2): %v", err)
	}
	if old == fresh {
		t.Fatal("再発行で同じキーが返った")
	}
	if _, ok := r.Verify(old); ok {
		t.Error("旧キーが通った")
	}
	if _, ok := r.Verify(fresh); !ok {
		t.Error("新キーが通らない")
	}
	if r.Len() != 1 {
		t.Errorf("Len = %d, want 1", r.Len())
	}
}

func TestVerifyRejects(t *testing.T) {
	r := New()
	if _, err := r.Issue(""); !errors.Is(err, ErrUnknownGuest) {
		t.Errorf("空のゲスト: err = %v, want ErrUnknownGuest", err)
	}
	key, _ := r.Issue("guest-pk")
	for _, bad := range []string{"", "wrong", key + "x", key[:len(key)-1]} {
		if _, ok := r.Verify(bad); ok {
			t.Errorf("不正なキー %q が通った", bad)
		}
	}
}

func TestIssueGenerationError(t *testing.T) {
	r := New()
	r.newToken = func() (string, error) { return "", errors.New("エントロピー障害") }
	if _, err := r.Issue("guest-pk"); err == nil {
		t.Error("生成失敗を伝播していない")
	}
}

func TestGuestsAndReset(t *testing.T) {
	r := New()
	for _, g := range []string{"bob", "alice"} {
		if _, err := r.Issue(g); err != nil {
			t.Fatalf("Issue: %v", err)
		}
	}
	got := r.Guests()
	if len(got) != 2 || got[0] != "alice" || got[1] != "bob" {
		t.Errorf("Guests = %v（昇順であるべき）", got)
	}
	r.Reset()
	if r.Len() != 0 || len(r.Guests()) != 0 {
		t.Error("Reset 後もキーが残っている")
	}
}
