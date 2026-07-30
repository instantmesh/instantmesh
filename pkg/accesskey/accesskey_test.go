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
	if got := r.Snapshot(); len(got) != 1 || got["guest-pk"] != fresh {
		t.Errorf("Snapshot = %v, want guest-pk → 新キーの 1 件", got)
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
	// Snapshot は 1 回のロックで全件を写す（表示・配布用）。
	snap := r.Snapshot()
	if len(snap) != 2 {
		t.Fatalf("Snapshot = %v, want 2 件", snap)
	}
	for _, g := range got {
		if k, ok := r.KeyFor(g); !ok || snap[g] != k {
			t.Errorf("Snapshot[%q] = %q, want %q", g, snap[g], k)
		}
	}
	// 返すのは複製であり、変更してもレジストリへ波及しない。
	delete(snap, "alice")
	if _, ok := r.KeyFor("alice"); !ok {
		t.Error("Snapshot の変更がレジストリへ波及した")
	}

	r.Reset()
	if len(r.Guests()) != 0 || len(r.Snapshot()) != 0 {
		t.Error("Reset 後もキーが残っている")
	}
}
