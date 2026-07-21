package nickname

import (
	"strings"
	"testing"
)

func TestCleanTrimsAndKeeps(t *testing.T) {
	got, err := Clean("  Alice  ")
	if err != nil {
		t.Fatalf("Clean エラー: %v", err)
	}
	if got != "Alice" {
		t.Errorf("Clean = %q, want %q", got, "Alice")
	}
}

func TestCleanMultibyte(t *testing.T) {
	got, err := Clean("たろう")
	if err != nil {
		t.Fatalf("日本語ニックネームは許可されるべき: %v", err)
	}
	if got != "たろう" {
		t.Errorf("Clean = %q", got)
	}
}

func TestCleanEmpty(t *testing.T) {
	if _, err := Clean("   "); err != ErrEmpty {
		t.Errorf("空白のみは ErrEmpty を返すべき, got %v", err)
	}
}

func TestCleanTooLong(t *testing.T) {
	if _, err := Clean(strings.Repeat("a", MaxLen+1)); err != ErrTooLong {
		t.Errorf("上限超過は ErrTooLong を返すべき, got %v", err)
	}
	// 上限ちょうどは許可。
	if _, err := Clean(strings.Repeat("a", MaxLen)); err != nil {
		t.Errorf("上限ちょうどは許可されるべき, got %v", err)
	}
}

func TestCleanControlChars(t *testing.T) {
	for _, s := range []string{"a\x00b", "a\tb", "a\nb", "line1\r\nline2"} {
		if _, err := Clean(s); err != ErrInvalidChar {
			t.Errorf("制御文字 %q は ErrInvalidChar を返すべき, got %v", s, err)
		}
	}
}

func TestCleanInvalidUTF8(t *testing.T) {
	// 不正な UTF-8 バイト列は制御文字判定の前に ErrInvalidChar で弾く。
	for _, s := range []string{"ab\xffcd", "\xff\xfe", "x\x80y"} {
		if _, err := Clean(s); err != ErrInvalidChar {
			t.Errorf("不正な UTF-8 %q は ErrInvalidChar を返すべき, got %v", s, err)
		}
	}
}
