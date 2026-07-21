package token

import (
	"encoding/base64"
	"errors"
	"regexp"
	"testing"
)

func TestNewRoomTokenEntropy(t *testing.T) {
	tok, err := NewRoomToken()
	if err != nil {
		t.Fatalf("NewRoomToken エラー: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		t.Fatalf("トークンがURLセーフbase64でない: %v", err)
	}
	if len(raw) != TokenBytes {
		t.Errorf("トークンのエントロピー = %d バイト, want %d", len(raw), TokenBytes)
	}
}

func TestNewRoomTokenUnique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 1000; i++ {
		tok, err := NewRoomToken()
		if err != nil {
			t.Fatalf("NewRoomToken エラー: %v", err)
		}
		if seen[tok] {
			t.Fatalf("トークンが重複した: %q", tok)
		}
		seen[tok] = true
	}
}

func TestEqual(t *testing.T) {
	if !Equal("abc123", "abc123") {
		t.Error("同一トークンは Equal=true であるべき")
	}
	if Equal("abc123", "abc124") {
		t.Error("異なるトークンは Equal=false であるべき")
	}
	if Equal("abc", "abcd") {
		t.Error("長さの異なるトークンは Equal=false であるべき")
	}
}

var sasFormat = regexp.MustCompile(`^[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}-[A-Z2-7]{4}$`)

func TestSASFormatAndDeterminism(t *testing.T) {
	key := []byte("this-is-a-32-byte-public-key!!!!") // 32 バイト
	a := SAS(key)
	b := SAS(key)
	if a != b {
		t.Errorf("SAS は決定的であるべき: %q != %q", a, b)
	}
	if !sasFormat.MatchString(a) {
		t.Errorf("SAS フォーマット不正: %q", a)
	}

	other := SAS([]byte("a-different-32-byte-public-key!!!"))
	if other == a {
		t.Error("異なる鍵は異なる SAS になるべき")
	}
}

func TestNewRoomTokenRandError(t *testing.T) {
	// randRead シームを失敗させ、エントロピー障害時のエラー伝播を検証する。
	orig := randRead
	randRead = func([]byte) (int, error) { return 0, errors.New("token: simulated entropy failure") }
	defer func() { randRead = orig }()

	if _, err := NewRoomToken(); err == nil {
		t.Error("乱数読み取りが失敗した場合はエラーを返すべき")
	}
}

func TestGroupBy(t *testing.T) {
	cases := []struct {
		s, sep, want string
		n            int
	}{
		{s: "abcdefgh", n: 4, sep: "-", want: "abcd-efgh"},
		{s: "abcd", n: 4, sep: "-", want: "abcd"},   // len == n はそのまま
		{s: "abc", n: 4, sep: "-", want: "abc"},     // len < n はそのまま
		{s: "", n: 4, sep: "-", want: ""},           // 空文字
		{s: "abcde", n: 0, sep: "-", want: "abcde"}, // n<=0 はそのまま
		{s: "abcdef", n: 2, sep: ":", want: "ab:cd:ef"},
		{s: "abcde", n: 2, sep: "-", want: "ab-cd-e"}, // 端数あり
	}
	for _, c := range cases {
		if got := groupBy(c.s, c.n, c.sep); got != c.want {
			t.Errorf("groupBy(%q,%d,%q) = %q, want %q", c.s, c.n, c.sep, got, c.want)
		}
	}
}

func TestSASEmptyKey(t *testing.T) {
	// 空鍵でもパニックせず、決定的で整形済みの SAS を返すこと。
	a := SAS(nil)
	b := SAS([]byte{})
	if a != b {
		t.Errorf("nil と空スライスは同じ SAS になるべき: %q != %q", a, b)
	}
	if !sasFormat.MatchString(a) {
		t.Errorf("SAS フォーマット不正: %q", a)
	}
}
