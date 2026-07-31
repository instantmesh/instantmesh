package portmap

import (
	"errors"
	"strconv"
	"testing"
)

const hostKey = "aG9zdC1wdWJsaWMta2V5LWJhc2U2NA=="

// TestDeriveDeterministic は「同じホスト・同じサービスなら毎回同じポート」（要件 §4.6.4 の
// 核心。ランダム割当を却下した理由）を確かめる。
func TestDeriveDeterministic(t *testing.T) {
	first, err := Derive(hostKey, 11434)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	for i := 0; i < 5; i++ {
		again, err := Derive(hostKey, 11434)
		if err != nil {
			t.Fatalf("Derive: %v", err)
		}
		if again != first {
			t.Fatalf("導出が揺れた: %d → %d", first, again)
		}
	}
	// 導出範囲に収まる。
	if first < Base || first >= Base+Span {
		t.Errorf("導出ポート = %d, want [%d, %d)", first, Base, Base+Span)
	}
	// ホストが違えば（通常は）別のポートへ写る。衝突しにくいことの確認で、
	// 衝突しないことの保証ではない（衝突時は線形探索で回避する）。
	other, err := Derive("b3RoZXItaG9zdC1rZXk=", 11434)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if other == first {
		t.Errorf("別ホストで同じポートへ写った: %d", first)
	}
	// ポートが違えば別のポートへ写る。
	dev, err := Derive(hostKey, 3000)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if dev == first {
		t.Errorf("別ポートで同じポートへ写った: %d", dev)
	}
}

// TestDeriveSeparatesKeyAndPort は公開鍵とポートの連結が曖昧でないことを確かめる。
// 区切りが無いと "key1" + 1234 と "key" + 11234 のような入力が同じハッシュになりうる。
func TestDeriveSeparatesKeyAndPort(t *testing.T) {
	a, err := Derive("key", 1)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	// "key\x00\x00\x01" と "key\x00\x00" + "\x01" が区別されること（後者は作れないので、
	// 末尾に数字を持つ鍵で近い入力を作って比較する）。
	b, err := Derive("key\x00", 1)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if a == b {
		t.Error("鍵とポートの境界が曖昧（同じハッシュになった）")
	}
}

func TestDeriveRejectsInvalid(t *testing.T) {
	if _, err := Derive("", 11434); !errors.Is(err, ErrNoHostKey) {
		t.Errorf("空の公開鍵: err = %v, want ErrNoHostKey", err)
	}
	for _, port := range []int{0, -1, 65536} {
		if _, err := Derive(hostKey, port); !errors.Is(err, ErrInvalidPort) {
			t.Errorf("ポート %d: err = %v, want ErrInvalidPort", port, err)
		}
	}
}

// TestCandidates は候補列が「元ポート → 導出ポート → 線形探索」の順で、重複なく返ることを
// 確かめる（ポート保存が第一希望であること）。
func TestCandidates(t *testing.T) {
	cands, err := Candidates(hostKey, 11434)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	if len(cands) != MaxProbe+1 {
		t.Fatalf("候補数 = %d, want %d", len(cands), MaxProbe+1)
	}
	if cands[0] != 11434 {
		t.Errorf("先頭 = %d, want 11434（ポート保存が第一希望）", cands[0])
	}
	derived, err := Derive(hostKey, 11434)
	if err != nil {
		t.Fatalf("Derive: %v", err)
	}
	if cands[1] != derived {
		t.Errorf("2 番目 = %d, want %d（導出ポート）", cands[1], derived)
	}
	// 3 番目以降は導出ポートからの線形探索。
	if cands[2] != derived+1 {
		t.Errorf("3 番目 = %d, want %d", cands[2], derived+1)
	}
	seen := make(map[int]bool, len(cands))
	for _, c := range cands {
		if seen[c] {
			t.Fatalf("候補が重複した: %d", c)
		}
		seen[c] = true
		if c != 11434 && (c < Base || c >= Base+Span) {
			t.Errorf("候補 %d が導出範囲外", c)
		}
	}
	// 元ポートが導出範囲に入る場合も重複しない（元ポート == 導出ポートになりうる）。
	for _, port := range []int{Base, Base + Span - 1} {
		cs, err := Candidates(hostKey, port)
		if err != nil {
			t.Fatalf("Candidates(%d): %v", port, err)
		}
		u := make(map[int]bool, len(cs))
		for _, c := range cs {
			if u[c] {
				t.Fatalf("port %d: 候補が重複した: %d", port, c)
			}
			u[c] = true
		}
	}
	if _, err := Candidates("", 1); !errors.Is(err, ErrNoHostKey) {
		t.Errorf("err = %v, want ErrNoHostKey", err)
	}
}

// TestCandidatesWrapsWithinRange は線形探索が導出範囲を巡回し、範囲外（Base+Span 以上）へ
// 出ないことを確かめる。導出ポートが上限付近になる鍵を総当たりで探す（Derive は決定的なので
// 見つかる鍵も毎回同じ＝テストは決定的）。
func TestCandidatesWrapsWithinRange(t *testing.T) {
	var key string
	var derived int
	for i := 0; i < 100000; i++ {
		k := "wrap-" + strconv.Itoa(i)
		d, err := Derive(k, 11434)
		if err != nil {
			t.Fatalf("Derive: %v", err)
		}
		if d >= Base+Span-MaxProbe {
			key, derived = k, d
			break
		}
	}
	if key == "" {
		t.Fatal("上限付近へ導出される鍵が見つからなかった（Derive の分布を確認）")
	}

	cands, err := Candidates(key, 11434)
	if err != nil {
		t.Fatalf("Candidates: %v", err)
	}
	wrapped := false
	for _, c := range cands[1:] {
		if c < Base || c >= Base+Span {
			t.Fatalf("巡回が範囲外へ出た: %d", c)
		}
		if c < derived {
			wrapped = true
		}
	}
	if !wrapped {
		t.Errorf("鍵 %q（導出 %d）で巻き戻りが起きていない", key, derived)
	}
}
