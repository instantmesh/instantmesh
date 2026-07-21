package qr

import (
	"bytes"
	"errors"
	"testing"
)

// --- GF(256) / Reed-Solomon --------------------------------------------------

func TestGFMul(t *testing.T) {
	cases := []struct {
		a, b, want byte
	}{
		{0, 5, 0},   // 吸収元（左）
		{5, 0, 0},   // 吸収元（右）
		{1, 7, 7},   // 単位元
		{2, 2, 4},   // α^1 · α^1 = α^2 = 4
		{16, 16, 29}, // α^4 · α^4 = α^8 = 29（0x100 を原始多項式で還元）
	}
	for _, c := range cases {
		if got := gfMul(c.a, c.b); got != c.want {
			t.Errorf("gfMul(%d,%d)=%d, want %d", c.a, c.b, got, c.want)
		}
	}
}

// TestReedSolomonISOVector は ISO/IEC 18004 附属書 I の "01234567"（V1-M）の
// データコードワード列に対する EC コードワードが規格例と一致することを検証する。
func TestReedSolomonISOVector(t *testing.T) {
	data := []byte{0x10, 0x20, 0x0C, 0x56, 0x61, 0x80, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11}
	want := []byte{0xA5, 0x24, 0xD4, 0xC1, 0xED, 0x36, 0xC7, 0x87, 0x2C, 0x55}
	if got := rsEncode(data, 10); !bytes.Equal(got, want) {
		t.Errorf("rsEncode = % X, want % X", got, want)
	}
}

// --- BCH（フォーマット / バージョン情報）------------------------------------

func TestFormatBits(t *testing.T) {
	// ISO/IEC 18004 Table 12: EC レベル M・マスク 0 のフォーマット情報 = 101010000010010b。
	if got := formatBits(Medium, 0); got != 0x5412 {
		t.Errorf("formatBits(Medium,0)=0x%04X, want 0x5412", got)
	}
}

func TestVersionBits(t *testing.T) {
	// ISO/IEC 18004 Table D.1: バージョン 7 のバージョン情報 = 000111110010010100b = 0x07C94。
	if got := versionBits(7); got != 0x7C94 {
		t.Errorf("versionBits(7)=0x%05X, want 0x7C94", got)
	}
}

// --- テーブル整合性 ---------------------------------------------------------

// TestVersionTableConsistency は各 (バージョン, EC レベル) について
// 総コードワード数 = データコードワード数 + ブロック数 × EC コードワード数 を検算し、
// テーブル打ち込みミスを検出する。
func TestVersionTableConsistency(t *testing.T) {
	for v := 1; v <= maxVersion; v++ {
		spec := versions[v]
		for lvl := Low; lvl <= High; lvl++ {
			e := spec.ec[lvl]
			got := e.dataCodewords() + e.numBlocks()*e.ecPerBlock
			if got != spec.totalCodewords {
				t.Errorf("version %d level %d: data+ec=%d, want total=%d", v, lvl, got, spec.totalCodewords)
			}
		}
	}
}

// --- データ符号化 -----------------------------------------------------------

func TestEncodeData(t *testing.T) {
	// V1（文字数 8 ビット）: "A"(0x41) → 0100 00000001 01000001 0000 → 0x40,0x14,0x10 + パッド。
	got := encodeData([]byte{0x41}, 1, 16)
	want := []byte{0x40, 0x14, 0x10, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC, 0x11, 0xEC}
	if !bytes.Equal(got, want) {
		t.Errorf("encodeData(V1) = % X, want % X", got, want)
	}
	// V10（文字数 16 ビット）: 先頭 4 バイトが 0x40,0x00,0x14,0x10 になる。
	got10 := encodeData([]byte{0x41}, 10, 20)
	if !bytes.Equal(got10[:4], []byte{0x40, 0x00, 0x14, 0x10}) {
		t.Errorf("encodeData(V10)[:4] = % X, want 40 00 14 10", got10[:4])
	}
}

func TestCharCountBits(t *testing.T) {
	if charCountBits(9) != 8 || charCountBits(10) != 16 {
		t.Fatalf("charCountBits: got (%d,%d), want (8,16)", charCountBits(9), charCountBits(10))
	}
}

func TestChooseVersion(t *testing.T) {
	if cap1 := byteCapacity(1, Low); cap1 != 17 {
		t.Fatalf("byteCapacity(1,Low)=%d, want 17", cap1)
	}
	if cap10 := byteCapacity(10, Low); cap10 != 271 {
		t.Fatalf("byteCapacity(10,Low)=%d, want 271", cap10)
	}
	cases := []struct {
		dataLen, wantVer int
		wantErr          bool
	}{
		{17, 1, false},
		{18, 2, false},
		{271, 10, false},
		{272, 0, true},
	}
	for _, c := range cases {
		v, err := chooseVersion(c.dataLen, Low)
		if c.wantErr {
			if !errors.Is(err, ErrTooLong) {
				t.Errorf("chooseVersion(%d): err=%v, want ErrTooLong", c.dataLen, err)
			}
			continue
		}
		if err != nil || v != c.wantVer {
			t.Errorf("chooseVersion(%d)=(%d,%v), want (%d,nil)", c.dataLen, v, err, c.wantVer)
		}
	}
}

// --- Encode（統合・構造不変条件）-------------------------------------------

func TestEncodeErrors(t *testing.T) {
	if _, err := Encode([]byte("x"), Level(99)); !errors.Is(err, ErrLevel) {
		t.Errorf("Encode(bad level): err=%v, want ErrLevel", err)
	}
	if _, err := Encode([]byte("x"), Level(-1)); !errors.Is(err, ErrLevel) {
		t.Errorf("Encode(negative level): err=%v, want ErrLevel", err)
	}
	if _, err := Encode(make([]byte, 272), Low); !errors.Is(err, ErrTooLong) {
		t.Errorf("Encode(too long): err=%v, want ErrTooLong", err)
	}
}

func TestEncodeStructure(t *testing.T) {
	cases := []struct {
		dataLen, wantVer, wantSize int
	}{
		{5, 1, 21},    // V1: アライメントなし・バージョン情報なし・文字数 8 ビット
		{110, 7, 45},  // V7: アライメント複数・バージョン情報あり
		{200, 10, 57}, // V10: グループ 2 あり・文字数 16 ビット
	}
	for _, c := range cases {
		code, err := Encode(make([]byte, c.dataLen), Medium)
		if err != nil {
			t.Fatalf("Encode(len=%d): %v", c.dataLen, err)
		}
		if code.Version != c.wantVer || code.Size != c.wantSize {
			t.Errorf("Encode(len=%d): version=%d size=%d, want version=%d size=%d",
				c.dataLen, code.Version, code.Size, c.wantVer, c.wantSize)
		}
		// ファインダパターンの外周角は常に暗（マスク非対象）。
		if !code.Module(0, 0) {
			t.Errorf("V%d: 左上ファインダ角 (0,0) が明", c.wantVer)
		}
		if !code.Module(code.Size-1, 0) {
			t.Errorf("V%d: 右上ファインダ角 が明", c.wantVer)
		}
		if !code.Module(0, code.Size-1) {
			t.Errorf("V%d: 左下ファインダ角 が明", c.wantVer)
		}
		// タイミングパターン（行 6・偶数列 8）は暗。
		if !code.Module(8, 6) {
			t.Errorf("V%d: タイミング (8,6) が明", c.wantVer)
		}
		// ダークモジュール (8, size-8) は常に暗。
		if !code.Module(8, code.Size-8) {
			t.Errorf("V%d: ダークモジュールが明", c.wantVer)
		}
	}
}

// TestEncodeQuartileGroups は EC レベル Quartile でグループ 2 を含む構成（V7-Q など）を通し、
// interleave のブロック分割・EC 付与を別レベルでも exercise する。
func TestEncodeQuartileGroups(t *testing.T) {
	code, err := Encode(make([]byte, 60), Quartile)
	if err != nil {
		t.Fatalf("Encode(Quartile): %v", err)
	}
	if code.Size != code.Version*4+17 {
		t.Errorf("size %d inconsistent with version %d", code.Size, code.Version)
	}
}

// --- マスクペナルティ（白箱）-----------------------------------------------

// matrixFrom は与えた mod（fn は全 false）で matrix を構築する。
func matrixFrom(mod [][]bool) *matrix {
	n := len(mod)
	m := &matrix{size: n, mod: mod}
	m.fn = make([][]bool, n)
	for i := range m.fn {
		m.fn[i] = make([]bool, n)
	}
	return m
}

func newBoolGrid(n int) [][]bool {
	g := make([][]bool, n)
	for i := range g {
		g[i] = make([]bool, n)
	}
	return g
}

func TestPenaltyRule1And2(t *testing.T) {
	// 全暗 5×5: 各行/各列が 5 連続 → rule1 = (5-2)×(5行+5列) = 30。
	// rule2 = 4×4 の 2×2 ブロック全部同色 → 16×3 = 48。
	g := newBoolGrid(5)
	for y := range g {
		for x := range g[y] {
			g[y][x] = true
		}
	}
	m := matrixFrom(g)
	if p := m.penaltyRule1(); p != 30 {
		t.Errorf("penaltyRule1(all dark 5x5)=%d, want 30", p)
	}
	if p := m.penaltyRule2(); p != 48 {
		t.Errorf("penaltyRule2(all dark 5x5)=%d, want 48", p)
	}

	// 内部で終わる長連続と短い遷移を含む行を作り、run のリセット分岐を通す。
	g2 := newBoolGrid(8)
	for x := 0; x < 6; x++ {
		g2[0][x] = true // 6 連続の後に明へ遷移（run>=5 で終了）
	}
	g2[0][7] = true // 単発（run<5 でリセット）
	m2 := matrixFrom(g2)
	if p := m2.penaltyRule1(); p == 0 {
		t.Errorf("penaltyRule1(mixed)=0, want >0")
	}
}

func TestPenaltyRule3(t *testing.T) {
	// 水平方向: 11 幅パターン A/B を行に置く。
	g := newBoolGrid(11)
	copy(g[0], rule3PatternA[:])
	copy(g[1], rule3PatternB[:])
	m := matrixFrom(g)
	if p := m.penaltyRule3(); p != 80 {
		t.Errorf("penaltyRule3(horizontal A+B)=%d, want 80", p)
	}

	// 垂直方向: パターン A を列 0 に置く。
	gv := newBoolGrid(11)
	for k, v := range rule3PatternA {
		gv[k][0] = v
	}
	mv := matrixFrom(gv)
	if p := mv.penaltyRule3(); p != 40 {
		t.Errorf("penaltyRule3(vertical A)=%d, want 40", p)
	}
}

func TestPenaltyRule4(t *testing.T) {
	// 全暗（比率 100%）: 45〜55% から大きく外れるため k ループが回る。
	g := newBoolGrid(5)
	for y := range g {
		for x := range g[y] {
			g[y][x] = true
		}
	}
	if p := matrixFrom(g).penaltyRule4(); p != 50 {
		t.Errorf("penaltyRule4(all dark 5x5)=%d, want 50", p)
	}

	// 比率 48%（12/25）: 45〜55% 内なので k=0・ペナルティ 0。
	g2 := newBoolGrid(5)
	set := 0
	for y := 0; y < 5 && set < 12; y++ {
		for x := 0; x < 5 && set < 12; x++ {
			g2[y][x] = true
			set++
		}
	}
	if p := matrixFrom(g2).penaltyRule4(); p != 0 {
		t.Errorf("penaltyRule4(48%%)=%d, want 0", p)
	}
}
