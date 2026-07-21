// Package qr は文字列を QR コード（Model 2）のモジュール行列へ符号化する純粋パッケージ。
//
// InstantMesh のホストは招待リンク（instantmesh://join?...）を対面で共有するため、
// 端末画面に QR コードを表示する（要件 §招待。帯域外での鍵ピン留め/MITM 照合の起点）。
// 本パッケージは URL 文字列 → 真偽値のモジュール行列（true = 暗モジュール）への変換のみを
// 担い、画像化・端末描画は利用側（cmd/client）が行う。トランスポート/OS/UI に依存しない。
//
// 対応範囲はバイトモード・バージョン 1〜10・EC レベル L/M/Q/H（招待 URL 用途に十分）。
// 時刻・乱数に依存しない決定的な変換であり、実装は ISO/IEC 18004 に準拠する。
package qr

import "errors"

// エラー。
var (
	// ErrTooLong はデータが対応バージョン（1〜10）に収まらないことを表す。
	ErrTooLong = errors.New("qr: data too long for supported versions (1-10)")
	// ErrLevel は未知の誤り訂正レベルが指定されたことを表す。
	ErrLevel = errors.New("qr: unknown error correction level")
)

// Code は符号化済み QR コードのモジュール行列。Size×Size の正方で、原点は左上。
type Code struct {
	Size    int // 一辺のモジュール数（バージョン v なら 4v+17）
	Version int // QR バージョン（1〜10）
	modules [][]bool
}

// Module は座標 (x, y) が暗モジュール（黒）なら true を返す。範囲外はパニックする。
func (c *Code) Module(x, y int) bool {
	return c.modules[y][x]
}

// Encode は data を QR コードへ符号化する。データが長すぎる場合は ErrTooLong、
// EC レベルが不正な場合は ErrLevel を返す。
func Encode(data []byte, level Level) (*Code, error) {
	if level < Low || level > High {
		return nil, ErrLevel
	}
	ver, err := chooseVersion(len(data), level)
	if err != nil {
		return nil, err
	}
	blocks := versions[ver].ec[level]
	dataCW := encodeData(data, ver, blocks.dataCodewords())
	final := interleave(dataCW, blocks)

	m := newMatrix(ver)
	m.placeData(final)
	m.applyBestMask(level)
	return &Code{Size: m.size, Version: ver, modules: m.mod}, nil
}

// charCountBits はバイトモードの文字数指標のビット幅。V1〜9 は 8、V10 以降は 16。
func charCountBits(ver int) int {
	if ver >= 10 {
		return 16
	}
	return 8
}

// byteCapacity は (ver, level) がバイトモードで格納できる最大バイト数。
func byteCapacity(ver int, level Level) int {
	dataBits := versions[ver].ec[level].dataCodewords() * 8
	return (dataBits - 4 - charCountBits(ver)) / 8
}

// chooseVersion は dataLen バイトを格納できる最小バージョンを返す。
func chooseVersion(dataLen int, level Level) (int, error) {
	for v := 1; v <= maxVersion; v++ {
		if dataLen <= byteCapacity(v, level) {
			return v, nil
		}
	}
	return 0, ErrTooLong
}

// --- データ符号化 ---------------------------------------------------------

// bitBuffer はビット列を MSB ファーストで蓄積する補助構造。
type bitBuffer struct{ bits []bool }

// appendBits は val の下位 n ビットを MSB から順に追加する。
func (b *bitBuffer) appendBits(val, n int) {
	for i := n - 1; i >= 0; i-- {
		b.bits = append(b.bits, (val>>i)&1 == 1)
	}
}

// bytes はビット列をバイト列へ詰める（長さは 8 の倍数である前提）。
func (b *bitBuffer) bytes() []byte {
	out := make([]byte, len(b.bits)/8)
	for i, bit := range b.bits {
		if bit {
			out[i/8] |= 1 << (7 - i%8)
		}
	}
	return out
}

// encodeData はバイトモードのデータコードワード列（長さ dataCW）を生成する。
// モード指標 → 文字数指標 → データ → ターミネータ → バイト境界パディング →
// パッドコードワード（0xEC/0x11 交互）の順（ISO/IEC 18004 §7.4）。
func encodeData(data []byte, ver, dataCW int) []byte {
	var bb bitBuffer
	bb.appendBits(0b0100, 4) // バイトモード指標
	bb.appendBits(len(data), charCountBits(ver))
	for _, d := range data {
		bb.appendBits(int(d), 8)
	}

	// ターミネータ（4 ビット固定）。バイトモードでは モード(4)+文字数(8 or 16)+データ(8n)+
	// ターミネータ(4) が常に 8 ビット境界へ整列するため、追加のバイト境界パディングは不要
	// （容量にも常に 4 ビット以上の余りがあり 4 ビットは必ず収まる）。
	bb.appendBits(0, 4)

	cw := bb.bytes()
	for i := 0; len(cw) < dataCW; i++ {
		if i%2 == 0 {
			cw = append(cw, 0xEC)
		} else {
			cw = append(cw, 0x11)
		}
	}
	return cw
}

// interleave はデータコードワードをブロック分割し各ブロックの EC を付して、
// データ→EC の順にインターリーブした最終コードワード列を返す（ISO/IEC 18004 §7.6）。
func interleave(dataCW []byte, blk ecBlocks) []byte {
	type block struct{ data, ec []byte }
	var blocks []block
	pos := 0
	add := func(count, size int) {
		for range count {
			d := dataCW[pos : pos+size]
			pos += size
			blocks = append(blocks, block{data: d, ec: rsEncode(d, blk.ecPerBlock)})
		}
	}
	add(blk.group1Blocks, blk.group1Data)
	add(blk.group2Blocks, blk.group2Data)

	var out []byte
	maxData := max(blk.group1Data, blk.group2Data)
	for i := 0; i < maxData; i++ {
		for _, b := range blocks {
			if i < len(b.data) {
				out = append(out, b.data[i])
			}
		}
	}
	for i := 0; i < blk.ecPerBlock; i++ {
		for _, b := range blocks {
			out = append(out, b.ec[i])
		}
	}
	return out
}

// --- モジュール行列 -------------------------------------------------------

// matrix は構築途中の QR モジュール行列。mod はモジュール値（true=暗）、
// fn は機能パターン（ファインダ/タイミング/アライメント/フォーマット等）でマスク非対象。
type matrix struct {
	size int
	mod  [][]bool
	fn   [][]bool
}

// newMatrix はバージョン ver の機能パターンを描いた行列を返す（データ領域は未配置）。
func newMatrix(ver int) *matrix {
	size := ver*4 + 17
	m := &matrix{size: size}
	m.mod = make([][]bool, size)
	m.fn = make([][]bool, size)
	for i := range m.mod {
		m.mod[i] = make([]bool, size)
		m.fn[i] = make([]bool, size)
	}
	m.drawFinder(0, 0)
	m.drawFinder(size-7, 0)
	m.drawFinder(0, size-7)
	m.drawTiming()
	m.drawAlignments(ver)
	m.mod[size-8][8] = true // ダークモジュール（常に暗）
	m.fn[size-8][8] = true
	m.drawVersion(ver)
	m.reserveFormat()
	return m
}

// drawFinder は左上座標 (x0, y0) にファインダパターン（7×7）とセパレータを描く。
func (m *matrix) drawFinder(x0, y0 int) {
	for dy := -1; dy <= 7; dy++ {
		for dx := -1; dx <= 7; dx++ {
			x, y := x0+dx, y0+dy
			if x < 0 || x >= m.size || y < 0 || y >= m.size {
				continue
			}
			ring := ((dx == 0 || dx == 6) && dy >= 0 && dy <= 6) ||
				((dy == 0 || dy == 6) && dx >= 0 && dx <= 6)
			core := dx >= 2 && dx <= 4 && dy >= 2 && dy <= 4
			m.mod[y][x] = ring || core
			m.fn[y][x] = true
		}
	}
}

// drawTiming は行 6・列 6 のタイミングパターンを描く（機能パターンと重なる部分は既設）。
func (m *matrix) drawTiming() {
	for i := 0; i < m.size; i++ {
		if !m.fn[6][i] {
			m.mod[6][i] = i%2 == 0
			m.fn[6][i] = true
		}
		if !m.fn[i][6] {
			m.mod[i][6] = i%2 == 0
			m.fn[i][6] = true
		}
	}
}

// drawAlignments はバージョンのアライメント中心候補からファインダと重なる 3 隅を除き描く。
func (m *matrix) drawAlignments(ver int) {
	centers := versions[ver].align
	n := len(centers)
	for i, r := range centers {
		for j, c := range centers {
			if (i == 0 && j == 0) || (i == 0 && j == n-1) || (i == n-1 && j == 0) {
				continue // ファインダ隅と重なる位置
			}
			m.drawAlignment(c, r)
		}
	}
}

// drawAlignment は中心 (cx, cy) に 5×5 のアライメントパターンを描く。
func (m *matrix) drawAlignment(cx, cy int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			m.mod[cy+dy][cx+dx] = max(abs(dx), abs(dy)) != 1
			m.fn[cy+dy][cx+dx] = true
		}
	}
}

// versionBits はバージョン ver（>=7）の 18 ビットバージョン情報（BCH(18,6)、生成多項式 0x1F25）を返す。
func versionBits(ver int) int {
	rem := ver
	for range 12 {
		rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
	}
	return ver<<12 | rem
}

// drawVersion はバージョン情報を V7 以上で 2 箇所に描く（ISO §7.10）。
func (m *matrix) drawVersion(ver int) {
	if ver < 7 {
		return
	}
	bits := versionBits(ver)
	size := m.size
	for i := 0; i < 18; i++ {
		b := (bits>>i)&1 == 1
		a := size - 11 + i%3
		d := i / 3
		m.mod[d][a] = b // 右上
		m.fn[d][a] = true
		m.mod[a][d] = b // 左下
		m.fn[a][d] = true
	}
}

// formatCoords は 15 ビットのフォーマット情報が置かれる (x, y) 座標を、ビット毎に
// [コピー1, コピー2] の順で返す（ISO/IEC 18004 §7.9）。
func (m *matrix) formatCoords() [15][2][2]int {
	size := m.size
	var c [15][2][2]int
	for i := 0; i <= 5; i++ {
		c[i][0] = [2]int{8, i}
	}
	c[6][0] = [2]int{8, 7}
	c[7][0] = [2]int{8, 8}
	c[8][0] = [2]int{7, 8}
	for i := 9; i < 15; i++ {
		c[i][0] = [2]int{14 - i, 8}
	}
	for i := 0; i < 8; i++ {
		c[i][1] = [2]int{size - 1 - i, 8}
	}
	for i := 8; i < 15; i++ {
		c[i][1] = [2]int{8, size - 15 + i}
	}
	return c
}

// reserveFormat はフォーマット情報領域を機能パターンとして予約する（値は drawFormat で確定）。
func (m *matrix) reserveFormat() {
	for _, pair := range m.formatCoords() {
		for _, xy := range pair {
			m.fn[xy[1]][xy[0]] = true
		}
	}
}

// formatBits は EC レベルとマスク番号から 15 ビットのフォーマット情報
// （BCH(15,5)、生成多項式 0x537、マスク定数 0x5412）を返す。
func formatBits(level Level, mask int) int {
	data := formatECCBits[level]<<3 | mask
	rem := data
	for range 10 {
		rem = (rem << 1) ^ ((rem >> 9) * 0x537)
	}
	return (data<<10 | rem) ^ 0x5412
}

// drawFormat は EC レベルとマスク番号から 15 ビットのフォーマット情報を計算し配置する。
func (m *matrix) drawFormat(level Level, mask int) {
	bits := formatBits(level, mask)
	coords := m.formatCoords()
	for i := 0; i < 15; i++ {
		b := (bits>>i)&1 == 1
		for _, xy := range coords[i] {
			m.mod[xy[1]][xy[0]] = b
		}
	}
}

// placeData はデータ+EC のビット列を、右下から 2 列ずつ上下ジグザグに配置する（§7.7）。
func (m *matrix) placeData(data []byte) {
	size := m.size
	bitIdx := 0
	for right := size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5 // 列 6（タイミング）をスキップ
		}
		for vert := 0; vert < size; vert++ {
			for j := 0; j < 2; j++ {
				x := right - j
				upward := (right+1)&2 == 0
				y := vert
				if upward {
					y = size - 1 - vert
				}
				if m.fn[y][x] {
					continue
				}
				if bitIdx < len(data)*8 {
					m.mod[y][x] = (data[bitIdx>>3]>>(7-bitIdx&7))&1 == 1
					bitIdx++
				}
			}
		}
	}
}

// --- マスク ---------------------------------------------------------------

// maskCondition は行 y・列 x がマスク番号 mask で反転対象かを返す（ISO/IEC 18004 §7.8.2）。
func maskCondition(mask, x, y int) bool {
	switch mask {
	case 0:
		return (y+x)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (y+x)%3 == 0
	case 4:
		return (y/2+x/3)%2 == 0
	case 5:
		return (y*x)%2+(y*x)%3 == 0
	case 6:
		return ((y*x)%2+(y*x)%3)%2 == 0
	default: // 7
		return ((y+x)%2+(y*x)%3)%2 == 0
	}
}

// applyMask はマスク番号 mask を機能パターン以外のモジュールに XOR 適用する（2 回で復元）。
func (m *matrix) applyMask(mask int) {
	for y := 0; y < m.size; y++ {
		for x := 0; x < m.size; x++ {
			if !m.fn[y][x] && maskCondition(mask, x, y) {
				m.mod[y][x] = !m.mod[y][x]
			}
		}
	}
}

// applyBestMask は 8 種のマスクを評価しペナルティ最小のものを確定適用する。
func (m *matrix) applyBestMask(level Level) int {
	best, bestPenalty := 0, 1<<30
	for mask := 0; mask < 8; mask++ {
		m.applyMask(mask)
		m.drawFormat(level, mask)
		if p := m.penalty(); p < bestPenalty {
			bestPenalty, best = p, mask
		}
		m.applyMask(mask) // 元へ戻す
	}
	m.applyMask(best)
	m.drawFormat(level, best)
	return best
}

// penalty は 4 規則の合計ペナルティを返す（ISO/IEC 18004 §7.8.3）。
func (m *matrix) penalty() int {
	return m.penaltyRule1() + m.penaltyRule2() + m.penaltyRule3() + m.penaltyRule4()
}

// penaltyRule1 は行・列方向の同色連続に対するペナルティ（5 連続で +3、以降 +1/マス）。
func (m *matrix) penaltyRule1() int {
	p := 0
	run := func(same bool, r *int) {
		if same {
			*r++
			return
		}
		if *r >= 5 {
			p += *r - 2
		}
		*r = 1
	}
	for y := 0; y < m.size; y++ {
		r := 1
		for x := 1; x < m.size; x++ {
			run(m.mod[y][x] == m.mod[y][x-1], &r)
		}
		if r >= 5 {
			p += r - 2
		}
	}
	for x := 0; x < m.size; x++ {
		r := 1
		for y := 1; y < m.size; y++ {
			run(m.mod[y][x] == m.mod[y-1][x], &r)
		}
		if r >= 5 {
			p += r - 2
		}
	}
	return p
}

// penaltyRule2 は 2×2 の同色ブロックごとに +3。
func (m *matrix) penaltyRule2() int {
	p := 0
	for y := 0; y < m.size-1; y++ {
		for x := 0; x < m.size-1; x++ {
			v := m.mod[y][x]
			if v == m.mod[y][x+1] && v == m.mod[y+1][x] && v == m.mod[y+1][x+1] {
				p += 3
			}
		}
	}
	return p
}

// rule3PatternA/B はファインダ類似パターン（暗:明:暗暗暗:明:暗 の前後に 4 明）。各出現で +40。
var (
	rule3PatternA = [11]bool{true, false, true, true, true, false, true, false, false, false, false}
	rule3PatternB = [11]bool{false, false, false, false, true, false, true, true, true, false, true}
)

// penaltyRule3 は行・列上の rule3 パターン出現ごとに +40。
func (m *matrix) penaltyRule3() int {
	p := 0
	at := func(get func(k int) bool, i int) bool {
		matchA, matchB := true, true
		for k := 0; k < 11; k++ {
			v := get(i + k)
			if v != rule3PatternA[k] {
				matchA = false
			}
			if v != rule3PatternB[k] {
				matchB = false
			}
		}
		return matchA || matchB
	}
	for y := 0; y < m.size; y++ {
		for x := 0; x+11 <= m.size; x++ {
			if at(func(k int) bool { return m.mod[y][k] }, x) {
				p += 40
			}
		}
	}
	for x := 0; x < m.size; x++ {
		for y := 0; y+11 <= m.size; y++ {
			if at(func(k int) bool { return m.mod[k][x] }, y) {
				p += 40
			}
		}
	}
	return p
}

// penaltyRule4 は暗モジュール比率の 50% からの偏りに対するペナルティ（5% ステップ毎に +10）。
func (m *matrix) penaltyRule4() int {
	dark := 0
	for y := range m.mod {
		for x := range m.mod[y] {
			if m.mod[y][x] {
				dark++
			}
		}
	}
	total := m.size * m.size
	k := 0
	for dark*20 < (9-2*k)*total || dark*20 > (11+2*k)*total {
		k++
	}
	return k * 10
}

// abs は整数の絶対値。
func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
