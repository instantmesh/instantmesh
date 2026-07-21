package qr

// 本ファイルは QR コード（Model 2）のバージョン別・誤り訂正レベル別の特性テーブルを保持する。
// 値は ISO/IEC 18004 §7.5.1 Table 9（誤り訂正特性）および §附属書 E（アライメントパターン位置）に基づく。
//
// 本実装が対象とするのはバージョン 1〜10 のバイトモードのみ（招待 URL 用途に十分。V10 の
// 最小 EC レベル L で 271 バイト格納可能）。範囲外は ErrTooLong を返す。

// Level は誤り訂正レベル（データ復元能力の強さ）。値が大きいほど冗長で堅牢だが容量は減る。
type Level int

const (
	// Low は約 7% の復元能力（最大容量）。
	Low Level = iota
	// Medium は約 15% の復元能力。招待 QR の既定。
	Medium
	// Quartile は約 25% の復元能力。
	Quartile
	// High は約 30% の復元能力（最小容量）。
	High
)

// formatECCBits はフォーマット情報に埋め込む EC レベル指標（2 ビット）。
// ISO/IEC 18004 Table 12。数値順（L<M<Q<H）とはビット割当が異なる点に注意。
var formatECCBits = [4]int{
	Low:      0b01,
	Medium:   0b00,
	Quartile: 0b11,
	High:     0b10,
}

// ecBlocks は 1 バージョン・1 EC レベルのブロック構成を表す。
// データコードワードは group1（各 group1Data 語のブロックが group1Blocks 個）と
// group2（各 group2Data 語のブロックが group2Blocks 個）に分割され、各ブロックへ
// 個別に ecPerBlock 語の EC を付す（ISO/IEC 18004 §7.5.1）。
type ecBlocks struct {
	ecPerBlock   int
	group1Blocks int
	group1Data   int
	group2Blocks int
	group2Data   int
}

// numBlocks はブロック総数。
func (e ecBlocks) numBlocks() int { return e.group1Blocks + e.group2Blocks }

// dataCodewords はデータコードワード総数。
func (e ecBlocks) dataCodewords() int {
	return e.group1Blocks*e.group1Data + e.group2Blocks*e.group2Data
}

// versionSpec は 1 バージョンの仕様。totalCodewords はデータ + EC の総コードワード数で、
// 各 EC レベルの dataCodewords + numBlocks*ecPerBlock と一致する（テストで検算する）。
type versionSpec struct {
	totalCodewords int
	align          []int // アライメントパターンの中心座標候補（昇順）。V1 は空。
	ec             [4]ecBlocks
}

// versions は index = バージョン番号（1〜10）の仕様表。index 0 はダミー。
var versions = [maxVersion + 1]versionSpec{
	1: {
		totalCodewords: 26,
		align:          nil,
		ec: [4]ecBlocks{
			Low:      {7, 1, 19, 0, 0},
			Medium:   {10, 1, 16, 0, 0},
			Quartile: {13, 1, 13, 0, 0},
			High:     {17, 1, 9, 0, 0},
		},
	},
	2: {
		totalCodewords: 44,
		align:          []int{6, 18},
		ec: [4]ecBlocks{
			Low:      {10, 1, 34, 0, 0},
			Medium:   {16, 1, 28, 0, 0},
			Quartile: {22, 1, 22, 0, 0},
			High:     {28, 1, 16, 0, 0},
		},
	},
	3: {
		totalCodewords: 70,
		align:          []int{6, 22},
		ec: [4]ecBlocks{
			Low:      {15, 1, 55, 0, 0},
			Medium:   {26, 1, 44, 0, 0},
			Quartile: {18, 2, 17, 0, 0},
			High:     {22, 2, 13, 0, 0},
		},
	},
	4: {
		totalCodewords: 100,
		align:          []int{6, 26},
		ec: [4]ecBlocks{
			Low:      {20, 1, 80, 0, 0},
			Medium:   {18, 2, 32, 0, 0},
			Quartile: {26, 2, 24, 0, 0},
			High:     {16, 4, 9, 0, 0},
		},
	},
	5: {
		totalCodewords: 134,
		align:          []int{6, 30},
		ec: [4]ecBlocks{
			Low:      {26, 1, 108, 0, 0},
			Medium:   {24, 2, 43, 0, 0},
			Quartile: {18, 2, 15, 2, 16},
			High:     {22, 2, 11, 2, 12},
		},
	},
	6: {
		totalCodewords: 172,
		align:          []int{6, 34},
		ec: [4]ecBlocks{
			Low:      {18, 2, 68, 0, 0},
			Medium:   {16, 4, 27, 0, 0},
			Quartile: {24, 4, 19, 0, 0},
			High:     {28, 4, 15, 0, 0},
		},
	},
	7: {
		totalCodewords: 196,
		align:          []int{6, 22, 38},
		ec: [4]ecBlocks{
			Low:      {20, 2, 78, 0, 0},
			Medium:   {18, 4, 31, 0, 0},
			Quartile: {18, 2, 14, 4, 15},
			High:     {26, 4, 13, 1, 14},
		},
	},
	8: {
		totalCodewords: 242,
		align:          []int{6, 24, 42},
		ec: [4]ecBlocks{
			Low:      {24, 2, 97, 0, 0},
			Medium:   {22, 2, 38, 2, 39},
			Quartile: {22, 4, 18, 2, 19},
			High:     {26, 4, 14, 2, 15},
		},
	},
	9: {
		totalCodewords: 292,
		align:          []int{6, 26, 46},
		ec: [4]ecBlocks{
			Low:      {30, 2, 116, 0, 0},
			Medium:   {22, 3, 36, 2, 37},
			Quartile: {20, 4, 16, 4, 17},
			High:     {24, 4, 12, 4, 13},
		},
	},
	10: {
		totalCodewords: 346,
		align:          []int{6, 28, 50},
		ec: [4]ecBlocks{
			Low:      {18, 2, 68, 2, 69},
			Medium:   {26, 4, 43, 1, 44},
			Quartile: {24, 6, 19, 2, 20},
			High:     {28, 6, 15, 2, 16},
		},
	},
}

// maxVersion は本実装が対応する最大 QR バージョン。
const maxVersion = 10
