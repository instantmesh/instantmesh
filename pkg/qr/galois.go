package qr

// 本ファイルは QR コードの誤り訂正に用いるガロア体 GF(256) 上の算術と
// Reed-Solomon 符号（EC コードワード生成）を実装する純粋ロジック。
//
// QR コード（ISO/IEC 18004 §7.5）は原始多項式 x^8 + x^4 + x^3 + x^2 + 1（= 0x11D）で
// 定義される GF(256) を用い、生成元は α = 2（0x02）。乗算は指数（log/antilog）テーブルで
// 行う。時刻・乱数に依存しない決定的な変換であり、テストシームは不要。

// gfExp は α^i（i = 0..254）を与える指数テーブル。加算をラップ不要にするため
// 255..509 に折り返し分を複製し、log 同士の和をそのまま添字に使えるようにする。
var gfExp [512]byte

// gfLog は逆写像（値 → 指数）。gfLog[0] は未定義（0 は乗算の吸収元として別扱い）。
var gfLog [256]byte

func init() {
	x := 1
	for i := 0; i < 255; i++ {
		gfExp[i] = byte(x)
		gfLog[byte(x)] = byte(i)
		x <<= 1
		if x&0x100 != 0 { // 8 ビットをはみ出したら原始多項式で法を取る
			x ^= 0x11D
		}
	}
	for i := 255; i < 512; i++ {
		gfExp[i] = gfExp[i-255]
	}
}

// gfMul は GF(256) 上の乗算。いずれかが 0 なら 0、そうでなければ log の和で求める。
func gfMul(a, b byte) byte {
	if a == 0 || b == 0 {
		return 0
	}
	return gfExp[int(gfLog[a])+int(gfLog[b])]
}

// rsDivisor は次数 degree の Reed-Solomon 生成多項式 g(x) = ∏_{i=0}^{degree-1}(x - α^i) の
// 係数を昇冪で返す（最高次の係数 1 は暗黙とし配列には含めない。長さ = degree）。
func rsDivisor(degree int) []byte {
	result := make([]byte, degree)
	result[degree-1] = 1 // 定数項 1 から開始（次数 0 の多項式）
	root := byte(1)       // α^0, α^1, ... と根を進める
	for range degree {
		// result(x) に (x - α^root) を掛ける。係数を 1 つ上の次数へ繰り上げつつ根を掛ける。
		for j := 0; j < degree; j++ {
			result[j] = gfMul(result[j], root)
			if j+1 < degree {
				result[j] ^= result[j+1]
			}
		}
		root = gfMul(root, 0x02)
	}
	return result
}

// rsRemainder は data を生成多項式 divisor で割った剰余（= EC コードワード列）を返す。
// 長さは len(divisor)。多項式の長除算を LFSR 状に実装する（ISO/IEC 18004 §7.5.2）。
func rsRemainder(data, divisor []byte) []byte {
	result := make([]byte, len(divisor))
	for _, b := range data {
		factor := b ^ result[0]
		copy(result, result[1:])
		result[len(result)-1] = 0
		for i, coef := range divisor {
			result[i] ^= gfMul(coef, factor)
		}
	}
	return result
}

// rsEncode は data に対する ecLen 個の EC コードワードを返す（呼び出し側の利便関数）。
func rsEncode(data []byte, ecLen int) []byte {
	return rsRemainder(data, rsDivisor(ecLen))
}
