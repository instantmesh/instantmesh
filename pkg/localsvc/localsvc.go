// Package localsvc は共有候補となるローカルサービスの既知ポート表と、プローブ結果・手動指定から
// 共有候補一覧を組み立てる純粋ロジックを提供する（要件定義書 §4.6.1）。
//
// 実際のプローブ（TCP connect）は OS の I/O を伴うため cmd/client が担い、本パッケージは
// 「どのポートを走査すべきか」「開いていたポートをどう提示するか」だけを決める。pkg/stun が
// メッセージの生成/解析のみを担い実送受信を cmd/ に委ねるのと同じ分割（要件 §4.6.5）。
//
// 設計原則8（pkg/ に製品固有・プロトコル固有の知識を持ち込まない）との関係: 本パッケージが持つのは
// 「ポート番号 → 表示ラベル」という表と、その決定的な並び順だけである。Ollama や MCP の
// アプリ層プロトコルは一切解釈しない。表が空でもメッシュは成立する（候補提示が空になり、ホストが
// ポートを直接指定する導線に落ちるだけ）ため、汎用コアの境界を越えない。
package localsvc

import (
	"errors"
	"fmt"
	"sort"
)

// ポート番号の有効範囲。
const (
	MinPort = 1
	MaxPort = 65535
)

// ErrInvalidPort は有効範囲外のポート番号を渡した場合に返る。
var ErrInvalidPort = errors.New("localsvc: port out of range")

// KnownService は既知ポートと、その表示ラベル（ホストの画面に出す候補名）。
type KnownService struct {
	// Port は走査対象のポート番号。
	Port int
	// Label は候補提示に使う表示名。プロトコル解釈は伴わない単なる目印であり、
	// 当該ポートで実際に動いているソフトが何かを保証するものではない。
	Label string
}

// knownServices は要件 §4.6.1 の既知ポート表（初期値）。この並びが候補一覧の表示順にもなる
// （ローカルAI 用途で選ばれる可能性が高い順）。
var knownServices = []KnownService{
	{Port: 11434, Label: "Ollama"},
	{Port: 1234, Label: "LM Studio"},
	{Port: 8000, Label: "vLLM"},
	{Port: 8080, Label: "Open WebUI"},
	{Port: 3000, Label: "開発サーバー"},
	{Port: 80, Label: "Dify"},
}

// KnownServices は既知ポート表のコピーを返す。呼び出し側の変更が表へ波及しないようコピーを返す。
func KnownServices() []KnownService {
	out := make([]KnownService, len(knownServices))
	copy(out, knownServices)
	return out
}

// ScanPorts は検出のために走査すべきポート番号を、既知ポート表の順で返す。
func ScanPorts() []int {
	out := make([]int, len(knownServices))
	for i, k := range knownServices {
		out[i] = k.Port
	}
	return out
}

// LabelFor は既知ポートの表示ラベルを返す。表にないポートは ok=false。
func LabelFor(port int) (string, bool) {
	for _, k := range knownServices {
		if k.Port == port {
			return k.Label, true
		}
	}
	return "", false
}

// ValidatePort はポート番号が有効範囲（1..65535）にあるかを検証する。
func ValidatePort(port int) error {
	if port < MinPort || port > MaxPort {
		return fmt.Errorf("localsvc: ポート %d: %w", port, ErrInvalidPort)
	}
	return nil
}

// Candidate は共有候補 1 件。共有するか否かはホストの明示選択であり、本構造体は候補提示のための
// 表示データに過ぎない（要件 §4.6.1）。
// json タグは pkg/appstate のビューモデルと同様、GUI の LocalAPI がそのまま配信するため付与する。
type Candidate struct {
	// Port は候補のポート番号。
	Port int `json:"port"`
	// Label は既知ポートの表示ラベル。表にないポートは空文字。
	Label string `json:"label,omitempty"`
	// Detected はプローブで待受を確認済みかどうか。手動指定のみの候補は false。
	Detected bool `json:"detected"`
}

// Candidates はプローブで開いていたポート open と、ホストが直接指定したポート manual をマージし、
// 決定的な表示順で候補一覧を返す。
//
// 表示順は「既知ポート表の順 → 表にないポートの昇順」。同じポートが open と manual の双方に
// 現れた場合は 1 件にまとめ Detected=true とする（各引数内の重複も 1 件に畳む）。
// 有効範囲外のポートが含まれる場合は ErrInvalidPort を包んだエラーを返す。
func Candidates(open, manual []int) ([]Candidate, error) {
	detected := make(map[int]bool, len(open)+len(manual))
	for _, p := range open {
		if err := ValidatePort(p); err != nil {
			return nil, err
		}
		detected[p] = true
	}
	for _, p := range manual {
		if err := ValidatePort(p); err != nil {
			return nil, err
		}
		if _, ok := detected[p]; !ok {
			detected[p] = false
		}
	}

	out := make([]Candidate, 0, len(detected))
	// 既知ポートを表の順で先に並べる。
	for _, k := range knownServices {
		d, ok := detected[k.Port]
		if !ok {
			continue
		}
		out = append(out, Candidate{Port: k.Port, Label: k.Label, Detected: d})
		delete(detected, k.Port)
	}
	// 残り（表にないポート）を昇順で並べる。
	rest := make([]int, 0, len(detected))
	for p := range detected {
		rest = append(rest, p)
	}
	sort.Ints(rest)
	for _, p := range rest {
		out = append(out, Candidate{Port: p, Detected: detected[p]})
	}
	return out, nil
}
