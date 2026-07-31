// Package clientconf はクライアントのローカル設定（メッシュ名ラベルと共有するポートの選択）の
// 表現・正規化と、保存形式（JSON）の符号化/復号を提供する純粋ロジック（要件定義書 付録C.9 D-14）。
//
// 目的: 要件 §4.6.2 の「セッションをまたいで名前が安定する」を満たすため。ゲストは
// `http://ollama.tanaka.mesh:11434` を .env や手順書へ書くので、ホスト側の名前が起動ごとに
// 変わってはならない。共有するポートの選択も同じ理由で持ち越す。
//
// 保存してよいのは**利用者自身の表示設定のみ**。WireGuard 秘密鍵・招待トークン・アクセストークン・
// アクセスキーは一切含めない（設計原則3）。Config のフィールドを上記 2 項目に限定することで、
// 「書き出す対象に秘密が混ざらない」ことを型で保証する。
//
// 保存場所の決定と実ファイル I/O は cmd/client が担い、本パッケージは I/O を持たない
// （pkg/stun がメッセージの生成/解析のみを担い実送受信を cmd/ へ委ねるのと同じ分割）。
//
// エフェメラル訴求（§4.3）との関係: 消えるべきは「サーバー側のセッション」と「OS へ加えた変更」で
// あり、利用者自身の表示設定はこれに含まれない（付録C.9 D-14）。
package clientconf

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/instantmesh/instantmesh/pkg/localsvc"
	"github.com/instantmesh/instantmesh/pkg/meshname"
)

// Version は設定ファイル形式の現行バージョン。互換性を壊す変更を入れるときに繰り上げる。
// 新しい版で書かれた設定は Decode が ErrUnsupportedVersion で拒否するため、古い版の
// クライアントが誤解釈したり上書きで壊したりしない。
const Version = 1

// MaxSharedPorts は保存できる共有ポート数の上限。1 ピアが広告できる名前数の上限
// （meshname.MaxNamesPerPeer）から、ホスト自身の名前 1 件分を除いた残りに合わせる。
// これを超える選択は広告を組み立てられない（localsvc.Advertise が失敗する）ため、
// 保存の段階で切り詰める。
const MaxSharedPorts = meshname.MaxNamesPerPeer - 1

// ErrUnsupportedVersion は自身が解釈できない版の設定を読んだことを表す。
var ErrUnsupportedVersion = errors.New("clientconf: unsupported config version")

// Config はクライアントのローカル設定。**秘密を含めてはならない**（パッケージコメント参照）。
type Config struct {
	// Version は設定ファイル形式の版。Encode が常に現行版を書く。
	Version int `json:"version"`
	// MeshLabel はメッシュ名に使うホストラベル（例 "tanaka"）。空なら未設定＝呼び出し側が
	// 既定（OS のホスト名由来）を決める。
	MeshLabel string `json:"meshLabel,omitempty"`
	// SharedPorts は共有するローカルサービスのポート集合（ホストの明示選択の記録・§4.6.1）。
	// 並び順は選択順を保つ（広告・切り詰めの決定性のため）。
	SharedPorts []int `json:"sharedPorts,omitempty"`
}

// Normalize は保存・適用の前に値を正規形へ落とす。
//
//   - Version は現行版に揃える。
//   - MeshLabel は LDH ラベルへ落とす（meshname.Sanitize）。ラベルとして成立しない入力は
//     空文字＝未設定になり、呼び出し側の既定が使われる。
//   - SharedPorts は有効範囲外を捨て、重複を畳み、MaxSharedPorts へ切り詰める（順序は保つ）。
//
// 冪等であり、Normalize(Normalize(c)) == Normalize(c)。
func (c Config) Normalize() Config {
	out := Config{Version: Version, MeshLabel: meshname.Sanitize(c.MeshLabel)}
	seen := make(map[int]bool, len(c.SharedPorts))
	for _, p := range c.SharedPorts {
		if localsvc.ValidatePort(p) != nil || seen[p] {
			continue
		}
		seen[p] = true
		out.SharedPorts = append(out.SharedPorts, p)
		if len(out.SharedPorts) == MaxSharedPorts {
			break
		}
	}
	return out
}

// Encode は設定を保存用の JSON（末尾改行つき・人が読める整形）へ符号化する。書き出す値は
// 常に正規形で、現行版のバージョンを持つ。
//
// error を返さないのは、Config が基本型（int・string・[]int）のみで構成され json.Marshal が
// 失敗しえないため。呼び出し側に扱えない失敗を渡さない。
func Encode(c Config) []byte {
	data, _ := json.MarshalIndent(c.Normalize(), "", "  ")
	return append(data, '\n')
}

// Decode は保存された JSON を設定へ復元する。未知のフィールドは無視し（前方互換）、値は
// 正規化して返す。解釈できない版は ErrUnsupportedVersion を返す（呼び出し側は既定値で続行し、
// **上書き保存を控える**ことで新しい版の設定を壊さない）。
//
// version 欠落（0）は本形式の初版として扱う。
func Decode(data []byte) (Config, error) {
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return Config{}, fmt.Errorf("clientconf: 設定の解析: %w", err)
	}
	if c.Version < 0 || c.Version > Version {
		return Config{}, fmt.Errorf("clientconf: 版 %d（対応は %d まで）: %w", c.Version, Version, ErrUnsupportedVersion)
	}
	return c.Normalize(), nil
}
