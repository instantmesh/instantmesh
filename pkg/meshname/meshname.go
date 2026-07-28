// Package meshname はメッシュ内の名前空間（`<サービス>.<ホスト>.mesh`）の定義と、
// 名前 ⇄ メッシュIP の写像（Zone）を提供する純粋ロジック（要件定義書 §4.6.3）。
//
// 「権威はホスト、解決はローカル」の後半（解決）を担う土台。ホストが定義した写像は既存の
// シグナリング経路（pkg/signaling の PeerInfo）で配布され、各クライアントが自プロセス内に
// 持つ Zone へ取り込む。Zone を引く DNS レスポンダは pkg/dnsmsg（メッセージの解析/組み立て）と
// cmd/client（UDP ソケットと OS への split DNS 注入）が担い、本パッケージは I/O を持たない。
//
// 設計原則8 との関係: 本パッケージが知っているのは「メッシュのピアに名前を付けられる」ことまでで、
// Ollama・MCP といった製品名やアプリ層プロトコルは一切知らない。どのサービスにどの名前を割り当てる
// かは上位（pkg/localsvc の既知ポート表と cmd/client）が決める。
//
// 信頼の位置づけ: 名前はホストの自己申告であり、ニックネーム（pkg/nickname）と同じく未検証の
// 表示データである。信頼の根拠は公開鍵の帯域外照合（SAS）であって名前ではない（§4.6.3）。
// したがって Zone へ取り込む前に、シグナリング経由で受け取った名前を必ず本パッケージで検証する。
package meshname

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// 名前空間の定数。
const (
	// Suffix はメッシュ名前空間の TLD。mDNS が予約する `.local` は使わない（§4.6.3）。
	Suffix = "mesh"
	// MaxLabelLen は 1 ラベルの最大長（RFC 1035）。
	MaxLabelLen = 63
	// MaxNameLen は FQDN 全体の最大長（RFC 1035 の 255 バイトから長さ表現分を除いた実効値）。
	MaxNameLen = 253
	// MaxNamesPerPeer は 1 ピアが広告できる名前数の上限。名前は信頼できない入力であり、
	// 無制限に受け取ると Zone とシグナリング中継が肥大するため上限を設ける。
	// pkg/signaling 側の中継上限（MaxPeerNames）と同値に保つこと。
	MaxNamesPerPeer = 32
)

// エラー。
var (
	// ErrInvalidLabel はラベルが LDH 規則（英小文字・数字・ハイフン／先頭末尾はハイフン不可）に反する。
	ErrInvalidLabel = errors.New("meshname: invalid label")
	// ErrNotInZone は名前が `.mesh` 名前空間の外にある。
	ErrNotInZone = errors.New("meshname: name is outside the mesh zone")
	// ErrNameTooLong は FQDN が MaxNameLen を超える。
	ErrNameTooLong = errors.New("meshname: name too long")
	// ErrTooManyNames は 1 ピアの名前数が MaxNamesPerPeer を超える。
	ErrTooManyNames = errors.New("meshname: too many names")
	// ErrNameConflict は既に別アドレスへ束縛済みの名前を要求した（先着優先）。
	ErrNameConflict = errors.New("meshname: name already bound to another address")
	// ErrInvalidAddr は無効なアドレス（ゼロ値等）を束縛しようとした。
	ErrInvalidAddr = errors.New("meshname: invalid address")
)

// Normalize は名前を比較・格納のための正規形（英小文字・末尾ドットなし）へ変換する。
// DNS 名は大文字小文字を区別しないため、Zone のキーと照合はこの正規形で行う。
func Normalize(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// ValidateLabel は 1 ラベルが LDH 規則を満たすか検証する。名前は自己申告の表示データとして
// UI にも出るため、ホモグラフや制御文字を持ち込ませないよう英小文字・数字・ハイフンに限定する。
func ValidateLabel(label string) error {
	if label == "" || len(label) > MaxLabelLen {
		return fmt.Errorf("meshname: ラベル %q: %w", label, ErrInvalidLabel)
	}
	if label[0] == '-' || label[len(label)-1] == '-' {
		return fmt.Errorf("meshname: ラベル %q: %w", label, ErrInvalidLabel)
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			continue
		}
		return fmt.Errorf("meshname: ラベル %q: %w", label, ErrInvalidLabel)
	}
	return nil
}

// InZone は名前がメッシュ名前空間（`*.mesh`）に属するかを返す。`mesh` 単体（ラベル無し）は
// 属さないものとして扱う。判定は正規化後に行う。
func InZone(name string) bool {
	n := Normalize(name)
	return strings.HasSuffix(n, "."+Suffix) && len(n) > len(Suffix)+1
}

// ValidateName は FQDN がメッシュ名前空間の妥当な名前かを検証し、正規形を返す。
func ValidateName(name string) (string, error) {
	n := Normalize(name)
	if len(n) > MaxNameLen {
		return "", fmt.Errorf("meshname: 名前 %q: %w", name, ErrNameTooLong)
	}
	if !InZone(n) {
		return "", fmt.Errorf("meshname: 名前 %q: %w", name, ErrNotInZone)
	}
	for _, label := range strings.Split(strings.TrimSuffix(n, "."+Suffix), ".") {
		if err := ValidateLabel(label); err != nil {
			return "", err
		}
	}
	return n, nil
}

// FQDN はラベル列から `<labels...>.mesh` の FQDN を組み立てる。例: FQDN("ollama", "tanaka") →
// "ollama.tanaka.mesh"。各ラベルは LDH 規則で検証する。
func FQDN(labels ...string) (string, error) {
	if len(labels) == 0 {
		return "", fmt.Errorf("meshname: ラベルがありません: %w", ErrInvalidLabel)
	}
	for _, l := range labels {
		if err := ValidateLabel(l); err != nil {
			return "", err
		}
	}
	name := strings.Join(labels, ".") + "." + Suffix
	if len(name) > MaxNameLen {
		return "", fmt.Errorf("meshname: 名前 %q: %w", name, ErrNameTooLong)
	}
	return name, nil
}

// Sanitize は任意の文字列（OS のホスト名・サービスの表示ラベル等）から LDH ラベルを導出する。
// 英小文字化し、[a-z0-9] 以外をハイフンへ畳んだうえで、連続ハイフンの圧縮・前後ハイフンの除去・
// MaxLabelLen への切り詰めを行う。ラベルとして成立しない場合（例: 日本語のみ）は空文字を返すので、
// 呼び出し側が代替（ポート番号由来の名前等）を決める。
func Sanitize(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			// 連続する非 LDH 文字は 1 個のハイフンへ畳む（先頭のハイフンは出力しない）。
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > MaxLabelLen {
		out = strings.Trim(out[:MaxLabelLen], "-")
	}
	return out
}

// ValidateNames は 1 ピアが広告してきた名前群を検証し、正規化・重複除去した一覧を返す。
// シグナリング経由で受け取った信頼できない入力は、Zone へ取り込む前に必ずこれを通す。
// 並び順は入力順を保つ（表示の決定性のため）。
func ValidateNames(names []string) ([]string, error) {
	if len(names) > MaxNamesPerPeer {
		return nil, fmt.Errorf("meshname: %d 件: %w", len(names), ErrTooManyNames)
	}
	out := make([]string, 0, len(names))
	seen := make(map[string]bool, len(names))
	for _, raw := range names {
		n, err := ValidateName(raw)
		if err != nil {
			return nil, err
		}
		if seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	return out, nil
}

// Entry は Zone の 1 件（名前とその解決先）。
type Entry struct {
	Name string     `json:"name"`
	Addr netip.Addr `json:"addr"`
}

// Zone は名前 ⇄ メッシュIP の写像。ローカルの DNS レスポンダ（cmd/client）が読み、シグナリング
// 受信ループが書くためゴルーチンセーフにする（pkg/manager と同じ方針）。
//
// 権威範囲は `.mesh` 全体であり、登録の無い `*.mesh` は「存在しない名前」として扱える
// （呼び出し側は NXDOMAIN を返せる）。`.mesh` 外は権威を持たない（REFUSED を返せる）。
type Zone struct {
	mu     sync.RWMutex
	byName map[string]netip.Addr
}

// NewZone は空の Zone を返す。
func NewZone() *Zone {
	return &Zone{byName: make(map[string]netip.Addr)}
}

// Replace は addr に束縛する名前群を names で置き換える（当該アドレスの旧登録は消える）。
// ピアが peer_info を再送するたびに呼ぶことを想定し、部分適用を避けて全件検証してから入れ替える。
//
// 別アドレスへ既に束縛されている名前が含まれる場合は ErrNameConflict を返し、Zone を変更しない
// （先着優先）。名前は自己申告であり、後から参加したピアが既存の名前を乗っ取れてはならないため。
func (z *Zone) Replace(addr netip.Addr, names []string) error {
	if !addr.IsValid() {
		return fmt.Errorf("meshname: %v: %w", addr, ErrInvalidAddr)
	}
	valid, err := ValidateNames(names)
	if err != nil {
		return err
	}

	z.mu.Lock()
	defer z.mu.Unlock()
	for _, n := range valid {
		if cur, ok := z.byName[n]; ok && cur != addr {
			return fmt.Errorf("meshname: 名前 %q は %v に束縛済み: %w", n, cur, ErrNameConflict)
		}
	}
	z.removeAddrLocked(addr)
	for _, n := range valid {
		z.byName[n] = addr
	}
	return nil
}

// Remove は addr に束縛された名前をすべて取り除く（ピアの離脱・キック時に呼ぶ）。
func (z *Zone) Remove(addr netip.Addr) {
	z.mu.Lock()
	defer z.mu.Unlock()
	z.removeAddrLocked(addr)
}

// removeAddrLocked は addr の登録を削除する（呼び出し側でロック済みであること）。
func (z *Zone) removeAddrLocked(addr netip.Addr) {
	for n, a := range z.byName {
		if a == addr {
			delete(z.byName, n)
		}
	}
}

// Authoritative は当該名前について自身が権威かを返す（`.mesh` 名前空間の内か）。
// dnsmsg.Resolver の一部。権威外のクエリには応答せず REFUSED を返すために使う。
func (z *Zone) Authoritative(name string) bool {
	return InZone(name)
}

// Lookup は名前に対応するアドレスを返す。未登録は ok=false。dnsmsg.Resolver の一部。
func (z *Zone) Lookup(name string) (netip.Addr, bool) {
	n := Normalize(name)
	z.mu.RLock()
	defer z.mu.RUnlock()
	addr, ok := z.byName[n]
	return addr, ok
}

// Entries は登録済みの全件を名前の昇順で返す（表示・テストの決定性のため）。
func (z *Zone) Entries() []Entry {
	z.mu.RLock()
	defer z.mu.RUnlock()
	out := make([]Entry, 0, len(z.byName))
	for n, a := range z.byName {
		out = append(out, Entry{Name: n, Addr: a})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
