// Package accesskey はゲストごとのアクセスキー（要件定義書 §4.7・有料プラン機能）の発行・検証・
// 失効を提供する純粋ロジック。
//
// 解決する課題: Ollama・LM Studio 等のローカル推論エンドポイントには**認証機構が無い**ため、
// ポートに到達できた者は誰でも叩ける（§1.1）。メッシュへの参加は待合室承認で制御できるが、
// 「参加は許すがこのサービスは貸さない」「このゲストの利用だけ止める」を表現できない。
// そこで共有サービスの前段に、ゲストごとに異なるキーを要求する層を置く。
//
// キーの性質:
//   - キーの失効はキック（メッシュからの遮断）と**独立**に行える（§4.7）。参加は維持したまま
//     特定サービスの利用だけを止められる。
//   - 検証は総当たりの定数時間比較で行う。ゲスト数は上限 20（§5）と小さく、キーの内容に
//     依存した早期脱出を作らないことを優先する。
//   - キーは秘密であり、メモリ内でのみ保持してディスクへ書かない（設計原則3）。本パッケージは
//     I/O を持たないため、この規約は利用側が守る。
//
// 本パッケージは HTTP 等の運搬方法を知らない。キーをどのヘッダで受け取るかは上位（cmd/client の
// L7 ゲート）が決める（設計原則1・8）。
package accesskey

import (
	"errors"
	"fmt"
	"sync"

	"github.com/instantmesh/instantmesh/pkg/token"
)

// ErrUnknownGuest は未発行のゲストを指定したことを表す。
var ErrUnknownGuest = errors.New("accesskey: no key issued for this guest")

// Registry はゲスト（公開鍵で識別）とアクセスキーの対応を保持する。GUI の操作ゴルーチンと
// 共有サービスの受け口（データパス）の双方から触られるためゴルーチンセーフにする。
type Registry struct {
	mu       sync.RWMutex
	byGuest  map[string]string // ゲスト公開鍵 → キー
	newToken func() (string, error)
}

// New は空のレジストリを返す。
func New() *Registry {
	return &Registry{byGuest: make(map[string]string), newToken: token.NewRoomToken}
}

// Issue はゲストへ新しいキーを発行して返す。既にキーがある場合は**再発行**となり、旧キーは
// 直ちに失効する（漏洩時の入れ替え手段）。
func (r *Registry) Issue(guest string) (string, error) {
	if guest == "" {
		return "", fmt.Errorf("accesskey: guest: %w", ErrUnknownGuest)
	}
	k, err := r.newToken()
	if err != nil {
		return "", fmt.Errorf("accesskey: 生成: %w", err)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byGuest[guest] = k
	return k, nil
}

// Verify はキーに対応するゲストを返す。未知のキーは ok=false。
//
// 比較は全エントリに対して定数時間で行い、一致した時点で打ち切らない。キーの前方一致長が
// 応答時間に現れないようにするため。
func (r *Registry) Verify(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	found, ok := "", false
	for guest, k := range r.byGuest {
		if token.Equal(k, key) {
			found, ok = guest, true
		}
	}
	return found, ok
}

// KeyFor はゲストの現在のキーを返す（表示・配布用）。未発行は ok=false。
func (r *Registry) KeyFor(guest string) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	k, ok := r.byGuest[guest]
	return k, ok
}

// Revoke はゲストのキーを失効させる。以後そのキーでは通らない。キックとは独立に呼べる。
func (r *Registry) Revoke(guest string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byGuest, guest)
}

// Snapshot は発行済みのゲスト → キーの対応を複製して返す（表示・配布用）。
// 1 回のロックで全件を写すため、呼び出し側がゲストを列挙して KeyFor を引き直す必要はない
// （並び順が要るなら呼び出し側で決める。表示の並びはゲスト一覧側の順序に従う）。
func (r *Registry) Snapshot() map[string]string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make(map[string]string, len(r.byGuest))
	for g, k := range r.byGuest {
		out[g] = k
	}
	return out
}

// Reset は全てのキーを失効させる（セッション終了時）。
func (r *Registry) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.byGuest)
}
