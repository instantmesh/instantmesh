// Package secret は秘密鍵などの機微なバイト列をメモリ上で安全に扱うための純粋ロジックを
// 提供する。ゼロ化（使用後の確実な消去）と、OS のメモリロック（スワップ流出防止）への
// フック（Locker）を備える。
//
// 設計方針（開発規約 §1.3・[[client-secret-management]]）:
//   - Go の string は不変でゼロ化できないため、ゼロ化が要る鍵素材は []byte で扱い、
//     使用後に本パッケージの Value.Wipe でゼロ化する。
//   - スワップ流出を防ぐメモリロック（Linux/macOS: mlock、Windows: VirtualLock）は OS 依存の
//     システムコールであり、本パッケージは Locker インターフェースとして抽象化する。実装は
//     利用側（cmd/client の build tag 別ファイル）が注入し、本パッケージ自体はトランスポート /
//     OS / UI に依存しない純粋ロジックである（フェイク注入で決定的にテストできる）。
package secret

import (
	"errors"
	"fmt"
	"runtime"
)

// errWiped は既にゼロ化済みの Value を操作しようとしたことを表す。
var errWiped = errors.New("secret: value already wiped")

// Locker は秘密バイト列をスワップ対象外に固定する OS 依存操作を抽象化する。
// Lock/Unlock は与えられた backing slice そのものに作用する（mlock/munlock は
// ページ単位のため、slice の指すメモリ範囲を含むページがロックされる）。
type Locker interface {
	// Lock は b の指すメモリをスワップ対象外に固定する。
	Lock(b []byte) error
	// Unlock は Lock で固定したメモリの固定を解除する。
	Unlock(b []byte) error
}

// Value は機微なバイト列を保持する。生成時に渡されたバイト列の所有権を取り（コピーしない）、
// Wipe でゼロ化する。任意で Lock によりスワップ流出を防ぐ。ゼロ値は使用不可（New で生成する）。
//
// ゴルーチンセーフではない。単一のゴルーチンから使うか、呼び出し側で同期すること。
type Value struct {
	buf    []byte
	locker Locker // Lock 成功時に保持し、Wipe が Unlock に使う
	wiped  bool
}

// New は b の所有権を取り（コピーしない）Value を返す。呼び出し側は b を以後直接参照せず、
// 使用後に Value.Wipe でゼロ化すること。b をコピーしないのは、コピーするとゼロ化されない
// 元バイト列がメモリに残ってしまうためである。
func New(b []byte) *Value {
	return &Value{buf: b}
}

// Lock は locker を用いて保持中のバイト列をスワップ対象外に固定する。成功すると locker を
// 保持し、Wipe が固定解除に用いる。失敗した場合はバイト列は固定されないまま使用可能な状態で
// 残り、エラーを返す（利用側がロックなしで続行するかを判断できる）。既にロック済みなら no-op、
// locker が nil なら no-op、既にゼロ化済みならエラーを返す。
func (v *Value) Lock(locker Locker) error {
	if v.wiped {
		return errWiped
	}
	if v.locker != nil {
		return nil
	}
	if locker == nil {
		return nil
	}
	if err := locker.Lock(v.buf); err != nil {
		return fmt.Errorf("secret: lock: %w", err)
	}
	v.locker = locker
	return nil
}

// Bytes は保持中のバイト列を返す。返り値は Wipe 以降参照してはならない。ゼロ化済みの Value に
// 対する呼び出しは（use-after-free に相当する誤用のため）panic する。
func (v *Value) Bytes() []byte {
	if v.wiped {
		panic("secret: use after wipe")
	}
	return v.buf
}

// Len は保持中のバイト列の長さを返す。
func (v *Value) Len() int { return len(v.buf) }

// Wipe はバイト列をゼロ化し、ロック済みなら固定を解除する。冪等（複数回呼んでよい）。
//
// 順序に注意: 先にゼロ化し、その後で固定を解除する。逆順（先に munlock）だと、munlock 完了から
// ゼロ化完了までの窓でメモリ逼迫が起きたとき、まだ平文の秘密を含むページがロック解除された状態で
// スワップアウトされうる。ロック中はページが非スワップであることが保証されるため、ロック中に
// ゼロ化を完了させてから解除することで、本パッケージの目的（スワップ流出防止）を保つ。
func (v *Value) Wipe() {
	if v.wiped {
		return
	}
	for i := range v.buf {
		v.buf[i] = 0
	}
	// ゼロ化書き込みが到達不能コードとして最適化除去されないことを保証する。
	runtime.KeepAlive(v.buf)
	if v.locker != nil {
		// 固定解除の失敗はゼロ化を妨げない（ベストエフォート）。ゼロ化完了後に解除する。
		_ = v.locker.Unlock(v.buf)
	}
	v.wiped = true
	v.locker = nil
}

// Wiped は Wipe 済みかどうかを返す。
func (v *Value) Wiped() bool { return v.wiped }

// String は秘密を漏らさないよう固定文字列を返す（ログ等での偶発的な露出を防ぐ）。
func (v *Value) String() string { return "secret.Value(redacted)" }
