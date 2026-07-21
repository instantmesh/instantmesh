package main

import (
	"log/slog"

	"github.com/instantmesh/instantmesh/pkg/secret"
)

// newSecret はバイト列 b の所有権を取り、可能なら OS のメモリロック（Linux/macOS: mlock、
// Windows: VirtualLock）でスワップ流出を防ぐ secret.Value にラップする。
//
// メモリロックに失敗しても（非特権・RLIMIT_MEMLOCK 制限・未対応OS など）ロックなしで続行する。
// スワップ抑止は best-effort であり、より本質的な防御（秘密鍵をディスクに保存しない・使用後に
// ゼロ化する）は Value 自体が維持するためである。呼び出し側は使用後に Wipe() でゼロ化すること。
//
// OS 依存のロック実装（newLocker）は build tag 別ファイル（memlock_{unix,windows,other}.go）が
// 提供する。cmd/client は I/O アダプタ層のため 100% カバレッジ対象外だが、クロスビルドで
// 各 OS の型崩れを検知する。
func newSecret(b []byte) *secret.Value {
	v := secret.New(b)
	if locker := newLocker(); locker != nil {
		if err := v.Lock(locker); err != nil {
			slog.Warn("秘密鍵のメモリロックに失敗（ロックなしで続行します）", "err", err)
		}
	}
	return v
}
