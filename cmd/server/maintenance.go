package main

import (
	"context"
	"time"
)

// maintainer は定期メンテナンスの対象。*hub.Hub が満たす。
type maintainer interface {
	// Sweep は制限時間超過・純アイドル超過のルームを解散し通知を配送する。
	Sweep(now time.Time)
	// ExpirePending は無応答の参加申請を失効させ通知を配送する。
	ExpirePending(now time.Time)
}

// runMaintenance は interval ごとに Sweep と ExpirePending を駆動する。ctx.Done で終了する。
// ゴルーチンリーク防止のため、必ず親のライフサイクルにひも付いた ctx を渡すこと。
func runMaintenance(ctx context.Context, m maintainer, interval time.Duration, now func() time.Time) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t := now()
			m.Sweep(t)
			m.ExpirePending(t)
		}
	}
}
