package relay

import (
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/plan"
)

func TestUnlimitedPlan(t *testing.T) {
	m := NewMeter(plan.MustLookup(plan.Pro)) // RelayByteLimit=0（無制限）
	now := time.Now()

	for i := 0; i < 5; i++ {
		if !m.Allow(50<<20, now) {
			t.Fatalf("Pro は無制限で常に許可されるべき（%d 回目）", i+1)
		}
	}
	if m.Throttled() {
		t.Error("Pro はスロットルしないべき")
	}
}

func TestFreeUnderLimit(t *testing.T) {
	m := NewMeter(plan.MustLookup(plan.Free))
	now := time.Now()

	if !m.Allow(50<<20, now) {
		t.Fatal("上限未満は許可されるべき")
	}
	if m.Throttled() {
		t.Error("上限未満はスロットルしないべき")
	}
	if m.Total() != 50<<20 {
		t.Errorf("Total = %d, want %d", m.Total(), 50<<20)
	}
}

func TestFreeReachLimitThenThrottle(t *testing.T) {
	spec := plan.MustLookup(plan.Free)
	m := NewMeter(spec)
	now := time.Now()

	// 上限(100MB)をまたぐ転送も許可する（切断しない）。
	if !m.Allow(spec.RelayByteLimit, now) {
		t.Fatal("上限に到達する転送も許可されるべき")
	}
	if !m.Throttled() {
		t.Fatal("上限到達後はスロットル状態になるべき")
	}

	bps := spec.RelayThrottledBps / 8 // 8000 バイト/秒
	// 初回は 1 秒分のバーストが通る。
	if !m.Allow(bps, now) {
		t.Error("初回 1 秒分のバーストは許可されるべき")
	}
	// 補充なし（同一時刻）の追加は拒否。
	if m.Allow(bps, now) {
		t.Error("補充なしの追加送出は拒否されるべき")
	}
	// 1 秒後は再び 1 秒分許可。
	if !m.Allow(bps, now.Add(time.Second)) {
		t.Error("1 秒後は再度許可されるべき")
	}
}

func TestThrottleBurstCap(t *testing.T) {
	spec := plan.MustLookup(plan.Free)
	m := NewMeter(spec)
	now := time.Now()

	m.Allow(spec.RelayByteLimit, now) // 上限到達
	bps := spec.RelayThrottledBps / 8
	m.Allow(bps, now) // 初回バーストを消費（残 0）

	// 10 秒経過してもバーストは 1 秒分までしか蓄積しない。
	later := now.Add(10 * time.Second)
	if !m.Allow(bps, later) {
		t.Fatal("補充後 1 回分は許可されるべき")
	}
	if m.Allow(1, later) {
		t.Error("バーストは 1 秒分に制限され、超過分は蓄積してはならない")
	}
}
