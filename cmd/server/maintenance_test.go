package main

import (
	"context"
	"sync"
	"testing"
	"time"
)

type fakeMaintainer struct {
	mu      sync.Mutex
	sweeps  int
	expires int
	ch      chan struct{}
}

func (f *fakeMaintainer) Sweep(time.Time) {
	f.mu.Lock()
	f.sweeps++
	f.mu.Unlock()
	select {
	case f.ch <- struct{}{}:
	default:
	}
}

func (f *fakeMaintainer) ExpirePending(time.Time) {
	f.mu.Lock()
	f.expires++
	f.mu.Unlock()
}

func TestRunMaintenance(t *testing.T) {
	f := &fakeMaintainer{ch: make(chan struct{}, 8)}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		runMaintenance(ctx, f, time.Millisecond, time.Now)
		close(done)
	}()

	// 数回ティックするのを待つ（ticker.C 分岐）。
	for i := 0; i < 2; i++ {
		select {
		case <-f.ch:
		case <-time.After(2 * time.Second):
			t.Fatal("メンテナンスがティックしない")
		}
	}

	// ctx キャンセルで終了すること（ctx.Done 分岐）。
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("ctx キャンセルで runMaintenance が終了しない")
	}

	f.mu.Lock()
	defer f.mu.Unlock()
	if f.sweeps == 0 || f.expires == 0 {
		t.Errorf("Sweep/ExpirePending が呼ばれるべき: sweeps=%d expires=%d", f.sweeps, f.expires)
	}
}
