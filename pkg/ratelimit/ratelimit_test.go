package ratelimit

import (
	"testing"
	"time"
)

func TestBurstThenDeny(t *testing.T) {
	l := New(1, 3) // 毎秒 1、バースト 3
	now := time.Now()

	for i := 0; i < 3; i++ {
		if !l.Allow("k", now) {
			t.Fatalf("バースト内 %d 回目は許可されるべき", i+1)
		}
	}
	if l.Allow("k", now) {
		t.Error("バースト超過は拒否されるべき")
	}
}

func TestRefillOverTime(t *testing.T) {
	l := New(1, 3)
	now := time.Now()

	for i := 0; i < 3; i++ {
		l.Allow("k", now)
	}
	if l.Allow("k", now) {
		t.Fatal("枯渇後は拒否されるべき")
	}
	// 1 秒後に 1 トークン回復。
	if !l.Allow("k", now.Add(time.Second)) {
		t.Error("1 秒後は 1 回許可されるべき")
	}
	if l.Allow("k", now.Add(time.Second)) {
		t.Error("回復分は 1 トークンのみのはず")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	l := New(1, 1)
	now := time.Now()

	if !l.Allow("a", now) {
		t.Fatal("a の初回は許可されるべき")
	}
	if !l.Allow("b", now) {
		t.Error("b は a と独立して許可されるべき")
	}
	if l.Allow("a", now) {
		t.Error("a の 2 回目は拒否されるべき")
	}
}

func TestReset(t *testing.T) {
	l := New(1, 1)
	now := time.Now()

	if !l.Allow("k", now) {
		t.Fatal("初回は許可されるべき")
	}
	if l.Allow("k", now) {
		t.Fatal("2 回目は枯渇で拒否されるべき")
	}
	l.Reset("k")
	if !l.Allow("k", now) {
		t.Error("Reset 後は満タンから再開し許可されるべき")
	}
}

func TestRefillClampsToBurst(t *testing.T) {
	l := New(1, 3)
	now := time.Now()

	for i := 0; i < 3; i++ {
		l.Allow("k", now)
	}
	if l.Allow("k", now) {
		t.Fatal("枯渇後は拒否されるべき")
	}

	// 長時間(10 秒)経過しても burst(3) を超えて蓄積しないこと。
	later := now.Add(10 * time.Second)
	for i := 0; i < 3; i++ {
		if !l.Allow("k", later) {
			t.Fatalf("補充後 %d 回目は許可されるべき", i+1)
		}
	}
	if l.Allow("k", later) {
		t.Error("burst 上限を超えて蓄積してはならない")
	}
}

func TestEvict(t *testing.T) {
	l := New(1, 3) // rate 1/s, burst 3
	now := time.Now()

	l.Allow("partial", now) // bucket 生成(3) → 1 消費 → 2 残（未満タン）
	for i := 0; i < 3; i++ {
		l.Allow("drained", now) // 生成(3) → 3 消費 → 0
	}

	// now 時点: どちらも未満タン（partial=2, drained=0）→ 破棄されない（elapsed==0 経路）。
	if n := l.Evict(now); n != 0 {
		t.Errorf("未満タンのバケットは破棄されないべき, got %d", n)
	}

	// 3 秒後: 両方 burst(3) まで回復 → 破棄される（elapsed>0 経路・tokens>=burst）。
	later := now.Add(3 * time.Second)
	if n := l.Evict(later); n != 2 {
		t.Errorf("満タン回復後は 2 件破棄されるべき, got %d", n)
	}
	// 破棄後も挙動は不変（満タンから再開）。
	if !l.Allow("drained", later) {
		t.Error("破棄後のキーは満タンから再開し許可されるべき")
	}
}

func TestEvictKeepsDrainedWithoutRefill(t *testing.T) {
	l := New(0, 2) // rate 0（補充なし）
	now := time.Now()
	l.Allow("k", now)
	l.Allow("k", now) // 2 消費 → 0
	// 補充なしのドレイン済みバケットを破棄するとリセット＝制限バイパスになるため破棄しない。
	if n := l.Evict(now.Add(time.Hour)); n != 0 {
		t.Errorf("補充なしのドレイン済みバケットは破棄されないべき, got %d", n)
	}
	if l.Allow("k", now.Add(time.Hour)) {
		t.Error("破棄されていないため枯渇のままであるべき")
	}
}

func TestAllowNConsumesMultiple(t *testing.T) {
	l := New(1, 5)
	now := time.Now()

	if !l.AllowN("k", 5, now) {
		t.Fatal("5 トークンを一度に消費できるべき")
	}
	if l.AllowN("k", 1, now) {
		t.Error("枯渇後は拒否されるべき")
	}
}
