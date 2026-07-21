// Package ratelimit はキー単位のトークンバケット型レート制限を提供する。
//
// 参加申請（1 トークン / 1 IP あたり）やルーム作成（1 アカウントあたり）の
// 濫用・踏み台 DoS を抑える用途に使う（要件定義書 §4.4 / §4.5）。
//
// 時刻は呼び出し側から now を渡す設計とし、テストを決定的にする。
package ratelimit

import (
	"sync"
	"time"
)

// Limiter はキーごとにトークンバケットを維持する。ゴルーチンセーフ。
type Limiter struct {
	mu      sync.Mutex
	rate    float64 // 1 秒あたりの補充トークン数
	burst   float64 // バケット容量（バースト上限）
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// New は毎秒 rate トークンを補充し、最大 burst まで蓄積できる Limiter を生成する。
func New(rate, burst float64) *Limiter {
	return &Limiter{
		rate:    rate,
		burst:   burst,
		buckets: make(map[string]*bucket),
	}
}

// Allow はキーのトークンを 1 つ消費できれば true を返す。
func (l *Limiter) Allow(key string, now time.Time) bool {
	return l.AllowN(key, 1, now)
}

// AllowN はキーのトークンを n 個消費できれば消費して true を返す。
// 足りなければ何も消費せず false を返す。
func (l *Limiter) AllowN(key string, n float64, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	} else if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
		b.tokens += elapsed * l.rate
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}

	if b.tokens >= n {
		b.tokens -= n
		return true
	}
	return false
}

// Reset は指定キーの状態を破棄する（次回アクセスで満タンから開始）。
func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, key)
}

// Evict は now 時点で満タン（バースト上限まで回復済み）のキーを破棄し、破棄した件数を返す。
// 満タンのバケットは未生成のキーと等価（次回アクセスで burst から開始）なので、破棄しても
// レート制限の挙動を一切変えずにメモリを解放できる。これによりキー空間が大きい常駐リミッタ
// （例: ホストアカウント単位のルーム作成リミッタ）のバケットマップの単調増加を防ぐ（L-01）。
// 定期的に呼び出す想定。rate<=0（補充なし）のバケットは満タンでない限り破棄されないため、
// ドレイン済みバケットのリセットによる制限バイパスは起きない。
func (l *Limiter) Evict(now time.Time) int {
	l.mu.Lock()
	defer l.mu.Unlock()

	evicted := 0
	for key, b := range l.buckets {
		tokens := b.tokens
		if elapsed := now.Sub(b.last).Seconds(); elapsed > 0 {
			tokens += elapsed * l.rate
		}
		if tokens >= l.burst {
			delete(l.buckets, key)
			evicted++
		}
	}
	return evicted
}
