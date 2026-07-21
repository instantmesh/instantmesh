// Package relay はリレー中継の通信量メータリングと速度制限（スロットル）ロジックを提供する。
//
// 要件定義書 §4.2 / §4.5:
//   - リレー 1 接続あたりの累計通信量が上限（無料プラン: 100MB）に到達したら
//     指定レート（64kbps）へ速度制限する。切断はしない。
//   - 上限に到達するまでの転送、および P2P 直通は無制限（メータの対象外）。
//   - 制限緩和プラン（Pro）では上限 0＝無制限。
//
// 本パッケージはネットワーク I/O を持たない純粋ロジックであり、時刻は呼び出し側から
// now を渡して決定的にテストできる。Meter は 1 リレー接続につき 1 つ生成し、
// ゴルーチンセーフではないため接続単位で直列化して使う想定。
package relay

import (
	"time"

	"github.com/instantmesh/instantmesh/pkg/plan"
)

// Meter は 1 リレー接続の累計転送量を計測し、上限到達後は速度制限する。
type Meter struct {
	limit       int64   // これを超えるとスロットルへ移行。0 以下は無制限。
	bytesPerSec float64 // スロットル時の許容レート（バイト/秒）
	total       int64   // 累計転送バイト数
	throttling  bool    // スロットル区間に入ったか
	tokens      float64 // スロットル時のトークンバケット残量（バイト）
	last        time.Time
}

// NewMeter はプラン仕様からメータを生成する。
// spec.RelayByteLimit を上限、spec.RelayThrottledBps を速度制限レートとして使う。
func NewMeter(spec plan.Spec) *Meter {
	return &Meter{
		limit:       spec.RelayByteLimit,
		bytesPerSec: float64(spec.RelayThrottledBps) / 8.0,
	}
}

// Allow は n バイトの転送を試みる。転送を許可する場合は累計へ加算して true を返す。
//
//   - 無制限プラン（limit<=0）: 常に true。
//   - 上限未到達: 常に true（上限をまたぐ最初の転送も許可する＝切断しない）。
//   - 上限到達後: 速度制限レートのトークンバケットで判定し、足りなければ false
//     （呼び出し側は送出を遅延させる。切断はしない）。
func (m *Meter) Allow(n int64, now time.Time) bool {
	if m.limit <= 0 || m.total < m.limit {
		m.total += n
		return true
	}

	// スロットル区間: 初回はレート 1 秒分をバーストとして与え、以降は経過時間で補充する。
	if !m.throttling {
		m.throttling = true
		m.last = now
		m.tokens = m.bytesPerSec
	} else if elapsed := now.Sub(m.last).Seconds(); elapsed > 0 {
		m.tokens += elapsed * m.bytesPerSec
		if m.tokens > m.bytesPerSec {
			m.tokens = m.bytesPerSec // バーストは 1 秒分に制限
		}
		m.last = now
	}

	if float64(n) <= m.tokens {
		m.tokens -= float64(n)
		m.total += n
		return true
	}
	return false
}

// Throttled は上限に到達して速度制限対象になっているかを返す。
func (m *Meter) Throttled() bool {
	return m.limit > 0 && m.total >= m.limit
}

// Total は累計転送バイト数を返す。
func (m *Meter) Total() int64 { return m.total }
