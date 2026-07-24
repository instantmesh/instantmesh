// Package plan は InstantMesh のプラン別仕様（無料 / 有料）を定義する。
//
// 要件定義書「5. プラン別仕様」を実装側で参照する唯一のミラーであり、
// ゲスト数上限・制限時間・ポート制限・リレー通信量などの確定値を保持する。
// 数値の食い違い（レビュー指摘 C1）を防ぐため、プラン値はここに一本化する。
package plan

import (
	"slices"
	"time"
)

// Tier はプラン種別を表す。
type Tier string

const (
	// Free は無料プラン。
	Free Tier = "free"
	// Pro は有料プラン。
	Pro Tier = "pro"
)

// 全プラン共通のライフサイクル定数。
const (
	// IdleTimeout は純アイドル（まったく通信が発生しない状態）が継続した場合に
	// ルームを自動解散するまでの時間。要件定義書 §4.3。
	IdleTimeout = 30 * time.Minute

	// JoinRequestTimeout は待合室の参加申請が無応答のまま失効するまでの時間。
	// 要件定義書 §4.4（仮 120 秒）。
	JoinRequestTimeout = 120 * time.Second
)

// リレー関連の既定値。
const (
	relayFreeByteLimit = 100 << 20 // 100MB（1接続あたりの累計上限）
	relayThrottleBps   = 64 * 1000 // 64kbps（上限到達後の速度制限）
)

// Spec は 1 プランの機能制限をまとめた仕様。
type Spec struct {
	Tier Tier

	// MaxGuests は 1 ルームあたりの最大ゲスト数（ホストを含まない）。
	MaxGuests int

	// MaxDuration はルームの最大制限時間。
	MaxDuration time.Duration

	// RelayByteLimit はリレー 1 接続あたりの累計通信量の上限（バイト）。
	// 到達すると速度制限へ移行する。0 は無制限。
	RelayByteLimit int64

	// RelayThrottledBps は上限到達後の速度制限値（bps）。切断はしない。0 は制限なし。
	RelayThrottledBps int64
}

var specs = map[Tier]Spec{
	Free: {
		Tier:              Free,
		MaxGuests:         5,
		MaxDuration:       1 * time.Hour,
		RelayByteLimit:    relayFreeByteLimit,
		RelayThrottledBps: relayThrottleBps,
	},
	Pro: {
		Tier:              Pro,
		MaxGuests:         20,
		MaxDuration:       24 * time.Hour,
		RelayByteLimit:    0, // 制限緩和
		RelayThrottledBps: 0,
	},
}

// TierForGroups は Cognito の所属グループ一覧から適用プランを判定する。proGroup に一致する
// グループが含まれれば Pro、そうでなければ Free（fail-safe に既定＝無料）を返す。proGroup が空
// （プロ判定用グループ未設定）の場合は常に Free。groups は署名検証済み ID トークンの
// cognito:groups 由来のため、クライアントは詐称できない（従来のクエリ ?tier= との違い）。
func TierForGroups(groups []string, proGroup string) Tier {
	if proGroup != "" && slices.Contains(groups, proGroup) {
		return Pro
	}
	return Free
}

// Lookup はプラン仕様を返す。未知の Tier は ok=false を返す。
func Lookup(t Tier) (Spec, bool) {
	s, ok := specs[t]
	return s, ok
}

// MustLookup は既知プラン前提で仕様を返す。未知なら panic する。
func MustLookup(t Tier) Spec {
	s, ok := Lookup(t)
	if !ok {
		panic("plan: unknown tier " + string(t))
	}
	return s
}
