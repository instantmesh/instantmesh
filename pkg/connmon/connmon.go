// Package connmon はピアごとの接続性（P2P 直通 / リレー）を管理する状態機械を提供する。
//
// NAT トラバーサルでは、まず STUN で交換した WAN エンドポイントへ直通（P2P）を試み、一定時間内に
// WireGuard ハンドシェイクが成立しなければリレーへフォールバックする。本パッケージは「直近の
// ハンドシェイク成立時刻の観測」から、直通確立・リレー転落・（任意で）直通の再試行という状態遷移を
// 決定する純粋ロジックである。実際のハンドシェイク時刻取得（pkg/wgstat）やエンドポイント切替
// （wireguard-go への適用）・リレー接続は利用側（cmd/client）が担う。
//
// 時刻は now 注入で決定的にテストできる。単一ピア用の Tracker を利用側がピアごとに保持する。
package connmon

import "time"

// State はピアの接続性状態。
type State int

const (
	// Probing は直通（WAN エンドポイント）でハンドシェイク成立を待っている状態。
	Probing State = iota
	// Direct は直通ハンドシェイクが成立し P2P 疎通している状態。
	Direct
	// Relay は直通に失敗しリレー経由で疎通している状態。
	Relay
)

// String は状態の表示名を返す。
func (s State) String() string {
	switch s {
	case Probing:
		return "probing"
	case Direct:
		return "direct"
	case Relay:
		return "relay"
	default:
		return "unknown"
	}
}

// Route はピアに現在設定すべき経路（WireGuard エンドポイントの向き先）。
type Route int

const (
	// RouteDirect は直通の WAN エンドポイントを使う経路（Probing / Direct 状態）。
	RouteDirect Route = iota
	// RouteRelay はリレー経由の経路（Relay 状態）。
	RouteRelay
)

// Config は状態遷移のしきい値。
type Config struct {
	// ProbeTimeout は直通のハンドシェイク成立を待つ上限。超過でリレーへフォールバックする。
	ProbeTimeout time.Duration
	// AliveTimeout は「直通が生きている」とみなす最終ハンドシェイクからの許容経過。これを超えて
	// 古くなったら直通は切れたとみなし再プローブへ戻る。WireGuard の再ハンドシェイク間隔（約2分）
	// より十分長く取り、定常疎通中の誤検知を避ける。
	AliveTimeout time.Duration
	// RetryInterval は Relay 滞在中に直通を再試行するまでの間隔（0 は再試行しない）。再試行は
	// 一時的にリレーを離れて直通を試すため、疎通中断のリスクと引き換え。既定（0）は転落後は
	// リレーに留まる保守的な挙動。
	RetryInterval time.Duration
}

// Tracker は単一ピアの接続性状態機械。ゴルーチンセーフではない（利用側が直列化する）。
type Tracker struct {
	cfg   Config
	state State
	// since は現在状態に入った時刻（プローブ開始・リレー転落の起点）。
	since time.Time
}

// New は Probing 状態で開始する Tracker を生成する（now はプローブ開始時刻）。
func New(cfg Config, now time.Time) *Tracker {
	return &Tracker{cfg: cfg, state: Probing, since: now}
}

// State は現在の状態を返す。
func (t *Tracker) State() State { return t.state }

// Route は現在設定すべき経路を返す。Probing / Direct は RouteDirect、Relay は RouteRelay。
func (t *Tracker) Route() Route {
	if t.state == Relay {
		return RouteRelay
	}
	return RouteDirect
}

// Step は最新の観測（現在時刻 now と、直近のハンドシェイク成立時刻 lastHandshake。未成立は zero）を
// 与えて状態機械を 1 ステップ進める。遷移後の状態と、経路（Route）が変わったか（＝利用側が
// エンドポイントを再適用すべきか）を返す。
//
// 遷移規則:
//   - Probing → Direct: このプローブ開始（since）より新しいハンドシェイクを観測（直通確立）。
//   - Probing → Relay:  ProbeTimeout を超えても確立しない（フォールバック）。
//   - Direct  → Probing: 最終ハンドシェイクが AliveTimeout を超えて古い（直通が切れた）。
//   - Relay   → Probing: RetryInterval 経過（>0 のときのみ。直通を再試行）。
//
// Probing↔Direct 間は経路が RouteDirect のままなので routeChanged=false（エンドポイント変更不要）。
// 経路が変わるのは Relay 境界を跨ぐときだけ。
func (t *Tracker) Step(now, lastHandshake time.Time) (state State, routeChanged bool) {
	prev := t.Route()

	// このプローブ開始以降に成立したハンドシェイクか（stale な成立を直通確立と誤認しないため）。
	freshSinceAttempt := !lastHandshake.IsZero() && lastHandshake.After(t.since)
	// 直通が生きているか（最終ハンドシェイクが十分に新しい）。
	alive := !lastHandshake.IsZero() && now.Sub(lastHandshake) <= t.cfg.AliveTimeout

	switch t.state {
	case Probing:
		if freshSinceAttempt {
			t.enter(Direct, now)
		} else if now.Sub(t.since) >= t.cfg.ProbeTimeout {
			t.enter(Relay, now)
		}
	case Direct:
		if !alive {
			t.enter(Probing, now)
		}
	case Relay:
		if t.cfg.RetryInterval > 0 && now.Sub(t.since) >= t.cfg.RetryInterval {
			t.enter(Probing, now)
		}
	}
	return t.state, t.Route() != prev
}

// enter は新状態へ遷移し起点時刻を更新する。
func (t *Tracker) enter(s State, now time.Time) {
	t.state = s
	t.since = now
}
