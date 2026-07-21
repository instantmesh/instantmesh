// Package room は InstantMesh のルーム（一時的な仮想ネットワーク）の集約ルートを提供する。
//
// 待合室フローの状態遷移（申請中 → 承認 / 拒否 / 無応答タイムアウト失効 / キック済み）、
// 承認前ネットワーク隔離（Pending は仮想IP未割当）、キックによる再参加ブロック
// （公開鍵ベースのブラックリスト）、ニックネームの重複解決、参加申請のレート制限、
// エフェメラルなライフサイクル（制限時間 / 純アイドル 30 分）を扱う。
//
// 本パッケージは AWS・GUI・OS に依存しない純粋なドメインロジックであり、
// 時刻は各メソッドに now を渡して決定的にテストできる。Room はゴルーチンセーフでは
// ないため、ルーム単位で直列化して使う想定（上位のサーバー層が担保する）。
package room

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"time"

	"github.com/instantmesh/instantmesh/pkg/ipam"
	"github.com/instantmesh/instantmesh/pkg/nickname"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/ratelimit"
	"github.com/instantmesh/instantmesh/pkg/token"
)

// GuestState はゲストの待合室〜参加状態。
type GuestState string

const (
	// Pending は申請中（待合室）。ネットワーク未参加・IP 未割当。
	Pending GuestState = "pending"
	// Approved は承認済み（ネットワーク参加・IP 割当済み）。
	Approved GuestState = "approved"
	// Rejected はホストに拒否された状態。
	Rejected GuestState = "rejected"
	// Expired は無応答タイムアウトで申請が失効した状態。
	Expired GuestState = "expired"
	// Kicked はキック（遮断）された状態。
	Kicked GuestState = "kicked"
)

// RoomState はルームのライフサイクル状態。
type RoomState string

const (
	// Active は稼働中。
	Active RoomState = "active"
	// Closed は解散済み。
	Closed RoomState = "closed"
)

// CloseReason はルーム解散の理由。
type CloseReason string

const (
	// CloseHost はホストによる明示的な解散。
	CloseHost CloseReason = "host"
	// CloseExpired は制限時間の経過。
	CloseExpired CloseReason = "expired"
	// CloseIdle は純アイドル 30 分の経過。
	CloseIdle CloseReason = "idle"
)

// MaxPendingGuests は 1 ルームが同時に保持できる待合室（Pending）申請数の上限。承認済み数は
// プラン上限（MaxGuests）で別途律速されるが、Pending には従来上限がなく、多数の distinct 公開鍵
// による参加申請フラッドで r.guests がメモリ / CPU を単調消費し得た（M-04）。正規の待合室が同時に
// これほどの申請を抱えることはないため、十分大きく採りつつ攻撃を有界化する。
const MaxPendingGuests = 256

// denyReason は再参加拒否の理由（キック / 拒否）。
type denyReason string

const (
	denyKicked   denyReason = "kicked"
	denyRejected denyReason = "rejected"
)

// ドメインエラー。
var (
	ErrRoomClosed   = errors.New("room: closed")
	ErrRoomExpired  = errors.New("room: expired")
	ErrRoomFull     = errors.New("room: guest capacity reached")
	ErrDenied       = errors.New("room: public key is denied (kicked or rejected)")
	ErrDuplicate    = errors.New("room: guest already present")
	ErrNotPending   = errors.New("room: guest is not in pending state")
	ErrUnknownGuest = errors.New("room: unknown guest")
	ErrRateLimited  = errors.New("room: join request rate limited")
	ErrEmptyPubKey  = errors.New("room: empty public key")
	// ErrWaitingRoomFull は待合室(Pending)の同時申請数が MaxPendingGuests に達した場合に返る。
	ErrWaitingRoomFull = errors.New("room: waiting room capacity reached")
)

// Guest は待合室に申請した / 参加したゲスト 1 名の状態。
type Guest struct {
	PubKey      string     // WireGuard 公開鍵の文字列表現（識別子）
	Nickname    string     // 正規化・重複解決済みの表示名（未検証）
	IP          netip.Addr // 承認後に割り当てられる仮想IP（Pending 時は無効値）
	State       GuestState
	JoinIP      string    // 参加申請元の実IP（レート制限・監査用）
	RequestedAt time.Time // 申請時刻
	DecidedAt   time.Time // 承認 / 拒否 / 失効 / キックの時刻
}

// CreateParams は Room 生成のパラメータ。
type CreateParams struct {
	ID            string
	HostAccountID string
	HostPubKey    string
	Tier          plan.Tier
	Token         string             // 招待トークン（token.NewRoomToken 等で生成した値）
	Prefix        netip.Prefix       // ルームの /24 レンジ（例: 10.0.0.0/24）
	Duration      time.Duration      // 0 以下 or 上限超はプラン上限にクランプ
	JoinLimiter   *ratelimit.Limiter // 参加申請のレート制限（nil 可）
}

// Room はルームの集約ルート。
type Room struct {
	ID            string
	HostAccountID string
	HostPubKey    string
	Spec          plan.Spec
	State         RoomState
	CloseReason   CloseReason
	CreatedAt     time.Time
	ExpiresAt     time.Time
	ClosedAt      time.Time

	token        string
	lastActivity time.Time
	alloc        *ipam.Allocator
	joinLimiter  *ratelimit.Limiter

	guests        map[string]*Guest     // key: PubKey
	denied        map[string]denyReason // 再参加拒否鍵（キック / 拒否）
	assignedNames map[string]bool       // 使用中の表示名（重複解決用）
	nameSeq       map[string]int        // 表示名ベースごとの次サフィックス探索開始位置（O(1) 償却の重複解決）
}

// Create は新しい Room を生成する。
func Create(p CreateParams, now time.Time) (*Room, error) {
	spec, ok := plan.Lookup(p.Tier)
	if !ok {
		return nil, fmt.Errorf("room: unknown plan tier %q", p.Tier)
	}
	if p.ID == "" || p.HostAccountID == "" || p.HostPubKey == "" || p.Token == "" {
		return nil, errors.New("room: missing required field")
	}
	alloc, err := ipam.New(p.Prefix, ipam.DefaultReuseCooldown)
	if err != nil {
		return nil, err
	}

	d := p.Duration
	if d <= 0 || d > spec.MaxDuration {
		d = spec.MaxDuration
	}

	return &Room{
		ID:            p.ID,
		HostAccountID: p.HostAccountID,
		HostPubKey:    p.HostPubKey,
		Spec:          spec,
		State:         Active,
		CreatedAt:     now,
		ExpiresAt:     now.Add(d),
		token:         p.Token,
		lastActivity:  now,
		alloc:         alloc,
		joinLimiter:   p.JoinLimiter,
		guests:        make(map[string]*Guest),
		denied:        make(map[string]denyReason),
		assignedNames: make(map[string]bool),
		nameSeq:       make(map[string]int),
	}, nil
}

// VerifyToken は与えられたトークンがルームの招待トークンと一致するか（定数時間比較）。
func (r *Room) VerifyToken(tok string) bool { return token.Equal(r.token, tok) }

// SetToken はルームの招待トークンを差し替える（招待リンク再発行）。旧トークンは
// 以後 VerifyToken を通らなくなる。承認済みピアは維持されるため、漏洩済み相手の
// 排除には Kick の併用が必要（アーキ §4.3）。トークンの索引更新は上位層が担う。
func (r *Room) SetToken(tok string) { r.token = tok }

// HostIP はホストの仮想IP(.1)を返す。
func (r *Room) HostIP() netip.Addr { return r.alloc.HostIP() }

// RequestJoin は待合室への参加申請を登録する（承認前ネットワーク隔離: IP は未割当）。
// 無応答で失効(Expired)した鍵の再申請は許可する。
func (r *Room) RequestJoin(pubKey, rawNickname, joinIP string, now time.Time) (*Guest, error) {
	if err := r.ensureOpen(now); err != nil {
		return nil, err
	}
	if pubKey == "" {
		return nil, ErrEmptyPubKey
	}
	if r.joinLimiter != nil && !r.joinLimiter.Allow(joinIP, now) {
		return nil, ErrRateLimited
	}
	if _, denied := r.denied[pubKey]; denied {
		return nil, ErrDenied
	}
	if g, ok := r.guests[pubKey]; ok {
		// 通常ここに残るのは Pending / Approved（重複申請）のみ。Rejected / Kicked は上の
		// denied で弾かれ、Expired は ExpirePending が即削除するため残らない。防御的に、
		// denied 未登録のまま非 Pending/Approved 状態のエントリが居た場合は再申請を拒否する。
		switch g.State {
		case Pending, Approved:
			return nil, ErrDuplicate
		default:
			return nil, ErrDenied
		}
	}
	// 待合室（Pending）フラッドで r.guests が無制限に膨らむのを防ぐ（M-04）。
	if r.pendingCount() >= MaxPendingGuests {
		return nil, ErrWaitingRoomFull
	}

	name, err := r.assignNickname(rawNickname)
	if err != nil {
		return nil, err
	}
	g := &Guest{
		PubKey:      pubKey,
		Nickname:    name,
		State:       Pending,
		JoinIP:      joinIP,
		RequestedAt: now,
	}
	r.guests[pubKey] = g
	return g, nil
}

// Approve は Pending のゲストを承認し、仮想IPを割り当てる。
// 承認済みゲスト数がプラン上限に達している場合は ErrRoomFull。
func (r *Room) Approve(pubKey string, now time.Time) (*Guest, error) {
	if err := r.ensureOpen(now); err != nil {
		return nil, err
	}
	g, ok := r.guests[pubKey]
	if !ok {
		return nil, ErrUnknownGuest
	}
	if g.State != Pending {
		return nil, ErrNotPending
	}
	if r.approvedCount() >= r.Spec.MaxGuests {
		return nil, ErrRoomFull
	}
	ip, err := r.alloc.Allocate(now)
	if err != nil {
		return nil, err
	}
	g.IP = ip
	g.State = Approved
	g.DecidedAt = now
	r.touch(now)
	return g, nil
}

// Reject は Pending のゲストを拒否する。当該鍵はルーム存続中の再参加を拒否される。
func (r *Room) Reject(pubKey string, now time.Time) error {
	if err := r.ensureOpen(now); err != nil {
		return err
	}
	g, ok := r.guests[pubKey]
	if !ok {
		return ErrUnknownGuest
	}
	if g.State != Pending {
		return ErrNotPending
	}
	g.State = Rejected
	g.DecidedAt = now
	r.denied[pubKey] = denyRejected
	r.touch(now)
	return nil
}

// Kick は承認済み / 申請中のゲストを遮断する。IP を回収し、公開鍵ベースで再参加を
// ブロックする（トークン失効のみでは新トークンで復帰可能なため）。冪等。
func (r *Room) Kick(pubKey string, now time.Time) error {
	g, ok := r.guests[pubKey]
	if !ok {
		return ErrUnknownGuest
	}
	if g.State == Kicked {
		return nil
	}
	if g.IP.IsValid() {
		_ = r.alloc.Release(g.IP, now)
		g.IP = netip.Addr{}
	}
	g.State = Kicked
	g.DecidedAt = now
	r.denied[pubKey] = denyKicked
	r.touch(now)
	return nil
}

// Leave はゲストの正常離脱（接続切断など）を処理する。仮想IPを回収し、表示名を解放して
// ゲストを除去する。キックと異なり再参加を拒否しない（denied に加えないため同一鍵で再参加可能）。
// 未知のゲストは ErrUnknownGuest。
func (r *Room) Leave(pubKey string, now time.Time) error {
	g, ok := r.guests[pubKey]
	if !ok {
		return ErrUnknownGuest
	}
	if g.IP.IsValid() {
		_ = r.alloc.Release(g.IP, now)
	}
	delete(r.assignedNames, g.Nickname)
	delete(r.guests, pubKey)
	r.touch(now)
	return nil
}

// ExpirePending は無応答タイムアウト(plan.JoinRequestTimeout)を超えた Pending 申請を
// 失効させ、失効したゲストを返す。定期的に呼び出す想定。
//
// 失効エントリは r.guests から実削除し、表示名も解放する。従来は状態を Expired にするだけで
// 残置していたため、参加申請フラッド（distinct 公開鍵）でルームスコープのメモリが単調増加した
// （M-04）。実削除により有界化し、同一鍵は新規申請として再参加できる（denied には載せない）。
func (r *Room) ExpirePending(now time.Time) []*Guest {
	var expired []*Guest
	deadlinePassed := func(g *Guest) bool {
		return !now.Before(g.RequestedAt.Add(plan.JoinRequestTimeout))
	}
	for pk, g := range r.guests {
		if g.State == Pending && deadlinePassed(g) {
			g.State = Expired
			g.DecidedAt = now
			delete(r.guests, pk)                // range 中の削除は安全。メモリ累積を防ぐ。
			delete(r.assignedNames, g.Nickname) // 表示名を解放（nameSeq は単調のまま据え置き）。
			expired = append(expired, g)
		}
	}
	return expired
}

// Touch は通信活動を記録し、アイドルタイマーを更新する。
func (r *Room) Touch(now time.Time) { r.touch(now) }

// IsExpired は制限時間を超過したか。
func (r *Room) IsExpired(now time.Time) bool { return now.After(r.ExpiresAt) }

// IsIdle は純アイドルが plan.IdleTimeout 継続したか。
func (r *Room) IsIdle(now time.Time) bool {
	return now.Sub(r.lastActivity) >= plan.IdleTimeout
}

// Close はルームを解散状態にする（冪等）。
func (r *Room) Close(reason CloseReason, now time.Time) {
	if r.State == Closed {
		return
	}
	r.State = Closed
	r.CloseReason = reason
	r.ClosedAt = now
}

// Guest は指定公開鍵のゲスト情報のコピーを返す。
func (r *Room) Guest(pubKey string) (Guest, bool) {
	g, ok := r.guests[pubKey]
	if !ok {
		return Guest{}, false
	}
	return *g, true
}

// ActiveGuests は承認済み（参加中）ゲストのコピー一覧を返す。
func (r *Room) ActiveGuests() []Guest {
	out := make([]Guest, 0)
	for _, g := range r.guests {
		if g.State == Approved {
			out = append(out, *g)
		}
	}
	return out
}

// --- 内部ヘルパー ---

func (r *Room) ensureOpen(now time.Time) error {
	if r.State == Closed {
		return ErrRoomClosed
	}
	if now.After(r.ExpiresAt) {
		return ErrRoomExpired
	}
	return nil
}

func (r *Room) approvedCount() int {
	n := 0
	for _, g := range r.guests {
		if g.State == Approved {
			n++
		}
	}
	return n
}

func (r *Room) pendingCount() int {
	n := 0
	for _, g := range r.guests {
		if g.State == Pending {
			n++
		}
	}
	return n
}

func (r *Room) touch(now time.Time) {
	if now.After(r.lastActivity) {
		r.lastActivity = now
	}
}

// assignNickname は表示名を正規化・検証し、ルーム内で重複する場合はサフィックス（例: "#2"）を
// 付与して一意化する。
//
// 重複時の探索は毎回 2 から線形走査すると、同名連投で 1 件あたり O(N)・全体 O(N²) の
// アルゴリズム的複雑性 DoS になり得た（M-04）。ベースごとに次の探索開始位置 nameSeq を記録し、
// 通常の同名連投を O(1) 償却で解決する。表示名にはユーザ申告の "#N" 形式も含まれ得るため、
// 記録位置が既に使用中のときのみ前進する保険ループを残す（攻撃的な同名連投はこのループに入らない）。
func (r *Room) assignNickname(raw string) (string, error) {
	base, err := nickname.Clean(raw)
	if err != nil {
		return "", err
	}
	if !r.assignedNames[base] {
		r.assignedNames[base] = true
		return base, nil
	}
	n := r.nameSeq[base]
	if n < 2 {
		n = 2
	}
	for r.assignedNames[base+"#"+strconv.Itoa(n)] {
		n++
	}
	name := base + "#" + strconv.Itoa(n)
	r.assignedNames[name] = true
	r.nameSeq[base] = n + 1 // 次回はここから探索（同名連投を 1 発で解決）。
	return name, nil
}
