// Package manager は複数ルームのライフサイクルを束ねるゴルーチンセーフな管理層を提供する。
//
// room.Room は単一ルームの集約でゴルーチンセーフではないため（room パッケージ参照）、
// 本パッケージがルームへの操作を直列化し、以下を担う:
//   - ルームID / 招待トークンの索引（トークン → ルーム解決、ローテーション対応）
//   - ルーム作成のレート制限（1 ホストアカウントあたり。要件定義書 §4.4）
//   - ルームごとの /24 レンジ払い出し（枯渇時は解放分を再利用）
//   - 制限時間超過・純アイドル超過ルームの掃除（Sweep）
//
// 本パッケージも AWS / Redis / WebSocket に依存しない純粋ロジックであり、時刻は
// 各メソッドに now を渡して決定的にテストできる。将来 Redis バックエンドへ差し替える
// 際の、インメモリ既定実装に相当する。
//
// 並行性: 公開メソッドはすべて内部ミューテックスで保護される。ただし返り値の
// *room.Room を「ロック外で並行に変更してはならない」。ルームへの変更操作は
// WithRoom（もしくは Manager のメソッド）経由で行い直列化すること。
package manager

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/ratelimit"
	"github.com/instantmesh/instantmesh/pkg/room"
	"github.com/instantmesh/instantmesh/pkg/token"
)

// ドメインエラー。
var (
	// ErrRoomNotFound は指定 ID のルームが存在しない場合に返る。
	ErrRoomNotFound = errors.New("manager: room not found")
	// ErrPrefixExhausted は払い出せる /24 レンジが枯渇した場合に返る。
	ErrPrefixExhausted = errors.New("manager: address prefix pool exhausted")
	// ErrCreateRateLimited はホストアカウントのルーム作成レート制限に達した場合に返る。
	ErrCreateRateLimited = errors.New("manager: room creation rate limited")
	// ErrTokenCollision は生成したルームID / トークンが既存と衝突した場合に返る（CSPRNG では現実的に発生しない防御的エラー）。
	ErrTokenCollision = errors.New("manager: generated id or token collided")
	// ErrNotRoomHost は操作要求元が当該ルームのホストでない場合に返る（所有権検証の失敗）。
	ErrNotRoomHost = errors.New("manager: not the host of this room")
)

// Config は Manager の構成。ゼロ値でも妥当な既定で動作する。
type Config struct {
	// Pool は各ルームへ払い出す /24 を切り出す元ブロック。既定は 10.0.0.0/8。
	// プレフィックス長は 24 以下（/24 を 1 つ以上内包できること）でなければならない。
	Pool netip.Prefix

	// CreateRate / CreateBurst はホストアカウント単位のルーム作成レート制限。
	// CreateBurst<=0 の場合はレート制限を適用しない。
	CreateRate  float64
	CreateBurst float64

	// JoinRate / JoinBurst は各ルームの参加申請レート制限（ルームごとに独立）。
	// JoinBurst<=0 の場合はレート制限を適用しない。
	JoinRate  float64
	JoinBurst float64
}

// CreateParams はルーム作成のパラメータ。ID とトークンは Manager が生成する。
type CreateParams struct {
	HostAccountID string
	HostPubKey    string
	Tier          plan.Tier
	Duration      time.Duration // 0 以下 or プラン上限超は room 側で上限にクランプ
}

// Manager は複数ルームのインメモリ管理層。ゴルーチンセーフ。
type Manager struct {
	mu       sync.Mutex
	rooms    map[string]*room.Room   // roomID -> Room
	byToken  map[string]string       // 現在有効なトークン -> roomID
	tokens   map[string]string       // roomID -> 現在のトークン（ローテーション時の索引更新用）
	prefixOf map[string]netip.Prefix // roomID -> 割当済み /24

	poolBase   netip.Addr
	poolBits   int
	prefixSeq  int            // 次に払い出す /24 の連番
	freePrefix []netip.Prefix // 解放され再利用可能な /24

	createLimiter *ratelimit.Limiter // nil ならレート制限なし
	joinRate      float64
	joinBurst     float64

	// 生成関数（テストで差し替え可能なシーム。既定は token.NewRoomToken）。
	newID    func() (string, error)
	newToken func() (string, error)
}

// New は構成から Manager を生成する。Pool が不正な場合はエラーを返す。
func New(cfg Config) (*Manager, error) {
	pool := cfg.Pool
	if pool == (netip.Prefix{}) {
		pool = netip.MustParsePrefix("10.0.0.0/8")
	}
	pool = pool.Masked()
	if !pool.Addr().Is4() || pool.Bits() > 24 {
		return nil, fmt.Errorf("manager: pool must be an IPv4 block with prefix length <= 24, got %s", cfg.Pool)
	}

	var createLim *ratelimit.Limiter
	if cfg.CreateBurst > 0 {
		createLim = ratelimit.New(cfg.CreateRate, cfg.CreateBurst)
	}

	return &Manager{
		rooms:         make(map[string]*room.Room),
		byToken:       make(map[string]string),
		tokens:        make(map[string]string),
		prefixOf:      make(map[string]netip.Prefix),
		poolBase:      pool.Addr(),
		poolBits:      pool.Bits(),
		createLimiter: createLim,
		joinRate:      cfg.JoinRate,
		joinBurst:     cfg.JoinBurst,
		newID:         token.NewRoomToken,
		newToken:      token.NewRoomToken,
	}, nil
}

// Create は新しいルームを生成し、ID / トークン索引・/24 レンジを割り当てる。
// 生成した room.Room を返す（呼び出し元は直後の読み取りのみ安全。以後の変更は
// WithRoom 経由で直列化すること）。
func (m *Manager) Create(p CreateParams, now time.Time) (*room.Room, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// 不正なリクエストもレート制限の対象とし、作成スパムを抑止する。
	if m.createLimiter != nil && !m.createLimiter.Allow(p.HostAccountID, now) {
		return nil, ErrCreateRateLimited
	}

	prefix, err := m.allocPrefix()
	if err != nil {
		return nil, err
	}

	id, err := m.newID()
	if err != nil {
		m.releasePrefix(prefix)
		return nil, fmt.Errorf("manager: generate room id: %w", err)
	}
	tok, err := m.newToken()
	if err != nil {
		m.releasePrefix(prefix)
		return nil, fmt.Errorf("manager: generate token: %w", err)
	}
	if _, exists := m.rooms[id]; exists {
		m.releasePrefix(prefix)
		return nil, ErrTokenCollision
	}
	if _, exists := m.byToken[tok]; exists {
		m.releasePrefix(prefix)
		return nil, ErrTokenCollision
	}

	var joinLim *ratelimit.Limiter
	if m.joinBurst > 0 {
		joinLim = ratelimit.New(m.joinRate, m.joinBurst)
	}

	r, err := room.Create(room.CreateParams{
		ID:            id,
		HostAccountID: p.HostAccountID,
		HostPubKey:    p.HostPubKey,
		Tier:          p.Tier,
		Token:         tok,
		Prefix:        prefix,
		Duration:      p.Duration,
		JoinLimiter:   joinLim,
	}, now)
	if err != nil {
		m.releasePrefix(prefix)
		return nil, err
	}

	m.rooms[id] = r
	m.byToken[tok] = id
	m.tokens[id] = tok
	m.prefixOf[id] = prefix
	return r, nil
}

// Get はルームIDでルームを返す。
func (m *Manager) Get(roomID string) (*room.Room, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.rooms[roomID]
	return r, ok
}

// LookupByToken は現在有効な招待トークンからルームを返す。
// ローテーション済みの旧トークンでは見つからない。
func (m *Manager) LookupByToken(tok string) (*room.Room, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.byToken[tok]
	if !ok {
		return nil, false
	}
	r, ok := m.rooms[id]
	return r, ok
}

// Token はルームの現在有効な招待トークンを返す。招待リンクの表示や作成完了通知に使う。
// ローテーション後は新トークンを返す。ルームが存在しなければ ok=false。
func (m *Manager) Token(roomID string) (string, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	tok, ok := m.tokens[roomID]
	return tok, ok
}

// RoomIDs は現在管理中（未解散）のルームIDの一覧を返す（順序不定・呼び出し元所有のコピー）。
// 参加申請の一斉失効など、全ルーム横断の定期処理の起点として使う。
func (m *Manager) RoomIDs() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids := make([]string, 0, len(m.rooms))
	for id := range m.rooms {
		ids = append(ids, id)
	}
	return ids
}

// RotateToken はルームの招待トークンを再発行する（招待リンク再発行）。旧トークンは
// 即時に無効化され、新トークンを返す。承認済みピアは維持される。所有権検証は行わない
// 低レベル操作であり、シグナリング経由の要求は RotateTokenForHost を用いること。
func (m *Manager) RotateToken(roomID string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.rooms[roomID]
	if !ok {
		return "", ErrRoomNotFound
	}
	return m.rotateTokenLocked(r)
}

// RotateTokenForHost はホスト hostPubKey が所有するルーム roomID の招待トークンを再発行する。
// 未知ルームは ErrRoomNotFound、ホスト公開鍵が一致しない場合は ErrNotRoomHost を返す。
// 所有権検証と再発行を単一ロック下で原子的に行う（シグナリングの再発行要求はこれを用いる）。
func (m *Manager) RotateTokenForHost(roomID, hostPubKey string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.rooms[roomID]
	if !ok {
		return "", ErrRoomNotFound
	}
	if r.HostPubKey != hostPubKey {
		return "", ErrNotRoomHost
	}
	return m.rotateTokenLocked(r)
}

// rotateTokenLocked は m.mu を保持し、かつ管理下に存在するルーム r を前提に招待トークンを
// 再発行する。旧トークンを索引から除去し、新トークンを索引・ルームへ反映して返す。
// 呼び出し側が取得済みの *room.Room を受け取ることで、「存在確認済み」の不変条件を型で明示し
// ルームの重複探索を避ける。
func (m *Manager) rotateTokenLocked(r *room.Room) (string, error) {
	newTok, err := m.newToken()
	if err != nil {
		return "", fmt.Errorf("manager: generate token: %w", err)
	}
	if _, exists := m.byToken[newTok]; exists {
		return "", ErrTokenCollision
	}

	delete(m.byToken, m.tokens[r.ID])
	m.byToken[newTok] = r.ID
	m.tokens[r.ID] = newTok
	r.SetToken(newTok)
	return newTok, nil
}

// Close はルームを解散し、索引から除去して /24 を再利用可能にする（ホストによる明示解散）。
func (m *Manager) Close(roomID string, reason room.CloseReason, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.rooms[roomID]
	if !ok {
		return ErrRoomNotFound
	}
	r.Close(reason, now)
	m.remove(roomID)
	return nil
}

// Sweep は制限時間超過・純アイドル超過のルームを解散して索引から除去し、
// 解散したルームを返す。定期的に呼び出す想定。
func (m *Manager) Sweep(now time.Time) []*room.Room {
	m.mu.Lock()
	defer m.mu.Unlock()

	var swept []*room.Room
	for id, r := range m.rooms {
		var reason room.CloseReason
		switch {
		case r.IsExpired(now):
			reason = room.CloseExpired
		case r.IsIdle(now):
			reason = room.CloseIdle
		default:
			continue
		}
		r.Close(reason, now)
		m.remove(id) // range 中のマップ要素削除は Go では安全。
		swept = append(swept, r)
	}
	// ホストアカウント単位の作成レート制限は常駐（キーはルーム破棄で消えない）ため、満タンに
	// 回復したバケットを破棄してマップの単調増加を防ぐ（L-01）。挙動は不変（満タン＝未生成と等価）。
	if m.createLimiter != nil {
		m.createLimiter.Evict(now)
	}
	return swept
}

// WithRoom はルームIDのルームに対してロック下で fn を実行し、その戻り値を返す。
// room.Room はゴルーチンセーフでないため、ルームへの変更操作はこの経路を通して
// 直列化する。fn 内から Manager の他メソッドを呼ぶと再入デッドロックになるため禁止。
func (m *Manager) WithRoom(roomID string, fn func(*room.Room) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	r, ok := m.rooms[roomID]
	if !ok {
		return ErrRoomNotFound
	}
	return fn(r)
}

// Count は管理中（未解散）のルーム数を返す。
func (m *Manager) Count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.rooms)
}

// --- 内部ヘルパー（呼び出し元は m.mu を保持していること） ---

// remove はルームを全索引から除去し、割当済み /24 を再利用プールへ戻す。
func (m *Manager) remove(roomID string) {
	if tok, ok := m.tokens[roomID]; ok {
		delete(m.byToken, tok)
	}
	if p, ok := m.prefixOf[roomID]; ok {
		m.releasePrefix(p)
	}
	delete(m.tokens, roomID)
	delete(m.prefixOf, roomID)
	delete(m.rooms, roomID)
}

// allocPrefix は次に割り当てる /24 を返す。解放済みプールを優先し、無ければ連番で払い出す。
func (m *Manager) allocPrefix() (netip.Prefix, error) {
	if n := len(m.freePrefix); n > 0 {
		p := m.freePrefix[n-1]
		m.freePrefix = m.freePrefix[:n-1]
		return p, nil
	}
	if m.prefixSeq >= (1 << (24 - m.poolBits)) {
		return netip.Prefix{}, ErrPrefixExhausted
	}
	arr := m.poolBase.As4()
	subnet := binary.BigEndian.Uint32(arr[:]) + uint32(m.prefixSeq)<<8
	m.prefixSeq++

	var b [4]byte
	binary.BigEndian.PutUint32(b[:], subnet)
	return netip.PrefixFrom(netip.AddrFrom4(b), 24), nil
}

// releasePrefix は /24 を再利用プールへ戻す。
func (m *Manager) releasePrefix(p netip.Prefix) {
	m.freePrefix = append(m.freePrefix, p)
}
