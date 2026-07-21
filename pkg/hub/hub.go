// Package hub はトランスポート非依存のサーバーコア（接続レジストリと配線）を提供する。
//
// pkg/session の純粋ディスパッチャ（Envelope→ドメイン操作→宛先タグ付き応答）と、
// 実際の WebSocket 等トランスポートの間に位置する。Hub は次を担う:
//   - 生存中クライアント接続の登録・解除（ライフサイクル）
//   - 受信エンベロープの処理: 接続コンテキストから session.Origin を組み立て、
//     Dispatcher を呼び、返った session.Result を適用する
//   - session.Target（Origin/Host/Guest）から実接続への解決とメッセージ送出
//   - session.Binding の記録（create_room / join_request 成功後の宛先索引更新）
//   - 定期フック（Sweep / ExpirePending）の駆動と、生成された通知の配送
//
// Hub は WebSocket を知らない。実際の符号化・ソケット書き込み・接続採番は Conn 実装
// （cmd/server 側の薄いアダプタ）が担う。これにより本パッケージはフェイク接続で決定的に
// テストできる。時刻はすべて呼び出し元から now を注入する。
//
// 並行性: 公開メソッドは内部ミューテックスで保護され、複数の接続ゴルーチンおよび定期
// ワーカーから安全に呼び出せる。ただし Conn.Send は Hub のロック外で（同一接続に対して
// 並行に）呼ばれ得るため、Conn 実装側で書き込みを直列化すること。
package hub

import (
	"sync"
	"time"

	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/room"
	"github.com/instantmesh/instantmesh/pkg/session"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

// Conn は 1 クライアント接続を表すトランスポート抽象。Hub はこの API のみを通じて
// クライアントへメッセージを送る。
type Conn interface {
	// ID は接続の一意な識別子（トランスポートが採番）。
	ID() string
	// Send はサーバー→クライアントのメッセージを送出する。符号化と書き込みは実装が担う。
	// 同一接続に対して並行に呼ばれ得るため、実装側で直列化すること。
	Send(env signaling.Envelope) error
}

// Auth は接続確立時に確定する認証・コンテキスト情報。トランスポート層が Register 時に与える。
type Auth struct {
	// Role は接続の役割（host: 認証済み / guest: 未認証で参加を試みる）。
	Role session.Role
	// AccountID はホスト認証済みアカウントID（ホストのみ）。
	AccountID string
	// PubKey はホストの WireGuard 公開鍵。ゲストは join_request のペイロードで確定するため空でよい。
	PubKey string
	// Tier はホストのプラン種別（create_room で参照）。
	Tier plan.Tier
	// RemoteIP は接続元の実IP（参加申請のレート制限・監査用）。
	RemoteIP string
}

// connState は 1 接続の内部状態。認証時の不変コンテキストと、ディスパッチで確立する
// バインディング（ルーム・公開鍵）を保持する。
type connState struct {
	conn      Conn
	role      session.Role
	accountID string
	pubKey    string
	tier      plan.Tier
	remoteIP  string
	roomID    string // バインド後に設定（未確立は空）
}

// pendingSend は解決済みの送出対象（ロック外で送るためのペア）。
type pendingSend struct {
	conn Conn
	env  signaling.Envelope
}

// Hub は接続レジストリと配線を束ねるサーバーコア。ゴルーチンセーフ。
type Hub struct {
	mu   sync.Mutex
	disp *session.Dispatcher

	conns       map[string]*connState        // connID -> 状態
	hostByRoom  map[string]string            // roomID -> ホストの connID
	guestByRoom map[string]map[string]string // roomID -> (guest pubKey -> connID)
}

// New は Dispatcher を配線する Hub を生成する。
func New(disp *session.Dispatcher) *Hub {
	return &Hub{
		disp:        disp,
		conns:       make(map[string]*connState),
		hostByRoom:  make(map[string]string),
		guestByRoom: make(map[string]map[string]string),
	}
}

// Register は接続確立時に接続を登録する。既存 ID は上書きする。
func (h *Hub) Register(c Conn, a Auth) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conns[c.ID()] = &connState{
		conn:      c,
		role:      a.Role,
		accountID: a.AccountID,
		pubKey:    a.PubKey,
		tier:      a.Tier,
		remoteIP:  a.RemoteIP,
	}
}

// Unregister は接続解除時に接続を索引から除去する。冪等。
func (h *Hub) Unregister(connID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	cs, ok := h.conns[connID]
	if !ok {
		return
	}
	delete(h.conns, connID)
	if cs.roomID == "" {
		return
	}
	switch cs.role {
	case session.RoleHost:
		// ルームのホストバインドは生涯 1 つ（create_room が新規ルームを発行する）ため、
		// 別接続で上書きされる競合はなく無条件に除去してよい。
		delete(h.hostByRoom, cs.roomID)
	case session.RoleGuest:
		// 無応答失効後の再参加で同一鍵が別接続へ再バインドされている場合があるため、
		// 自分が現在の登録主のときのみ除去する（他接続のルーティングを壊さない）。
		m := h.guestByRoom[cs.roomID]
		if m[cs.pubKey] == connID {
			delete(m, cs.pubKey)
			if len(m) == 0 {
				delete(h.guestByRoom, cs.roomID)
			}
		}
	}
}

// Handle は接続からの受信エンベロープ 1 件を処理し、本処理で確立したバインディング（create_room /
// join_request 成功時のみ非 nil）を返す。トランスポート層は返り値を監査ログ等に利用できる。
// 未知の接続は黙って捨て nil を返す。
func (h *Hub) Handle(connID string, env signaling.Envelope, now time.Time) *session.Binding {
	h.mu.Lock()
	cs, ok := h.conns[connID]
	if !ok {
		h.mu.Unlock()
		return nil
	}
	origin := session.Origin{
		Role:      cs.role,
		RoomID:    cs.roomID,
		PubKey:    cs.pubKey,
		AccountID: cs.accountID,
		Tier:      cs.tier,
		RemoteIP:  cs.remoteIP,
	}
	res := h.disp.Dispatch(origin, env, now)
	if res.Bind != nil {
		h.bind(cs, connID, *res.Bind)
	}
	sends := h.resolve(connID, res.Out)
	h.mu.Unlock()

	for _, s := range sends {
		_ = s.conn.Send(s.env) // ベストエフォート（切断済み接続への送出失敗は無視）。
	}
	return res.Bind
}

// Sweep は制限時間超過・純アイドル超過のルームを解散し、参加者へ room_closed を配送する。
// 定期ワーカーが一定間隔で呼び出す想定。
func (h *Hub) Sweep(now time.Time) { h.deliver(h.disp.Sweep(now)) }

// ExpirePending は全ルームの無応答 Pending 申請を失効させ、対象ゲストへ join_rejected を配送する。
// 定期ワーカーが一定間隔で呼び出す想定。
func (h *Hub) ExpirePending(now time.Time) { h.deliver(h.disp.ExpirePending(now)) }

// CloseRoom はルームを解散し、承認済みゲストへ room_closed を配送する。ホスト切断時などに
// トランスポート層が呼び出す（メッセージ起因でない解散）。既に解散済みなら何もしない。
func (h *Hub) CloseRoom(roomID string, reason room.CloseReason, now time.Time) {
	h.deliver(h.disp.CloseRoom(roomID, reason, now))
}

// NotifyGuestLeft はゲストの正常離脱を処理し、ホストへ guest_left を配送する。ゲスト切断時に
// トランスポート層が呼び出す。ルーム/ゲストが不在なら何もしない。
func (h *Hub) NotifyGuestLeft(roomID, guestPubKey string, now time.Time) {
	h.deliver(h.disp.GuestLeft(roomID, guestPubKey, now))
}

// --- 内部ヘルパー ---

// bind は送信元接続へバインディングを記録し、宛先索引を更新する（h.mu 保持下）。
func (h *Hub) bind(cs *connState, connID string, b session.Binding) {
	cs.role = b.Role
	cs.roomID = b.RoomID
	cs.pubKey = b.PubKey
	switch b.Role {
	case session.RoleHost:
		h.hostByRoom[b.RoomID] = connID
	case session.RoleGuest:
		m := h.guestByRoom[b.RoomID]
		if m == nil {
			m = make(map[string]string)
			h.guestByRoom[b.RoomID] = m
		}
		m[b.PubKey] = connID
	}
}

// resolve は宛先タグ付きメッセージ群を実接続への送出ペアへ解決する（h.mu 保持下）。
// 解決先が見つからない宛先（切断済みなど）は黙って捨てる。
func (h *Hub) resolve(originID string, msgs []session.OutMessage) []pendingSend {
	sends := make([]pendingSend, 0, len(msgs))
	for _, m := range msgs {
		var connID string
		switch m.To.Kind {
		case session.TargetOrigin:
			connID = originID
		case session.TargetHost:
			connID = h.hostByRoom[m.To.RoomID]
		case session.TargetGuest:
			// nil マップの読み取りはゼロ値を返すため、ルーム未登録でも安全。
			connID = h.guestByRoom[m.To.RoomID][m.To.PubKey]
		}
		if cs, ok := h.conns[connID]; ok {
			sends = append(sends, pendingSend{conn: cs.conn, env: m.Env})
		}
	}
	return sends
}

// deliver は定期フックが生成した通知を解決・送出する（送出はロック外）。
func (h *Hub) deliver(out []session.OutMessage) {
	if len(out) == 0 {
		return
	}
	h.mu.Lock()
	sends := h.resolve("", out) // 定期フックは TargetOrigin を生成しない。
	h.mu.Unlock()
	for _, s := range sends {
		_ = s.conn.Send(s.env)
	}
}
