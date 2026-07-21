package main

import (
	"encoding/json"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gorilla/websocket"
	"github.com/instantmesh/instantmesh/pkg/auditlog"
	"github.com/instantmesh/instantmesh/pkg/hub"
	"github.com/instantmesh/instantmesh/pkg/ratelimit"
	"github.com/instantmesh/instantmesh/pkg/room"
	"github.com/instantmesh/instantmesh/pkg/session"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

// maxSignalingMessageBytes はコントロールプレーン 1 メッセージの受信上限。シグナリングの
// JSON は数百バイト規模のため十分な余裕を見つつ、未認証（pre-auth）で到達可能な巨大フレーム
// による受信バッファ経由のメモリ枯渇 DoS を防ぐ（gorilla は既定で無制限）。上限超過の
// メッセージを受けた接続は ReadMessage がエラーを返してクローズされる（H-01）。
const maxSignalingMessageBytes = 32 << 10 // 32 KiB

// 接続あたりのシグナリングメッセージ流量制限。制御メッセージ（作成/参加/承認/キック/peer_info 等）
// は本来低頻度のため、これを超える流量は濫用とみなしドロップし、CPU / ファンアウト増幅 DoS を
// 抑止する（L-06）。ドロップのみで切断はしない（バーストは吸収する）。
const (
	signalMsgRate  = 20 // メッセージ/秒（平均補充）
	signalMsgBurst = 40 // 瞬間バースト上限
)

// Server は WebSocket シグナリングトランスポート。pkg/hub にソケット・認証・監査を配線する
// 薄いアダプタで、ドメインロジックは持たない。
type Server struct {
	hub      *hub.Hub
	auth     Authenticator
	audit    AuditLogger
	upgrader websocket.Upgrader
	now      func() time.Time

	nextID atomic.Uint64

	mu     sync.Mutex
	conns  map[string]*wsConn // 生存中接続（シャットダウン時の一括クローズ用）
	closed bool
}

// NewServer は Hub・認証・監査を配線した Server を生成する。
func NewServer(h *hub.Hub, auth Authenticator, audit AuditLogger) *Server {
	return &Server{
		hub:   h,
		auth:  auth,
		audit: audit,
		upgrader: websocket.Upgrader{
			// フェーズ1は最小構成。Origin 検査は本番で厳格化する。
			CheckOrigin: func(*http.Request) bool { return true },
		},
		now:   time.Now,
		conns: make(map[string]*wsConn),
	}
}

// ServeWS は 1 本の WebSocket 接続を処理する HTTP ハンドラ。認証 → アップグレード →
// Hub 登録 → 受信ループ → 切断時に登録解除、という接続ライフサイクルを担う。
func (s *Server) ServeWS(w http.ResponseWriter, r *http.Request) {
	auth, err := s.auth.Authenticate(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return // Upgrade はエラー応答を書き込み済み。
	}
	ws.SetReadLimit(maxSignalingMessageBytes) // 巨大フレームによるメモリ枯渇 DoS を防ぐ（H-01）。

	conn := &wsConn{id: strconv.FormatUint(s.nextID.Add(1), 10), ws: ws}
	if !s.addConn(conn) {
		// すでにシャットダウン中。
		_ = ws.Close()
		return
	}
	s.hub.Register(conn, auth)
	s.audit.Log(auditlog.Event{Time: s.now(), Kind: auditlog.KindConnect, Role: string(auth.Role), AccountID: auth.AccountID, RemoteIP: auth.RemoteIP})

	// 切断時のライフサイクル用に、確立したバインドを追跡する。
	// ホスト: ルーム解散、ゲスト: ホストへの離脱通知（いずれもエフェメラル）。
	var hostRoomID, guestRoomID, guestPubKey string
	defer func() {
		s.hub.Unregister(conn.id)
		s.removeConn(conn.id)
		_ = ws.Close()
		s.audit.Log(auditlog.Event{Time: s.now(), Kind: auditlog.KindDisconnect, Role: string(auth.Role), AccountID: auth.AccountID, RemoteIP: auth.RemoteIP})
		switch {
		case hostRoomID != "":
			// ホスト切断 → ルーム解散、承認済みゲストへ room_closed（冪等：明示解散済みなら何もしない）。
			s.hub.CloseRoom(hostRoomID, room.CloseHost, s.now())
		case guestRoomID != "":
			// ゲスト切断 → IP/枠回収、ホストへ guest_left（ピア除去用）。
			s.hub.NotifyGuestLeft(guestRoomID, guestPubKey, s.now())
		}
	}()

	// 接続あたりのメッセージ流量制限（この接続のみで参照。切断でそのまま GC され蓄積しない）。
	msgLimiter := ratelimit.New(signalMsgRate, signalMsgBurst)
	for {
		_, data, err := ws.ReadMessage()
		if err != nil {
			return // クライアント切断・読み取りエラーでループ終了。
		}
		if !msgLimiter.Allow("", s.now()) {
			continue // 流量超過はドロップ（CPU/ファンアウト増幅の抑止・L-06）。
		}
		env, err := signaling.Decode(data)
		if err != nil {
			_ = conn.Send(errorEnvelope("bad_request", "malformed signaling message"))
			continue
		}
		bind := s.hub.Handle(conn.id, env, s.now())
		s.recordAction(auth, env.Type, bind)
		if bind != nil {
			switch bind.Role {
			case session.RoleHost:
				hostRoomID = bind.RoomID
			case session.RoleGuest:
				guestRoomID, guestPubKey = bind.RoomID, bind.PubKey
			}
		}
	}
}

// recordAction は成功したアクション（ルーム作成・参加）を接続メタデータとして監査記録する。
// bind が nil（アクション不成立・その他の種別）の場合は何もしない。
func (s *Server) recordAction(auth hub.Auth, mt signaling.MessageType, bind *session.Binding) {
	if bind == nil {
		return
	}
	switch mt {
	case signaling.TypeCreateRoom:
		s.audit.Log(auditlog.Event{Time: s.now(), Kind: auditlog.KindRoomCreate, Role: string(auth.Role), AccountID: auth.AccountID, RemoteIP: auth.RemoteIP, RoomID: bind.RoomID})
	case signaling.TypeJoinRequest:
		s.audit.Log(auditlog.Event{Time: s.now(), Kind: auditlog.KindGuestJoin, Role: string(auth.Role), RemoteIP: auth.RemoteIP, RoomID: bind.RoomID})
	}
}

// CloseConns は生存中の全接続をクローズし、以後の新規接続を拒否する（グレースフルシャットダウン）。
// 各接続の ReadMessage が解除され受信ループが終了する。
func (s *Server) CloseConns() {
	s.mu.Lock()
	s.closed = true
	conns := make([]*wsConn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	for _, c := range conns {
		_ = c.ws.Close()
	}
}

func (s *Server) addConn(c *wsConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c.id] = c
	return true
}

func (s *Server) removeConn(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, id)
}

// wsConn は 1 本の WebSocket 接続を hub.Conn として実装する。
type wsConn struct {
	id string
	ws *websocket.Conn
	mu sync.Mutex // 書き込みを直列化（gorilla は同時書き込み不可。hub は並行 Send を許容する）。
}

// ID は hub.Conn を実装する。
func (c *wsConn) ID() string { return c.id }

// Send は hub.Conn を実装する。エンベロープを JSON テキストフレームとして送出する。
func (c *wsConn) Send(env signaling.Envelope) error {
	data, _ := json.Marshal(env) // signaling.Envelope は必ず marshal 可能。
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.WriteMessage(websocket.TextMessage, data)
}

// errorEnvelope はサーバー起因の error エンベロープを組み立てる。
func errorEnvelope(code, message string) signaling.Envelope {
	raw, _ := json.Marshal(signaling.Error{Code: code, Message: message})
	return signaling.Envelope{Type: signaling.TypeError, Payload: raw}
}
