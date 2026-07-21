package main

import (
	"errors"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/gorilla/websocket"
	"github.com/instantmesh/instantmesh/pkg/manager"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/relayframe"
	"github.com/instantmesh/instantmesh/pkg/relayhub"
	"github.com/instantmesh/instantmesh/pkg/room"
)

// ErrRelayUnauthorized はリレー接続の認証（ルームID/公開鍵）に失敗したことを表す。
var ErrRelayUnauthorized = errors.New("relay: unauthorized")

// maxRelayFrameBytes はリレー 1 フレームの受信上限。中継するのは暗号化 WireGuard パケット
// （MTU + オーバーヘッド。クライアントの読取バッファは 2048B）であり、余裕を見て 4 KiB で
// 上限化する。上限超過フレームは ReadMessage がエラーを返して当該接続をクローズすることで
// 拒否し、巨大フレームによるメモリ枯渇 DoS を防ぐ（H-01）。
const maxRelayFrameBytes = 4 << 10 // 4 KiB

// RelayAuthorizer はリレー接続のルームIDと公開鍵を検証し、ルームキーとプラン仕様を返す。
type RelayAuthorizer interface {
	Authorize(roomID, pubKey string) (roomKey string, spec plan.Spec, err error)
}

// managerAuthorizer は共有 manager でリレー接続を検証する。ルームIDからルームを解決し、
// ホストまたは承認済みゲストのみ許可する（キック/拒否/未承認は不可）。メータ仕様は
// ルームのプランを用いる。
//
// 認可は招待トークンに依存しない（ルームIDと承認済みメンバーシップで判定する）。これにより
// 招待トークンのローテーション（招待リンク再発行）が起きても、承認済みピアのリレー疎通は
// 維持される。招待トークンは「新規参加のための資格」であり、参加後のデータプレーン認可とは
// 責務を分離する。
type managerAuthorizer struct{ mgr *manager.Manager }

// Authorize は RelayAuthorizer を実装する。
func (a managerAuthorizer) Authorize(roomID, pubKey string) (string, plan.Spec, error) {
	r, ok := a.mgr.Get(roomID)
	if !ok {
		return "", plan.Spec{}, ErrRelayUnauthorized
	}
	// ID / HostPubKey / Spec は作成後不変のためロック外で読んでよい。
	if pubKey == r.HostPubKey {
		return r.ID, r.Spec, nil
	}
	authorized := false
	_ = a.mgr.WithRoom(r.ID, func(rm *room.Room) error {
		g, ok := rm.Guest(pubKey)
		authorized = ok && g.State == room.Approved
		return nil
	})
	if !authorized {
		return "", plan.Spec{}, ErrRelayUnauthorized
	}
	return r.ID, r.Spec, nil
}

// RelayServer はリレー（データプレーン）の WebSocket トランスポート。pkg/relayhub に配線する。
type RelayServer struct {
	hub      *relayhub.RelayHub
	auth     RelayAuthorizer
	upgrader websocket.Upgrader
	nextID   atomic.Uint64

	mu     sync.Mutex
	conns  map[string]*wsRelayConn
	closed bool
}

// NewRelayServer は Hub と認証を配線した RelayServer を生成する。
func NewRelayServer(h *relayhub.RelayHub, auth RelayAuthorizer) *RelayServer {
	return &RelayServer{
		hub:      h,
		auth:     auth,
		upgrader: websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }},
		conns:    make(map[string]*wsRelayConn),
	}
}

// ServeRelay は 1 本のリレー接続を処理する HTTP ハンドラ。?room= と ?pubkey= で認証し、
// 以降はバイナリフレーム（宛先公開鍵＋暗号化ペイロード）を同一ルームのピアへ転送する。
func (s *RelayServer) ServeRelay(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	roomKey, spec, err := s.auth.Authorize(q.Get("room"), q.Get("pubkey"))
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	pubKey := q.Get("pubkey")

	ws, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		return
	}
	ws.SetReadLimit(maxRelayFrameBytes) // 巨大フレームによるメモリ枯渇 DoS を防ぐ（H-01）。
	conn := &wsRelayConn{id: strconv.FormatUint(s.nextID.Add(1), 10), ws: ws}
	if !s.addConn(conn) {
		_ = ws.Close()
		return
	}
	if !s.hub.Register(conn, roomKey, pubKey, spec) {
		// 同一公開鍵の登録が既に存在し上書きを拒否した（先着優先・M-02）。この接続は登録されて
		// いないため、Unregister せずに閉じる（登録主の接続を巻き添えにしない）。
		s.removeConn(conn.id)
		_ = ws.Close()
		return
	}

	defer func() {
		s.hub.Unregister(roomKey, pubKey, conn.id)
		s.removeConn(conn.id)
		_ = ws.Close()
	}()

	for {
		mt, data, err := ws.ReadMessage()
		if err != nil {
			return
		}
		if mt != websocket.BinaryMessage {
			continue // リレーはバイナリフレームのみ扱う。
		}
		dst, payload, err := relayframe.Decode(data)
		if err != nil {
			continue
		}
		s.hub.Forward(roomKey, pubKey, dst, payload)
	}
}

// CloseConns は生存中の全リレー接続をクローズし、新規接続を拒否する。
func (s *RelayServer) CloseConns() {
	s.mu.Lock()
	s.closed = true
	conns := make([]*wsRelayConn, 0, len(s.conns))
	for _, c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	for _, c := range conns {
		_ = c.ws.Close()
	}
}

func (s *RelayServer) addConn(c *wsRelayConn) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.conns[c.id] = c
	return true
}

func (s *RelayServer) removeConn(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.conns, id)
}

// wsRelayConn は 1 本のリレー接続を relayhub.RelayConn として実装する。
type wsRelayConn struct {
	id string
	ws *websocket.Conn
	mu sync.Mutex // 書き込み直列化
}

// ID は relayhub.RelayConn を実装する。
func (c *wsRelayConn) ID() string { return c.id }

// Send は relayhub.RelayConn を実装する。src と payload をバイナリフレームで送出する。
// 公開鍵はサーバーが採番/検証済みで MaxKeyLen を超えないため符号化は失敗しない。
func (c *wsRelayConn) Send(src string, payload []byte) error {
	frame, _ := relayframe.Encode(src, payload)
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.ws.WriteMessage(websocket.BinaryMessage, frame)
}
