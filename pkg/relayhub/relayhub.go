// Package relayhub は P2P 直通に失敗したピア間で暗号化パケットを中継する、
// トランスポート非依存のリレーサーバーコア（DERP 相当）を提供する。
//
// サーバーは E2E 暗号化を復号せず、宛先公開鍵に基づいてパケットをバイパス転送するだけである
// （アーキテクチャ定義書 §3-5, §4.1）。転送量は接続ごとに pkg/relay.Meter で計測し、無料プラン
// の上限（100MB）到達後は速度制限する。要件どおり切断はせず、超過分パケットをドロップして
// レートを抑える（ポリシング）。制限緩和プラン（Pro）は無制限。
//
// 本パッケージは WebSocket 等のトランスポートに依存しない。実際のソケット・フレーミング・
// 認証はトランスポート層（cmd/server のリレーアダプタ）が担う。時刻は now 注入で決定的に
// テストできる。公開メソッドはゴルーチンセーフ。
package relayhub

import (
	"sync"
	"time"

	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/relay"
)

// RelayConn は 1 本のリレー接続を表すトランスポート抽象。
type RelayConn interface {
	// ID は接続の一意な識別子（トランスポートが採番）。
	ID() string
	// Send は srcPubKey から中継されたパケットをこの接続のピアへ送出する。
	// 同一接続へ並行に呼ばれ得るため、実装側で書き込みを直列化すること。
	Send(srcPubKey string, payload []byte) error
}

// peer は 1 ピアの接続と通信量メータ。
type peer struct {
	conn  RelayConn
	mu    sync.Mutex // meter を直列化（Meter はゴルーチンセーフでない）
	meter *relay.Meter
}

func (p *peer) allow(n int, now time.Time) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.meter.Allow(int64(n), now)
}

// RelayHub はリレールーム（同一トークンのピア群）を管理し、パケットを転送・計測する。ゴルーチンセーフ。
type RelayHub struct {
	mu    sync.RWMutex
	rooms map[string]map[string]*peer // roomKey -> pubKey -> peer
	now   func() time.Time
}

// New は空の RelayHub を生成する。
func New() *RelayHub {
	return &RelayHub{
		rooms: make(map[string]map[string]*peer),
		now:   time.Now,
	}
}

// Register はリレー接続をルームへ登録し、登録できたら true を返す。spec は当該ルームのプラン
// 仕様（メータ上限に使う）。
//
// 同一ルーム・同一公開鍵の登録が既に存在する場合は上書きせず false を返す（先着優先）。これは、
// リレー接続が公開鍵の秘密鍵所有を証明しない（PoP 欠如）ことを突き、承認済み内部者がホスト等の
// 公開鍵を騙って既存登録を上書きし中継スロットを奪取する攻撃（M-02）を、稼働中の登録がある限り
// 防ぐための当面の緩和策である。正規の再接続は、旧接続の切断で Unregister が登録を除去した後に
// 成功する。根治（秘密鍵チャレンジによる PoP）は将来課題。
func (h *RelayHub) Register(conn RelayConn, roomKey, pubKey string, spec plan.Spec) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	room := h.rooms[roomKey]
	if room == nil {
		room = make(map[string]*peer)
		h.rooms[roomKey] = room
	}
	if _, exists := room[pubKey]; exists {
		return false // 既登録あり: 上書きを拒否（先着優先）。
	}
	room[pubKey] = &peer{conn: conn, meter: relay.NewMeter(spec)}
	return true
}

// Unregister はリレー接続を除去する。自分が現在の登録主（connID 一致）のときのみ除去し、
// 再接続で別接続に置き換わっている場合は何もしない。冪等。
func (h *RelayHub) Unregister(roomKey, pubKey, connID string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	room := h.rooms[roomKey]
	if room == nil {
		return
	}
	if p, ok := room[pubKey]; ok && p.conn.ID() == connID {
		delete(room, pubKey)
		if len(room) == 0 {
			delete(h.rooms, roomKey)
		}
	}
}

// Forward は同一ルームの src から dst へ payload を中継する。中継できたら true を返す。
// 送信元未登録・宛先不在・速度制限中のドロップでは false（いずれも切断はしない）。
func (h *RelayHub) Forward(roomKey, srcPubKey, dstPubKey string, payload []byte) bool {
	h.mu.RLock()
	room := h.rooms[roomKey]
	var src, dst *peer
	if room != nil {
		src = room[srcPubKey]
		dst = room[dstPubKey]
	}
	h.mu.RUnlock()

	if src == nil || dst == nil {
		return false
	}
	if !src.allow(len(payload), h.now()) {
		return false // 上限到達後の速度制限によるドロップ。
	}
	_ = dst.conn.Send(srcPubKey, payload)
	return true
}

// PeerCount はルームに登録中のピア数を返す（監視・テスト用）。
func (h *RelayHub) PeerCount(roomKey string) int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.rooms[roomKey])
}
