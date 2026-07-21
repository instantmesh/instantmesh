package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log/slog"
	"time"

	"github.com/instantmesh/instantmesh/pkg/connmon"
	"github.com/instantmesh/instantmesh/pkg/wgconf"
)

// defaultConnmonConfig はフォールバック状態機械の既定しきい値。
//   - ProbeTimeout: 直通ハンドシェイクをこの時間待って成立しなければリレーへ転落。
//   - AliveTimeout: 直通が生きているとみなす最終ハンドシェイクからの許容経過（WG 再ハンドシェイク
//     間隔≒2分より長く取り、定常疎通中の誤検知を避ける）。
//   - RetryInterval: 0 = 転落後はリレーに留まる（直通再試行での疎通中断を避ける保守設定）。
var defaultConnmonConfig = connmon.Config{
	ProbeTimeout:  8 * time.Second,
	AliveTimeout:  180 * time.Second,
	RetryInterval: 0,
}

// monitorInterval はハンドシェイク観測と状態機械更新の周期。
const monitorInterval = 1 * time.Second

// relayDialFunc はリレー接続を確立し relayTransport を返す。onFrame は受信フレームの配送先
// （relayProxy.Deliver）。ルームID・公開鍵・リレー URL は呼び出し側がクロージャに束ねる。
type relayDialFunc func(onFrame func(srcPubKey string, payload []byte)) (relayTransport, error)

// peerConn は監視対象 1 ピアの状態。すべて run ゴルーチン（tick/コマンド処理）からのみ触るため
// ロック不要。
type peerConn struct {
	pubKey    string // base64（シグナリング/リレーで使う識別子）
	pubKeyHex string // 16 進（WireGuard UAPI 照合用）
	directEP  string // 直通 WAN エンドポイント（peer_info 由来）
	// build はエンドポイントを差し替えてピアの WireGuard 設定を再構築する（ホスト/ゲストで
	// allowed_ip ポリシーが異なるため meshpeer.HostPeer/GuestPeer をクロージャで束ねる）。
	build   func(endpoint string) (wgconf.Config, error)
	tracker *connmon.Tracker
	applied connmon.Route // 現在 WireGuard に適用済みの経路
}

// connMonitor はピアごとに connmon を駆動し、直通⇄リレーのエンドポイント切替を行う。
//
// 外部イベント（Track/Untrack）はコマンドチャネル経由で run ゴルーチンへ渡し、ピア状態への
// アクセスを単一ゴルーチンに閉じてデータ競合を避ける。WireGuard 操作（ハンドシェイク取得・
// 設定適用）とリレー接続はフィールドの関数で注入し、単体テスト可能にする。
type connMonitor struct {
	handshake  func(pubKeyHex string) time.Time // 直近ハンドシェイク時刻（未成立は zero）
	apply      func(cfg wgconf.Config) error     // WireGuard へ差分設定を適用
	listenPort uint16                            // WG 待受ポート（リレー注入先の算出用）
	dial       relayDialFunc
	cfg        connmon.Config
	interval   time.Duration
	now        func() time.Time

	cmds  chan func()
	peers map[string]*peerConn
	proxy *relayProxy // 初回フォールバック時に遅延生成
}

// newConnMonitor は Tunnel に配線した connMonitor を生成する。dial はリレー URL・ルームID・自公開鍵を
// 束ねたダイヤラ。
func newConnMonitor(tun *Tunnel, dial relayDialFunc) *connMonitor {
	return &connMonitor{
		handshake:  func(hexKey string) time.Time { ts, _ := tun.PeerHandshake(hexKey); return ts },
		apply:      tun.Apply,
		listenPort: tun.ListenPort(),
		dial:       dial,
		cfg:        defaultConnmonConfig,
		interval:   monitorInterval,
		now:        time.Now,
		cmds:       make(chan func(), 16),
		peers:      make(map[string]*peerConn),
	}
}

// run は監視ループ。ctx 終了でリレープロキシを閉じて戻る。
func (m *connMonitor) run(ctx context.Context) {
	ticker := time.NewTicker(m.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if m.proxy != nil {
				_ = m.proxy.Close()
			}
			return
		case fn := <-m.cmds:
			fn()
		case <-ticker.C:
			m.tick(m.now())
		}
	}
}

// Track はピアの監視を開始/更新する。directEP は直通 WAN エンドポイント、build はエンドポイント
// 差し替えでピア設定を再構築するクロージャ。既存ピアは直通エンドポイントを更新し状態機械を初期化
// （Probing）する（peer_info 再受信＝再 STUN に対応）。m が nil なら no-op。
func (m *connMonitor) Track(pubKey, pubKeyHex, directEP string, build func(string) (wgconf.Config, error)) {
	if m == nil {
		return
	}
	m.cmds <- func() { m.track(pubKey, pubKeyHex, directEP, build) }
}

func (m *connMonitor) track(pubKey, pubKeyHex, directEP string, build func(string) (wgconf.Config, error)) {
	if pc, ok := m.peers[pubKey]; ok {
		pc.pubKeyHex = pubKeyHex
		pc.directEP = directEP
		pc.build = build
		pc.tracker = connmon.New(m.cfg, m.now())
		pc.applied = connmon.RouteDirect
		return
	}
	m.peers[pubKey] = &peerConn{
		pubKey:    pubKey,
		pubKeyHex: pubKeyHex,
		directEP:  directEP,
		build:     build,
		tracker:   connmon.New(m.cfg, m.now()),
		applied:   connmon.RouteDirect,
	}
}

// Untrack はピアの監視を終了し、あればリレーのループバックソケットを解放する。m が nil なら no-op。
func (m *connMonitor) Untrack(pubKey string) {
	if m == nil {
		return
	}
	m.cmds <- func() {
		delete(m.peers, pubKey)
		if m.proxy != nil {
			m.proxy.Remove(pubKey)
		}
	}
}

// tick は全ピアの状態機械を 1 周進め、望ましい経路と適用済み経路が食い違えば切り替える。
func (m *connMonitor) tick(now time.Time) {
	for _, pc := range m.peers {
		pc.tracker.Step(now, m.handshake(pc.pubKeyHex))
		desired := pc.tracker.Route()
		if desired == pc.applied {
			continue
		}
		if m.applyRoute(pc, desired) {
			pc.applied = desired
		}
	}
}

// applyRoute はピアのエンドポイントを route（直通/リレー）へ切り替える。成功で true。失敗時は
// applied を更新せず次 tick で再試行する（リレー確立の一時失敗などから自己回復する）。
func (m *connMonitor) applyRoute(pc *peerConn, route connmon.Route) bool {
	var endpoint string
	switch route {
	case connmon.RouteRelay:
		proxy, err := m.ensureProxy()
		if err != nil {
			slog.Warn("リレー接続確立に失敗（直通のまま）", "peer", pc.pubKey, "err", err)
			return false
		}
		ep, err := proxy.Endpoint(pc.pubKey)
		if err != nil {
			slog.Warn("リレーエンドポイント取得に失敗", "peer", pc.pubKey, "err", err)
			return false
		}
		endpoint = ep
	default: // RouteDirect
		endpoint = pc.directEP
		if m.proxy != nil {
			m.proxy.Remove(pc.pubKey) // 直通へ戻るのでループバックソケットを解放。
		}
	}

	cfg, err := pc.build(endpoint)
	if err != nil {
		slog.Warn("ピア設定の再構築に失敗", "peer", pc.pubKey, "err", err)
		return false
	}
	if err := m.apply(cfg); err != nil {
		slog.Warn("エンドポイント切替の適用に失敗", "peer", pc.pubKey, "err", err)
		return false
	}
	if route == connmon.RouteRelay {
		slog.Info("経路をリレーへ切替（P2P直通に失敗）", "peer", pc.pubKey, "relay_endpoint", endpoint)
	} else {
		slog.Info("経路を直通へ切替", "peer", pc.pubKey, "endpoint", endpoint)
	}
	return true
}

// ensureProxy はリレープロキシを遅延生成する。初回のみリレー接続を確立する。
func (m *connMonitor) ensureProxy() (*relayProxy, error) {
	if m.proxy != nil {
		return m.proxy, nil
	}
	p := newRelayProxy(nil, m.listenPort)
	tr, err := m.dial(p.Deliver)
	if err != nil {
		return nil, err
	}
	p.transport = tr
	m.proxy = p
	return p, nil
}

// pubKeyToHex は base64 の WireGuard 公開鍵を UAPI 照合用の 16 進表現へ変換する。
func pubKeyToHex(b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return "", fmt.Errorf("pubkey base64: %w", err)
	}
	return hex.EncodeToString(raw), nil
}
