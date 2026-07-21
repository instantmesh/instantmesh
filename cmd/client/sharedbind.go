package main

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wireguard/conn"

	"github.com/instantmesh/instantmesh/pkg/stunmux"
)

// errSTUNTimeout は STUN 応答が制限時間内に得られなかったことを表す。
var errSTUNTimeout = errors.New("stun: 応答タイムアウト")

// sharedBind は wireguard-go の conn.Bind をラップし、WireGuard が使う UDP ソケットに相乗りして
// STUN を行えるようにする。受信ループに割り込んで STUN 応答だけを横取り（stunmux.Consume）し、
// 残りのパケットはそのまま WireGuard に渡す。これにより STUN で観測する WAN マッピングが WireGuard
// の送信マッピングと一致し、NAT hole punching が成立する。
//
// conn.Bind を埋め込み、Open のみをラップする。他メソッドは基底 Bind へ委譲される。
type sharedBind struct {
	conn.Bind
	mux  *stunmux.Mux
	port atomic.Uint32 // 実際の UDP 待受ポート（Open で確定）。リレー注入の宛先算出に使う。
}

// newSharedBind は既定の conn.Bind をラップした sharedBind を生成する。
func newSharedBind() *sharedBind {
	return &sharedBind{Bind: conn.NewDefaultBind(), mux: stunmux.New()}
}

// Open は基底 Bind を開き、各受信関数を STUN 応答を横取りするようラップして返す。
func (b *sharedBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
	fns, actualPort, err := b.Bind.Open(port)
	if err != nil {
		return nil, 0, err
	}
	b.port.Store(uint32(actualPort))
	wrapped := make([]conn.ReceiveFunc, len(fns))
	for i, fn := range fns {
		wrapped[i] = b.filter(fn)
	}
	return wrapped, actualPort, nil
}

// ListenPort は WireGuard が実際に待ち受けている UDP ポートを返す（Open 前は 0）。
func (b *sharedBind) ListenPort() uint16 {
	return uint16(b.port.Load())
}

// filter は受信関数 fn をラップし、STUN 応答を mux へ吸い上げて WireGuard の受信から除外する。
func (b *sharedBind) filter(fn conn.ReceiveFunc) conn.ReceiveFunc {
	return func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		n, err := fn(packets, sizes, eps)
		kept := 0
		for j := 0; j < n; j++ {
			if b.mux.Consume(packets[j][:sizes[j]]) {
				continue
			}
			packets[kept], sizes[kept], eps[kept] = packets[j], sizes[j], eps[j]
			kept++
		}
		return kept, err
	}
}

// DiscoverWAN は WireGuard と同一の UDP ソケットから STUN サーバー stunServer へ Binding Request を
// 送り、WAN 側マッピングを発見する。timeout は応答待ちの上限。
func (b *sharedBind) DiscoverWAN(stunServer string, timeout time.Duration) (netip.AddrPort, error) {
	addr, err := net.ResolveUDPAddr("udp4", stunServer)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun サーバー解決: %w", err)
	}
	ep, err := b.Bind.ParseEndpoint(addr.String())
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("エンドポイント解析: %w", err)
	}
	req, resp, cancel, err := b.mux.Begin()
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer cancel()
	if err := b.Bind.Send([][]byte{req}, ep); err != nil {
		return netip.AddrPort{}, fmt.Errorf("stun 送信: %w", err)
	}
	select {
	case ap := <-resp:
		return ap, nil
	case <-time.After(timeout):
		return netip.AddrPort{}, errSTUNTimeout
	}
}
