// Package stunmux は WireGuard が使う UDP ソケット（conn.Bind）に相乗りして STUN を行うための
// 多重化ロジックを提供する。
//
// NAT トラバーサルでは、STUN で観測する WAN 側マッピングと、WireGuard が実際にピアへ送信する際の
// マッピングが一致しなければ hole punching は成立しない。両者を確実に一致させる方法は、WireGuard と
// 同一の UDP ソケットから STUN を行うことである。しかしそのソケットの受信は WireGuard の受信ループが
// 占有するため、STUN 応答だけを横取りして残りを WireGuard へ渡す仕組みが要る。
//
// 本パッケージはその「送るべき STUN リクエストの生成」と「受信パケットの STUN 応答判定・振り分け」を
// 担う純粋ロジックであり、実際の UDP 送受信（conn.Bind への結線）は利用側（cmd/client）が担う。
// トランスポート / OS / UI に依存しない。
package stunmux

import (
	"net/netip"
	"sync"

	"github.com/instantmesh/instantmesh/pkg/stun"
)

// newRequest は STUN Binding Request の生成関数（既定は stun.NewRequest）。テストで乱数障害の
// エラーパスを検証するためのシーム。
var newRequest = stun.NewRequest

// Mux は WireGuard ソケットに相乗りする STUN トランザクションを管理する。複数トランザクションを
// トランザクションIDで識別し、ゴルーチンセーフに扱う。
type Mux struct {
	mu      sync.Mutex
	pending map[stun.TxID]chan netip.AddrPort
}

// New は空の Mux を生成する。
func New() *Mux {
	return &Mux{pending: make(map[stun.TxID]chan netip.AddrPort)}
}

// Begin は新しい STUN Binding Request を生成し、その応答を受け取るチャネルを登録して返す。
// 呼び出し側は request を（WireGuard と同一の）ソケットで STUN サーバーへ送信し、resp から
// WAN マッピングを受け取る。応答待ちを打ち切る際は cancel を必ず呼び、トランザクション登録を
// 解除すること（漏れ防止）。resp はバッファ 1 で、応答到着時にブロックせず配送される。
func (m *Mux) Begin() (request []byte, resp <-chan netip.AddrPort, cancel func(), err error) {
	req, tx, err := newRequest()
	if err != nil {
		return nil, nil, nil, err
	}
	ch := make(chan netip.AddrPort, 1)
	m.mu.Lock()
	m.pending[tx] = ch
	m.mu.Unlock()
	cancel = func() {
		m.mu.Lock()
		delete(m.pending, tx)
		m.mu.Unlock()
	}
	return req, ch, cancel, nil
}

// Consume は受信パケット pkt を検査する。進行中トランザクション宛の STUN 応答なら、解析結果を
// 対応するチャネルへ配送して true を返す（＝WireGuard には渡さない）。STUN メッセージだが該当
// トランザクションが無い場合も、WireGuard のパケットではないため消費して true を返す。STUN で
// なければ false を返し、呼び出し側は WireGuard へパススルーする。
func (m *Mux) Consume(pkt []byte) bool {
	tx, ok := stun.MessageTxID(pkt)
	if !ok {
		return false // WireGuard のパケット
	}
	m.mu.Lock()
	ch, found := m.pending[tx]
	if found {
		delete(m.pending, tx)
	}
	m.mu.Unlock()
	if !found {
		return true // STUN だが自分の進行中トランザクション宛ではない（遅延応答等）。消費して捨てる。
	}
	ap, err := stun.ParseResponse(pkt, tx)
	if err != nil {
		return true // 壊れた応答。消費するが配送しない（呼び出し側がタイムアウトで拾う）。
	}
	ch <- ap // バッファ 1 のためブロックしない。
	return true
}
