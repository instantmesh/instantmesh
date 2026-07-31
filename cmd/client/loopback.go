package main

// 本ファイルはゲスト側 loopback プロキシ（要件定義書 §4.6.4・経路(3)）。ホストが共有している
// サービスを、ゲストの `127.0.0.1` の同一ポートへ出す**代替手段**。
//
// なぜ副の手段か（付録C.7・D-7）: 「設定変更ゼロ」が成立するのはポートが空いているときだけで、
// ローカルAI を自分でも動かしている熱心な利用者ほど `11434` は埋まっている。さらにプロキシが元
// ポートを取ると、ゲストは後から自分の同種サービスを起動できなくなる。したがって主導線は名前解決
// （§4.6.3）とし、本経路は **OS の DNS 設定を触れない環境向けの代替**として `-loopback` で明示的に
// 有効化する（既定 false）。
//
// 方針:
//   - 待受は `127.0.0.1` のみ（`0.0.0.0` にはバインドしない）。ゲストの LAN へ再露出させない。
//   - 元ポートが空いていれば同じポート。埋まっていれば **決定的に導出**した代替ポートへ退避する
//     （写像の規則は pkg/portmap。ランダム割当は目的を失うため採らない）。
//   - 実際の待受ポートは表示状態（pkg/appstate の SharedService.Local）へ載せ、UI がコピー可能な
//     URL を出せるようにする。
//   - 共有停止・キック・解散・時間切れで**直ちに解放**する（ホストが元ポートを占有し続けると
//     ゲストが自分の同種サービスを起動できない）。解放と差分適用の器はホスト側の転送と共通
//     （listenerSet）で、ここが与えるのは「候補列を順に bind 試行する」という開き方だけ。
//   - 転送コアもホスト側と同一（svcforward.go の forwarder）。向きと待受アドレスだけを変える。
//
// 対象は TCP のみ（UDP は名前解決／メッシュIP 直接の経路を使う）。

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"strconv"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/portmap"
)

// errNoLoopbackPort は全候補が埋まっていて待受を確保できなかったことを表す。
var errNoLoopbackPort = errors.New("loopback: no available port for the shared service")

// startLoopback は enabled のとき loopback プロキシを生成する（無効なら nil を返し、以後の
// apply / closeAll は no-op）。hostIP を解釈できない場合も無効として扱う。
func startLoopback(ctx context.Context, enabled bool, hostKey, hostIP string) *loopbackProxy {
	if !enabled {
		return nil
	}
	addr, err := netip.ParseAddr(hostIP)
	if err != nil {
		slog.Warn("ホストのメッシュIP を解釈できず loopback プロキシを起動しません", "host_ip", hostIP, "err", err)
		return nil
	}
	slog.Info("loopback プロキシを有効化しました（共有サービスを 127.0.0.1 へ出します）", "host_ip", hostIP)
	return newLoopbackProxy(ctx, hostKey, addr)
}

// loopbackProxy はホストの共有サービスをゲストの `127.0.0.1` へ出す待受群を管理する。
// 待受の集合管理は listenerSet が担い、ここは「どのポートで開くか」の方針だけを持つ。
type loopbackProxy struct {
	// hostKey はホストの公開鍵。代替ポートの決定的な導出に使う（同じホストなら毎回同じポート）。
	hostKey string
	// hostIP は転送先ホストのメッシュIP。
	hostIP netip.Addr

	// listen は待受を開く関数（テストでフェイクへ差し替え可能）。既定は 127.0.0.1 への TCP bind。
	listen func(port int) (net.Listener, error)
	// dial は転送先（ホストのメッシュIP:ポート）への接続（同上）。
	dial func(network, addr string) (net.Conn, error)

	set *listenerSet
}

// newLoopbackProxy は指定ホストの共有サービスを loopback へ出すプロキシを返す。
// ctx 終了で全解放する（プロセス終了・退出・解散のいずれもここを通る）。
func newLoopbackProxy(ctx context.Context, hostKey string, hostIP netip.Addr) *loopbackProxy {
	p := &loopbackProxy{
		hostKey: hostKey,
		hostIP:  hostIP,
		listen:  listenLoopback,
		dial:    net.Dial,
	}
	p.set = newListenerSet(ctx, p.open)
	return p
}

// listenLoopback は `127.0.0.1` のみで TCP 待受を開く（§4.6.4: ゲストの LAN へ再露出させない）。
func listenLoopback(port int) (net.Listener, error) {
	return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
}

// apply はホストが広告した共有ポート集合へ待受を合わせ、元ポート → 実待受ポートの対応を返す
// （p が nil なら nil＝経路無効）。待受を開けなかったサービスは含まれない。
func (p *loopbackProxy) apply(ports []int) map[int]int {
	if p == nil {
		return nil
	}
	return p.set.apply(ports)
}

// open は 1 サービス分の待受を開く（listenerSet が呼ぶ）。元ポート → 導出ポート → 線形探索の
// 順で bind を試し、最初に成功したものを使う。
//
// 空きの判定は**実際の bind 試行**で行う。「空いているか確認してから bind し直す」二段構えは、
// その間に他プロセスへ取られうるため採らない。
func (p *loopbackProxy) open(port int, inUse func(int) bool) (portListener, int, error) {
	cands, err := portmap.Candidates(p.hostKey, port)
	if err != nil {
		// ポートが有効範囲外・ホスト公開鍵が空。広告が壊れている場合。
		slog.Warn("loopback プロキシのポート写像を決められませんでした", "port", port, "err", err)
		return nil, 0, err
	}
	for _, local := range cands {
		if inUse(local) {
			continue // 自分の他の待受と衝突する候補は試さない
		}
		ln, lerr := p.listen(local)
		if lerr != nil {
			continue // 他プロセスが使用中。次の候補へ（衝突は通常系・§4.6.4）
		}
		target := net.JoinHostPort(p.hostIP.String(), strconv.Itoa(port))
		slog.Info("loopback プロキシを開始しました",
			"local", net.JoinHostPort("127.0.0.1", strconv.Itoa(local)), "target", target, "moved", local != port)
		return newForwarder(ln, target, p.dial), local, nil
	}
	// 全候補が埋まるのは異常に近い（名前解決またはメッシュIP 直接の経路へ案内する必要がある）。
	slog.Warn("loopback プロキシの待受ポートを確保できませんでした（名前解決またはメッシュIP 直接で到達してください）", "port", port)
	return nil, 0, errNoLoopbackPort
}

// closeAll は全ての待受を解放する（退出・解散・時間切れ・プロセス終了時）。
func (p *loopbackProxy) closeAll() {
	if p == nil {
		return
	}
	p.set.closeAll()
}

// applyLoopback は loopback プロキシの待受を共有中サービスへ合わせ、実際の待受ポートを list の
// 各要素へ書き戻す（lp が nil なら何もしない＝経路無効）。共有から外れたサービスの待受は
// ここで直ちに閉じられる。
//
// 待受を開けなかったサービスは Local が 0 のまま残る。表示からは消さない——名前解決とメッシュIP
// 直接の経路では到達できるため、「この 1 経路だけ使えない」ことが分かる形で残す（§4.6.2）。
func applyLoopback(lp *loopbackProxy, list []appstate.SharedService) {
	if lp == nil {
		return
	}
	ports := make([]int, 0, len(list))
	for _, sv := range list {
		ports = append(ports, sv.Port)
	}
	local := lp.apply(ports)
	for i := range list {
		list[i].Local = local[list[i].Port]
	}
}
