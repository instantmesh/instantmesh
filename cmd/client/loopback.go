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
//     ゲストが自分の同種サービスを起動できない）。
//   - 転送コアはホスト側と同一（svcforward.go の forwarder）。向きと待受アドレスだけを変える。
//
// 対象は TCP のみ（UDP は名前解決／メッシュIP 直接の経路を使う）。

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"

	"github.com/instantmesh/instantmesh/pkg/portmap"
)

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
// ホストの広告を受けるたびに apply で差分適用し、外れたサービスの待受は直ちに閉じる。
type loopbackProxy struct {
	// hostKey はホストの公開鍵。代替ポートの決定的な導出に使う（同じホストなら毎回同じポート）。
	hostKey string

	// listen は待受を開く関数（テストでフェイクへ差し替え可能）。既定は 127.0.0.1 への TCP bind。
	listen func(port int) (net.Listener, error)
	// dial は転送先（ホストのメッシュIP:ポート）への接続（同上）。
	dial func(network, addr string) (net.Conn, error)

	mu     sync.Mutex
	hostIP netip.Addr             // 転送先ホストのメッシュIP（承認後に確定）
	active map[int]*loopbackEntry // 元ポート → 稼働中の待受
	closed bool
}

// loopbackEntry は 1 サービス分の待受と、その写像。
type loopbackEntry struct {
	fwd   *forwarder
	local int  // 実際の待受ポート
	moved bool // 元ポートから退避したか
}

// newLoopbackProxy は指定ホストの共有サービスを loopback へ出すプロキシを返す。
// ctx 終了で全解放する（プロセス終了・退出・解散のいずれもここを通る）。
func newLoopbackProxy(ctx context.Context, hostKey string, hostIP netip.Addr) *loopbackProxy {
	p := &loopbackProxy{
		hostKey: hostKey,
		hostIP:  hostIP,
		listen: func(port int) (net.Listener, error) {
			// 待受は 127.0.0.1 限定（§4.6.4）。
			return net.Listen("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(port)))
		},
		dial:   net.Dial,
		active: make(map[int]*loopbackEntry),
	}
	go func() {
		<-ctx.Done()
		p.closeAll()
	}()
	return p
}

// apply はホストが広告した共有ポート集合へ待受を合わせ、元ポート → 実待受ポートの写像を返す
// （p が nil なら nil を返す＝経路無効）。戻り値は表示状態へ載せるためのもので、待受を開けなかった
// サービスは含まれない。
//
// 既に同じ元ポートで稼働している待受は張り替えない（確立済み接続を切らないため）。共有から外れた
// ものは直ちに閉じる。
func (p *loopbackProxy) apply(ports []int) []portmap.Mapping {
	if p == nil {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}

	want := make(map[int]bool, len(ports))
	for _, port := range ports {
		want[port] = true
	}
	// 共有から外れたものを直ちに解放する（§4.6.4 の即時解放）。
	for port, e := range p.active {
		if !want[port] {
			e.fwd.close()
			delete(p.active, port)
			slog.Info("loopback プロキシを停止しました", "port", port, "local", e.local)
		}
	}

	// 継続中のものは現在の写像を維持し、新規のものだけ待受を開く。claim は実際の bind 試行で、
	// 「空いているか」の唯一確実な判定になる（先に確認してから bind する二段構えは競合する）。
	pending := make([]int, 0, len(ports))
	for _, port := range ports {
		if _, ok := p.active[port]; !ok {
			pending = append(pending, port)
		}
	}
	opened := make(map[int]net.Listener, len(pending))
	claim := func(candidate int) bool {
		if p.inUseLocked(candidate) {
			return false
		}
		ln, err := p.listen(candidate)
		if err != nil {
			return false
		}
		opened[candidate] = ln
		return true
	}
	mappings, err := portmap.Assign(p.hostKey, pending, claim)
	if err != nil {
		// ポートが有効範囲外・ホスト公開鍵が空。広告が壊れている場合で、開いた待受は捨てる。
		for _, ln := range opened {
			_ = ln.Close()
		}
		slog.Warn("loopback プロキシのポート写像を決められませんでした", "err", err)
		return p.mappingsLocked()
	}
	for _, m := range mappings {
		ln, ok := opened[m.Local]
		if !ok {
			continue // 起きないが、写像と待受の不整合で握ったままにしない
		}
		delete(opened, m.Local)
		target := net.JoinHostPort(p.hostIP.String(), strconv.Itoa(m.Port))
		p.active[m.Port] = &loopbackEntry{
			fwd:   newForwarder(ln, target, p.dial),
			local: m.Local, moved: m.Moved,
		}
		slog.Info("loopback プロキシを開始しました",
			"local", net.JoinHostPort("127.0.0.1", strconv.Itoa(m.Local)), "target", target, "moved", m.Moved)
	}
	// 採用されなかった待受（Assign が別候補を選んだ場合）は閉じる。
	for _, ln := range opened {
		_ = ln.Close()
	}
	// 待受を開けなかったサービスを利用者へ知らせる（ポート衝突は通常系だが、全候補が埋まるのは
	// 異常に近い＝名前解決またはメッシュIP 直接の経路へ案内する必要がある）。
	for _, port := range pending {
		if _, ok := p.active[port]; !ok {
			slog.Warn("loopback プロキシの待受ポートを確保できませんでした（名前解決またはメッシュIP 直接で到達してください）", "port", port)
		}
	}
	return p.mappingsLocked()
}

// inUseLocked は当該ポートを自身が既に使っているかを返す（呼び出し側でロック済みであること）。
// 自分の他の待受と衝突する候補を bind 前に除く。
func (p *loopbackProxy) inUseLocked(port int) bool {
	for _, e := range p.active {
		if e.local == port {
			return true
		}
	}
	return false
}

// mappingsLocked は現在の写像を元ポートの昇順で返す（呼び出し側でロック済みであること）。
// 並び順を固定するのは表示のちらつきとテストの非決定性を避けるため。
func (p *loopbackProxy) mappingsLocked() []portmap.Mapping {
	out := make([]portmap.Mapping, 0, len(p.active))
	for port, e := range p.active {
		out = append(out, portmap.Mapping{Port: port, Local: e.local, Moved: e.moved})
	}
	sortMappings(out)
	return out
}

// closeAll は全ての待受を解放する（退出・解散・時間切れ・プロセス終了時）。以後の apply は
// 何もしない。
func (p *loopbackProxy) closeAll() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.closed = true
	for port, e := range p.active {
		e.fwd.close()
		delete(p.active, port)
	}
}

// sortMappings は元ポートの昇順へ並べる（件数は最大でも同時共有サービス数なので単純挿入で足る）。
func sortMappings(ms []portmap.Mapping) {
	for i := 1; i < len(ms); i++ {
		for j := i; j > 0 && ms[j].Port < ms[j-1].Port; j-- {
			ms[j], ms[j-1] = ms[j-1], ms[j]
		}
	}
}
