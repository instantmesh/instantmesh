package main

// 本ファイルは「共有中サービスぶんの TCP 待受をまとめて管理する」共通の器。
//
// 共有層には待受を持つ側が 2 つある:
//   - ホスト側の転送（メッシュIP:ポート → localhost:ポート・付録C.9 D-10・svcforward.go）
//   - ゲスト側の loopback プロキシ（127.0.0.1:ポート → ホストのメッシュIP:ポート・§4.6.4・loopback.go）
//
// 両者で異なるのは**待受をどう開くか**（ホストは固定ポート 1 回・ゲストは候補列を順に bind 試行）
// だけで、ライフサイクル——共有内容の変更に対する差分適用、共有から外れた待受の**即時解放**、
// ルーム終了時の全解放——は同一である。この不変条件は §4.6.4 が要求するものなので、片方だけ
// 直して他方に届かない状態を作らないよう、管理層を 1 箇所に置いて開く方法だけを注入する。

import (
	"context"
	"net"
	"sync"
)

// portListener は 1 共有サービス分の待受（生 TCP 転送 / HTTP プロキシ）。
type portListener interface {
	addr() net.Addr
	close()
}

// openFunc は論理ポート（共有元のポート番号）に対する待受を開く。
//
// inUse は「その実ポートを自身が既に使っているか」を返す述語で、候補を試す実装（ゲスト側）が
// 自分の他の待受との衝突を bind 前に除くために使う。戻り値の local は実際に待ち受けた
// ポート番号（ホスト側は port と同じ、ゲスト側は退避した場合に異なる）。
type openFunc func(port int, inUse func(int) bool) (l portListener, local int, err error)

// listenerSet は論理ポート → 待受の対応を保持する。GUI の操作ゴルーチンとシグナリング受信
// ループの双方から apply される（ホスト側は publish 経由、ゲスト側は広告受信経由）ため
// ゴルーチンセーフにする。
type listenerSet struct {
	open openFunc

	mu     sync.Mutex
	active map[int]*listenerEntry
	closed bool
}

// listenerEntry は稼働中の待受 1 件。
type listenerEntry struct {
	l     portListener
	local int // 実際に待ち受けているポート（論理ポートと異なりうる）
}

// newListenerSet は待受集合を返す。ctx 終了で全解放する（ルーム解散・退出・プロセス終了）。
func newListenerSet(ctx context.Context, open openFunc) *listenerSet {
	s := &listenerSet{open: open, active: make(map[int]*listenerEntry)}
	go func() {
		<-ctx.Done()
		s.closeAll()
	}()
	return s
}

// apply は ports に合わせて待受を差分適用し、論理ポート → 実待受ポートの対応を返す
// （s が nil、または既に全解放済みなら nil）。
//
// 共有から外れた待受は直ちに閉じる（§4.6.4 の即時解放。ホストが元ポートを占有し続けると
// ゲストが自分の同種サービスを起動できない）。継続中の待受は張り替えない（確立済み接続を
// 切らないため）。開けなかったポートは戻り値に含まれない。
func (s *listenerSet) apply(ports []int) map[int]int {
	if s == nil {
		return nil
	}
	want := make(map[int]bool, len(ports))
	for _, p := range ports {
		want[p] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	for port, e := range s.active {
		if !want[port] {
			e.l.close()
			delete(s.active, port)
		}
	}
	for _, port := range ports {
		if _, ok := s.active[port]; ok {
			continue
		}
		l, local, err := s.open(port, s.inUseLocked)
		if err != nil {
			continue // 開けなかった理由の記録は open の実装（層ごとに意味が違う）に任せる
		}
		s.active[port] = &listenerEntry{l: l, local: local}
	}
	return s.mappingLocked()
}

// inUseLocked は当該実ポートを自身が既に使っているかを返す（apply が open へ渡す述語。
// apply がロックを保持している間だけ呼ばれる）。
func (s *listenerSet) inUseLocked(local int) bool {
	for _, e := range s.active {
		if e.local == local {
			return true
		}
	}
	return false
}

// mappingLocked は論理ポート → 実待受ポートの対応を返す（呼び出し側でロック済みであること）。
func (s *listenerSet) mappingLocked() map[int]int {
	out := make(map[int]int, len(s.active))
	for port, e := range s.active {
		out[port] = e.local
	}
	return out
}

// listenerFor は論理ポートに対応する待受を返す（テストと、待受アドレスを知りたい呼び出し用）。
func (s *listenerSet) listenerFor(port int) (portListener, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.active[port]
	if !ok {
		return nil, false
	}
	return e.l, true
}

// closeAllListeners は稼働中の待受をすべて閉じるが、集合は使い続けられる状態に保つ
// （次の apply で開き直せる）。待受の性質そのものが変わる場合——ホスト側で生 TCP 転送と
// HTTP プロキシを切り替えるとき——に使う。
func (s *listenerSet) closeAllListeners() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closeActiveLocked()
}

// closeAll は全ての待受を解放する。以後の apply は何もしない（セッション終了）。
func (s *listenerSet) closeAll() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	s.closeActiveLocked()
}

// closeActiveLocked は稼働中の待受を閉じて表から外す（呼び出し側でロック済みであること）。
func (s *listenerSet) closeActiveLocked() {
	for port, e := range s.active {
		e.l.close()
		delete(s.active, port)
	}
}
