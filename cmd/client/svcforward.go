package main

// 本ファイルは共有サービスへの転送（要件定義書 §4.6.2「前提: ホスト側の転送」・付録C.9 D-10）。
//
// なぜ要るか: ホストのサービスが `127.0.0.1` にのみバインドしている場合、メッシュIP 宛に届いた
// パケットは当該ソケットに受け付けられない。転送が無いとゲストは到達できず、`OLLAMA_HOST=0.0.0.0`
// 相当の設定を要求することになって D-9（それを不要にするのが設計要件）と矛盾する。
//
// 方針:
//   - ユーザ空間で転送する。OS の DNAT（iptables / pf / netsh portproxy）は使わない——OS ごとに
//     実装が割れ、異常終了時の残骸回収の責任が増えるため（split DNS と同じ理由・付録C.4）。
//   - ポート番号は保存する。`10.0.0.1:11434` と `127.0.0.1:11434` はアドレスが異なるため、
//     ホスト側では衝突しない（衝突が通常系になるのはゲスト側だけ・§4.6.4）。
//   - サービスが既に `0.0.0.0` で待ち受けていてメッシュIP:ポートを bind できない場合は、転送せず
//     そのまま直接到達させる（bind の可否がそのまま両者の判別になる）。
//   - 共有停止・ルーム終了で**直ちに解放**する。
//
// 転送コア（forwarder）は向きと待受アドレスを変えるだけでゲスト側 loopback プロキシ（§4.6.4）へ
// 転用できるよう、待受と転送先を独立した引数で受ける。対象は TCP のみ（UDP は名前解決／メッシュIP
// 直接の経路を使う）。

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
)

// forwarder は listen で受けた TCP 接続を target へ中継する。
type forwarder struct {
	ln     net.Listener
	target string
	dial   func(network, addr string) (net.Conn, error)

	closeOnce sync.Once
	conns     sync.Map // net.Conn → struct{}（解放時に確立済み接続も切るため）
}

// newForwarder は既に確立済みのリスナーで転送を開始する。ゲスト側 loopback プロキシ（§4.6.4）は
// 「bind できたポートをそのまま使う」形で空きを判定するため、リスナーを先に握ってから渡す
// （確認してから bind し直す二段構えは、その間に他プロセスへ取られうる）。ホスト側も同じ形で、
// 待受を開くのは serviceForwarder.open だけである。
func newForwarder(ln net.Listener, target string, dial func(network, addr string) (net.Conn, error)) *forwarder {
	f := &forwarder{ln: ln, target: target, dial: dial}
	go f.accept()
	return f
}

// addr は実際の待受アドレスを返す（ポート 0 指定時の確認用）。
func (f *forwarder) addr() net.Addr { return f.ln.Addr() }

// close はリスナーと確立済みの接続をすべて閉じる。共有停止・キック・解散・時間切れのいずれでも
// 直ちに呼び、ポートを解放する（要件 §4.6.4）。
func (f *forwarder) close() {
	f.closeOnce.Do(func() {
		_ = f.ln.Close()
		f.conns.Range(func(k, _ any) bool {
			_ = k.(net.Conn).Close()
			return true
		})
	})
}

// accept は接続を受け付け、1 接続 1 ゴルーチンで中継する。リスナーが閉じたら抜ける。
func (f *forwarder) accept() {
	for {
		c, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(c)
	}
}

// handle は 1 接続分の双方向中継。転送先へ繋げなければ受け側も閉じる。
func (f *forwarder) handle(src net.Conn) {
	f.conns.Store(src, struct{}{})
	defer func() {
		f.conns.Delete(src)
		_ = src.Close()
	}()

	dst, err := f.dial("tcp", f.target)
	if err != nil {
		slog.Debug("共有サービスへの接続に失敗", "target", f.target, "err", err)
		return
	}
	f.conns.Store(dst, struct{}{})
	defer func() {
		f.conns.Delete(dst)
		_ = dst.Close()
	}()

	// 片方向が終わっても、もう片方向が終わるまでは流し続ける（HTTP のレスポンス待ち等）。
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = io.Copy(dst, src)
		halfClose(dst)
	}()
	_, _ = io.Copy(src, dst)
	halfClose(src)
	<-done
}

// halfClose は TCP の送信方向だけを閉じ、相手に EOF を伝える（全体を閉じると折り返しが切れる）。
func halfClose(c net.Conn) {
	if t, ok := c.(*net.TCPConn); ok {
		_ = t.CloseWrite()
	}
}

// （bind 失敗が「使用中」かの判定 isAddrInUseErr は OS ごとにエラー値が異なるため
// addrinuse_{windows,other}.go に置く。）

// serviceForwarder は共有中サービスぶんの転送をまとめて管理する。待受の集合管理（差分適用・
// 即時解放・全解放）は listenerSet が担い、ここは「メッシュIP の固定ポートで開く」方法だけを
// 与える薄い層（ゲスト側 loopback プロキシも同じ器を使う）。
//
// gate が非 nil のときは生 TCP 転送ではなく HTTP プロキシとして待ち受け、ゲストごとのキーと
// 上限を強制する（要件 §4.7・付録C.9 D-16）。この場合、共有できるのは HTTP のサービスに限られる。
type serviceForwarder struct {
	addr netip.Addr // 待受アドレス（自身のメッシュIP）

	// targetFor は転送先を返す（既定は localhost:ポート）。127.0.0.1 と ::1 のどちらに bind した
	// サービスでも届くよう、名前で解決して両系統を試させる（Go のダイヤラが順に試行する）。
	targetFor func(port int) string
	// dial は転送先への接続（テストでフェイクへ差し替え可能）。
	dial func(network, addr string) (net.Conn, error)

	// gate は L7（HTTP）の統制層。nil なら生 TCP 転送のまま（統制なし）。requireKey 等の
	// 設定変更は gate 自身が抱えるため、ここが握るのは「HTTP プロキシとして開くか」だけ。
	gate *l7Gate

	set *listenerSet
	mu  sync.Mutex // gate の読み書きを守る（待受の集合は listenerSet が守る）
}

// newServiceForwarder は指定アドレスで待ち受ける転送マネージャを返す。ctx 終了で全解放する。
func newServiceForwarder(ctx context.Context, addr netip.Addr) *serviceForwarder {
	s := &serviceForwarder{
		addr:      addr,
		targetFor: func(port int) string { return net.JoinHostPort("localhost", strconv.Itoa(port)) },
		dial:      net.Dial,
	}
	s.set = newListenerSet(ctx, s.open)
	return s
}

// setGate は L7 統制の有効/無効を切り替える。待受の性質そのものが変わる（生 TCP 転送 ⇄ HTTP
// プロキシ）ため既存の待受を一度すべて閉じ、次の apply で開き直す。
//
// gate 自身の設定（キーを要求するか）の変更ではここを通らない —— l7Gate は長命な 1 個で、
// 各リクエストが現在値を読むため待受の張り替えは不要。
func (s *serviceForwarder) setGate(g *l7Gate) {
	if s == nil {
		return
	}
	s.mu.Lock()
	changed := (s.gate == nil) != (g == nil)
	s.gate = g
	s.mu.Unlock()
	if changed {
		s.set.closeAllListeners()
	}
}

// apply は共有中ポート集合に合わせて転送を差分適用する（s が nil なら何もしない）。
func (s *serviceForwarder) apply(ports []int) {
	if s == nil {
		return
	}
	s.set.apply(ports)
}

// open は 1 ポート分の待受を開く（listenerSet が呼ぶ）。ホスト側はポート番号を保存するため
// 候補を試さず、inUse も使わない（メッシュIP と localhost はアドレスが違うので衝突しない）。
func (s *serviceForwarder) open(port int, _ func(int) bool) (portListener, int, error) {
	s.mu.Lock()
	gate := s.gate
	s.mu.Unlock()

	// 待受はここで 1 度だけ開き、性質（生 TCP 転送 / HTTP プロキシ）に応じて包む。bind の失敗は
	// そのまま「サービス自身が全アドレスで待ち受けている」ことの判別を兼ねるため、開く場所と
	// 意味づけを離さない。
	listen := netip.AddrPortFrom(s.addr, uint16(port))
	ln, err := net.Listen("tcp", listen.String())
	if err != nil {
		if isAddrInUseErr(err) {
			// サービス自身が全アドレスで待ち受けている＝メッシュIP で直接到達できる。
			slog.Info("既に全アドレスで待ち受けているため転送しません（直接到達できます）", "port", port)
		} else {
			slog.Warn("共有サービスの転送を開始できませんでした", "port", port, "err", err)
		}
		return nil, 0, err
	}
	target := s.targetFor(port)
	var l portListener
	if gate != nil {
		l = newHTTPProxy(ln, target, uint16(port), gate)
	} else {
		l = newForwarder(ln, target, s.dial)
	}
	slog.Info("共有サービスの転送を開始しました", "listen", l.addr().String(), "target", target, "l7", gate != nil)
	return l, port, nil
}

// closeAll は全ての転送を解放する（ルーム解散・退出・プロセス終了時）。
func (s *serviceForwarder) closeAll() {
	if s == nil {
		return
	}
	s.set.closeAll()
}
