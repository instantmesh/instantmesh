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

// startForwarder は listen で待ち受け、接続を target へ中継する転送を開始する。
func startForwarder(listen netip.AddrPort, target string, dial func(network, addr string) (net.Conn, error)) (*forwarder, error) {
	ln, err := net.Listen("tcp", listen.String())
	if err != nil {
		return nil, err
	}
	f := &forwarder{ln: ln, target: target, dial: dial}
	go f.accept()
	return f, nil
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

// serviceForwarder は共有中サービスぶんの転送をまとめて管理する。共有内容の変更で差分適用し、
// 共有から外れたポートは直ちに解放する。
type serviceForwarder struct {
	addr netip.Addr // 待受アドレス（自身のメッシュIP）

	// targetFor は転送先を返す（既定は localhost:ポート）。127.0.0.1 と ::1 のどちらに bind した
	// サービスでも届くよう、名前で解決して両系統を試させる（Go のダイヤラが順に試行する）。
	targetFor func(port int) string
	// dial は転送先への接続（テストでフェイクへ差し替え可能）。
	dial func(network, addr string) (net.Conn, error)

	mu     sync.Mutex
	active map[int]*forwarder
	closed bool
}

// newServiceForwarder は指定アドレスで待ち受ける転送マネージャを返す。ctx 終了で全解放する。
func newServiceForwarder(ctx context.Context, addr netip.Addr) *serviceForwarder {
	s := &serviceForwarder{
		addr:      addr,
		targetFor: func(port int) string { return net.JoinHostPort("localhost", strconv.Itoa(port)) },
		dial:      net.Dial,
		active:    make(map[int]*forwarder),
	}
	go func() {
		<-ctx.Done()
		s.closeAll()
	}()
	return s
}

// apply は共有中ポート集合に合わせて転送を差分適用する（s が nil なら何もしない）。
func (s *serviceForwarder) apply(ports []int) {
	if s == nil {
		return
	}
	want := make(map[int]bool, len(ports))
	for _, p := range ports {
		want[p] = true
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	// 共有から外れたものを直ちに解放する。
	for port, f := range s.active {
		if !want[port] {
			f.close()
			delete(s.active, port)
			slog.Info("共有サービスの転送を停止しました", "port", port)
		}
	}
	// 新たに共有されたものを開始する。
	for _, port := range ports {
		if _, ok := s.active[port]; ok {
			continue
		}
		f, err := startForwarder(netip.AddrPortFrom(s.addr, uint16(port)), s.targetFor(port), s.dial)
		if err != nil {
			if isAddrInUseErr(err) {
				// サービス自身が全アドレスで待ち受けている＝メッシュIP で直接到達できる。
				slog.Info("既に全アドレスで待ち受けているため転送しません（直接到達できます）", "port", port)
			} else {
				slog.Warn("共有サービスの転送を開始できませんでした", "port", port, "err", err)
			}
			continue
		}
		s.active[port] = f
		slog.Info("共有サービスの転送を開始しました", "listen", f.addr().String(), "target", s.targetFor(port))
	}
}

// closeAll は全ての転送を解放する（ルーム解散・退出・プロセス終了時）。
func (s *serviceForwarder) closeAll() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	for port, f := range s.active {
		f.close()
		delete(s.active, port)
	}
}
