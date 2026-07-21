package main

import (
	"errors"
	"net"
	"sync"
)

// errRelayProxyClosed はクローズ済みプロキシに対する操作で返る。
var errRelayProxyClosed = errors.New("relay proxy: closed")

// relayTransport はリレーサーバー（/relay）との 1 本の接続を抽象する。宛先公開鍵付きで
// ペイロードを送出し、受信フレームは生成時に渡すハンドラ（relayProxy.Deliver）へ配送される。
// WebSocket 実装は relaytransport.go の wsRelay。テストではフェイクへ差し替える。
type relayTransport interface {
	// Send は dstPubKey 宛にペイロードを送出する。payload は呼び出し後に再利用され得るため、
	// 実装が保持する場合はコピーすること（relayframe.Encode はコピーする）。
	Send(dstPubKey string, payload []byte) error
	// Close はリレー接続を閉じる。
	Close() error
}

// relayProxy は WireGuard とリレーの間をループバック UDP で橋渡しする。
//
// リレー対象ピアごとに 127.0.0.1 上のループバック UDP ソケットを 1 つ持つ。そのローカルアドレスを
// 当該ピアの WireGuard エンドポイントとして設定することで、WireGuard の暗号化パケットは
// ソケット宛（WG→proxy）に送られ、それをリレーへ転送する。逆にリレーから届いたパケットは同じ
// ソケットから WG の待受ポートへ書き戻す（proxy→WG）。この書き戻しの送信元アドレスがループバック
// エンドポイントに一致するため、WireGuard は当該ピアからの受信として扱う（roaming）。
//
// これにより wireguard-go の内部エンドポイント型に手を入れず、標準 UDP のみでリレー経路を実現する。
// E2E 暗号化ペイロードは復号せず素通しする。ゴルーチンセーフ。
type relayProxy struct {
	transport relayTransport
	wgAddr    *net.UDPAddr // WG のループバック待受アドレス（127.0.0.1:listenPort）。

	mu     sync.Mutex
	links  map[string]*relayLink // dstPubKey(base64) -> リンク
	closed bool
}

// relayLink は 1 ピア分のループバック UDP ソケットと宛先公開鍵。
type relayLink struct {
	sock *net.UDPConn
	dst  string
}

// newRelayProxy は WG 待受ポート wgListenPort（127.0.0.1）へ橋渡しする relayProxy を生成する。
func newRelayProxy(transport relayTransport, wgListenPort uint16) *relayProxy {
	return &relayProxy{
		transport: transport,
		wgAddr:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(wgListenPort)},
		links:     make(map[string]*relayLink),
	}
}

// Endpoint はピア dstPubKey 用ループバックエンドポイント（WG に設定する "127.0.0.1:port"）を返す。
// 初回はソケットを作成し受信ループを起動する。冪等（既存リンクは同じアドレスを返す）。
func (p *relayProxy) Endpoint(dstPubKey string) (string, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return "", errRelayProxyClosed
	}
	if l, ok := p.links[dstPubKey]; ok {
		return l.sock.LocalAddr().String(), nil
	}
	sock, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		return "", err
	}
	l := &relayLink{sock: sock, dst: dstPubKey}
	p.links[dstPubKey] = l
	go p.readLoop(l)
	return sock.LocalAddr().String(), nil
}

// readLoop は WG→proxy 方向を担う。リンクソケットに届いた WireGuard パケットをリレーへ転送する。
func (p *relayProxy) readLoop(l *relayLink) {
	buf := make([]byte, 2048) // 暗号化 WireGuard パケットは MTU + オーバーヘッドに収まる。
	for {
		n, _, err := l.sock.ReadFromUDP(buf)
		if err != nil {
			return // ソケットクローズ（Remove / Close）で終了。
		}
		_ = p.transport.Send(l.dst, buf[:n])
	}
}

// Deliver は proxy→WG 方向を担う。リレーから受信した srcPubKey 発ペイロードを、対応リンクの
// ソケットから WG 待受ポートへ書き戻す（送信元＝ループバックエンドポイント）。リンク不在は捨てる。
func (p *relayProxy) Deliver(srcPubKey string, payload []byte) {
	p.mu.Lock()
	l := p.links[srcPubKey]
	p.mu.Unlock()
	if l == nil {
		return
	}
	_, _ = l.sock.WriteToUDP(payload, p.wgAddr)
}

// Remove はピアのリンクを閉じて除去する（ゲスト離脱・キック時など）。冪等。
func (p *relayProxy) Remove(dstPubKey string) {
	p.mu.Lock()
	l := p.links[dstPubKey]
	delete(p.links, dstPubKey)
	p.mu.Unlock()
	if l != nil {
		_ = l.sock.Close()
	}
}

// Close は全リンクとトランスポートを閉じる。以後の Endpoint は errRelayProxyClosed。
func (p *relayProxy) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	links := p.links
	p.links = make(map[string]*relayLink)
	p.mu.Unlock()
	for _, l := range links {
		_ = l.sock.Close()
	}
	if p.transport == nil {
		return nil // 遅延構築中（トランスポート未接続）でも安全にクローズできる。
	}
	return p.transport.Close()
}
