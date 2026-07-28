package main

// 本ファイルはメッシュ名の解決（要件定義書 §4.6.3）の I/O アダプタ。
// 「どう答えるか」は純粋ロジック（pkg/dnsmsg の応答組み立てと pkg/meshname.Zone の写像）にあり、
// ここは UDP ソケットの開閉・受信ループと、OS への split DNS 注入の駆動だけを担う（要件 §4.6.5）。
//
// 待受は自身のメッシュIP の :53。ループバックの :53 は systemd-resolved・dnsmasq・Docker 等と
// 競合しうるのに対し、メッシュIP は本プロセスが払い出しを受けたアドレスで競合せず、仮想NIC が
// 消えれば同時に消えるためエフェメラル性とも整合する。ポート 53 の bind には特権が要るが、
// 仮想NIC（-tunnel）で既に管理者/root 権限を取得済みのため追加の権限要求は発生しない。

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/instantmesh/instantmesh/pkg/dnsmsg"
	"github.com/instantmesh/instantmesh/pkg/meshname"
)

const (
	// dnsPort は DNS の待受ポート。OS の split DNS 設定（Windows の NRPT 等）はポート番号を
	// 指定できないものがあるため 53 に固定する。
	dnsPort = 53
	// dnsTTL は回答の TTL（秒）。メッシュIP はセッションごとに変わるため短く保ち、
	// 名前が別セッションの古いIPへ張り付かないようにする。
	dnsTTL = 30
	// maxDNSQuery は受信バッファ長。EDNS(0) を宣言してくる stub リゾルバのクエリも収まる大きさ
	// （応答側では OPT を返さないため、我々の応答は常に 512 バイト未満に収まる）。
	maxDNSQuery = 1232
)

// dnsResponder はメッシュ名に応答するローカル DNS レスポンダ。
type dnsResponder struct {
	conn  *net.UDPConn
	zone  *meshname.Zone
	bound netip.Addr
}

// startDNSResponder は addr で UDP レスポンダを起動する。ctx 終了でソケットを閉じて受信ループを
// 抜ける。Port が 0 の場合は OS が空きポートを割り当てる（テスト用）。
func startDNSResponder(ctx context.Context, addr netip.AddrPort, zone *meshname.Zone) (*dnsResponder, error) {
	conn, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
	if err != nil {
		return nil, fmt.Errorf("DNS レスポンダの待受: %w", err)
	}
	r := &dnsResponder{conn: conn, zone: zone, bound: addr.Addr()}
	go func() {
		<-ctx.Done()
		_ = conn.Close()
	}()
	go r.serve()
	return r, nil
}

// localAddr は実際の待受アドレスを返す（ポート 0 指定時の確認用）。
func (r *dnsResponder) localAddr() netip.AddrPort {
	if a, ok := r.conn.LocalAddr().(*net.UDPAddr); ok {
		return a.AddrPort()
	}
	return netip.AddrPort{}
}

// close はソケットを閉じて受信ループを終了させる。
func (r *dnsResponder) close() { _ = r.conn.Close() }

// serve は 1 ゴルーチンでクエリを受け付け、応答を返す。ソケットが閉じられたら抜ける。
func (r *dnsResponder) serve() {
	buf := make([]byte, maxDNSQuery)
	for {
		n, src, err := r.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return // クローズ（ctx 終了 / close）
		}
		if !allowDNSSource(src.Addr(), r.bound) {
			slog.Debug("メッシュ外からの DNS クエリを破棄", "src", src.String())
			continue
		}
		resp, err := dnsmsg.Respond(buf[:n], r.zone, dnsTTL)
		if err != nil {
			continue // 応答してはいけない入力（ヘッダ長未満・応答メッセージ）は黙って破棄
		}
		if _, err := r.conn.WriteToUDPAddrPort(resp, src); err != nil {
			slog.Debug("DNS 応答の送信に失敗", "src", src.String(), "err", err)
		}
	}
}

// allowDNSSource は問い合わせ元を自機に限定する。レスポンダはメッシュIP に bind するため、
// 同じメッシュの他ピアからもクエリが届きうる。名前解決は各クライアントのローカルで完結させる
// 設計であり他ピアへ答える必要は無いため、メッシュ内で踏み台にされないよう自機発のみ応答する。
//
// 自機のリゾルバが自分のメッシュIP 宛に送るとき、送信元アドレスは同じメッシュIP（またはループ
// バック）になる。
func allowDNSSource(src, bound netip.Addr) bool {
	return src.IsLoopback() || src.Unmap() == bound.Unmap()
}

// nameResolution は名前解決の稼働一式（ローカルレスポンダ＋OS への split DNS 注入）。
// nil レシーバでも stop できるようにして、無効時の呼び出し側を単純に保つ。
type nameResolution struct {
	responder *dnsResponder
	dns       splitDNS
	injected  bool
}

// startNameResolution は割当メッシュIP でレスポンダを起動し、`.mesh` のクエリだけをそこへ向ける
// split DNS を OS へ注入する。enabled が false（-dns 無効 / -tunnel 無効）なら何もしない。
//
// 失敗はメッシュ疎通そのものを止めないよう警告に留める。名前解決が使えなくても、ゲストは
// メッシュIP 直接（要件 §4.6.2 経路(2)）で到達できる。
func startNameResolution(ctx context.Context, enabled bool, ifname, assignedIP string, zone *meshname.Zone) *nameResolution {
	if !enabled {
		return nil
	}
	addr, err := netip.ParseAddr(assignedIP)
	if err != nil {
		slog.Warn("メッシュIP を解釈できず名前解決を無効化します", "assigned_ip", assignedIP, "err", err)
		return nil
	}
	resp, err := startDNSResponder(ctx, netip.AddrPortFrom(addr, dnsPort), zone)
	if err != nil {
		slog.Warn("ローカル DNS レスポンダを起動できませんでした（メッシュIP 直接での到達は可能）", "err", err)
		return nil
	}

	n := &nameResolution{responder: resp, dns: splitDNS{Suffix: meshname.Suffix, Server: addr, IfName: ifname}}
	if err := applySplitDNS(n.dns); err != nil {
		slog.Warn("OS への split DNS 設定に失敗しました（メッシュIP 直接での到達は可能）", "err", err)
		return n
	}
	n.injected = true
	slog.Info("メッシュ名の解決を有効化しました", "suffix", "."+meshname.Suffix, "responder", resp.localAddr().String())
	return n
}

// stop は OS 設定を戻し、レスポンダを停止する（n が nil なら何もしない）。
func (n *nameResolution) stop() {
	if n == nil {
		return
	}
	if n.injected {
		if err := clearSplitDNS(n.dns); err != nil {
			slog.Warn("split DNS 設定の解除に失敗しました（次回起動時に回収します）", "err", err)
		}
	}
	n.responder.close()
}
