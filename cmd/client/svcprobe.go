package main

// 本ファイルはホスト側のローカルサービス検出（要件定義書 §4.6.1）の I/O アダプタ。
// 「どのポートを走査するか」「開いていたポートをどう並べるか」という判断は純粋ロジック
// （pkg/localsvc）にあり、ここは実際の TCP connect と並行制御だけを担う（要件 §4.6.5）。
//
// プローブは TCP connect までに留める。HTTP リクエストを送ると、相手が HTTP でない場合の
// 誤検出に加え、推論エンドポイントに意図しない副作用を与えうるため（§4.6.1）。接続できた
// 時点で待受の存在は確認できるので、何も送らず直ちに閉じる。
//
// 走査対象はローカルループバックのみ。ホスト側サービスに 0.0.0.0 バインドを要求しないことが
// 設計要件であり（§4.6.1・付録C D-9）、検出側も 127.0.0.1 / ::1 だけを見る。

import (
	"context"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/instantmesh/instantmesh/pkg/localsvc"
)

// プローブの既定パラメータ。ループバックへの connect は成功・拒否とも即座に返るため短くてよい。
// timeout が効くのはフィルタ等で応答が返らない場合の待ち切りであり、検出全体を遅らせない値にする。
const (
	probeTimeout     = 300 * time.Millisecond
	probeConcurrency = 8
)

// loopbackHosts は待受を探すループバックアドレス。127.0.0.1 だけでは、`localhost` が ::1 に
// 解決される環境（Windows の Node 系開発サーバー等）で IPv6 のみに bind したサービスを
// 取りこぼすため、両系統を試して片方でも接続できれば「開いている」とみなす。
var loopbackHosts = []string{"127.0.0.1", "::1"}

// dialFunc は TCP connect の注入点（テストでフェイクへ差し替える）。net.Dialer.DialContext と同形。
type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// dialTCP は実 TCP connect。
func dialTCP(ctx context.Context, network, addr string) (net.Conn, error) {
	var d net.Dialer
	return d.DialContext(ctx, network, addr)
}

// detectLocalServices は既知ポート（pkg/localsvc の表）を走査し、手動指定 manual と併せた共有候補
// 一覧を返す。候補提示であって共有の実行ではない（共有可否はホストの明示選択による・§4.6.1）。
func detectLocalServices(ctx context.Context, manual []int, dial dialFunc) ([]localsvc.Candidate, error) {
	open := probePorts(ctx, localsvc.ScanPorts(), probeTimeout, dial)
	return localsvc.Candidates(open, manual)
}

// probePorts は ports の各ポートへ TCP connect を試み、接続できたポートを昇順で返す。
// 並行数は probeConcurrency に制限する。ctx がキャンセルされた場合は、その時点までに
// 確認できた分だけを返す（呼び出し側は部分結果を候補提示に使ってよい）。
func probePorts(ctx context.Context, ports []int, timeout time.Duration, dial dialFunc) []int {
	sem := make(chan struct{}, probeConcurrency)
	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		open []int
	)
	for _, p := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
			case <-ctx.Done():
				return
			}
			defer func() { <-sem }()

			if !probeOne(ctx, port, timeout, dial) {
				return
			}
			mu.Lock()
			open = append(open, port)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Ints(open)
	return open
}

// probeOne は 1 ポートについて、ループバック各系統への TCP connect を順に試す。
// 接続できたら何も送信せずに閉じて true を返す。
func probeOne(ctx context.Context, port int, timeout time.Duration, dial dialFunc) bool {
	addr := strconv.Itoa(port)
	for _, host := range loopbackHosts {
		dialCtx, cancel := context.WithTimeout(ctx, timeout)
		conn, err := dial(dialCtx, "tcp", net.JoinHostPort(host, addr))
		// 接続確立後のキャンセルは既存コネクションに影響しない（net.Dialer.DialContext の規定）ため、
		// ここで解放してよい。
		cancel()
		if err != nil {
			continue
		}
		_ = conn.Close()
		return true
	}
	return false
}
