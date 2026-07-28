package main

// 本ファイルは共有サービスの前段に立つ L7（HTTP）の統制層（要件定義書 §4.7）。
//
// 解決する課題: Ollama・LM Studio 等のローカル推論エンドポイントには認証機構が無く、ポートに
// 到達できた者は誰でも GPU を叩ける（§1.1）。メッシュへの参加は待合室承認で制御できるが、
// 「参加は許すがこのサービスは貸さない」「このゲストの利用だけ止める」は表現できない。
// そこで共有サービスの手前に HTTP プロキシを置き、ゲストごとのキーと上限を強制する。
//
// 適用範囲（付録C.9 D-16）:
//   - **HTTP に限定する。** 対象は Ollama / OpenAI 互換 API（`Authorization: Bearer` を送れる
//     既存ツールがそのまま使える）。TLS 終端や非 HTTP プロトコルは対象外で、その場合は
//     キー要求を無効にして L4 の到達制御（付録C.9 D-11）だけで運用する。
//   - **モデル単位の識別は行わない。** 本文（JSON）の解釈が要るため後続とする。ここで数えるのは
//     リクエスト数までで、バイト数は L4 側（tunfilter）が計上する。
//
// 認可はキーで、計上と上限判定は接続元のメッシュIP で行う。キーは「誰として使うか」の申告で
// あり、実際にどのピアから来たかは送信元アドレスが示すため。

import (
	"encoding/json"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"github.com/instantmesh/instantmesh/pkg/accesskey"
	"github.com/instantmesh/instantmesh/pkg/usage"
)

// keyHeader はアクセスキーを載せる独自ヘッダ。`Authorization: Bearer <key>` を送れない
// クライアント向けの代替で、通常は Authorization を使う。
const keyHeader = "X-InstantMesh-Key"

// l7Gate は共有サービスへの HTTP リクエストを検査する。keys が nil ならキーを要求しない。
type l7Gate struct {
	keys *accesskey.Registry
	rec  *usage.Recorder
	now  func() time.Time
	// requireKey が真のときだけキーを要求する（有料プラン機能・§5）。
	requireKey bool
}

// verdict は 1 リクエストに対する判定。
type verdict struct {
	status int    // 0 は通過
	reason string // 拒否理由（利用者向け）
}

// check はリクエストの可否を判定し、通す場合はリクエスト数を計上する。
// peer は接続元のメッシュIP、port は共有サービスのポート。
func (g *l7Gate) check(peer netip.Addr, port uint16, header http.Header) verdict {
	if g.requireKey {
		key := extractKey(header)
		if _, ok := g.keys.Verify(key); !ok {
			// キーの有無・誤りを区別せず同じ応答にする（存在探索の手がかりを与えない）。
			return verdict{status: http.StatusUnauthorized, reason: "アクセスキーが必要です"}
		}
	}
	// 上限に達したゲストだけを遮断する（ルーム全体には影響させない・§4.7）。
	if g.rec.Exceeded(peer) {
		return verdict{status: http.StatusTooManyRequests, reason: "利用上限に達しました"}
	}
	g.rec.AddRequest(peer, port, g.now())
	return verdict{}
}

// extractKey は Authorization: Bearer / 独自ヘッダからキーを取り出す。
func extractKey(h http.Header) string {
	if a := h.Get("Authorization"); a != "" {
		if k, ok := strings.CutPrefix(a, "Bearer "); ok {
			return strings.TrimSpace(k)
		}
		if k, ok := strings.CutPrefix(a, "bearer "); ok {
			return strings.TrimSpace(k)
		}
	}
	return strings.TrimSpace(h.Get(keyHeader))
}

// httpProxy は 1 共有サービス分の HTTP プロキシ（メッシュIP:ポート → localhost:ポート）。
// forwarder と同じく待受と転送先を独立に受け、close で直ちに解放する。
type httpProxy struct {
	ln  net.Listener
	srv *http.Server
}

// startHTTPProxy は listen で待ち受け、gate を通した要求だけを target へ中継する。
func startHTTPProxy(listen netip.AddrPort, target string, port uint16, gate *l7Gate) (*httpProxy, error) {
	ln, err := net.Listen("tcp", listen.String())
	if err != nil {
		return nil, err
	}
	rp := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(&url.URL{Scheme: "http", Host: target})
			// Host ヘッダは元のまま保つ。絶対URLを生成するアプリやオリジン検査の挙動を
			// ローカル実行時と揃えるため（§4.6.4 と同じ理由）。
			r.Out.Host = r.In.Host
			// 上流へキーを渡さない（共有サービス自身は本プロダクトのキーを知らない）。
			r.Out.Header.Del(keyHeader)
		},
		// 推論の応答はトークンを逐次流す（SSE / NDJSON）。バッファすると体感が壊れるため即時に流す。
		FlushInterval: -1,
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			slog.Debug("共有サービスへの中継に失敗", "target", target, "err", err)
			writeGateError(w, http.StatusBadGateway, "共有サービスへ接続できません")
		},
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		peer := peerAddr(r.RemoteAddr)
		if v := gate.check(peer, port, r.Header); v.status != 0 {
			if v.status == http.StatusUnauthorized {
				w.Header().Set("WWW-Authenticate", "Bearer")
			}
			writeGateError(w, v.status, v.reason)
			return
		}
		rp.ServeHTTP(w, r)
	})
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	go func() { _ = srv.Serve(ln) }()
	return &httpProxy{ln: ln, srv: srv}, nil
}

// addr は実際の待受アドレスを返す。
func (p *httpProxy) addr() net.Addr { return p.ln.Addr() }

// close は待受と確立済み接続を直ちに閉じる（共有停止・解散で即時解放する）。
func (p *httpProxy) close() { _ = p.srv.Close() }

// peerAddr は RemoteAddr（"IP:port"）から接続元アドレスを取り出す。
func peerAddr(remote string) netip.Addr {
	host, _, err := net.SplitHostPort(remote)
	if err != nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}
	}
	return a.Unmap()
}

// writeGateError は拒否理由を JSON で返す。OpenAI 互換クライアントが本文を読めるよう
// 単純な {"error": "..."} 形式にする。
func writeGateError(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": reason})
}
