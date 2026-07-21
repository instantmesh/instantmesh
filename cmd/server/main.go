// Command server は InstantMesh のシグナリング＋リレーサーバー。
//
// コントロールプレーン（/ws）: WebSocket でホスト / ゲストのコントロールメッセージを受け、
// トランスポート非依存の pkg/hub（→ pkg/session → pkg/manager/room）へ配線する。
// データプレーン（/relay）: P2P 直通に失敗したピア間の暗号化パケットを pkg/relayhub で中継する。
//
// 両者はコード上 pkg/hub / pkg/relayhub として論理分離しつつ、フェーズ1は単一プロセスで
// manager（セッションストア）を共有して動作する（スケール時に別インスタンスへ分離可能）。
// E2E 暗号化の原則どおり、サーバーは WireGuard 秘密鍵などの復号鍵を一切受信・保持しない。
//
// フェーズ1は最小構成: 認証は DevAuthenticator（Cognito JWT のモック）、リレー認証は共有
// manager によるトークン/承認/プラン検証、監査は slog 出力、セッションはインメモリ。
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/instantmesh/instantmesh/pkg/clientip"
	"github.com/instantmesh/instantmesh/pkg/cognitojwt"
	"github.com/instantmesh/instantmesh/pkg/hub"
	"github.com/instantmesh/instantmesh/pkg/manager"
	"github.com/instantmesh/instantmesh/pkg/relayhub"
	"github.com/instantmesh/instantmesh/pkg/session"
)

// ルーム作成・参加申請のレート制限（要件 §4.4）。
const (
	createRate  = 1.0 / 60.0 // 1 アカウントあたり平均 1 分に 1 室
	createBurst = 5          // 瞬間 5 室まで
	joinRate    = 1.0 / 10.0 // 1 ルーム 1 IP あたり平均 10 秒に 1 回
	joinBurst   = 10         // 瞬間 10 回まで
)

// config はサーバー設定。
type config struct {
	addr                string
	path                string // シグナリング（コントロールプレーン）のパス
	relayPath           string // リレー（データプレーン）のパス
	maintenanceInterval time.Duration
	shutdownGrace       time.Duration
	pool                netip.Prefix   // ルームへ払い出す /24 の元ブロック
	trustedProxies      []netip.Prefix // X-Forwarded-For を信頼するリバースプロキシの CIDR（空=直接公開・XFF 無視）
	cognitoIssuer       string         // Cognito issuer URL。audience とともに設定すると JWT 認証を有効化（空=DevAuthenticator）
	cognitoAudience     string         // 要求する Cognito app client id（aud）
	cognitoProGroup     string         // Pro とみなす cognito:groups 名（空なら全ホスト Free）
	cognitoJWKSTTL      time.Duration  // JWKS キャッシュの有効期間
	auditS3Bucket       string         // 監査ログの S3 バケット（空=slog 出力のみ）
	auditS3Region       string         // 監査バケットのリージョン
	auditS3KMSKeyID     string         // SSE-KMS キーID（空=バケット既定の暗号化）
	auditS3Prefix       string         // 監査オブジェクトのキープレフィックス
	auditBatchMax       int            // この件数に達したらフラッシュ
	auditBatchAge       time.Duration  // 最古イベントがこの経過時間に達したらフラッシュ
	auditFlushInterval  time.Duration  // 経過時間フラッシュのチェック周期
}

// connCloser はグレースフルシャットダウンで生存接続をクローズできるトランスポート。
type connCloser interface{ CloseConns() }

// auditCloser はシャットダウン時に残りの監査バッチをフラッシュできる監査ロガー。
type auditCloser interface{ Close() }

// builtServer は組み立て済みのサーバー構成。
type builtServer struct {
	http    *http.Server
	maint   maintainer   // 定期メンテナンス対象（シグナリング Hub）
	closers []connCloser // シャットダウン時にクローズするトランスポート群
	audit   auditCloser  // バッファ付き監査ロガーのフラッシュ用（nil 可）
}

func main() {
	cfg, err := parseFlags(os.Args[1:])
	if err != nil {
		slog.Error("引数の解析に失敗", "err", err)
		os.Exit(2)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		slog.Error("サーバーエラー", "err", err)
		os.Exit(1)
	}
}

// parseFlags は引数を解析して config を返す。
func parseFlags(args []string) (config, error) {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	addr := fs.String("addr", ":8080", "listen address")
	path := fs.String("path", "/ws", "signaling (control plane) endpoint path")
	relayPath := fs.String("relay-path", "/relay", "relay (data plane) endpoint path")
	interval := fs.Duration("maintenance-interval", 30*time.Second, "room sweep / pending-expiry interval")
	grace := fs.Duration("shutdown-grace", 5*time.Second, "graceful shutdown timeout")
	poolStr := fs.String("pool", "10.0.0.0/8", "IPv4 address pool (prefix <= /24) for room subnets")
	proxiesStr := fs.String("trusted-proxies", "", "comma-separated CIDRs of trusted reverse proxies for X-Forwarded-For (empty = ignore XFF)")
	cognitoIssuer := fs.String("cognito-issuer", "", "Cognito issuer URL (https://cognito-idp.<region>.amazonaws.com/<poolId>); set with -cognito-audience to enable JWT auth (else DevAuthenticator)")
	cognitoAudience := fs.String("cognito-audience", "", "required Cognito app client id (aud) when JWT auth is enabled")
	cognitoProGroup := fs.String("cognito-pro-group", "pro", "cognito:groups name that grants the Pro plan (empty = all hosts are Free)")
	cognitoJWKSTTL := fs.Duration("cognito-jwks-ttl", time.Hour, "JWKS cache TTL for Cognito JWT auth")
	auditBucket := fs.String("audit-s3-bucket", "", "S3 bucket for audit logs (empty = slog only)")
	auditRegion := fs.String("audit-s3-region", "ap-northeast-1", "AWS region for the audit S3 bucket")
	auditKMS := fs.String("audit-s3-kms-key-id", "", "KMS key id for SSE-KMS (empty = bucket default encryption)")
	auditPrefix := fs.String("audit-s3-prefix", "audit", "key prefix for audit objects")
	auditBatchMax := fs.Int("audit-batch-max", 100, "flush after this many buffered audit events")
	auditBatchAge := fs.Duration("audit-batch-age", 5*time.Minute, "flush after the oldest buffered event reaches this age")
	auditFlush := fs.Duration("audit-flush-interval", 30*time.Second, "how often to check the age-based flush")
	if err := fs.Parse(args); err != nil {
		return config{}, err
	}
	pool, err := netip.ParsePrefix(*poolStr)
	if err != nil {
		return config{}, fmt.Errorf("invalid -pool %q: %w", *poolStr, err)
	}
	proxies, err := parseCIDRs(*proxiesStr)
	if err != nil {
		return config{}, err
	}
	return config{
		addr:                *addr,
		path:                *path,
		relayPath:           *relayPath,
		maintenanceInterval: *interval,
		shutdownGrace:       *grace,
		pool:                pool,
		trustedProxies:      proxies,
		cognitoIssuer:       *cognitoIssuer,
		cognitoAudience:     *cognitoAudience,
		cognitoProGroup:     *cognitoProGroup,
		cognitoJWKSTTL:      *cognitoJWKSTTL,
		auditS3Bucket:       *auditBucket,
		auditS3Region:       *auditRegion,
		auditS3KMSKeyID:     *auditKMS,
		auditS3Prefix:       *auditPrefix,
		auditBatchMax:       *auditBatchMax,
		auditBatchAge:       *auditBatchAge,
		auditFlushInterval:  *auditFlush,
	}, nil
}

// parseCIDRs はカンマ区切りの CIDR 一覧を netip.Prefix へ解析する。空文字列は nil（信頼プロキシ
// なし）。空要素は無視し、不正な CIDR はエラーにする。
func parseCIDRs(s string) ([]netip.Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, nil
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("invalid -trusted-proxies entry %q: %w", part, err)
		}
		out = append(out, p)
	}
	return out, nil
}

// buildServer は設定からドメイン層を組み立て、シグナリング / リレー両エンドポイントを
// 束ねた HTTP サーバーを返す（I/O は行わない）。両者は共有 manager 上で動く。
func buildServer(cfg config) (*builtServer, error) {
	mgr, err := manager.New(manager.Config{
		Pool:        cfg.pool,
		CreateRate:  createRate,
		CreateBurst: createBurst,
		JoinRate:    joinRate,
		JoinBurst:   joinBurst,
	})
	if err != nil {
		return nil, fmt.Errorf("manager 初期化: %w", err)
	}

	sigHub := hub.New(session.New(mgr))
	audit := newAuditLogger(cfg)
	sig := NewServer(sigHub, newAuthenticator(cfg), audit)
	rly := NewRelayServer(relayhub.New(), managerAuthorizer{mgr: mgr})

	mux := http.NewServeMux()
	mux.HandleFunc(cfg.path, sig.ServeWS)
	mux.HandleFunc(cfg.relayPath, rly.ServeRelay)

	bs := &builtServer{
		// ReadHeaderTimeout: ヘッダ受信を時間制限し Slowloris 系の接続占有 DoS を抑止する
		// （WebSocket は長寿命のため ReadTimeout/WriteTimeout は設定しない。H-01 備考）。
		http:    &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second},
		maint:   sigHub,
		closers: []connCloser{sig, rly},
	}
	// バッファ付き監査ロガー（S3）はシャットダウン時に残バッチをフラッシュする。
	if c, ok := audit.(auditCloser); ok {
		bs.audit = c
	}
	return bs, nil
}

// newAuditLogger は設定に応じて監査ロガーを選ぶ。-audit-s3-bucket 指定時は S3 へバッチ書き込み
// する BufferedAuditLogger を、未指定時は slog 出力の SlogAuditLogger を返す。S3 クライアントの
// 初期化に失敗した場合は監査を止めないため slog へフォールバックする。
func newAuditLogger(cfg config) AuditLogger {
	if cfg.auditS3Bucket == "" {
		return SlogAuditLogger{}
	}
	sink, err := NewS3Sink(context.Background(), cfg.auditS3Region, cfg.auditS3Bucket, cfg.auditS3KMSKeyID)
	if err != nil {
		slog.Error("S3 監査 Sink の初期化に失敗。slog にフォールバックします", "err", err)
		return SlogAuditLogger{}
	}
	slog.Info("S3 監査ログを有効化", "bucket", cfg.auditS3Bucket, "region", cfg.auditS3Region)
	return NewBufferedAuditLogger(sink, cfg.auditS3Prefix, cfg.auditBatchMax, cfg.auditBatchAge, cfg.auditFlushInterval, time.Now)
}

// newAuthenticator は設定に応じて認証器を選ぶ。Cognito の issuer と audience が両方設定されて
// いれば Cognito JWT 検証（CognitoAuthenticator）を、そうでなければ開発用 DevAuthenticator
// （JWT を検証しない）を返す。JWKS URL は issuer から導出する。
func newAuthenticator(cfg config) Authenticator {
	proxies := clientip.NewResolver(cfg.trustedProxies)
	if cfg.cognitoIssuer != "" && cfg.cognitoAudience != "" {
		jwksURL := strings.TrimRight(cfg.cognitoIssuer, "/") + "/.well-known/jwks.json"
		slog.Info("Cognito JWT 認証を有効化", "issuer", cfg.cognitoIssuer, "audience", cfg.cognitoAudience)
		return NewCognitoAuthenticator(
			cognitojwt.Config{
				Issuer:   cfg.cognitoIssuer,
				Audience: cfg.cognitoAudience,
				TokenUse: "id",
				Leeway:   60 * time.Second,
			},
			jwksURL, cfg.cognitoProGroup, proxies, cfg.cognitoJWKSTTL, time.Now,
		)
	}
	slog.Warn("DevAuthenticator を使用中（JWT を検証しません）。本番では -cognito-issuer と -cognito-audience を指定してください")
	return DevAuthenticator{Proxies: proxies}
}

// warnIfInsecureBind は非ループバックアドレスに平文(ws)で待ち受けている場合に警告する。
// サーバーバイナリ自体は TLS を終端せず、本番は ALB 等で WSS 終端する方針だが、運用ミスで
// ALB を介さず直接公開すると招待トークン / ルームトークンが平文で流れ、受動盗聴でルーム
// 乗っ取りに繋がる。コードで TLS を強制できないため、少なくとも警告で気付けるようにする（L-03）。
func warnIfInsecureBind(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	if !ip.IsLoopback() {
		slog.Warn("非ループバックアドレスに平文(ws)で待ち受けています。本番では ALB 等で TLS(WSS) を終端し、直接公開しないでください", "addr", addr)
	}
}

// run は設定からサーバーを構築し、リスナーを開いて serve に委譲する。
func run(ctx context.Context, cfg config) error {
	b, err := buildServer(cfg)
	if err != nil {
		return err
	}
	ln, err := net.Listen("tcp", cfg.addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", cfg.addr, err)
	}
	return serve(ctx, cfg, ln, b)
}

// serve は listener 上でサービスを提供する。定期メンテナンスを起動し、ctx 終了時に全接続を
// クローズしてグレースフルシャットダウンする。Serve が想定外に失敗した場合はその error を返す。
func serve(ctx context.Context, cfg config, ln net.Listener, b *builtServer) error {
	go runMaintenance(ctx, b.maint, cfg.maintenanceInterval, time.Now)

	errCh := make(chan error, 1)
	go func() { errCh <- b.http.Serve(ln) }()
	slog.Info("server listening", "addr", ln.Addr().String(), "signaling", cfg.path, "relay", cfg.relayPath)
	warnIfInsecureBind(ln.Addr().String())

	select {
	case <-ctx.Done():
		slog.Info("シャットダウン開始")
		for _, c := range b.closers {
			c.CloseConns()
		}
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.shutdownGrace)
		defer cancel()
		_ = b.http.Shutdown(shutdownCtx)
		if b.audit != nil {
			b.audit.Close() // 残りの監査バッチを S3 へフラッシュ。
		}
		return nil
	case err := <-errCh:
		return err
	}
}
