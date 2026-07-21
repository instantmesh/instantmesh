// Command client は InstantMesh のヘッドレス・シグナリング / P2P クライアント（フェーズ1骨格）。
//
// 鍵生成（pkg/wgkey）・招待リンク（pkg/invite）・シグナリング（pkg/signalclient + pkg/wsconn）・
// STUN（pkg/stun）・WireGuard 設定（pkg/wgconf + pkg/meshpeer）を束ね、ホスト（作成・承認）／
// ゲスト（参加・帯域外MITM照合）のフローを行い、-tunnel 指定時は wireguard-go 仮想NICを起動して
// 受信した peer_info からピアを構成する。
//
// STUN（フェーズ1）: -tunnel 起動時は WireGuard と同一の UDP ソケット（sharedBind）から STUN を
// 行うため、得られる WAN マッピングは WireGuard の送信マッピングと一致し hole punching が成立する
// （対称NAT×対称NAT はリレー必須で対象外）。-tunnel 無しの場合は別ソケットの STUN にフォールバック
// する（マッピングがずれうる）。
//
// P2P直通⇄リレーフォールバック（フェーズ1）: -tunnel かつ -relay 有効時、ピアごとに接続モニタ
// （connMonitor＋pkg/connmon）を起動する。直通 WAN エンドポイント適用後、WireGuard の最終
// ハンドシェイク成立（pkg/wgstat）を周期観測し、一定時間（ProbeTimeout）成立しなければリレーへ
// フォールバックする。リレー経路は wsRelay（/relay への WebSocket・pkg/relayframe）と loopback UDP
// プロキシ（relayProxy）で実現し、WireGuard のエンドポイントを 127.0.0.1 のループバックへ差し替える
// ことで、暗号化パケットをリレー経由でピアへ橋渡しする（サーバーは復号しない）。直通が失敗する
// 対称的な NAT では双方が同時期に転落してリレーで疎通する。
//
// 仮想NICへの IP 付与・ルーティング（フェーズ1）: -tunnel 起動時、ルーム参加が確定した時点で割当
// メッシュIP をインターフェースに付与し、メッシュ /24 を当該インターフェース経由にルート設定する
// （pkg/netcfg で算出、OS 依存の適用は configureLink）。要管理者/root 権限。
//
// 使い方:
//
//	client -mode host  -server ws://HOST:8080/ws -account <token> [-tunnel -stun stun.l.google.com:19302]
//	client -mode guest -invite "instantmesh://join?..." [-nick alice -tunnel -stun ...]
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/invite"
	"github.com/instantmesh/instantmesh/pkg/meshpeer"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/secret"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
	"github.com/instantmesh/instantmesh/pkg/signaling"
	"github.com/instantmesh/instantmesh/pkg/stun"
	"github.com/instantmesh/instantmesh/pkg/wgconf"
	"github.com/instantmesh/instantmesh/pkg/wgkey"
	"github.com/instantmesh/instantmesh/pkg/wsconn"
)

func main() {
	mode := flag.String("mode", "gui", "host / guest / gui（既定 gui。省略時は GUI モードで起動）")
	server := flag.String("server", "wss://s1.instantmesh.net/ws", "シグナリングサーバー WebSocket URL（host。既定は公開サーバー。ローカル検証は ws://localhost:8080/ws を指定）")
	account := flag.String("account", "dev-account", "ホスト認証トークン（host）")
	nick := flag.String("nick", "guest", "ニックネーム（guest）")
	inviteURL := flag.String("invite", "", "招待リンク（guest）")
	duration := flag.Int64("duration", 3600, "ルーム制限時間（秒・host）")
	auto := flag.Bool("auto-approve", false, "参加申請を自動承認する（host・デモ用）。既定は手動承認（標準入力に approve/reject を入力）")
	useTunnel := flag.Bool("tunnel", false, "wireguard-go 仮想NICを起動する（要管理者権限）")
	ifname := flag.String("ifname", "wg-mesh", "仮想NICのインターフェース名（Linux 任意/macOS は utun）")
	stunAddr := flag.String("stun", "", "STUN サーバー host:port（指定時に WAN を発見し peer_info を広告）")
	relay := flag.Bool("relay", true, "P2P直通に失敗したらリレーへ自動フォールバックする（要 -tunnel）")
	guiAddr := flag.String("gui-addr", "127.0.0.1:8088", "GUI モードで待ち受ける localhost アドレス（外部公開しない）")
	cognitoDomain := flag.String("cognito-domain", "https://instantmesh-net.auth.ap-northeast-1.amazoncognito.com", "Cognito Hosted UI ベース URL。既定は公開サーバーのユーザープール。ホストは PKCE サインインで ID トークンを取得する。ローカルの DevAuthenticator サーバーに繋ぐ場合は空文字を指定して無効化する（その場合は -account を Bearer に使用）")
	cognitoClientID := flag.String("cognito-client-id", "1mhe007gbarnh3u2f0dkglm8ep", "Cognito アプリクライアント ID（公開クライアント・シークレット無し）。既定は公開サーバーのアプリクライアント")
	cognitoScope := flag.String("cognito-scope", "openid", "要求スコープ（カンマ区切り）")
	flag.Parse()

	cognito := cognitoConfig{
		domain:      *cognitoDomain,
		clientID:    *cognitoClientID,
		redirectURI: defaultCognitoRedirect, // Cognito 登録値に固定（フラグ廃止）
		scopes:      splitScopes(*cognitoScope),
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var err error
	switch *mode {
	case "host":
		cfg := hostConfig{
			server: *server, account: *account, durationSec: *duration,
			auto: *auto, useTunnel: *useTunnel, ifname: *ifname, stunAddr: *stunAddr,
			relay: *relay, stdinConsole: true, cognito: cognito,
		}
		err = runHost(ctx, cfg, newViewStore(), nil)
	case "guest":
		cfg := guestConfig{
			inviteURL: *inviteURL, nick: *nick, useTunnel: *useTunnel,
			ifname: *ifname, stunAddr: *stunAddr, relay: *relay,
		}
		err = runGuest(ctx, cfg, newViewStore(), nil)
	case "gui":
		warnIfNonLoopbackGUIAddr(*guiAddr)
		opts := guiOptions{
			server: *server, account: *account, duration: *duration,
			useTunnel: *useTunnel, ifname: *ifname, stunAddr: *stunAddr, relay: *relay,
			cognito: cognito,
		}
		err = runGUI(ctx, *guiAddr, opts)
	default:
		slog.Error("-mode は host / guest / gui を指定してください")
		os.Exit(2)
	}
	if err != nil {
		slog.Error("client エラー", "err", err)
		os.Exit(1)
	}
}

// warnIfNonLoopbackGUIAddr は GUI LocalAPI を非ループバックアドレスで待ち受ける設定を警告する。
// 既定は 127.0.0.1 で、pkg/originguard が非ループバック Host の /api/* を fail-closed で 403 に
// するため機密メタデータ API 自体は保護されるが、誤って 0.0.0.0 等で公開する設定に気付けるよう
// 警告する（L-08）。
func warnIfNonLoopbackGUIAddr(addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return
	}
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return
	}
	if !ip.IsLoopback() {
		slog.Warn("GUI を非ループバックアドレスで待ち受けています。意図しない限り外部公開は避けてください（既定 127.0.0.1）", "gui_addr", addr)
	}
}

// hostConfig は runHost の設定一式。CLI フラグ（ヘッドレス）と GUI（LocalAPI）双方から
// 組み立てられ、同じ受信ループを駆動する（設計原則1: UI とコアの分離）。
type hostConfig struct {
	server, account  string
	durationSec      int64
	auto             bool // 参加申請を自動承認する（デモ用。既定 false。GUI では人が承認するため false）
	useTunnel        bool
	ifname, stunAddr string
	relay            bool
	stdinConsole     bool          // 標準入力でホスト操作（approve/reject/rotate）を受け付ける（ヘッドレスのみ。GUI は POST で操作）
	cognito          cognitoConfig // 設定時は PKCE サインインで ID トークンを取得し Bearer に用いる（未設定なら account）
}

// runHost はホストとして接続し、ルーム作成・待合室承認・ピア構成を処理する。
// 表示状態は store（ゴルーチンセーフな appstate ビューモデル）へ反映し、GUI はこれを購読する。
// onClient は接続確立後に signalclient を呼び出し側へ公開するフック（GUI が承認/再発行/退出の
// 操作に使う。ヘッドレスでは nil）。
func runHost(ctx context.Context, cfg hostConfig, store *viewStore, onClient func(*signalclient.Client)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	priv, pub, err := wgkey.GenerateSecret()
	if err != nil {
		return fmt.Errorf("鍵生成: %w", err)
	}
	// 秘密鍵はメモリロック（可能なら）＋使用後ゼロ化できるバッファで保持する。
	sk := newSecret(priv)
	tun, err := openTunnel(cfg.useTunnel, cfg.ifname, sk)
	// 秘密鍵は wireguard-go デバイスへ適用済み。自コピーは以後不要なので即ゼロ化する。
	sk.Wipe()
	if err != nil {
		return err
	}
	if tun != nil {
		defer tun.Close()
	}

	// ホスト認証トークン: Cognito 設定があれば PKCE サインインで ID トークンを取得し、
	// なければ従来どおり -account の値を Bearer に用いる（開発フロー互換）。
	bearer := cfg.account
	if cfg.cognito.enabled() {
		token, err := newCognitoLogin(cfg.cognito).signIn(ctx)
		if err != nil {
			return fmt.Errorf("Cognito サインイン: %w", err)
		}
		bearer = token
	}

	conn, err := wsconn.Dial(withQuery(cfg.server, "role", "host", "pubkey", pub),
		http.Header{"Authorization": {"Bearer " + bearer}})
	if err != nil {
		return fmt.Errorf("接続: %w", err)
	}
	defer conn.Close()
	go closeOnDone(ctx, conn)

	c := signalclient.New(conn)
	if onClient != nil {
		onClient(c)
	}
	if err := c.CreateRoom(cfg.durationSec); err != nil {
		return err
	}
	// 標準入力からホスト操作（承認/拒否/招待リンク再発行）を受け付ける（ヘッドレス運用の簡易コンソール）。
	if cfg.stdinConsole {
		go watchStdinConsole(ctx, c, store)
	}

	// GUI ビューモデル（表示状態の単一の真実）。各イベントで store を更新し、GUI はこれを
	// 購読して描画する（設計原則1: UI とコアの分離）。
	store.update(func(m *appstate.Model) { _ = m.StartHosting() })

	var monitor *connMonitor // ルーム作成後に生成（トークンが要る）
	for {
		env, err := c.Next()
		if err != nil {
			return err
		}
		// 後続イベントの反映を機に直近の非致命エラー文言を消す（回復時にバナーを残さない）。
		store.update(func(m *appstate.Model) { m.ClearError() })
		switch env.Type {
		case signaling.TypeRoomCreated:
			var rc signaling.RoomCreated
			_ = env.Unmarshal(&rc)
			inv := invite.Invite{Server: cfg.server, Token: rc.Token, HostPubKey: pub}
			link, _ := inv.URL()
			store.update(func(m *appstate.Model) { _ = m.RoomCreated(rc.RoomID, link, inv.SAS()) })
			slog.Info("ルーム作成", "room_id", rc.RoomID, "host_ip", rc.HostIP)
			fmt.Println("招待リンク:", link)
			fmt.Println("SAS:", inv.SAS())
			printInviteQR(os.Stdout, link)
			// 仮想NICにホストIP付与＋メッシュルート設定、続いて直通監視＋リレーフォールバックを起動。
			configureTunnel(tun, rc.HostIP)
			applyPlanFilter(tun, rc.Tier) // プランに応じた無料版ポート制限フィルタ
			monitor = startMonitor(ctx, tun, cfg.relay, cfg.server, rc.RoomID, pub)
		case signaling.TypeJoinPending:
			var jp signaling.JoinPending
			_ = env.Unmarshal(&jp)
			store.update(func(m *appstate.Model) { _ = m.AddPending(jp.GuestPubKey, jp.Nickname, jp.SAS) })
			slog.Info("参加申請", "nickname", jp.Nickname, "sas", jp.SAS, "guest", jp.GuestPubKey)
			if cfg.auto {
				if err := c.Approve(jp.GuestPubKey); err != nil {
					return err
				}
				store.update(func(m *appstate.Model) { _ = m.Approve(jp.GuestPubKey) })
				slog.Info("自動承認", "guest", jp.GuestPubKey)
			} else if cfg.stdinConsole {
				// 手動承認: SAS/ニックネームを帯域外照合したうえで標準入力から承認/拒否する。
				// guest_pub_key はクライアント任意文字列（サーバー・ホストとも正規の公開鍵として
				// 検証しない）で制御文字を含めうるため、必ず %q で出力して端末エスケープ注入
				// （SAS 表示行の上書き等でオペレータを欺き中間者を誤承認させる攻撃）を無害化する（M-05）。
				fmt.Printf("待合室に参加申請: nick=%q SAS=%s\n  承認は `approve %q` / 拒否は `reject %q`（先頭数文字でも可）\n",
					jp.Nickname, jp.SAS, jp.GuestPubKey, jp.GuestPubKey)
			}
		case signaling.TypeGuestJoined:
			var gj signaling.GuestJoined
			_ = env.Unmarshal(&gj)
			store.update(func(m *appstate.Model) { _ = m.GuestJoined(gj.GuestPubKey, gj.AssignedIP) })
			slog.Info("ゲスト参加", "nickname", gj.Nickname, "assigned_ip", gj.AssignedIP, "guest", gj.GuestPubKey)
			advertise(c, tun, cfg.stunAddr, pub) // 新ゲストへ自エンドポイントを広告
		case signaling.TypeGuestLeft:
			var gl signaling.GuestLeft
			_ = env.Unmarshal(&gl)
			store.update(func(m *appstate.Model) { _ = m.GuestLeft(gl.GuestPubKey) })
			slog.Info("ゲスト離脱", "guest", gl.GuestPubKey)
			// WireGuard ピアを除去し、監視終了＋リレーのループバックソケットを解放する。
			applyPeer(tun, meshpeer.RemovePeer(gl.GuestPubKey), nil)
			monitor.Untrack(gl.GuestPubKey)
		case signaling.TypePeerInfo:
			var pi signaling.PeerInfo
			_ = env.Unmarshal(&pi)
			slog.Info("ピア情報受信", "pubkey", pi.PubKey, "endpoint", pi.WANEndpoint)
			if ip, ok := store.guestIP(pi.PubKey); ok {
				build := func(endpoint string) (wgconf.Config, error) {
					return meshpeer.HostPeer(pi.PubKey, ip, endpoint)
				}
				// まず直通エンドポイントを適用し、続けて直通監視を開始する（失敗時リレーへ転落）。
				pcfg, cerr := build(pi.WANEndpoint)
				applyPeer(tun, pcfg, cerr)
				store.update(func(m *appstate.Model) { _ = m.PeerUp(pi.PubKey, appstate.RouteDirect) })
				trackPeer(monitor, pi.PubKey, pi.WANEndpoint, build)
			}
		case signaling.TypeInviteReissued:
			var ir signaling.InviteReissued
			_ = env.Unmarshal(&ir)
			// 新トークンで招待リンク/QR を再生成する。旧トークンはサーバー側で失効済み。
			// リレー認可はルームIDベースでトークン非依存のため、承認済みピアのリレー疎通は
			// 再発行の影響を受けず維持される（監視の再設定は不要）。
			inv := invite.Invite{Server: cfg.server, Token: ir.Token, HostPubKey: pub}
			link, _ := inv.URL()
			store.update(func(m *appstate.Model) { _ = m.ReissueInvite(link) })
			slog.Info("招待リンクを再発行しました（旧リンクは即時失効・承認済みピアは維持）")
			fmt.Println("新しい招待リンク:", link)
			fmt.Println("SAS:", inv.SAS())
			printInviteQR(os.Stdout, link)
		case signaling.TypeRoomClosed:
			var rcz signaling.RoomClosed
			_ = env.Unmarshal(&rcz)
			store.update(func(m *appstate.Model) { m.Close(rcz.Reason) })
			slog.Info("ルーム解散", "reason", rcz.Reason)
			return nil
		case signaling.TypeError:
			var e signaling.Error
			_ = env.Unmarshal(&e)
			store.update(func(m *appstate.Model) { m.SetError(e.Message) })
			slog.Error("サーバーエラー", "code", e.Code, "message", e.Message)
		default:
			slog.Warn("未対応の受信種別", "type", env.Type)
		}
	}
}

// guestConfig は runGuest の設定一式。CLI フラグ（ヘッドレス）と GUI（LocalAPI）双方から
// 組み立てられ、同じ受信ループを駆動する。
type guestConfig struct {
	inviteURL, nick  string
	useTunnel        bool
	ifname, stunAddr string
	relay            bool
}

// runGuest はゲストとして招待リンクから参加を申請し、承認・ピア構成を処理する。
// 表示状態は store へ反映し、onClient は接続確立後に signalclient を公開する（GUI の退出操作用。
// ヘッドレスでは nil）。
func runGuest(ctx context.Context, cfg guestConfig, store *viewStore, onClient func(*signalclient.Client)) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 招待リンクを解析し、以後の参照はローカル変数で持つ（server/token/ホスト鍵/SAS は不変）。
	inv, err := invite.Parse(cfg.inviteURL)
	if err != nil {
		return fmt.Errorf("招待リンク解析: %w", err)
	}
	server, joinToken, hostPubKey, sas := inv.Server, inv.Token, inv.HostPubKey, inv.SAS()
	// 解析済みの inv を渡して二重パースを避ける（StartJoining は内部で再度 invite.Parse する）。
	store.update(func(m *appstate.Model) { _ = m.StartJoiningInvite(inv, cfg.nick) })

	priv, pub, err := wgkey.GenerateSecret()
	if err != nil {
		return fmt.Errorf("鍵生成: %w", err)
	}
	// 秘密鍵はメモリロック（可能なら）＋使用後ゼロ化できるバッファで保持する。
	sk := newSecret(priv)
	tun, err := openTunnel(cfg.useTunnel, cfg.ifname, sk)
	// 秘密鍵は wireguard-go デバイスへ適用済み。自コピーは以後不要なので即ゼロ化する。
	sk.Wipe()
	if err != nil {
		return err
	}
	if tun != nil {
		defer tun.Close()
	}

	conn, err := wsconn.Dial(withQuery(server, "role", "guest"), nil)
	if err != nil {
		return fmt.Errorf("接続: %w", err)
	}
	defer conn.Close()
	go closeOnDone(ctx, conn)

	c := signalclient.New(conn)
	if onClient != nil {
		onClient(c)
	}
	slog.Info("参加申請中", "server", server, "host_sas", sas)
	if err := c.JoinRequest(joinToken, cfg.nick, pub); err != nil {
		return err
	}
	store.update(func(m *appstate.Model) { _ = m.MarkRequested() })

	// 監視はルームIDが確定する承認後（join_approved）に起動する。リレー認可はルームIDベースの
	// ため、招待トークンではなくサーバーが払い出したルームIDを束ねる（ピア登録は peer_info 受信時）。
	var monitor *connMonitor
	var hostIP string // 承認時に確定するホストのメッシュ IP（peer_info でピア構成に使う）
	for {
		env, err := c.Next()
		if err != nil {
			return err
		}
		// 後続イベントの反映を機に直近の非致命エラー文言を消す（回復時にバナーを残さない）。
		store.update(func(m *appstate.Model) { m.ClearError() })
		switch env.Type {
		case signaling.TypeJoinApproved:
			var ja signaling.JoinApproved
			_ = env.Unmarshal(&ja)
			// 帯域外MITM照合: 招待に埋め込まれたホスト公開鍵と一致するか（不一致なら中止）。
			if !store.verifyHostKey(ja.HostPubKey) {
				return fmt.Errorf("MITM 検知: ホスト公開鍵が招待と不一致のため中止")
			}
			hostIP = ja.HostIP
			store.update(func(m *appstate.Model) { _ = m.Approved(ja.AssignedIP, ja.HostIP) })
			slog.Info("承認されました", "assigned_ip", ja.AssignedIP, "host_ip", ja.HostIP, "host_verified", true)
			configureTunnel(tun, ja.AssignedIP) // 仮想NICに割当IP付与＋メッシュルート設定
			applyPlanFilter(tun, ja.Tier)       // プランに応じた無料版ポート制限フィルタ
			// ルームIDが確定したので直通監視＋リレーフォールバックを起動する。
			monitor = startMonitor(ctx, tun, cfg.relay, server, ja.RoomID, pub)
			advertise(c, tun, cfg.stunAddr, pub) // ホストへ自エンドポイントを広告
		case signaling.TypeJoinRejected:
			var jr signaling.JoinRejected
			_ = env.Unmarshal(&jr)
			store.update(func(m *appstate.Model) { _ = m.RejectedByHost(jr.Reason) })
			slog.Info("参加を拒否されました", "reason", jr.Reason)
			return nil
		case signaling.TypeRoomClosed:
			var rcz signaling.RoomClosed
			_ = env.Unmarshal(&rcz)
			store.update(func(m *appstate.Model) { m.Close(rcz.Reason) })
			slog.Info("ルーム解散", "reason", rcz.Reason)
			return nil
		case signaling.TypePeerInfo:
			var pi signaling.PeerInfo
			_ = env.Unmarshal(&pi)
			slog.Info("ピア情報受信", "pubkey", pi.PubKey, "endpoint", pi.WANEndpoint)
			if pi.PubKey == hostPubKey {
				build := func(endpoint string) (wgconf.Config, error) {
					return meshpeer.GuestPeer(hostPubKey, hostIP, endpoint)
				}
				// まず直通エンドポイントを適用し、続けて直通監視を開始する（失敗時リレーへ転落）。
				pcfg, cerr := build(pi.WANEndpoint)
				applyPeer(tun, pcfg, cerr)
				store.update(func(m *appstate.Model) { _ = m.PeerUp(pi.PubKey, appstate.RouteDirect) })
				trackPeer(monitor, pi.PubKey, pi.WANEndpoint, build)
			}
		case signaling.TypeError:
			var e signaling.Error
			_ = env.Unmarshal(&e)
			store.update(func(m *appstate.Model) { m.SetError(e.Message) })
			slog.Error("サーバーエラー", "code", e.Code, "message", e.Message)
		default:
			slog.Warn("未対応の受信種別", "type", env.Type)
		}
	}
}

// openTunnel は -tunnel 有効時に wireguard-go 仮想NICを起動して返す（無効時は nil）。
// 秘密鍵はゼロ化・メモリロック可能な secret.Value で受け取り、生バイトのまま UAPI へ渡す
// （base64 文字列として materialize しない）。
func openTunnel(enabled bool, ifname string, priv *secret.Value) (*Tunnel, error) {
	if !enabled {
		return nil, nil
	}
	t, err := OpenTunnel(ifname, wgconf.Config{PrivateKeyRaw: priv.Bytes()})
	if err != nil {
		return nil, fmt.Errorf("仮想NIC起動: %w", err)
	}
	slog.Info("仮想NIC起動", "ifname", t.Name())
	return t, nil
}

// applyPlanFilter はシグナリングで確定したプラン種別 tier に基づき、無料版ポート制限の既定
// フィルタをトンネルへ適用する（tun が nil / tier が空 / 未知プランなら適用しない＝緩和策の
// 性質上フェイルオープン）。要件 §4.5。
func applyPlanFilter(tun *Tunnel, tier string) {
	if tun == nil || tier == "" {
		return
	}
	spec, ok := plan.Lookup(plan.Tier(tier))
	if !ok {
		slog.Warn("未知のプラン種別のためポートフィルタを適用しません", "tier", tier)
		return
	}
	tun.SetPlan(spec)
	if spec.PortRestricted {
		slog.Info("無料版ポート制限フィルタを適用しました", "tier", tier, "allowed_tcp", plan.AllowedTCPPorts)
	}
}

// configureTunnel は割当メッシュIP をトンネルに付与しメッシュルートを設定する（tun が nil なら何もしない）。
// OS 依存の設定失敗はシグナリング一巡を止めないよう警告に留める（要管理者権限）。
func configureTunnel(tun *Tunnel, assignedIP string) {
	if tun == nil {
		return
	}
	if err := tun.Configure(assignedIP); err != nil {
		if errors.Is(err, ErrSubnetConflict) {
			slog.Warn("既存ネットワークとの重複により仮想NICの設定を中止しました", "assigned_ip", assignedIP, "err", err)
		} else {
			slog.Warn("仮想NICのアドレス/ルート設定に失敗", "assigned_ip", assignedIP, "err", err)
		}
		return
	}
	slog.Info("仮想NICを設定しました", "assigned_ip", assignedIP, "ifname", tun.Name())
}

// applyPeer はピア設定を仮想NICへ適用する（tun が nil なら設定内容をログするのみ）。
func applyPeer(tun *Tunnel, cfg wgconf.Config, err error) {
	if err != nil {
		slog.Warn("ピア設定の構築に失敗", "err", err)
		return
	}
	if tun == nil {
		slog.Info("ピア設定（仮想NIC未起動のため未適用）", "peers", len(cfg.Peers))
		return
	}
	if err := tun.Apply(cfg); err != nil {
		slog.Warn("ピア適用に失敗", "err", err)
		return
	}
	slog.Info("ピアを適用しました")
}

// startMonitor はトンネル起動時かつ relay 有効時に接続モニタを生成し監視ゴルーチンを起動する。
// tun が nil / relay 無効なら nil を返し、以降の Track/Untrack は no-op（監視・フォールバック無効）。
// server はシグナリング URL（同一ホストの /relay を導出する）、roomID はルームID、pubKey は自公開鍵。
// リレー認可はルームID（不変）と公開鍵で行うため、招待トークンをローテーションしてもフォールバックは
// 壊れない（roomID をクロージャに値で束ねてよい）。
func startMonitor(ctx context.Context, tun *Tunnel, relay bool, server, roomID, pubKey string) *connMonitor {
	if tun == nil || !relay {
		return nil
	}
	relayURL, err := relayURLFromServer(server)
	if err != nil {
		slog.Warn("リレー URL の導出に失敗、フォールバック無効", "err", err)
		return nil
	}
	dial := func(onFrame func(srcPubKey string, payload []byte)) (relayTransport, error) {
		return dialRelay(relayURL, roomID, pubKey, onFrame)
	}
	m := newConnMonitor(tun, dial)
	go m.run(ctx)
	slog.Info("接続モニタ起動（P2P直通監視＋リレーフォールバック）", "relay_url", relayURL)
	return m
}

// trackPeer は監視対象ピアを登録する。直通エンドポイント適用は呼び出し側で済んでいる前提で、
// 以降のハンドシェイク成否監視とリレーフォールバックを担わせる。公開鍵の16進変換に失敗した場合は
// 監視を見送る（疎通自体は直通適用済みのため継続）。monitor が nil なら no-op。
func trackPeer(monitor *connMonitor, pubKey, directEP string, build func(string) (wgconf.Config, error)) {
	if monitor == nil {
		return
	}
	hexKey, err := pubKeyToHex(pubKey)
	if err != nil {
		slog.Warn("公開鍵の16進変換に失敗、監視を見送り", "peer", pubKey, "err", err)
		return
	}
	monitor.Track(pubKey, hexKey, directEP, build)
}

// advertise は STUN で WAN エンドポイントを発見し、peer_info として広告する（stunAddr 空なら何もしない）。
// tun が起動していれば WireGuard と同一ソケットから STUN を行い（WAN マッピングが WireGuard の送信
// マッピングと一致）、未起動なら別ソケットの STUN にフォールバックする（対称NAT下では WireGuard と
// マッピングがずれ hole punching が成立しない限界がある）。
func advertise(c *signalclient.Client, tun *Tunnel, stunAddr, pubKey string) {
	if stunAddr == "" {
		return
	}
	var (
		wan    netip.AddrPort
		shared = tun != nil
		err    error
	)
	if shared {
		wan, err = tun.DiscoverWAN(stunAddr, 5*time.Second)
	} else {
		wan, err = discoverWANStandalone(stunAddr)
	}
	if err != nil {
		slog.Warn("STUN によるWAN発見に失敗", "err", err)
		return
	}
	slog.Info("WAN エンドポイント発見", "endpoint", wan.String(), "shared_socket", shared)
	if err := c.SendPeerInfo(pubKey, wan.String()); err != nil {
		slog.Warn("peer_info 送信に失敗", "err", err)
	}
}

// discoverWANStandalone は WireGuard とは別の一時 UDP ソケットで STUN を行い WAN 側 IP:Port を返す。
// tunnel 未起動時のフォールバック。得られるマッピングは WireGuard の待受ソケットと異なりうる。
func discoverWANStandalone(stunAddr string) (netip.AddrPort, error) {
	udp, err := net.ListenUDP("udp4", nil)
	if err != nil {
		return netip.AddrPort{}, err
	}
	defer udp.Close()
	srv, err := net.ResolveUDPAddr("udp4", stunAddr)
	if err != nil {
		return netip.AddrPort{}, err
	}
	return stun.Discover(udp, srv, 5*time.Second)
}

// closeOnDone は ctx 終了時に接続をクローズし、受信ループを解除する。
func closeOnDone(ctx context.Context, conn *wsconn.Conn) {
	<-ctx.Done()
	_ = conn.Close()
}

// splitScopes はカンマ区切りのスコープ文字列を要素へ分解する（前後空白除去・空要素無視）。
// 空文字列なら nil を返し、oauthpkce 側が既定（openid）を適用する。
func splitScopes(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// withQuery は base URL にクエリパラメータ（key, value, key, value, ...）を付与する。
func withQuery(base string, kv ...string) string {
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	q := u.Query()
	for i := 0; i+1 < len(kv); i += 2 {
		q.Set(kv[i], kv[i+1])
	}
	u.RawQuery = q.Encode()
	return u.String()
}
