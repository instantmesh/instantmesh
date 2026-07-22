---
name: cmd-transport-wiring
description: InstantMesh の cmd/server・cmd/client に WebSocket や OS 依存処理を配線するときのスキル。純粋コア（pkg/hub・session・relayhub・signalclient）への配線、Conn 抽象の実装と書き込み直列化、接続ライフサイクル、認証/監査インターフェース、定期ワーカー、グレースフルシャットダウン、フラグ設計、実 WebSocket 結合テストの規約を示す。
---

# cmd/ トランスポート配線ガイド

`cmd/server`・`cmd/client` は純粋コア（`pkg/`）を WebSocket・OS・認証・監査へ配線する**薄い I/O アダプタ層**。`pkg/` の 100% カバレッジ規約の対象外だが、**実 WebSocket 結合テスト**（`httptest`＋`gorilla` クライアント）で網羅する。未カバーは `main()` の `os.Exit`・シグナル処理程度に留める。

## 1. サーバーの接続ライフサイクル（cmd/server）

シグナリング（`/ws`）は `pkg/hub`→`pkg/session`→`pkg/manager` へ配線する。`ServeWS`（`cmd/server/server.go:51`）の流れ:

1. `Authenticator.Authenticate(r)` → 失敗は 401（`hub.Auth` を得る）。
2. `upgrader.Upgrade` で WebSocket 化し、`wsConn{id, ws}` を生成。`addConn` が false（シャットダウン中）なら閉じる。
3. `hub.Register(conn, auth)` ＋ `AuditConnect` 監査。
4. 受信ループ: `ws.ReadMessage()`→`signaling.Decode`（失敗は error エンベロープを `Send` して continue）→`bind := hub.Handle(conn.id, env, now())`→`recordAction`。`bind` が非 nil ならローカルに `hostRoomID`/`guestRoomID`+`guestPubKey` を控える（切断処理用）。
5. `defer`: `hub.Unregister`→`removeConn`→`ws.Close`→`AuditDisconnect`→ホストなら `hub.CloseRoom(roomID, room.CloseHost, now())`、ゲストなら `hub.NotifyGuestLeft(roomID, pubKey, now())`。これでエフェメラル解散・ゲスト離脱通知が発火する。

### Conn 抽象と書き込み直列化（重要）

`hub.Conn`（`ID() string` / `Send(env signaling.Envelope) error`、`pkg/hub/hub.go:33`）を実装する。**同一接続への `Send` は並行に呼ばれ得るため、実装側で `sync.Mutex` により書き込みを直列化する**（`gorilla/websocket` は同時書き込み不可）。`cmd/server/server.go:170` の `wsConn.Send` が範例。リレー側 `wsRelayConn.Send`（`relay.go:161`）も同様。

## 2. 認証（差し替え可能な I/F）

`Authenticator` I/F（`auth.go:16`：`Authenticate(r) (hub.Auth, error)`）。現状は `DevAuthenticator`（`role`/`Bearer`/`pubkey`/`tier` クエリから `hub.Auth` を組む Cognito のモック）。実 Cognito JWT 検証へは**この I/F を温存したまま**差し替える。`hub.Auth` は `Role`/`AccountID`/`PubKey`/`Tier`/`RemoteIP`（ゲストは Role と RemoteIP のみ、PubKey は `join_request` で確定）。`clientIP` は `X-Forwarded-For` 優先。

## 3. 監査ログ（接続メタデータのみ）

`AuditLogger` I/F（`cmd/server/audit.go`：`Log(ev auditlog.Event)`）。`auditlog.Event`（`pkg/auditlog`）は `Time`/`Kind`/`Role`/`AccountID`/`RemoteIP`/`RoomID` の**メタデータのみ**で、**通信ペイロードは絶対に含めない**（E2E・法的防衛線）。イベント種別は `connect`/`disconnect`/`room_create`/`guest_join`（`AuditJoinRequest` の値は `"guest_join"`）。`recordAction`（`server.go`）が `hub.Handle` の返す `Binding` を見て `room_create`/`guest_join` を RoomID 付きで記録する。実装は `Nop`/`Slog` に加え、**S3（Object Lock+KMS）実装済み**（`cmd/server/s3audit.go`。フラグ指定時に切替）。

## 4. データプレーン（リレー /relay）

シグナリングとは**別系統**の `pkg/relayhub` へ配線する（`cmd/server/relay.go`）。`RelayAuthorizer`（`Authorize(token, pubKey) (roomKey, spec, err)`）で検証（`managerAuthorizer` が共有 `manager` でトークン/ホスト・承認済みゲスト/プランを検証）。フレームは `pkg/relayframe`（`BinaryMessage`）。`relayhub.Register/Unregister/Forward` を使う。E2E のためサーバーは復号鍵を持たず、宛先公開鍵で暗号化ペイロードを転送するだけ。

## 5. 定期ワーカーと決定的時刻

`runMaintenance(ctx, m maintainer, interval, now func() time.Time)`（`maintenance.go:18`）が `ticker` で `m.Sweep(now())`・`m.ExpirePending(now())` を駆動し、`ctx.Done()` で停止する。**`now` は関数注入**（テストは固定関数を渡す）。`*hub.Hub` が `maintainer` を満たす。

## 6. フラグとサーバー組み立て

- `flag.NewFlagSet("server", flag.ContinueOnError)`＋`SetOutput(io.Discard)` で `parseFlags` を単体テスト可能にする（`main.go:80`）。
- `buildServer(cfg)`（I/O なしでドメイン層を組む）→`net.Listen`→`serve(ctx, cfg, ln, b)` と分離し、`serve` を `net.Listener` 注入でテストする。
- クライアントのフラグ例は `cmd/client/main.go:56`（`-mode`/`-server`/`-tunnel`/`-stun`/`-relay` など）。

## 7. グレースフルシャットダウン（ゴルーチンリーク防止）

`signal.NotifyContext(ctx, SIGINT, SIGTERM)`。`ctx.Done()` で全トランスポートの `CloseConns()`（生存接続を閉じ受信ループを解除）→`http.Shutdown(timeoutCtx)`。`CloseConns` は `Server`/`RelayServer` のメソッド（`hub.Hub` には無い）。

## 8. クライアント配線（cmd/client）

- シグナリング: `pkg/signalclient`（型付き送受信 `CreateRoom`/`JoinRequest`/`Approve`/`SendPeerInfo`/`Next`/`Leave`）＋`pkg/wsconn`（gorilla アダプタ）。受信は `c.Next()` の `env.Type` で分岐（`runHost`/`runGuest`、`main.go`）。
- 接続モニタ（直通⇄リレー）は `connMonitor` として**コマンドチャネルで単一ゴルーチンに閉じ**、`Track`/`Untrack` はクロージャを送るだけにしてデータ競合を避ける（`connmonitor.go`）。ハンドシェイク取得・設定適用・リレーダイヤルは**関数注入**でユニットテストする。詳細は [[nat-traversal-signaling]]・[[wireguard-go-integrator]]。

## 9. テスト

`cmd/server/e2e_test.go` のように `httptest.NewServer`＋実 `gorilla` クライアントで「作成→参加→承認→peer_info→解散」を往復検証する。ループバックのみで完結させ、WireGuard 実機・管理者権限を要さない形にする（リレープロキシ等）。

関連スキル: [[pkg-pure-logic]]（配線先のコア規約）、[[aws-mesh-infrastructure]]（認証/監査/セッションストアの本番差し替え）。
