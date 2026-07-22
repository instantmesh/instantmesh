---
name: aws-mesh-infrastructure
description: InstantMesh のシグナリング/リレーを AWS（EC2 Graviton・ElastiCache Redis・Cognito・S3）へ本番展開するときのスキル。現行のインメモリ/モック実装（pkg/manager・Authenticator I/F・AuditLogger I/F）を、I/F を温存したまま Redis/Cognito/S3 実装へ差し替える指針とインフラ設計を示す。Cognito 認証・S3 監査は実装済み（S1-1/S1-2）。IaC（CDK）は別リポジトリ管理、Redis 化・本番導通は未着手。
---

# AWS メッシュインフラ構築ガイド

> **現状**: フェーズ1のサーバー（`cmd/server`）は単一プロセスで、セッションストアはインメモリ（`pkg/manager`。Redis 未使用）。認証・監査は既存インターフェースを温存したまま実装を差し替える方針で、**Cognito JWT 認証（`cmd/server/cognito.go`＋`pkg/cognitojwt`・`pkg/oauthpkce`）と S3 監査（`cmd/server/s3audit.go`）は実装済み**（フラグ指定時に `DevAuthenticator`/`SlogAuditLogger` から切替）。**IaC（AWS CDK）は別リポジトリで管理**。Redis 化（水平スケール）と本番導通確認は未着手（`TODO.md` 残タスク・`docs/AWS展開設計書.md`）。

## 1. 差し替えポイント（コード側の接続点）

本番化は新規サーバーを書き直すのではなく、以下の I/F 実装を差し替える。

| 関心事 | 現行実装 | 本番差し替え先 |
| :--- | :--- | :--- |
| セッションストア（ルーム/TTL） | `pkg/manager`（`sync.Mutex`・`runMaintenance` が `Sweep`/`ExpirePending`） | ElastiCache for Redis（`EXPIRE`＋Keyspace Notifications）※未着手 |
| ホスト認証 | `Authenticator` I/F の `DevAuthenticator`（`cmd/server/auth.go`） | Cognito JWT 検証（`hub.Auth` を返す）※**実装済み**：`cmd/server/cognito.go`＋`pkg/cognitojwt` |
| 監査ログ | `AuditLogger` I/F の `SlogAuditLogger`（`cmd/server/audit.go`） | S3 実装（Object Lock + KMS）※**実装済み**：`cmd/server/s3audit.go` |

`Authenticator`（`Authenticate(r) (hub.Auth, error)`）と `AuditLogger`（`Log(auditlog.Event)`）は I/F 化済みで、**Cognito/S3 版は実装済み**（フラグ指定時に `buildServer`（`cmd/server/main.go`）でモックから切替）。残るセッションストアの Redis 化は、`pkg/manager` の公開 API（`Create`/`LookupByToken`/`WithRoom`/`Sweep` 等）と同等の契約を満たす Redis バックエンドを用意する（未着手）。

## 2. AWS 構成の全体像（ap-northeast-1 固定）

- **EC2（`t4g` / Graviton ARM）**: Go 実装なので `t4g.small`/`medium` が高コスパ。パブリックサブネット＋Elastic IP。シグナリング（`/ws`）とリレー（`/relay`）はコード上論理分離済みで、フェーズ1は同一プロセス。スケール時に別インスタンス/マルチAZへ切り出す。
- **ElastiCache for Redis**: `EXPIRE`（TTL）で期限切れルームを自動消滅。シグナリングからのみ到達可能なプライベートサブネット。
- **Cognito**: ホストのユーザープール。Google/GitHub の IdP 連携、TOTP MFA 任意。
- **S3**: 監査ログ（`auditlog.Event` の接続メタデータのみ）。Object Lock（改ざん防止）＋KMS＋最小権限。

## 3. セキュリティグループ（インバウンド）

| プロトコル | ポート | 用途 |
| :--- | :--- | :--- |
| TCP | `443` | シグナリング（WSS）・リレー（HTTPS/DERP 相当）。企業/公衆 Wi-Fi 制限の回避に標準 HTTPS を使う |
| UDP | `3478` | STUN（クライアントが WAN マッピングを取得。共有ソケット STUN の宛先） |
| UDP | （環境依存） | TURN 相当のリレー UDP（必要に応じ 443/TCP へカプセル化） |

E2E の原則上、サーバーは復号鍵を持たない。リレーは宛先公開鍵で暗号化ペイロード（`pkg/relayframe`）を転送するだけ。

## 4. Redis でのエフェメラル・ライフサイクル（差し替え時の指針）

現行 `pkg/manager` は「TTL 相当を `room.IsExpired`/`IsIdle` で判定し、`runMaintenance` の ticker が `Sweep` で解散」する方式。Redis 化では TTL をストア側に持たせ、失効イベントを購読する:

```go
// 指針例（未実装）。現行 pkg/manager.Create 相当を Redis で実装するイメージ。
pipe := rdb.TxPipeline()
pipe.Set(ctx, "room:"+roomID+":token", hostToken, ttl)
pipe.Set(ctx, "room:"+roomID+":status", "active", ttl)
_, err := pipe.Exec(ctx)
```

- Keyspace Notifications（`config set notify-keyspace-events Ex`）でキー失効を検知し、接続中の WebSocket へ `room_closed` を配送する（`hub.CloseRoom` 相当）。
- 純アイドル 30 分・制限時間・ホスト解散という 3 つの消滅条件（要件）を TTL＋アプリロジックで再現する。使用ライブラリ（`go-redis` 等）は本番実装時に確定する。

## 5. 進め方

1. ~~`Authenticator` の Cognito 実装（JWT 検証→`hub.Auth`）を追加し `buildServer` で注入。~~ **実装済み**（`cmd/server/cognito.go`＋`pkg/cognitojwt`・`pkg/oauthpkce`）。
2. ~~`AuditLogger` の S3 実装を追加（メタデータのみ・ペイロード禁止は厳守）。~~ **実装済み**（`cmd/server/s3audit.go`）。
3. IaC（構成管理）で EC2/SG/Cognito/S3 を再現可能に。**別リポジトリで管理**。
4. （水平スケール時）`pkg/manager` の公開 API 契約を満たす Redis 実装を用意（インメモリ版とテストを共有できると良い）。未着手。

関連スキル: [[cmd-transport-wiring]]（I/F 注入と配線）、[[nat-traversal-signaling]]（リレー/STUN のポート要件）。
