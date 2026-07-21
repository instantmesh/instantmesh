---
name: aws-mesh-infrastructure
description: InstantMesh のシグナリング/リレーを AWS（EC2 Graviton・ElastiCache Redis・Cognito・S3）へ本番展開するときのスキル。現行のインメモリ/モック実装（pkg/manager・Authenticator I/F・AuditLogger I/F）を、I/F を温存したまま Redis/Cognito/S3 実装へ差し替える指針とインフラ設計を示す。フェーズ1では未実装（将来指針）。
---

# AWS メッシュインフラ構築ガイド

> **現状**: フェーズ1のサーバー（`cmd/server`）は単一プロセスで、セッションストアはインメモリ（`pkg/manager`）、認証は `DevAuthenticator`（モック）、監査は `SlogAuditLogger`。本番化は**既存インターフェースを温存したまま実装を差し替える**方針。AWS 実装は未着手（`TODO.md` セクション D）。

## 1. 差し替えポイント（コード側の接続点）

本番化は新規サーバーを書き直すのではなく、以下の I/F 実装を差し替える。

| 関心事 | 現行実装 | 本番差し替え先 |
| :--- | :--- | :--- |
| セッションストア（ルーム/TTL） | `pkg/manager`（`sync.Mutex`・`runMaintenance` が `Sweep`/`ExpirePending`） | ElastiCache for Redis（`EXPIRE`＋Keyspace Notifications） |
| ホスト認証 | `Authenticator` I/F の `DevAuthenticator`（`cmd/server/auth.go`） | Cognito JWT 検証実装（`hub.Auth` を返す） |
| 監査ログ | `AuditLogger` I/F の `SlogAuditLogger`（`cmd/server/audit.go`） | S3 実装（Object Lock + KMS） |

`Authenticator`（`Authenticate(r) (hub.Auth, error)`）と `AuditLogger`（`Log(AuditEvent)`）は既に I/F 化済みなので、Cognito/S3 版を実装して `buildServer`（`cmd/server/main.go`）で注入すればよい。セッションストアは `pkg/manager` の公開 API（`Create`/`LookupByToken`/`WithRoom`/`Sweep` 等）と同等の契約を満たす Redis バックエンドを用意する。

## 2. AWS 構成の全体像（ap-northeast-1 固定）

- **EC2（`t4g` / Graviton ARM）**: Go 実装なので `t4g.small`/`medium` が高コスパ。パブリックサブネット＋Elastic IP。シグナリング（`/ws`）とリレー（`/relay`）はコード上論理分離済みで、フェーズ1は同一プロセス。スケール時に別インスタンス/マルチAZへ切り出す。
- **ElastiCache for Redis**: `EXPIRE`（TTL）で期限切れルームを自動消滅。シグナリングからのみ到達可能なプライベートサブネット。
- **Cognito**: ホストのユーザープール。Google/GitHub の IdP 連携、TOTP MFA 任意。
- **S3**: 監査ログ（`AuditEvent` の接続メタデータのみ）。Object Lock（改ざん防止）＋KMS＋最小権限。

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

1. `pkg/manager` の公開 API 契約を満たす Redis 実装を用意（インメモリ版とテストを共有できると良い）。
2. `Authenticator` の Cognito 実装（JWT 検証→`hub.Auth`）を追加し `buildServer` で注入。
3. `AuditLogger` の S3 実装を追加（メタデータのみ・ペイロード禁止は厳守）。
4. IaC（構成管理）で EC2/SG/Redis/Cognito/S3 を再現可能に。

関連スキル: [[cmd-transport-wiring]]（I/F 注入と配線）、[[nat-traversal-signaling]]（リレー/STUN のポート要件）。
