# InstantMesh プロジェクト開発ルール

本ドキュメントは、InstantMeshプロジェクトにおいて、AIコードアシスタント（エージェント）および開発者が遵守すべき設計原則とコーディング規約を定義します。

---

## 1. 基本設計原則

### 1.1. 将来のSDK化を見据えたUIとコアロジックの完全分離
*   **規則**: 接続制御、シグナリング、WireGuard制御、NATトラバーサルなどのコア機能は、UI（GUIフレームワーク等）に直接依存させてはなりません。
*   **構成**: すべてのコアロジックは `pkg/` ディレクトリ配下に独立したGoパッケージとして実装し、UIクライアント（`cmd/client/`）やサーバー（`cmd/server/`）はそれらのAPIを呼び出す形をとります。

### 1.2. E2E（エンドツーエンド）暗号化の厳守
*   **規則**: サーバー（シグナリングおよびリレー）は、ユーザーの通信パケットを復号するためのいかなる暗号化キー（WireGuardの秘密鍵など）も受信・保持してはなりません。
*   **例外**: サーバーが扱うのは、シグナリングのための公開鍵やメタデータ（ルームID、トークン、ニックネーム）のみです。

### 1.3. 秘密情報のメモリ内管理（ディスク書き込み禁止）
*   **規則**: クライアントが生成するWireGuardの秘密鍵、および一時的な認証トークンは、PCのストレージ（SSD/HDD）にファイルとして保存してはなりません。
*   **実装**: すべてメモリ上で生成・保持し、接続終了時やアプリ終了時にメモリを確実にゼロクリアまたはガベージコレクションの対象にします。

---

## 2. 実装・コーディング規約

### 2.1. Go言語規約
*   Goの標準的なディレクトリ構成（`cmd/`, `pkg/`）に従います。
*   非同期処理（goroutine）は、リークを防ぐために必ず適切な `context.Context` やチャネルによるキャンセルライフサイクルを持たせます。
*   エラーハンドリングは省略せず、エラーが発生したコンテキスト情報を付与して上位層へ伝播させます。

### 2.2. リレー通信量監視規約
*   リレーパケットを転送するループ内で、データ送信量をアトミックに加算します。
*   100MBの上限値を超えた場合は、接続インスタンスを直ちにクローズし、リソースの解放漏れがないようにします。

### 2.3. Redisセッション管理
*   Redisにルーム情報を登録する際は、必ず要件定義で設定された時間（例: 1時間、3時間）に基づくTTL（Expire）を設定します。

---

## 3. 開発スキル（実装の統一化）

領域別・横断の実装規約を `.agents/skills/`（正本）にまとめています。実装前に該当スキルを参照してください。`.claude/skills/` には Claude Code が自動ロードするためのスタブがあり、正本を参照します（内容は正本に一元化し、二重管理による乖離を防止）。

**横断（作業種別）**
| スキル | 使う場面 |
| :--- | :--- |
| [pkg-pure-logic](skills/pkg_pure_logic/SKILL.md) | `pkg/` に純粋ロジックを追加・変更する（now 注入・失敗を値で返す・100%カバレッジ） |
| [cmd-transport-wiring](skills/cmd_transport_wiring/SKILL.md) | `cmd/server`・`cmd/client` に WebSocket/OS を配線する（Conn 抽象・認証/監査 I/F・結合テスト） |
| [client-secret-management](skills/client_secret_management/SKILL.md) | 秘密鍵/トークンを扱う・UI とコアを分離する（メモリ内保持・MITM 照合） |

**領域別（技術）**
| スキル | 使う場面 |
| :--- | :--- |
| [nat-traversal-signaling](skills/nat_traversal_signaling/SKILL.md) | STUN 共有ソケット・シグナリング・直通⇄リレーフォールバック |
| [wireguard-go-integrator](skills/wireguard_go_integrator/SKILL.md) | wireguard-go 組み込み・UAPI・ピア写像・仮想NIC 設定 |
| [aws-mesh-infrastructure](skills/aws_mesh_infrastructure/SKILL.md) | AWS 本番展開（Redis/Cognito/S3 への I/F 差し替え・未実装） |

**運用（Git ワークフロー）**
| スキル | 使う場面 |
| :--- | :--- |
| [commit-push](skills/commit_push/SKILL.md) | 変更を `git add`/`commit`/`push` する（確認なし・日本語 Conventional Commits・`Co-Authored-By` フッタ） |
