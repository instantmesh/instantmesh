# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

InstantMesh は、アカウント登録不要・使い終われば自動消滅するエフェメラルな Mesh VPN（WireGuard ベースの E2E 暗号化 P2P ネットワーク）。フェーズ1（Windows/macOS/Linux デスクトップ）を実装中。全体像・要件は `README.md` と `docs/`、進捗の詳細は `TODO.md` が正。

## 検証・ビルドのワークフロー（重要）

**ローカル環境に `go` を導入できない。** テスト・ビルドは基本 CI（GitHub Actions）で実行し、`gh run list` / `gh run view` で結果を確認する。開発サーバーでの手動実行は補助。コードを変更したら push して CI の結果を待つのが標準フロー。

CI（`.github/workflows/ci.yml`）が push/PR ごとに実行する内容（ローカルで再現する場合も同じコマンド）:

```bash
go mod verify
go vet ./...
go build ./...
GOOS=windows GOARCH=amd64 go build ./...   # OS依存アダプタの型崩れ検知（クロスビルド）
GOOS=darwin  GOARCH=arm64 go build ./...
go test -race -covermode=atomic -coverprofile=coverage.out ./...
go test ./pkg/... -cover                    # pkg/ は全パッケージ 100% を強制（未満なら CI 失敗）
```

- 単一テスト実行: `go test -run TestName ./pkg/<pkg>/`
- **`pkg/` の 100% カバレッジは規約。** `pkg/` に新規ロジックを足したら必ずテストも足す（`cmd/` は I/O アダプタ層のため 100% 対象外）。
- クロスビルドは `cmd/client/linkconfig_<os>.go` などの build tag 別ファイルの型崩れを Linux ランナー上で検知するためのもの。OS 依存の実適用（仮想NIC設定）は非特権 CI では検証できない。

### 動作確認（開発サーバー等で手動実行する場合）

```bash
# サーバー（シグナリング /ws ＋ リレー /relay を単一プロセスで提供）
go run ./cmd/server -addr :8080

# ホスト（ルーム作成 → 招待リンク/SAS 出力 → 参加を自動承認）
# ローカルの DevAuthenticator サーバーに繋ぐため -cognito-domain= で Cognito を無効化する
go run ./cmd/client -mode host  -server ws://localhost:8080/ws -cognito-domain= -account dev-account  # -tunnel/-stun は既定有効(要管理者)。権限なしでシグナリングのみは -tunnel=false

# ゲスト（招待リンクから参加 → 帯域外MITM照合）
go run ./cmd/client -mode guest -invite "instantmesh://join?..." -nick alice  # 同上（-tunnel/-stun 既定有効）
```

`-tunnel` は wireguard-go 仮想NICを起動する（**既定 true**・要管理者/root 権限。権限なしでシグナリングのみ確認するときは `-tunnel=false`）。`-stun` は STUN サーバー（**既定 `stun.l.google.com:19302`**・無効化は `-stun=`）で WAN マッピングを発見し `peer_info` を広告する。`-relay` は P2P 直通失敗時のリレー自動フォールバック（既定 true・要 `-tunnel`）。クライアントの既定は公開サーバー（`-server wss://s1.instantmesh.net/ws`）＋ Cognito 認証（`-cognito-domain`/`-cognito-client-id` に公開プール値が既定で入る）。ローカル検証時は上記のとおり `-server` を上書きし `-cognito-domain=` で Cognito を無効化する。

## アーキテクチャ

### レイヤリング：純粋コア（`pkg/`）と I/O アダプタ（`cmd/`）の分離

最重要の設計制約。**接続制御・シグナリング・WireGuard 制御・NATトラバーサル等のコアロジックはすべて `pkg/` 配下の UI/トランスポート/AWS 非依存の純粋パッケージ**として実装する（将来の SDK 切り出しを見据える）。`cmd/server`・`cmd/client` は WebSocket・wireguard-go・OS・認証などを純粋コアへ配線する薄いアダプタ。

依存の向きは常に `cmd/` → `pkg/`。`pkg/` から `cmd/` や UI/トランスポートへ依存させない。

制御フローの層（サーバー側）:

```
cmd/server (WebSocket/認証/監査/ワーカー)
  → pkg/hub        接続レジストリ・Target→実接続の解決・Bind 記録・定期フック配送
    → pkg/session  純粋ディスパッチャ（後述）
      → pkg/manager 複数ルームのゴルーチンセーフ管理（ID/トークン索引・/24 払出・掃除）
        → pkg/room  単一ルームの集約（待合室承認/拒否/失効/キック/ライフサイクル）
          → pkg/{plan,token,ipam,nickname,ratelimit} ドメイン基礎
```

データプレーンは別系統: `cmd/server` の `/relay` → `pkg/relayhub`（DERP 相当・宛先公開鍵ベース転送）→ `pkg/relay`（接続ごと通信量メータ/スロットル）。制御プレーンとデータプレーンはコード上論理分離しつつ、フェーズ1は単一プロセスで `manager` を共有する。

### 純粋ディスパッチャのパターン（`pkg/session`）

シグナリングの中核は「メッセージ → ドメイン操作 → 宛先付き応答」を返す全域関数として書かれ、I/O を一切行わない。理解すべき語彙:

- **Envelope**（`pkg/signaling`）: 型タグ付きのワイヤメッセージ。エンコード/デコード/検証を担う。
- **Origin**: 送信元コンテキスト（役割・確立済みルーム・公開鍵・アカウント・プラン・実IP）。トランスポート層が接続状態から注入する。
- **Target**（`Origin`/`Host`/`Guest`）: 宛先の抽象表現。実コネクションへの解決は `pkg/hub`（＝`cmd/server`）が担う。
- **Result{Out, Bind}**: ディスパッチ結果。`Out` は宛先タグ付き応答群、`Bind` は「送信元接続に確立すべきバインディング」でトランスポートが以後の宛先解決に使う。
- **error を返さない**: Go の `error` ではなく、全ての失敗を送信元宛て `error` エンベロープ（`code`+`message`）で表現する。

この分離により、トランスポート（WebSocket）を使わずフェイク接続だけで結合テストでき、`pkg/` の 100% カバレッジを維持できる。

### 時刻は注入（決定的テスト）

TTL・アイドル掃除・レート制限・接続状態機械など時間依存ロジックは、現在時刻を `now func() time.Time` として引数注入する（`cmd/server` が `time.Now` を渡す）。テストは固定時刻で決定的に検証する。新規の時間依存コードも同じパターンに従う。

### NATトラバーサルと直通⇄リレーのフォールバック（クライアント）

- **STUN 共有ソケット**（現ブランチの主眼）: `-tunnel` 起動時は `sharedBind`（wireguard-go の `conn.Bind` をラップ）＋ `pkg/stunmux` で **WireGuard と同一の UDP ソケットから STUN を実施**する。これにより得られる WAN マッピングが WG 送信のマッピングと一致し hole punching が成立する。`-tunnel` 無効時は別ソケット STUN（`discoverWANStandalone`）へフォールバック（マッピングがずれうる）。
- **成否検知とフォールバック**: `pkg/wgstat`（wireguard-go UAPI の `last_handshake_time` を解析）でハンドシェイク成立を検知し、`pkg/connmon`（ピアごとの `Probing→Direct/Relay` 状態機械・now 注入）で直通が一定時間成立しなければリレーへ転落する。`cmd/client/connmonitor.go` の `connMonitor` が単一ゴルーチンに閉じて駆動しデータ競合を回避（ハンドシェイク取得・設定適用・リレーダイヤルは関数注入でテスト）。
- **リレー経路**: `pkg/relayframe`（サーバー/クライアント共有のワイヤフレーム）＋ `cmd/client` の `wsRelay`（`/relay` WebSocket）＋ `relayProxy`（WireGuard⇄リレーを loopback UDP で橋渡し）。
- **OS 依存の仮想NIC設定**: `cmd/client/linkconfig_{linux,windows,darwin,other}.go` を build tag で切替（linux=`ip`／windows=`netsh`／darwin=`ifconfig`+`route`）。付与アドレス(/32)・メッシュ経由ルート(/24)の算出は純粋ロジック `pkg/netcfg`。

## 設計原則（`.agents/AGENTS.md` — 遵守必須）

1. **UI とコアロジックの完全分離**（上記レイヤリング。将来の SDK 化）。
2. **E2E 暗号化の厳守**: サーバー（シグナリング/リレー）は WireGuard 秘密鍵などの復号鍵を一切受信・保持しない。扱うのは公開鍵とメタデータ（ルームID/トークン/ニックネーム）のみ。
3. **秘密情報のメモリ内管理**: WireGuard 秘密鍵・一時トークンはディスクに書き出さず、メモリ上で生成・保持し終了時にゼロクリア。
4. **監査ログは接続メタデータのみ**: 「どのホストが・いつルーム作成／どのIPのゲストが参加」を記録。通信内容は一切含めない。
5. **Go 規約**: goroutine は必ず `context.Context`／チャネルでキャンセルライフサイクルを持たせリークを防ぐ。エラーはコンテキストを付与して上位へ伝播。

## 実装スキル（作業前に参照）

領域別・横断の実装規約を `.agents/skills/`（正本）に整備している。`.claude/skills/` には自動ロード用スタブがあり正本を参照する（内容は正本に一元化）。作業内容に対応するスキルを実装前に読むこと。

- **pkg-pure-logic** … `pkg/` に純粋ロジックを追加・変更するとき
- **cmd-transport-wiring** … `cmd/server`・`cmd/client` に WebSocket/OS を配線するとき
- **client-secret-management** … 秘密鍵/トークンを扱う・UI とコアを分離するとき
- **nat-traversal-signaling** … STUN・シグナリング・直通⇄リレーフォールバック
- **wireguard-go-integrator** … wireguard-go・UAPI・ピア写像・仮想NIC 設定
- **aws-mesh-infrastructure** … AWS 本番展開（I/F 差し替え・未実装）
- **commit-push** … 変更を `git add`/`commit`/`push` する（確認なし・日本語 Conventional Commits・`Co-Authored-By` フッタ）

## ドキュメントの正（source of truth）

- 要件: `docs/要件定義書.md`（機能/非機能/プラン/状態遷移のマスター）
- アーキテクチャ: `docs/システムアーキテクチャ定義書.md`
- 開発ルール: `.agents/AGENTS.md`
- 進捗・パッケージ一覧: `TODO.md`（`pkg/` 全パッケージの役割と状態を網羅。新規パッケージを足したらここも更新する）
