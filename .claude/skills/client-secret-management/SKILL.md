---
name: client-secret-management
description: InstantMesh クライアントで WireGuard 秘密鍵・招待トークンなどの秘密情報を扱うとき、および UI とコアロジックを分離するときのスキル。メモリ内保持・ディスク非保存・使用後ゼロ化・mlock の規約、E2E を壊さない鍵の流れ、帯域外MITM照合、GUI をコアから分離する構造を示す。
---

# クライアント秘密情報 & UI 分離ガイド

InstantMesh の安全性の根拠は「サーバーが復号鍵を持たない E2E」と「帯域外での鍵照合」にある。クライアント実装ではこれを壊さないため、秘密情報の扱いと UI/コア分離に規約を設ける。

## 1. 秘密鍵はメモリ内のみ・ディスク非保存

- WireGuard 秘密鍵は `wgkey.Generate()`（`pkg/wgkey/wgkey.go:33`、`crypto/ecdh` の X25519・base64 文字列）でメモリ上に生成する。**ファイル・設定・ログに書き出さない。**
- 一時トークン（招待トークン等）も同様にメモリ保持。永続化しない。
- 公開鍵の導出は `wgkey.PublicFromPrivate`。秘密鍵から必要な公開情報だけを取り出す。

## 2. 使用後ゼロ化・mlock（実装済み）

`pkg/wgkey` は鍵の**生成/符号化**を担い、機微なバイト列のメモリ内安全保持（ゼロ化・メモリロック）は `pkg/secret`（`secret.Value`）＋利用側 `cmd/client` が担う（実装済み）。規約:

- 秘密鍵などの鍵素材は `secret.New([]byte)` でラップし、UAPI（`wgconf.Config.UAPI()` が hex 化して `dev.IpcSet` に渡す）へ適用したら **`Value.Wipe()` でゼロ化**する。Go の `string` は不変でゼロ化しづらいため、ゼロ化が要る鍵素材は `[]byte` で扱う。
- スワップ流出を防ぐメモリロック（`mlock` / Windows の `VirtualLock`）は OS 依存処理として `cmd/client` に build tag で実装済み（`cmd/client/memlock_{unix,windows,other}.go`。`newSecret` が `secret.Value.Lock(locker)` を呼ぶ。`linkconfig_<os>.go` と同じ分離方針）。ロック失敗（非特権・RLIMIT_MEMLOCK 等）は best-effort でロックなし続行。
- GC 対象化を確実にするため、鍵を握るライフタイムを短く保つ。

## 3. E2E を壊さない鍵の流れ

- サーバー（シグナリング/リレー）へ**秘密鍵を送らない**。`peer_info` で交換するのは**公開鍵と WAN エンドポイントのみ**（`signaling.PeerInfo{PubKey, WANEndpoint}`）。
- リレーはサーバーが復号できない暗号化パケットを宛先公開鍵で転送するだけ（`pkg/relayframe`）。平文鍵は載せない。

## 4. 帯域外 MITM 照合（安全性の核心）

- ホスト公開鍵は招待リンク/QR に埋め込み、シグナリングを**経由しない**帯域外で共有する（`pkg/invite`）。
- ゲストは承認時に受け取った `join_approved.HostPubKey` を `inv.VerifyHostKey(...)` で照合し、**不一致なら接続を中止**する（`cmd/client/main.go` の `runGuest`）。この照合を省略・迂回してはならない。
- 承認 UI ではゲスト公開鍵の短縮フィンガープリント（SAS、`token.SAS`）を表示し、ホストが目視確認できるようにする。

## 5. UI とコアの分離（GUI 実装済み）

GUI は **LocalAPI 方式**で実装済み（`cmd/client/guiserver.go` が 127.0.0.1 に HTTP を立て、埋め込み SPA `guiindex.go` を配信。Windows は WebView2 アプリ内ウィンドウ `appwindow_windows.go`）。制御ロジックを UI 層に置かない構造を維持する。

- 表示状態は `pkg/appstate`（ゴルーチンセーフなビューモデル）に集約し、GUI（`GET /api/state` ポーリング）・ヘッドレス CLI とも購読する。UI は `pkg/signalclient.Client`（型付き送受信）と `cmd/client` の `Tunnel`（`OpenTunnel`/`Configure`/`Apply`/`DiscoverWAN`/`PeerHandshake`）を**呼ぶだけ**にする。
- GUI とヘッドレス CLI（`-mode host`/`guest`）は同一の受信ループ（`runHost`/`runGuest` の `env.Type` 分岐）を駆動する。GUI 操作は `POST /api/{host,join,approve,reject,rotate,leave,reset}` で行い、`pkg/originguard` で同一オリジン検証（CSRF・DNS リバインディング対策）。秘密鍵などの復号鍵は API に載せない（公開鍵・招待・表示メタデータのみ）。
- 将来の SDK 化（[[pkg-pure-logic]]）を見据え、再利用可能なロジックは `pkg/` へ寄せる。

## 6. チェックリスト

1. 追加コードが秘密鍵/トークンをディスク・ログ・サーバー送信していないか。
2. `peer_info`・リレーで公開情報のみを扱っているか。
3. ゲスト側で `VerifyHostKey` 照合を通っているか（MITM 対策）。
4. OS 依存の鍵保護（mlock 等）は build tag で `cmd/client` に分離しているか。

関連スキル: [[wireguard-go-integrator]]（鍵から UAPI・トンネルへの適用）、[[nat-traversal-signaling]]（peer_info 交換）、[[pkg-pure-logic]]（再利用ロジックの分離先）。
