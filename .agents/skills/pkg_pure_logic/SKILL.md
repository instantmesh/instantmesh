---
name: pkg-pure-logic
description: InstantMesh の pkg/ に純粋ロジック（トランスポート/OS/UI/AWS 非依存のドメインパッケージ）を追加・変更するときのスキル。now 注入による決定的テスト・失敗を値で返す設計・テストシーム・テーブル駆動・100%カバレッジ・SDK 化を見据えた分離の規約を示す。新パッケージ作成、pkg/ 配下の関数追加、ドメインロジック実装時に使う。
---

# pkg/ 純粋ロジック実装ガイド

InstantMesh のコアロジックはすべて `pkg/` 配下の**純粋パッケージ**として実装する。将来の SDK 切り出しを見据え、UI・トランスポート（WebSocket）・OS・AWS への依存を持ち込まない。実 I/O は `cmd/` 側（`package main`）が担う。CI（`.github/workflows/ci.yml`）が **`pkg/` 全パッケージ 100% カバレッジを強制**する（未満はビルド失敗）。

## 1. 依存の向きと純粋性

- 依存は常に `cmd/` → `pkg/`。`pkg/` から `cmd/`・UI・`gorilla/websocket`・`wireguard-go` へ依存してはならない。
- ネットワーク I/O を持つパッケージも「純粋な変換」に留める。例:
  - `pkg/stun` は STUN メッセージの**バイト列生成/解析**のみを行い、実送受信は `PacketConn` インターフェース越し（`pkg/stun/stun.go:162`）。実 UDP は `cmd/client` が渡す。
  - `pkg/relayframe` は**フレームの Encode/Decode のみ**（`pkg/relayframe/relayframe.go:32,46`）。実 WebSocket 送受信は `cmd` 側。
  - `pkg/signaling` は Envelope の型・エンコード・検証のみ。
- 「1 機能 1 パッケージ」。ディレクトリ名は snake_case、frontmatter/宣言の識別子は Go 慣習（短い小文字）。公開 API は最小限に。

## 2. 決定的な時刻（now 注入）— 必須

時間依存ロジックは `time.Now()` を内部で呼ばず、**現在時刻を引数で受ける**。テストは固定時刻で決定的に検証する。

- ドメイン層は各メソッドが `now time.Time` を受ける。例: `room.Room` の全操作（`pkg/room/room.go`：`Approve(pubKey string, now time.Time)`、`IsExpired(now time.Time)` 等）、`session.Dispatcher.Dispatch(o, env, now)`。
- 状態機械は生成と遷移の両方で時刻を受ける。例: `connmon`（`pkg/connmon/connmon.go:73,100`）は `New(cfg, now)` と `Step(now, lastHandshake)` に `time.Time` を渡し、内部に時計を持たない。
- `cmd/` 側が `time.Now` を注入する（例 `runMaintenance(ctx, m, interval, time.Now)`）。

```go
// 良い例（pkg/room 相当）
func (r *Room) IsIdle(now time.Time) bool {
    return now.Sub(r.lastActivity) >= plan.IdleTimeout
}
// 悪い例: 内部で time.Now() を呼ぶとテストが非決定的になり 100% を維持できない
```

## 3. 失敗の表現

層によって使い分ける。

- **ドメイン層（`pkg/room`・`pkg/manager` 等）はセンチネルエラーを返す。** 公開した `Err*` 変数（例 `room.ErrRoomFull`・`room.ErrNotPending`・`manager.ErrPrefixExhausted`）を返し、呼び出し側は `errors.Is` で判定する。
- **ディスパッチャ層（`pkg/session`）は Go の `error` を返さない全域関数。** すべての失敗を送信元宛て（`Target{Kind: TargetOrigin}`）の `signaling.TypeError` エンベロープ（`code`+`message`）で表現する（`pkg/session/session.go:138`）。ドメインのセンチネルは `classify`（`session.go:527`）が `errors.Is` でエラーコード（`ErrCodeRoomFull` 等）へ写像する。新しいドメインエラーを足したら `classify` のテーブルとそのテスト（`TestClassify`）を必ず更新する。

## 4. テストシーム（決定性のための注入点）

乱数・ID・鍵生成など非決定的な要素は、差し替え可能なパッケージ変数/フィールドにする。

- パッケージ変数: `var randReader io.Reader = rand.Reader`（`pkg/stun/stun.go:47`、`pkg/wgkey/wgkey.go:22`）、`var newRequest = stun.NewRequest`（`pkg/stunmux/stunmux.go:23`）。
- 構造体フィールド: `manager.Manager` の `newID`/`newToken func() (string, error)`（既定 `token.NewRoomToken`）。
- テストはこれらを固定値/決定的関数に差し替えてから検証する。

## 5. テストの書き方

- **白箱テスト**（`package room` のように対象と同一パッケージ）で非公開フィールドも直接検証してよい（例 `pkg/room/room_test.go` は `r.guests["pk"].State` を直接操作）。
- **テーブル駆動**を写像・分類系で使う（例 `session_test.go` の `TestClassify` が `[]struct{ err error; code string }` で全エラー→コードを網羅）。分岐が多いものは 1 テスト内で複数ケースを順に検証してもよい。
- **ドメイン/ディスパッチャ層ではフェイク `Conn` を使わない。** これらは値（`room` の戻り値、`session.Result{Out, Bind}`）を返す純粋層なので、戻り値の構造体（`res.Out[i].To.Kind`・`.Env.Type`・decode したペイロード）を直接アサートする。`Conn` 抽象は `pkg/hub` 以上の関心事。
- 相対時刻でシナリオを組む（`now := time.Now()` を起点に `now.Add(plan.JoinRequestTimeout)` 等）。
- レート制限の「1 回だけ許可」は `ratelimit.New(0, 1)`（rate=0, burst=1）で作る。

## 6. 新パッケージ追加時のチェックリスト

1. `pkg/<name>/` に純粋実装＋`<name>_test.go` を置き、**100% カバレッジ**にする（分岐・エラー経路も網羅）。
2. トランスポート/OS 依存が紛れていないか確認（紛れる場合は I/F で切り出し `cmd/` に実装を置く）。
3. `TODO.md` のパッケージ一覧表に 1 行追加し、`README.md` のプロジェクト構成ツリーにも反映する（数の追従漏れを防ぐ）。
4. `go vet ./...` とクロスビルド（`GOOS=windows/darwin`）が通ることを CI で確認する。

関連スキル: [[cmd-transport-wiring]]（このコアを WebSocket/OS へ配線する側）、[[client-secret-management]]（秘密情報の扱い）。
