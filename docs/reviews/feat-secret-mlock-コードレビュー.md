# コードレビュー: `feat/secret-mlock`

- 対象ブランチ: `feat/secret-mlock`（`main` との差分）
- 対象コミット: `a5e7f01`（秘密鍵の mlock/ゼロ化）・`13e9504`（無料版ポート制限フィルタの TUN 配線）・`76b2aa6`（招待リンク再発行の配線）
- レビュー日: 2026-07-14
- 観点: 正しさ（recall 重視）・秘密情報管理・規約遵守

このファイルは当該ブランチの変更に対するレビュー所見の記録。修正時にチェックボックスを更新する。

---

## 所見一覧（重大度順）

### 1. 【重大】招待トークン再発行がリレーフォールバックを壊す

- 位置: `cmd/client/main.go:148`（ホスト）/ `cmd/client/main.go:264`（ゲスト）
- 種別: correctness（データプレーン疎通喪失）
- 状態: ✅ 対応済み（リレー認可をルームIDベースへ変更し招待トークン非依存化。ホスト・ゲスト両対応）

`startMonitor(...token...)` がルームトークンを `dialRelay` のクロージャに**値で束ねる**（`relaytransport.go:30` で `?token=` に付与）。リレー接続は初回フォールバック時に遅延生成される（`connmonitor.go` の `ensureProxy`）。一方リレーのデータプレーン認証は `managerAuthorizer.Authorize` → `manager.LookupByToken` で行われ、**ローテーション済みの旧トークンは拒否される**（`cmd/server/relay.go:33`・`pkg/manager/manager.go:198`）。

**再現シナリオ**
1. ホストがルーム作成 → トークン `T1`。`startMonitor(...T1...)` が `T1` をクロージャに束ねる。
2. まだどのピアもリレーへ落ちていない（proxy 未生成）。
3. `rotate_token` で `T1` → `T2` に再発行（`T1` は即時失効）。
4. 以後どれかのピアで直通が切れリレーへ転落 → `ensureProxy` → `dialRelay(relayURL, T1, ...)` → サーバーが `LookupByToken(T1)` で失効トークンを弾き **401** → リレー確立失敗 → 当該ピアと疎通不能。

ゲスト側も参加時の `inv.Token`（＝ホストが再発行すると失効する）を保持するため同様。`invite_reissued` 受信ハンドラ（`main.go:186-194`）は招待リンクを再生成するのみで、**監視の保持トークンを更新していない**。ドキュメントの「承認済みピアは維持」に反し、再発行前にまだリレーへ落ちていない全ピアのフォールバックが静かに壊れる。

**修正方針の候補**
- `connMonitor` に保持トークンの更新口を設け、`invite_reissued` 受信時にホスト（および将来的にゲストへ通知して）更新する。
- あるいはリレー認証をトークンではなく別のセッション資格（例: ルームID＋公開鍵の署名）に基づかせ、招待トークンのローテーションと独立させる（より本質的）。

---

### 2. 【中】`secret.Wipe` がゼロ化より前に munlock している

- 位置: `pkg/secret/secret.go:90`
- 種別: security（スワップ流出防止の目的を一部損なう）
- 状態: ✅ 対応済み（Wipe を「ゼロ化 → munlock」の順序へ入替。順序検証テストを追加）

`Wipe()` は先に `v.locker.Unlock(v.buf)`（mlock/VirtualLock 解除・L90）を呼び、その後の for ループでゼロ化する（L92-94）。munlock 完了からゼロ化完了までの窓でメモリ逼迫が起きると、**秘密鍵を含むページがロック解除された状態でスワップアウトされうる**。本パッケージの目的（スワップ流出防止）に照らすと順序が逆。

**修正方針**: 「先にゼロ化（ロック中は非スワップを保証）→ その後 munlock」に入れ替える。

---

### 3. 【中】ポートフィルタが部分読み取りエラー時に素通しする（フィルタバイパス）

- 位置: `cmd/client/portfilter.go:465`
- 種別: correctness（緩和策の抜け穴）
- 状態: ✅ 対応済み（エラー時も返された n 件へフィルタを適用し err を伝播。部分読み取りエラーの回帰テストを追加）

`filterDevice.Read` は `n, err := d.Device.Read(...); if err != nil { return n, err }` で、エラー時は**フィルタループへ入らず n 件をそのまま返す**（L462-466）。Linux の `NativeTun` は GRO 分割時に有効パケット数 `n(>0)` と `tun.ErrTooManySegments` を同時返却しうる。wireguard-go はこのエラーを消化して n 件を処理するため、Free プランでも許可外パケット（UDP・許可外 TCP）が送出され、既定フィルタが効かない。

**修正方針**: エラーが返っても、返された `n` 件については前詰めフィルタを適用してから `(kept, err)` を返す。

---

### 4. 【低】`watchStdinRotate` ゴルーチンがキャンセルされずリークする

- 位置: `cmd/client/main.go:127`（起動）/ `main.go:213`（本体）
- 種別: conventions（CLAUDE.md 設計原則5違反）
- 状態: ✅ 対応済み（ctx を渡し本体を ctx.Done() で終了。stdin 読み取りを別ゴルーチンへ隔離）

`go watchStdinRotate(c)` は `sc.Scan()` で `os.Stdin` をブロック読みするだけで `ctx` を監視しない。`room_closed` や `Next` エラーで `runHost` が return しても stdin が EOF になるまで残存する。CLAUDE.md 設計原則5「goroutine は必ず `context.Context`／チャネルでキャンセルライフサイクルを持たせリークを防ぐ」に反する。

> 補足: 現状は単一プロセス・単一起動で、プロセス終了時に回収されるため実害は限定的。ただし将来 `runHost` を再入する構成では毎回リークが累積する。

**修正方針**: stdin 読み取りを ctx でキャンセル可能にする（読み取りゴルーチンを別立てし、`ctx.Done()` で打ち切るなど）。

---

### 5. 【低】`GenerateSecret` が crypto/ecdh 内部に非ゼロ化の秘密鍵コピーを残す

- 位置: `pkg/wgkey/wgkey.go:49-51`
- 種別: correctness（ゼロ化保証の限界）
- 状態: ✅ 対応済み（`GenerateSecret` の doc コメントに制約を明記。根治は自前 X25519 実装が必要なため将来課題）

`GenerateSecret` は `ecdh.X25519().GenerateKey(...)` の戻り値 `key` の内部に秘密スカラの**第2コピー**を残したまま `key.Bytes()`（別コピー）だけを返す。呼び出し側が返り値を `secret.Value` でロック/ゼロ化しても、ecdh 内部コピーは munlock 対象外・非ゼロ化のまま GC 到達まで平文でヒープに残る。「秘密鍵のメモリ内保持・使用後ゼロ化・mlock」の保証が部分的にしか成立しない。

> 補足: 既存の `Generate()` も同じ制約を持ち、本ブランチが悪化させたわけではない（むしろ base64 文字列コピーを避けた分だけ改善）。根治には別の X25519 実装が要る。まずは限界としてドキュメント化する。

---

### 6. 【低・整理】manager のローテーション経路でルームを三重に探索している

- 位置: `pkg/manager/manager.go:263`
- 種別: simplification
- 状態: ✅ 対応済み（取得済みの `*room.Room` を `rotateTokenLocked` へ渡し重複探索を除去）

`RotateToken` は `m.rooms[roomID]` を存在確認（L237）、`RotateTokenForHost` は `r, ok := m.rooms[roomID]` を取得（L250）した上で、いずれも `rotateTokenLocked` が `r := m.rooms[roomID]` を再取得する（L263）。取得済みの `*room.Room` を `rotateTokenLocked` に引数で渡せば重複探索を除け、「存在確認済みが前提」という不変条件も型で明示できる。

---

## 検証して問題なしだった項目（記録）

- **Tier 伝播の一貫性**: ホストの `room_created` は `string(tier)`、ゲストの `join_approved` は `rm.Spec.Tier` を送るが、`room.Create` が未知 tier を弾く（`pkg/room/room.go:133`）ため、作成に成功したルームでは常に一致する。
- **`filterDevice.Read` の前詰めロジック**: ドロップ後の前詰め（`copy` + `sizes` 更新）は各スロットが別バッキング配列で `kept <= i` のため安全。全件ドロップ時の `(0, nil)` も wireguard-go の read ルーチンは「そのバッチにパケット無し」として扱い継続する（EOF 扱いにならない）。
- **`wgconf.PrivateKeyRaw`**: 32 バイト長チェック・`PrivateKey` に対する優先順位・両者未設定時の挙動は妥当。`encoding/hex` も import 済み。
- **`rotate_token` のサーバー配線**: `signaling.Decode` → `hub.Handle` → `Dispatch` の共通経路で処理され、`TypeRotateToken` は `MessageType.Valid()` にも登録済み。実 WebSocket E2E（`TestServerInviteReissue`）で往復を検証。
- **`secret.Value` の状態遷移**: Wipe の冪等性・use-after-wipe の panic・Lock 失敗時にバイト列を破壊しない挙動・nil locker の no-op は網羅テスト済み。
