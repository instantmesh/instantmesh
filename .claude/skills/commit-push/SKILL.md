---
name: commit-push
description: 変更を Git にコミット＆プッシュするときのスキル。git add / git commit / git push は確認なし（事前承認済み）で実行してよい。差分確認 → ステージ → リポジトリ規約に沿った日本語 Conventional Commits メッセージ作成（Co-Authored-By フッタ付き）→ 現在ブランチへ push までの手順と禁止事項を示す。ユーザーが「コミット」「プッシュ」「保存して」等を求めたとき、または /commit-push 実行時に使う。
---

# コミット & プッシュ（git add / commit / push）

変更を Git にコミットしてリモートへ反映するときのスキル。`git add` / `git commit` / `git push` は**確認なしで実行してよい**（`.claude/settings.local.json` で事前承認済み。状態把握用の `git status` / `git diff` / `git log` も同様）。

## 実行タイミング

- ユーザーが「コミットして」「プッシュして」「保存して」「push しといて」等を求めたとき。
- `/commit-push` を実行したとき。

## 手順

1. **状態把握（Bash ツールで並列実行）** — 読み取りのみで確認不要。
   - `git status` … 変更ファイルの一覧
   - `git diff` と `git diff --staged` … 実際の変更内容
   - `git log --oneline -10` … 直近のコミットメッセージ様式を踏襲するため
2. **ステージ** — 関連する変更をまとめる。既定は `git add -A`。無関係な生成物・秘密情報（鍵・トークン）が混ざっていないか diff で確認してから add する。
3. **コミット** — 下記のメッセージ規約に従い、Bash ツールで実行する（heredoc でフッタまで一括投入）。
   ```bash
   git commit -F - <<'EOF'
   type(scope): 変更の要約（日本語・命令形・末尾に句点なし）

   （必要なら本文。何を・なぜ変えたか）

   Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>
   EOF
   ```
4. **プッシュ** — 現在のブランチへ push する。
   - 上流未設定なら `git push -u origin HEAD`、設定済みなら `git push`。
   - push 後、CI 結果を確認する場合は `gh run list` / `gh run view`（ビルド/テストは CI が主）。

## コミットメッセージ規約（このリポジトリ）

- **日本語の Conventional Commits**。`type(scope): 要約` の形式で、直近の履歴に合わせる（例: `feat(...)`, `chore(test): ...`, `docs(agents): ...`）。
- type 例: `feat` / `fix` / `chore` / `docs` / `refactor` / `test`。scope は変更領域（`test`, `agents`, パッケージ名など。無ければ省略可）。
- 要約は簡潔に、末尾に句点は付けない。理由・背景が必要なら本文で補足する。
- **末尾に必ず `Co-Authored-By: Claude Opus 4.8 (1M context) <noreply@anthropic.com>` を付ける。**

## 禁止・注意

- `--no-verify` で pre-commit フックを飛ばさない。フックが失敗したら原因を直す。
- `--force` / `--force-with-lease` の push はしない（ユーザーが明示要求した場合のみ）。
- 生成物・秘密鍵・一時トークンをコミットしない（`.gitignore` と diff で確認）。秘密情報の扱いは [[client-secret-management]] を参照。
- 現在のブランチへ push する。このリポジトリは PR 経由で main にマージする運用なので、main 上で作業していて PR 化したい場合は事前に feature ブランチを切る（このスキルはブランチ作成をしない）。
