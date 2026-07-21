---
name: commit-push
description: 変更を Git にコミット＆プッシュするときのスキル。git add / git commit / git push は確認なし（事前承認済み）で実行してよい。差分確認 → ステージ → リポジトリ規約に沿った日本語 Conventional Commits メッセージ作成（Co-Authored-By フッタ付き）→ 現在ブランチへ push までの手順と禁止事項を示す。ユーザーが「コミット」「プッシュ」「保存して」等を求めたとき、または /commit-push 実行時に使う。
---

# コミット & プッシュ（正本参照）

このスキルの**正本は `.agents/skills/commit_push/SKILL.md`** です。二重管理による乖離を防ぐため内容はそちらに一元化しています。

**作業前に必ず `.agents/skills/commit_push/SKILL.md` を Read し、その手順・規約に従ってください。**

要点（詳細は正本）: `git add` / `git commit` / `git push` は確認なしで実行可（事前承認済み）。状態把握（status/diff/log）→ ステージ（既定 `git add -A`）→ 日本語 Conventional Commits（`type(scope): 要約` ＋ `Co-Authored-By` フッタ）→ 現在ブランチへ push。`--no-verify` / `--force` 禁止、生成物・秘密情報はコミットしない。
