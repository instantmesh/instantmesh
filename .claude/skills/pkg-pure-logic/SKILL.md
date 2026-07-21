---
name: pkg-pure-logic
description: InstantMesh の pkg/ に純粋ロジック（トランスポート/OS/UI/AWS 非依存のドメインパッケージ）を追加・変更するときのスキル。now 注入による決定的テスト・失敗を値で返す設計・テストシーム・テーブル駆動・100%カバレッジ・SDK 化を見据えた分離の規約を示す。新パッケージ作成、pkg/ 配下の関数追加、ドメインロジック実装時に使う。
---

# pkg/ 純粋ロジック実装ガイド（正本参照）

このスキルの**正本は `.agents/skills/pkg_pure_logic/SKILL.md`** です。二重管理による再乖離を防ぐため内容はそちらに一元化しています。

**作業前に必ず `.agents/skills/pkg_pure_logic/SKILL.md` を Read し、その規約に従ってください。**

要点（詳細は正本）: 依存は cmd/→pkg/ の一方向・時刻は now 引数注入・ドメイン層はセンチネルエラー / session は error エンベロープ・pkg/ は 100% カバレッジ必須（CI 強制）。
