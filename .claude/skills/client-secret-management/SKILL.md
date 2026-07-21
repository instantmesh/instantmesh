---
name: client-secret-management
description: InstantMesh クライアントで WireGuard 秘密鍵・招待トークンなどの秘密情報を扱うとき、および UI とコアロジックを分離するときのスキル。メモリ内保持・ディスク非保存・使用後ゼロ化・mlock の規約、E2E を壊さない鍵の流れ、帯域外MITM照合、GUI をコアから分離する構造を示す。
---

# クライアント秘密情報 & UI 分離ガイド（正本参照）

このスキルの**正本は `.agents/skills/client_secret_management/SKILL.md`** です。二重管理による再乖離を防ぐため内容はそちらに一元化しています。

**作業前に必ず `.agents/skills/client_secret_management/SKILL.md` を Read し、その規約に従ってください。**

要点（詳細は正本）: 秘密鍵/トークンはメモリ内のみ（ディスク・ログ・サーバー送信禁止）・peer_info/リレーは公開情報のみ・ゲストは VerifyHostKey で MITM 照合・mlock/ゼロ化は build tag で cmd/client に分離・UI は pkg のコアを呼ぶだけ。
