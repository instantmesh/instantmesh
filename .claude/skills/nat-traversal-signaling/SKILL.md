---
name: nat-traversal-signaling
description: InstantMesh の NAT トラバーサル（STUN 共有ソケットによる UDP Hole Punching）、WebSocket シグナリング（pkg/signaling の Envelope スキーマ）、P2P 直通⇄リレーの自動フォールバック（pkg/connmon 状態機械・pkg/relayframe）を実装・デバッグするスキル。自前 pkg/stun・pkg/stunmux・sharedBind を用いた実装の実態に即す。
---

# NATトラバーサル ＆ シグナリング実装ガイド（正本参照）

このスキルの**正本は `.agents/skills/nat_traversal_signaling/SKILL.md`** です。二重管理による再乖離を防ぐため内容はそちらに一元化しています。

**作業前に必ず `.agents/skills/nat_traversal_signaling/SKILL.md` を Read し、その規約に従ってください。**

要点（詳細は正本）: STUN は自前 pkg/stun（pion 不使用）・WireGuard と同一ソケットで STUN（sharedBind+pkg/stunmux）・シグナリングは pkg/signaling の Envelope・直通⇄リレーは pkg/connmon 状態機械＋pkg/relayframe＋relayProxy。
