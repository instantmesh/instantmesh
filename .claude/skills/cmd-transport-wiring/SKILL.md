---
name: cmd-transport-wiring
description: InstantMesh の cmd/server・cmd/client に WebSocket や OS 依存処理を配線するときのスキル。純粋コア（pkg/hub・session・relayhub・signalclient）への配線、Conn 抽象の実装と書き込み直列化、接続ライフサイクル、認証/監査インターフェース、定期ワーカー、グレースフルシャットダウン、フラグ設計、実 WebSocket 結合テストの規約を示す。
---

# cmd/ トランスポート配線ガイド（正本参照）

このスキルの**正本は `.agents/skills/cmd_transport_wiring/SKILL.md`** です。二重管理による再乖離を防ぐため内容はそちらに一元化しています。

**作業前に必ず `.agents/skills/cmd_transport_wiring/SKILL.md` を Read し、その規約に従ってください。**

要点（詳細は正本）: cmd は薄い I/O アダプタ・hub.Conn の Send は mu で直列化・認証/監査は I/F 注入（メタデータのみ）・now は関数注入・httptest+gorilla で実 WebSocket 結合テスト・グレースフルシャットダウンで CloseConns。
