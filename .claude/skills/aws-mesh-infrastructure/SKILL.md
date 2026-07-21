---
name: aws-mesh-infrastructure
description: InstantMesh のシグナリング/リレーを AWS（EC2 Graviton・ElastiCache Redis・Cognito・S3）へ本番展開するときのスキル。現行のインメモリ/モック実装（pkg/manager・Authenticator I/F・AuditLogger I/F）を、I/F を温存したまま Redis/Cognito/S3 実装へ差し替える指針とインフラ設計を示す。フェーズ1では未実装（将来指針）。
---

# AWS メッシュインフラ構築ガイド（正本参照）

このスキルの**正本は `.agents/skills/aws_mesh_infrastructure/SKILL.md`** です。二重管理による再乖離を防ぐため内容はそちらに一元化しています。

**作業前に必ず `.agents/skills/aws_mesh_infrastructure/SKILL.md` を Read し、その規約に従ってください。**

要点（詳細は正本）: 新規に書き直さず I/F 実装を差し替える（セッションストア=pkg/manager→Redis、認証=Authenticator→Cognito、監査=AuditLogger→S3）・ap-northeast-1 固定・SG は 443/UDP3478・E2E のためサーバーは復号鍵を持たない。フェーズ1未実装。
