---
name: wireguard-go-integrator
description: InstantMesh クライアントで wireguard-go を組み込み、UAPI 設定ビルダー（pkg/wgconf）・鍵（pkg/wgkey）・ピア写像（pkg/meshpeer）・仮想NICのIP付与とルーティング（pkg/netcfg + linkconfig_<os>.go）・ハンドシェイク検知（pkg/wgstat）を扱うスキル。STUN 相乗り用の sharedBind を使った device 生成の実態に即す。
---

# wireguard-go インテグレーションガイド（正本参照）

このスキルの**正本は `.agents/skills/wireguard_go_integrator/SKILL.md`** です。二重管理による再乖離を防ぐため内容はそちらに一元化しています。

**作業前に必ず `.agents/skills/wireguard_go_integrator/SKILL.md` を Read し、その規約に従ってください。**

要点（詳細は正本）: device.NewDevice には sharedBind を渡す（conn.NewDefaultBind ではない）・UAPI は鍵を hex 要求（keyToHex）・meshpeer は star（ホスト=ゲスト/32、ゲスト=メッシュ/24）・NIC 設定は netcfg+linkconfig_<os>.go・直通成否は wgstat のハンドシェイク時刻。
