---
name: wireguard-go-integrator
description: InstantMesh クライアントで wireguard-go を組み込み、UAPI 設定ビルダー（pkg/wgconf）・鍵（pkg/wgkey）・ピア写像（pkg/meshpeer）・仮想NICのIP付与とルーティング（pkg/netcfg + linkconfig_<os>.go）・ハンドシェイク検知（pkg/wgstat）を扱うスキル。STUN 相乗り用の sharedBind を使った device 生成の実態に即す。
---

# wireguard-go インテグレーションガイド（実装準拠）

InstantMesh クライアント（`cmd/client`）は wireguard-go をユーザースペースで組み込み、純粋パッケージ（`pkg/wgkey`・`pkg/wgconf`・`pkg/meshpeer`・`pkg/netcfg`・`pkg/wgstat`）を配線する。要初回管理者/root 権限。

## 1. device の生成（sharedBind を使う）

`cmd/client/tunnel.go` の `OpenTunnel(ifName, cfg)`（`tunnel.go:45`）が実態:

```go
tunDev, _ := tun.CreateTUN(ifName, device.DefaultMTU) // 要管理者/root
name := tunDev.Name()
bind := newSharedBind()                               // ← conn.NewDefaultBind() ではない
dev := device.NewDevice(tunDev, bind, device.NewLogger(device.LogLevelError, "wg("+name+") "))
uapi, _ := cfg.UAPI()
dev.IpcSet(uapi)
dev.Up()
```

**重要**: 標準の `conn.NewDefaultBind()` ではなく `sharedBind`（`sharedbind.go`）を渡す。これにより STUN を WireGuard と同一 UDP ソケットで実施でき hole punching が成立する（詳細は [[nat-traversal-signaling]]）。

`Tunnel` の公開 API: `Apply(cfg)` / `Configure(assignedIP)` / `DiscoverWAN(stun, timeout)` / `ListenPort()` / `PeerHandshake(pubKeyHex)` / `Name()` / `Close()`。

## 2. 鍵と UAPI（base64 ⇔ hex）

- 鍵は `pkg/wgkey`（`crypto/ecdh` の X25519、**base64 文字列**。`KeyPair{Private, Public}`）。秘密鍵の扱いは [[client-secret-management]]。
- `pkg/wgconf` が UAPI 設定文字列を組む。`Config{PrivateKey, ListenPort, ReplacePeers, Peers}`、`Peer{PublicKey, Remove, Endpoint, AllowedIPs, PersistentKeepaliveSec}`。`Config.UAPI()`（`wgconf.go:49`）が `key=value\n` 行を出力する。
- **wireguard-go の UAPI は鍵を hex で要求する。** `keyToHex`（`wgconf.go:99`）が base64→32バイト検証→hex 変換する。Endpoint は `netip.ParseAddrPort`、AllowedIPs は `netip.ParsePrefix` で検証。
- 差分適用は `Tunnel.Apply(cfg)`（`IpcSet`）。ピア削除は `Peer.Remove=true`。

## 3. ピア写像（star トポロジ、pkg/meshpeer）

`peer_info` で得た公開鍵・IP・エンドポイントからピア設定を作る（`meshpeer.go`）。keepalive は 25 秒。

- `HostPeer(guestPubKey, guestIP, endpoint)`（`meshpeer.go:23`）— ホスト側にゲストを追加。AllowedIPs は**ゲスト割当IPのみ**（IPv4 なら `/32`）。
- `GuestPeer(hostPubKey, hostIP, endpoint)`（`meshpeer.go:38`）— ゲスト側にホストを追加。AllowedIPs は**メッシュ全体**（`/24`、`10.0.0.1`→`10.0.0.0/24`）。ゲストはホスト経由で他ゲストへ到達する star 構成。
- `RemovePeer(pubKey)`（`meshpeer.go:53`）— `Remove:true` の Config を返す（`guest_left` 受信時に `Tunnel.Apply`）。

## 4. 仮想NICの IP 付与とルーティング（pkg/netcfg + OS 別アダプタ）

- 算出は純粋ロジック `pkg/netcfg`：`For(assignedIP)`（`netcfg.go:32`）が `Plan{Address: /32, Routes: [/24]}` を返す（フェーズ1は IPv4 のみ）。`Plan.Conflicts(existing)`（`netcfg.go:56`）が `Overlaps` で既存サブネットとの重複を検出。
- 適用は OS 依存の `configureLink(ifName, plan)`（`cmd/client/linkconfig_<os>.go`、build tag で切替）。`Tunnel.Configure(assignedIP)`（`tunnel.go:89`）が `netcfg.For`→衝突チェック→`configureLinkFn` を呼ぶ。

| OS | build tag | 使うコマンド |
| :--- | :--- | :--- |
| Linux | `//go:build linux` | `ip address add` / `ip link set up` / `ip route add`（要 root/CAP_NET_ADMIN） |
| Windows | `//go:build windows` | `netsh interface ipv4 add address` / `... add route`（Wintun・要管理者） |
| macOS | `//go:build darwin` | `ifconfig <if> inet <addr> <local> alias` / `route -q -n add -inet`（utun・要 root） |
| その他 | `//go:build !linux && !windows && !darwin` | 未対応エラーを返す |

OS 依存の実適用は非特権 CI で検証できないため、**CI はクロスビルド（`GOOS=windows/darwin`）で型崩れのみ検知**する。配線自体は `configureLinkFn`・`localPrefixesFn` の関数注入でユニットテストする。

## 5. サブネット衝突検知

`checkSubnetConflict`（`tunnel.go:107`）が `localOnlinkPrefixes(excludeIfName)`（`subnets.go:15`：自 NIC を除外し、up かつ非ループバックの既存 IPv4 サブネットを列挙）で既存ネットワークを集め、`Plan.Conflicts` が非空なら `ErrSubnetConflict` を返して**仮想NIC設定を中止**する（メッシュ /24 が既存 LAN と衝突する事故を防ぐ）。列挙失敗はベストエフォートで許可（警告のみ）。

## 6. ハンドシェイク検知（直通成否の判定）

`pkg/wgstat`（`Parse`/`LastHandshake`、`wgstat.go`）が `dev.IpcGet()` の UAPI 出力を解析し、ピア（16進公開鍵キー）ごとの `Endpoint`・`LastHandshake time.Time`（`last_handshake_time_sec`/`_nsec`、未成立は zero）を返す。`Tunnel.PeerHandshake(pubKeyHex)` が直近時刻を返し、直通⇄リレー判定（[[nat-traversal-signaling]] の `connmon`）に使う。

## 7. Windows のヘルパーサービス（将来案）

現状は起動プロセスが直接 `tun.CreateTUN` する（初回のみ管理者権限）。将来、一般 UI プロセスと分離したい場合は SYSTEM 権限の常駐サービス＋名前付きパイプ/ローカル gRPC で VPN 起動を委譲する設計を検討する（フェーズ1では未実装）。

関連スキル: [[nat-traversal-signaling]]（STUN 共有ソケット・フォールバック）、[[client-secret-management]]（秘密鍵の保護）、[[cmd-transport-wiring]]（クライアント配線）。
