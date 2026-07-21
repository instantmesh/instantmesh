---
name: nat-traversal-signaling
description: InstantMesh の NAT トラバーサル（STUN 共有ソケットによる UDP Hole Punching）、WebSocket シグナリング（pkg/signaling の Envelope スキーマ）、P2P 直通⇄リレーの自動フォールバック（pkg/connmon 状態機械・pkg/relayframe）を実装・デバッグするスキル。自前 pkg/stun・pkg/stunmux・sharedBind を用いた実装の実態に即す。
---

# NATトラバーサル ＆ シグナリング実装ガイド（実装準拠）

> このガイドは InstantMesh の**現行実装**に準拠する。外部ライブラリ（pion 等）ではなく、`module github.com/instantmesh/instantmesh` の自前パッケージを使う。

## 1. STUN は自前 pkg/stun（外部 stun ライブラリは不使用）

`pkg/stun`（RFC 5389）が STUN メッセージのバイト列を**生成/解析**する純粋パッケージ。実 UDP 送受信は `PacketConn` I/F（`WriteTo`/`ReadFrom`/`SetReadDeadline`、`stun.go:162`）越しに呼び出し側が担う。

主な公開 API:
- `NewRequest() ([]byte, TxID, error)`（`stun.go:53`）— 属性なし Binding Request と 96bit `TxID` を生成。
- `IsMessage(p []byte) bool`（`stun.go:70`）/ `MessageTxID(p []byte) (TxID, bool)`（`stun.go:78`）— WireGuard パケットと STUN 応答を判別。
- `ParseResponse(data []byte, tx TxID) (netip.AddrPort, error)`（`stun.go:89`）— XOR-MAPPED-ADDRESS を復号。
- `Discover(conn PacketConn, server net.Addr, timeout) (netip.AddrPort, error)`（`stun.go:170`）— 別ソケット STUN 用（`-tunnel` 無効時のフォールバック）。

## 2. 肝：WireGuard と同一 UDP ソケットから STUN する（共有ソケット）

hole punching が成立する条件は「STUN で得た WAN マッピング＝WireGuard が送信に使うマッピング」であること。InstantMesh はこれを**ソケット共有**で保証する（旧来の「別ソケット STUN でマッピングがずれる」限界を解消）。

- `pkg/stunmux`：WireGuard の受信経路に相乗りする STUN 多重化（純粋ロジック）。`Mux.Begin()`（`stunmux.go:41`）で Request＋TxID 登録＋応答チャネルを得て、受信パケットを `Mux.Consume(pkt)`（`stunmux.go:62`）に通す。非 STUN は `false`（WireGuard へパススルー）、進行中 tx 宛の STUN 応答は消費して `true`。
- `cmd/client/sharedBind`（`sharedbind.go`）：`conn.NewDefaultBind()` を埋め込み、`Open` で得た各 `ReceiveFunc` を `filter` でラップして受信を `mux.Consume` に通す（消費分は WireGuard 受信配列から除外）。`DiscoverWAN(stunServer, timeout)`（`sharedbind.go:73`）が同一ソケットで STUN を実施。
- `-tunnel` 無効時は `discoverWANStandalone`（一時 UDP ソケット＋`stun.Discover`）にフォールバック（マッピングがずれうる＝対称NATで不利）。

## 3. シグナリング（pkg/signaling の Envelope）

すべてのコントロールメッセージは `Envelope{Type MessageType, Payload json.RawMessage}` でやり取りする（`signaling.go:63`）。`Encode(type, payload)` / `Decode(data)` / `(Envelope).Unmarshal(&v)`。

メッセージ種別（`type` の文字列値、`signaling.go:19`）:

| 方向 | type | ペイロード（主フィールド） |
| :--- | :--- | :--- |
| C→S ホスト | `create_room` | `duration_seconds` |
| S→C ホスト | `room_created` | `room_id`, `token`, `host_ip` |
| C→S ゲスト | `join_request` | `token`, `nickname`, `guest_pub_key` |
| S→C ホスト | `join_pending` | `guest_pub_key`, `nickname`, `sas` |
| C→S ホスト | `decision` | `guest_pub_key`, `approve` |
| S→C ゲスト | `join_approved` | `assigned_ip`, `host_pub_key`, `host_ip` |
| S→C ホスト | `guest_joined` | `guest_pub_key`, `assigned_ip`, `nickname` |
| S→C ホスト | `guest_left` | `guest_pub_key` |
| S→C ゲスト | `join_rejected` | `reason` |
| C→S ホスト | `kick` / `close_room` | `guest_pub_key` / （なし） |
| S→C | `room_closed` | `reason` |
| C↔S 双方向中継 | `peer_info` | `pub_key`, `wan_endpoint` |
| S→C | `error` | `code`, `message` |

- `peer_info` は**なりすまし防止**のため送信元鍵と一致が必須（`session.handlePeerInfo`）。ホスト→承認済みゲスト全員／ゲスト（承認済みのみ）→ホストへ中継。
- クライアントは `pkg/signalclient`（`CreateRoom`/`JoinRequest`/`Approve`/`Reject`/`Kick`/`CloseRoom`/`SendPeerInfo`/`Next`/`Leave`）と `pkg/wsconn`（gorilla アダプタ）を使う。専用の退出メッセージは無く、`Leave()`＝接続クローズ。

## 4. UDP Hole Punching の流れ（実態）

1. 参加確定後、各クライアントが `DiscoverWAN`（共有ソケット）で WAN `ip:port` を取得し、`SendPeerInfo(pubKey, wanEndpoint)` で広告する。
2. 受信した `peer_info` から `pkg/meshpeer`（`HostPeer`=ゲスト/32・`GuestPeer`=メッシュ/24）で WireGuard ピア設定を作り `Tunnel.Apply` する（詳細は [[wireguard-go-integrator]]）。
3. WireGuard の `persistent_keepalive`（25 秒）が双方向にパケットを送り、両端の NAT に対向への穴を開けてトンネルが確立する。
4. 対称NAT×対称NATはマッピングが宛先ごとに変わり原理的に不成立 → リレー必須（次項）。

## 5. 直通⇄リレーの自動フォールバック

**成否検知**: `pkg/wgstat`（`Parse`/`LastHandshake`）が wireguard-go の `IpcGet` UAPI 出力を解析し、ピアごとの `last_handshake_time` を返す。`Tunnel.PeerHandshake(pubKeyHex)` 経由で取得。

**状態機械**: `pkg/connmon`（純粋・now 注入）。`State` は `Probing`/`Direct`/`Relay`。遷移（`connmon.go:100` `Step(now, lastHandshake)`）:
- Probing→Direct: 直近ハンドシェイクが試行開始時刻より新しい。
- Probing→Relay: `now-since >= ProbeTimeout`（既定 8s、`connmonitor.go`）。
- Direct→Probing: ハンドシェイクが `AliveTimeout`（既定 180s）を超えて途絶。
- Relay→Probing: `RetryInterval > 0` のときのみ（既定 0＝転落後はリレー維持の保守設定）。

**リレー経路**: `pkg/relayframe`（`[鍵長2B][公開鍵][暗号化ペイロード]`、`Encode`/`Decode`）を server/client で共有。`cmd/client` の `wsRelay`（`/relay` への WebSocket、`relaytransport.go`）＋ `relayProxy`（`relayproxy.go`：リレー対象ピアごとに loopback UDP ソケットを開き、WireGuard のエンドポイントを `127.0.0.1:port` に差し替えて暗号化パケットを橋渡し）。

**配線**: `connMonitor`（`connmonitor.go`）がピアごとに `connmon.Tracker` を駆動。**単一ゴルーチン＋コマンドチャネル**でデータ競合を回避し、`Track`/`Untrack` はクロージャ送出のみ。ハンドシェイク取得・設定適用・リレーダイヤルは関数注入でユニットテスト可能。`-relay` フラグで有効/無効、`peer_info` 受信で直通適用＋監視開始、`guest_left` で `Untrack`。

## 6. デバッグの勘所

- 直通が張れない: STUN が共有ソケット経由か（`shared_socket=true` ログ）、`peer_info` の `wan_endpoint` が妥当か、`PeerHandshake` が非ゼロになるか。
- 転落しない/過剰に転落: `ProbeTimeout`/`AliveTimeout`（`defaultConnmonConfig`）を確認。`connmon` は純粋なので固定時刻でユニット再現可能。
- リレーで疎通しない: `relayframe` の宛先公開鍵、`managerAuthorizer` の承認判定、`relayProxy` のループバック差し替えを確認。

関連スキル: [[wireguard-go-integrator]]（ピア構成・トンネル適用）、[[cmd-transport-wiring]]（WebSocket/リレーサーバー配線）、[[pkg-pure-logic]]（stun/stunmux/connmon/relayframe の純粋設計）。
