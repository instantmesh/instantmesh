package main

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"

	"github.com/instantmesh/instantmesh/pkg/netcfg"
	"github.com/instantmesh/instantmesh/pkg/wgconf"
	"github.com/instantmesh/instantmesh/pkg/wgstat"
)

// ErrSubnetConflict はメッシュ /24 が適用先ホストの既存オンリンクサブネットと重複しており、
// アドレス/ルートの適用を中止したことを表す。呼び出し側は errors.Is で判定し、OS 依存の適用失敗と
// 区別してユーザーへ通知できる。
var ErrSubnetConflict = errors.New("メッシュサブネットが既存ネットワークと重複")

// Tunnel は wireguard-go のユーザースペース WireGuard デバイスを管理する。
//
// スコープ（フェーズ1・現段階）: デバイスの生成・設定・起動・停止に加え、割当メッシュIPの
// 付与とメッシュ経由ルート設定（Configure）まで。アドレス/ルートの実適用は OS 依存
// （Linux: ip、Windows: netsh、macOS: ifconfig/route）で configureLink（linkconfig_<os>.go）が担い、
// 付与すべきアドレス/ルートの算出は純粋ロジック pkg/netcfg に分離している。
type Tunnel struct {
	dev  *device.Device
	bind *sharedBind
	name string
	// filter は無料版ポート制限の既定フィルタを適用する tun.Device ラッパ。プラン確定時に
	// SetPlan で仕様を設定する（portfilter.go）。
	filter *filterDevice
	// configureLinkFn は解決済みの netcfg.Plan を実インターフェースへ適用する OS 依存関数。
	// 既定は configureLink（OS別実装）。テストではフェイクへ差し替える。
	configureLinkFn func(ifName string, plan netcfg.Plan) error
	// localPrefixesFn は excludeIfName 以外のインターフェースが持つオンリンクの IPv4 サブネットを
	// 列挙する（メッシュ /24 と適用先ホストの既存 LAN の衝突検知に使う）。既定は
	// localOnlinkPrefixes。テストではフェイクへ差し替える。nil の場合は衝突検知を行わない。
	localPrefixesFn func(excludeIfName string) ([]netip.Prefix, error)
}

// OpenTunnel は名前 ifName の TUN デバイスを作成し、初期設定 cfg を適用して起動する。
// ifName は OS により制約がある（Linux: 任意名、macOS: "utun"/"utunN"、Windows: 任意名で Wintun）。
// 初回は管理者/root 権限が必要。
func OpenTunnel(ifName string, cfg wgconf.Config) (*Tunnel, error) {
	tunDev, err := tun.CreateTUN(ifName, device.DefaultMTU)
	if err != nil {
		return nil, fmt.Errorf("tun 作成: %w", err)
	}
	name, err := tunDev.Name()
	if err != nil {
		_ = tunDev.Close()
		return nil, fmt.Errorf("tun 名取得: %w", err)
	}

	// WireGuard と STUN で同一の UDP ソケットを共有する bind を使う。これにより STUN で観測する
	// WAN マッピングが WireGuard の送信マッピングと一致し、NAT hole punching が成立する。
	bind := newSharedBind()
	// 無料版ポート制限の既定フィルタを適用するため tun.Device をラップする（プラン確定まで素通し）。
	filter := newFilterDevice(tunDev)
	dev := device.NewDevice(filter, bind, device.NewLogger(device.LogLevelError, "wg("+name+") "))

	uapi, err := cfg.UAPI()
	if err != nil {
		dev.Close()
		return nil, err
	}
	if err := dev.IpcSet(uapi); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg 設定: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wg 起動: %w", err)
	}
	return &Tunnel{dev: dev, bind: bind, name: name, filter: filter, configureLinkFn: configureLink, localPrefixesFn: localOnlinkPrefixes}, nil
}

// Apply は差分設定（ピアの追加/更新/削除など）を適用する。
func (t *Tunnel) Apply(cfg wgconf.Config) error {
	uapi, err := cfg.UAPI()
	if err != nil {
		return err
	}
	return t.dev.IpcSet(uapi)
}

// Configure は割当メッシュIP assignedIP を仮想NICに付与し、メッシュ宛(/24)を当該インターフェース
// 経由にルーティング設定する。ホストは room_created の HostIP、ゲストは join_approved の AssignedIP
// を渡す。付与すべきアドレス/ルートは pkg/netcfg で算出し、実適用は OS 依存の configureLinkFn が担う。
func (t *Tunnel) Configure(assignedIP string) error {
	plan, err := netcfg.For(assignedIP)
	if err != nil {
		return err
	}
	if err := t.checkSubnetConflict(plan); err != nil {
		return err
	}
	return t.configureLinkFn(t.name, plan)
}

// checkSubnetConflict はメッシュ /24 が適用先ホストの既存オンリンクサブネットと重複していないかを
// 検査する。重複があれば ErrSubnetConflict をラップしたエラーを返し、呼び出し側（Configure）は
// アドレス/ルートの適用を中止する。重複した /24 のルートは既存ネットワーク（実ルータ・NAS 等）宛の
// トラフィックをトンネルへ奪い、実LAN への到達性を壊すため、適用しない方が安全である。
//
// 既存サブネットの列挙に失敗した場合は、衝突の有無を判断できないためベストエフォートで適用を許可する
// （警告のみ・nil を返す）。localPrefixesFn が nil の場合も検知を行わず適用を許可する。
func (t *Tunnel) checkSubnetConflict(plan netcfg.Plan) error {
	if t.localPrefixesFn == nil {
		return nil
	}
	existing, err := t.localPrefixesFn(t.name)
	if err != nil {
		log.Printf("既存サブネットの列挙に失敗したため衝突検知をスキップします: %v", err)
		return nil
	}
	if conflicts := plan.Conflicts(existing); len(conflicts) > 0 {
		return fmt.Errorf("%w: メッシュ %v が既存ネットワーク %v と重複するため適用を中止しました",
			ErrSubnetConflict, plan.Routes, conflicts)
	}
	return nil
}

// Name は仮想NICのインターフェース名を返す。
func (t *Tunnel) Name() string { return t.name }

// Close はデバイス（と TUN）を閉じる。
func (t *Tunnel) Close() { t.dev.Close() }

// DiscoverWAN は WireGuard と同一の UDP ソケットから STUN サーバー stunServer へ Binding Request を
// 送り、WAN 側マッピングを発見する。timeout は応答待ちの上限。共有ソケットを使うため、得られる
// マッピングは WireGuard の送信マッピングと一致する。
func (t *Tunnel) DiscoverWAN(stunServer string, timeout time.Duration) (netip.AddrPort, error) {
	return t.bind.DiscoverWAN(stunServer, timeout)
}

// ListenPort は WireGuard が実際に待ち受けている UDP ポートを返す。リレーのループバック注入先
// （127.0.0.1:port）の算出に使う。
func (t *Tunnel) ListenPort() uint16 { return t.bind.ListenPort() }

// PeerHandshake は公開鍵 pubKeyHex（16 進）のピアの直近ハンドシェイク成立時刻を返す。デバイスの
// 状態（IpcGet）を解析して得る。未成立・ピア不在・取得失敗は ok=false（＝直通未確立）。接続モニタ
// （connmon）が P2P 直通の成否判定に用いる。
func (t *Tunnel) PeerHandshake(pubKeyHex string) (time.Time, bool) {
	uapi, err := t.dev.IpcGet()
	if err != nil {
		return time.Time{}, false
	}
	return wgstat.LastHandshake(uapi, pubKeyHex)
}
