package main

// 本ファイルは「共有するローカルサービスを選んで貸す」導線（要件定義書 §4.6）の状態保持と配線。
//
// ホスト側: どのポートを貸しているかを shareController が持ち、変更を
//  (1) ローカル DNS ゾーン（自分自身も名前で到達できるようにする）
//  (2) 表示状態（appstate 経由で GUI へ）
//  (3) peer_info の再広告（既存のシグナリング経路で名前と共有内容を配る・§4.6.3）
// へ反映する。名前とポートの対応づけ自体は純粋ロジック（pkg/localsvc.Advertise）が決める。
//
// ゲスト側: 受信した peer_info の広告を applyPeerAdvert で取り込む。名前は相手の自己申告で
// あるため（信頼の根拠は SAS・§4.6.3）、Zone へ入れる前に pkg/meshname で必ず検証する。

import (
	"log/slog"
	"net/netip"
	"os"
	"sync"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/localsvc"
	"github.com/instantmesh/instantmesh/pkg/meshname"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

// defaultMeshLabel は OS のホスト名からラベルを導出できなかった場合の代替。
const defaultMeshLabel = "host"

// meshHostLabel はメッシュ名に使うラベルを決める（-mesh-name 指定 > OS のホスト名 > "host"）。
// 名前はセッションをまたいで安定していることに価値がある（ゲストの .env や手順書に書ける・
// 要件 §4.6.2）ため、既定値も実行のたびに変わらない OS のホスト名から導出する。
func meshHostLabel(flagValue string) string {
	if l := meshname.Sanitize(flagValue); l != "" {
		return l
	}
	if h, err := os.Hostname(); err == nil {
		if l := meshname.Sanitize(h); l != "" {
			return l
		}
	}
	return defaultMeshLabel
}

// shareController はホストの共有状態（貸しているポートの集合）を保持する。GUI の操作ゴルーチンと
// シグナリング受信ループの双方から触られるため、状態は mu で保護する。
type shareController struct {
	label string // メッシュ名のホストラベル（例 "tanaka"）

	mu       sync.Mutex
	ports    []int
	addr     netip.Addr           // 自身のメッシュIP（ルーム作成後に確定）
	endpoint string               // STUN で発見した WAN エンドポイント（peer_info 再送に使う）
	client   *signalclient.Client // 再広告の送出先（セッション確立後に確定）
	pubKey   string
	zone     *meshname.Zone
	store    *viewStore
}

// newShareController は指定ラベルの共有コントローラを返す。セッション開始前に生成してよく、
// セッション固有の依存（ゾーン・表示状態・接続）は bind で与える。
func newShareController(label string) *shareController {
	return &shareController{label: label}
}

// bind はセッション確立時（ルーム作成完了）に依存と自身のメッシュIP を与え、現在の共有内容を
// 反映する。前セッションの残り（IP・接続）は上書きされる。
func (c *shareController) bind(zone *meshname.Zone, store *viewStore, client *signalclient.Client, pubKey, hostIP string) {
	addr, err := netip.ParseAddr(hostIP)
	if err != nil {
		slog.Warn("ホストのメッシュIP を解釈できず共有の名前配布を見送ります", "host_ip", hostIP, "err", err)
		return
	}
	c.mu.Lock()
	c.zone, c.store, c.client, c.pubKey, c.addr = zone, store, client, pubKey, addr
	c.mu.Unlock()
	c.publish()
}

// reset はセッション終了後に共有状態を初期化する（GUI がプロセス常駐のまま次のセッションを
// 始めるため、前セッションの IP・接続を引きずらない）。共有するポートの選択も持ち越さない。
func (c *shareController) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ports, c.addr, c.endpoint, c.client, c.pubKey, c.zone, c.store = nil, netip.Addr{}, "", nil, "", nil, nil
}

// setPorts は共有するポート集合を設定し、名前配布と表示へ反映する。共有の実行はホストの明示的な
// 選択によるという要件（§4.6.1）に対応する唯一の入口。ポートや名前が不正なら何も変更しない。
func (c *shareController) setPorts(ports []int) error {
	// 反映前に妥当性を確認する（範囲外ポート・名前数の上限超過をここで弾く）。
	if _, _, err := localsvc.Advertise(c.label, ports); err != nil {
		return err
	}
	c.mu.Lock()
	c.ports = append([]int(nil), ports...)
	c.mu.Unlock()
	c.publish()
	return nil
}

// setEndpoint は STUN で発見した WAN エンドポイントを記録する。共有内容の変更を peer_info で
// 再送する際、STUN をやり直さずに済ませるために保持する。
func (c *shareController) setEndpoint(ep string) {
	c.mu.Lock()
	c.endpoint = ep
	c.mu.Unlock()
}

// advert は peer_info に載せる広告（名前群・共有中サービス）を返す。組み立てに失敗した場合は
// 空を返し、広告なしの peer_info（従来どおりのエンドポイント交換）に落とす。
func (c *shareController) advert() ([]string, []signaling.SharedService) {
	c.mu.Lock()
	label, ports := c.label, append([]int(nil), c.ports...)
	c.mu.Unlock()

	names, shared, err := localsvc.Advertise(label, ports)
	if err != nil {
		slog.Warn("共有の広告を組み立てられませんでした", "err", err)
		return nil, nil
	}
	svcs := make([]signaling.SharedService, 0, len(shared))
	for _, s := range shared {
		svcs = append(svcs, signaling.SharedService{Name: s.Name, Port: s.Port})
	}
	return names, svcs
}

// publish は現在の共有内容を Zone・表示状態・ピアへ反映する。ルーム作成前（addr 未確定）は
// 何もしない（bind 時に改めて反映される）。
func (c *shareController) publish() {
	c.mu.Lock()
	addr, zone, store, client, pubKey, endpoint := c.addr, c.zone, c.store, c.client, c.pubKey, c.endpoint
	c.mu.Unlock()
	if !addr.IsValid() {
		return
	}

	names, svcs := c.advert()
	if zone != nil {
		// 自身の名前も自分のゾーンへ入れる（ホストの画面に出す URL をホスト自身でも検証できる）。
		if err := zone.Replace(addr, names); err != nil {
			slog.Warn("メッシュ名の登録に失敗しました", "err", err)
		}
	}
	if store != nil {
		list := make([]appstate.SharedService, 0, len(svcs))
		for _, s := range svcs {
			label, _ := localsvc.LabelFor(s.Port)
			list = append(list, appstate.SharedService{Port: s.Port, Label: label, Name: s.Name, Addr: addr.String()})
		}
		hostName := ""
		if len(names) > 0 {
			hostName = names[0] // Advertise の先頭はホスト自身の名前
		}
		store.update(func(m *appstate.Model) {
			m.SetMeshName(hostName)
			_ = m.SetShared(list)
		})
	}
	// 承認済みゲストへ再広告する。WAN エンドポイントが未確定（STUN 無効 / 未実行）の場合は
	// peer_info を組めないため送らない。次にエンドポイントが確定した広告時に相乗りする。
	if client == nil || endpoint == "" {
		return
	}
	if err := client.SendPeerInfo(pubKey, endpoint, names, svcs); err != nil {
		slog.Warn("共有内容の再広告に失敗しました", "err", err)
	}
}

// applyPeerAdvert は受信した peer_info の広告をローカルへ取り込む。peerIP は送信元ピアの
// メッシュIP。display が真なら共有中サービスの表示（ゲスト画面）も更新する。
//
// 名前は相手の自己申告であり、別人が同じ名前を名乗りうる。Zone は先着優先で衝突を拒否し、
// ここでは pkg/meshname による構文検証を通してから取り込む。信頼の根拠は名前ではなく
// 公開鍵の帯域外照合（SAS）である（要件 §4.6.3）。
func applyPeerAdvert(zone *meshname.Zone, store *viewStore, peerIP string, pi signaling.PeerInfo, display bool) {
	addr, err := netip.ParseAddr(peerIP)
	if err != nil {
		return
	}
	if len(pi.Names) == 0 {
		zone.Remove(addr)
	} else if err := zone.Replace(addr, pi.Names); err != nil {
		// 別ピアが先に使っている名前を含む等。名前解決は無効のままだがメッシュ疎通は続行する。
		slog.Warn("ピアの名前を取り込めませんでした", "peer_ip", peerIP, "err", err)
		return
	}
	if !display {
		return
	}

	list := make([]appstate.SharedService, 0, len(pi.Services))
	for _, s := range pi.Services {
		name, err := meshname.ValidateName(s.Name)
		if err != nil {
			continue
		}
		// Names に含まれない（＝このピアの IP へ解決しない）名前は表示しない。
		if a, ok := zone.Lookup(name); !ok || a != addr {
			continue
		}
		// 表示ラベルは相手の申告ではなく自前の既知ポート表から導出する。
		label, _ := localsvc.LabelFor(s.Port)
		list = append(list, appstate.SharedService{Port: s.Port, Label: label, Name: name, Addr: peerIP})
	}
	hostName := ""
	if len(pi.Names) > 0 {
		hostName = meshname.Normalize(pi.Names[0]) // 送信側 Advertise の先頭はピア自身の名前
	}
	store.update(func(m *appstate.Model) {
		m.SetMeshName(hostName)
		_ = m.SetShared(list)
	})
	if len(list) > 0 {
		slog.Info("共有サービスの広告を受信しました", "count", len(list), "host_name", hostName)
	}
}
