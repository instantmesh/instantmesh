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
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/instantmesh/instantmesh/pkg/accesskey"
	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/clientconf"
	"github.com/instantmesh/instantmesh/pkg/localsvc"
	"github.com/instantmesh/instantmesh/pkg/meshname"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
	"github.com/instantmesh/instantmesh/pkg/signaling"
	"github.com/instantmesh/instantmesh/pkg/usage"
)

// defaultMeshLabel は OS のホスト名からラベルを導出できなかった場合の代替。
const defaultMeshLabel = "host"

// errShareLimit はプランの同時共有サービス数（pkg/plan の MaxSharedServices・要件 §5）を超えた
// 選択を表す。UI はこれを利用者向けの案内に写す。
var errShareLimit = errors.New("sharing: plan limit for concurrent shared services")

// errControlPlan は統制機能（アクセスキー・ゲスト単位上限）が現在のプランで使えないことを表す。
var errControlPlan = errors.New("sharing: control features require the paid plan")

// errControlUnavailable は仮想NIC が無く統制を適用できないことを表す（-tunnel 無効時）。
var errControlUnavailable = errors.New("sharing: control features require the tunnel")

// errInvalidMeshLabel はメッシュ名ラベルとして使えない入力（英数字を含まない等）を表す。
var errInvalidMeshLabel = errors.New("sharing: invalid mesh name label")

// meshHostLabel はメッシュ名に使うラベルを決める。候補を優先順に受け取り、LDH ラベルへ落とせた
// 最初のものを採る（呼び出し側の順序は -mesh-name 指定 > 保存済み設定）。いずれも使えなければ
// OS のホスト名、それも無理なら "host"。
//
// 名前はセッションをまたいで安定していることに価値がある（ゲストの .env や手順書に書ける・
// 要件 §4.6.2）。だからこそ保存済み設定を候補に含め（付録C.9 D-14）、既定値も実行のたびに
// 変わらない OS のホスト名から導出する。
func meshHostLabel(candidates ...string) string {
	for _, c := range candidates {
		if l := meshname.Sanitize(c); l != "" {
			return l
		}
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

	// pubMu は publish（状態の取得 → ゾーン・転送・到達制御・再広告への適用）を直列化する。
	// 取得と適用を分けると、並行操作で古い内容が新しい内容を上書きしうる（外れたポートの待受が
	// 残る・古い名前が配られる）。mu より先に取ること（この順序以外で両方を取らない）。
	pubMu sync.Mutex

	mu       sync.Mutex
	ports    []int
	maxPorts int                  // 同時共有サービス数の上限（プラン由来・ルーム作成時に確定）
	usageOK  bool                 // 利用記録を閲覧できるプランか（§5・有料機能）
	keysOK   bool                 // ゲストごとのアクセスキーを使えるプランか（同上）
	limitsOK bool                 // ゲスト単位の上限を設定できるプランか（同上）
	reqKey   bool                 // 共有サービスへアクセスキーを要求する（ホストの明示操作）
	keys     *accesskey.Registry  // 発行済みキー（メモリ内のみ・設計原則3）
	addr     netip.Addr           // 自身のメッシュIP（ルーム作成後に確定）
	endpoint string               // STUN で発見した WAN エンドポイント（peer_info 再送に使う）
	client   *signalclient.Client // 再広告の送出先（セッション確立後に確定）
	pubKey   string
	zone     *meshname.Zone
	store    *viewStore
	fwd      *serviceForwarder
	tun      *Tunnel

	// save はメッシュ名ラベルと共有の選択をローカル設定へ書き出す関数（付録C.9 D-14）。
	// nil なら保存しない（`-config=` で無効化した場合・ヘッドレス運用）。秘密は渡さない。
	save func(clientconf.Config)
}

// newShareController は指定ラベルの共有コントローラを返す。セッション開始前に生成してよく、
// セッション固有の依存（ゾーン・表示状態・接続・プラン）は bind で与える。
// ルーム作成前は上限を無料プランの値に置く（プランはルーム作成時にサーバーが確定させるため）。
//
// ports は保存済み設定から復元した共有の選択（付録C.9 D-14。無ければ nil）。save は設定の
// 保存関数（nil なら保存しない）。復元した選択が実際に貸し出されるのはルーム作成後（bind →
// publish）で、その時点のプラン上限までが対象になる（超過分は選択として保持されるだけ）。
func newShareController(label string, ports []int, save func(clientconf.Config)) *shareController {
	return &shareController{
		label:    label,
		ports:    append([]int(nil), ports...),
		maxPorts: plan.MustLookup(plan.Free).MaxSharedServices,
		keys:     accesskey.New(),
		save:     save,
	}
}

// shareSession はセッション確立時に共有コントローラへ与える依存一式。
type shareSession struct {
	zone   *meshname.Zone
	store  *viewStore
	client *signalclient.Client
	fwd    *serviceForwarder // 共有サービスへの転送（nil 可＝-tunnel 無効時）
	tun    *Tunnel           // 到達制御（共有していない宛先を落とす）の適用先（nil 可）
	pubKey string
	hostIP string
	tier   string // サーバーが確定させたプラン（空ならフェイルセーフに無料プラン）
}

// bind はセッション確立時（ルーム作成完了）に依存と自身のメッシュIP を与え、現在の共有内容を
// 反映する。前セッションの残り（IP・接続）は上書きされる。
func (c *shareController) bind(sess shareSession) {
	zone, store, client, pubKey, hostIP, tier := sess.zone, sess.store, sess.client, sess.pubKey, sess.hostIP, sess.tier
	addr, err := netip.ParseAddr(hostIP)
	if err != nil {
		slog.Warn("ホストのメッシュIP を解釈できず共有の名前配布を見送ります", "host_ip", hostIP, "err", err)
		return
	}
	// プラン未指定（Tier 省略）はフェイルセーフに無料プランとして扱う。
	spec, ok := plan.Lookup(plan.Tier(tier))
	if !ok {
		spec = plan.MustLookup(plan.Free)
	}
	c.mu.Lock()
	c.zone, c.store, c.client, c.pubKey, c.addr = zone, store, client, pubKey, addr
	c.fwd, c.tun = sess.fwd, sess.tun
	c.maxPorts = spec.MaxSharedServices
	c.usageOK, c.keysOK, c.limitsOK = spec.UsageRecords, spec.AccessKeys, spec.GuestLimits
	if !c.keysOK {
		c.reqKey = false // プランが下がったらキー要求も落とす（フェイルセーフ）
	}
	selected := len(c.ports)
	c.mu.Unlock()
	// 選択がプランの同時共有サービス数を超える場合、実際に貸すのは先頭から上限までになる
	// （切り詰めは advert が決定的に行う）。選択そのものは保持し、上位プランのセッションでは元へ戻る
	// ——保存済みの選択（付録C.9 D-14）を無料プランのセッション 1 回で恒久的に失わせないため。
	if selected > spec.MaxSharedServices {
		slog.Warn("プランの同時共有サービス数を超えるため一部の共有を見送ります（選択は保持します）",
			"tier", spec.Tier, "max", spec.MaxSharedServices, "selected", selected)
	}
	c.publish()
}

// reset はセッション終了後に共有状態を初期化する（GUI がプロセス常駐のまま次のセッションを
// 始めるため、前セッションの IP・接続・発行済みキー・プランを引きずらない）。
//
// メッシュ名ラベルと共有するポートの選択は**持ち越す**（付録C.9 D-14）。ゲストは
// `http://ollama.tanaka.mesh:11434` を手順書へ書くため、セッションをまたいで名前と貸し出し内容が
// 安定していることに価値がある（要件 §4.6.2）。実際に貸し出されるのは次のルーム作成後
// （bind → publish）で、その時点のプラン上限までが対象になる。
func (c *shareController) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.addr, c.endpoint, c.client, c.pubKey, c.zone, c.store, c.fwd, c.tun = netip.Addr{}, "", nil, "", nil, nil, nil, nil
	free := plan.MustLookup(plan.Free)
	c.maxPorts, c.usageOK, c.keysOK, c.limitsOK = free.MaxSharedServices, free.UsageRecords, free.AccessKeys, free.GuestLimits
	c.reqKey = false
	c.keys.Reset()
}

// setPorts は共有するポート集合を設定し、名前配布と表示へ反映する。共有の実行はホストの明示的な
// 選択によるという要件（§4.6.1）に対応する唯一の入口。ポートや名前が不正なら何も変更しない。
func (c *shareController) setPorts(ports []int) error {
	c.mu.Lock()
	// 反映前に妥当性を確認する（範囲外ポート・名前数の上限超過をここで弾く）。ラベルは setLabel と
	// 同時に触られうるためロック下で読む（検証と反映を同じ臨界区間に収める）。
	if _, _, err := localsvc.Advertise(c.label, ports); err != nil {
		c.mu.Unlock()
		return err
	}
	if len(ports) > c.maxPorts {
		limit := c.maxPorts
		c.mu.Unlock()
		return fmt.Errorf("同時に共有できるサービスは %d 件までです（選択 %d 件）: %w", limit, len(ports), errShareLimit)
	}
	c.ports = append([]int(nil), ports...)
	c.mu.Unlock()
	c.publish()
	c.persist() // 次回起動でも同じサービスを貸せるようにする（付録C.9 D-14）
	return nil
}

// setLabel はメッシュ名に使うホストラベルを変更する（GUI の「名前を保存」・付録C.9 D-14）。
// 入力は meshname.Sanitize で LDH ラベルへ落とすため "Tanaka Note" → "tanaka-note" のように
// 受け付けるが、ラベルとして成立しない入力（英数字を含まない等）は errInvalidMeshLabel で拒む。
//
// セッション中の変更も許す。ゾーン・表示・広告へ即座に反映され、以前の名前は解決しなくなる
// （ゲストへ配った URL は貼り替えが必要）。名前は自己申告であり信頼の根拠ではないため
// （§4.6.3）、変更に承認は要らない。
func (c *shareController) setLabel(label string) error {
	l := meshname.Sanitize(label)
	if err := meshname.ValidateLabel(l); err != nil {
		return fmt.Errorf("メッシュ名 %q は使えません（英小文字・数字・ハイフン）: %w", label, errInvalidMeshLabel)
	}
	c.mu.Lock()
	c.label = l
	c.mu.Unlock()
	c.publish()
	c.persist()
	return nil
}

// persist は現在の表示設定（メッシュ名ラベルと共有の選択）をローカル設定へ書き出す。
// 保存関数が無ければ何もしない。渡すのは pkg/clientconf.Config だけであり、秘密鍵・招待トークン・
// アクセスキーは構造上ここへ載らない（設計原則3）。
func (c *shareController) persist() {
	c.mu.Lock()
	save, conf := c.save, clientconf.Config{MeshLabel: c.label, SharedPorts: append([]int(nil), c.ports...)}
	c.mu.Unlock()
	if save == nil {
		return
	}
	save(conf)
}

// settingsView はローカル設定の表示状態（GUI 向け）。秘密は含まない。
type settingsView struct {
	MeshLabel string `json:"meshLabel"` // メッシュ名に使うホストラベル（例 "tanaka"）
	MeshName  string `json:"meshName"`  // 組み上がったホスト名（例 "tanaka.mesh"）
	Ports     []int  `json:"ports"`     // 共有するポートの選択（保存対象）
	Persisted bool   `json:"persisted"` // 設定がこの端末へ保存されるか（-config で無効化できる）
}

// settings は現在のローカル設定を返す（GUI の GET /api/config）。
func (c *shareController) settings() settingsView {
	c.mu.Lock()
	label, ports, save := c.label, append([]int{}, c.ports...), c.save
	c.mu.Unlock()
	name, _ := meshname.FQDN(label) // ラベルは常に検証済みのため失敗しない（失敗時は空表示）
	return settingsView{MeshLabel: label, MeshName: name, Ports: ports, Persisted: save != nil}
}

// usageRecords は共有サービスの利用記録（要件 §4.7）を返す。閲覧できないプラン、または
// 記録器が無い（-tunnel 無効）場合は ok=false。
//
// 計上はプランに関わらずホスト側クライアントで行い（設計原則2 によりサーバーでは計上できない）、
// 閲覧の可否だけをプランで分ける。
func (c *shareController) usageRecords() ([]usage.Record, bool) {
	c.mu.Lock()
	visible, tunl := c.usageOK, c.tun
	c.mu.Unlock()
	if !visible || tunl == nil {
		return nil, false
	}
	return tunl.Usage().Snapshot(), true
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
	// プラン上限を超える選択は先頭から上限までを貸す（順序は Candidates と同じ規則で決まるため
	// 超過分の切り捨ても決定的）。選択自体は減らさない（bind のコメント参照）。
	if len(ports) > c.maxPorts {
		ports = ports[:c.maxPorts]
	}
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

// publish は現在の共有内容を Zone・転送・到達制御・表示状態・ピアへ反映する。ルーム作成前
// （addr 未確定）は何もしない（bind 時に改めて反映される）。
//
// pubMu で直列化するため、GUI の操作が並行しても適用の順序は入れ替わらない。最後に走る publish は
// 直近の状態（ラベル・選択）を取ってから適用するので、外れたポートの待受が残ることはない。
func (c *shareController) publish() {
	c.pubMu.Lock()
	defer c.pubMu.Unlock()
	c.mu.Lock()
	addr, zone, store, client, pubKey, endpoint, fwd, tunl := c.addr, c.zone, c.store, c.client, c.pubKey, c.endpoint, c.fwd, c.tun
	gate := c.gateLocked()
	c.mu.Unlock()
	if !addr.IsValid() {
		return
	}

	names, svcs := c.advert()
	// 共有中サービスへの転送を差分適用する。127.0.0.1 バインドのサービスへゲストが到達できる
	// ようにするための必須部品で（付録C.9 D-10）、共有から外れたポートは直ちに解放される。
	ports := make([]int, 0, len(svcs))
	for _, sv := range svcs {
		ports = append(ports, sv.Port)
	}
	fwd.setGate(gate)
	fwd.apply(ports)
	// 到達制御へも同じ集合を反映する。選ばれていないポートへの新規接続はここで落ちる（D-11）。
	if tunl != nil {
		tunl.SetSharedPorts(addr, ports)
	}
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

// gateLocked は現在の設定に応じた L7 ゲートを返す（呼び出し側でロック済みであること）。
// キーを要求しない場合でも、上限が設定されていれば HTTP で数えるためゲートを立てる。
// 到達制御（L4）のみで足りる場合は nil を返し、生 TCP 転送のままにする。
func (c *shareController) gateLocked() *l7Gate {
	if c.tun == nil || (!c.reqKey && !c.limitsOK) {
		return nil
	}
	if !c.reqKey && !c.hasLimitsLocked() {
		return nil
	}
	return &l7Gate{keys: c.keys, rec: c.tun.Usage(), now: time.Now, requireKey: c.reqKey}
}

// hasLimitsLocked はいずれかのゲストに上限が設定されているかを返す。
func (c *shareController) hasLimitsLocked() bool {
	if c.tun == nil || c.store == nil {
		return false
	}
	for _, g := range c.store.snapshot().Guests {
		if addr, err := netip.ParseAddr(g.AssignedIP); err == nil {
			if l := c.tun.Usage().LimitFor(addr); l.MaxBytes > 0 || l.MaxRequests > 0 {
				return true
			}
		}
	}
	return false
}

// setRequireKey は共有サービスへアクセスキーを要求するかを切り替える（有料プラン機能）。
func (c *shareController) setRequireKey(on bool) error {
	c.mu.Lock()
	if on && !c.keysOK {
		c.mu.Unlock()
		return errControlPlan
	}
	c.reqKey = on
	c.mu.Unlock()
	c.publish() // 待受を張り替える（生 TCP 転送 ⇄ HTTP プロキシ）
	return nil
}

// issueKey はゲストへアクセスキーを発行する（再発行なら旧キーは即時失効）。
func (c *shareController) issueKey(guest string) (string, error) {
	c.mu.Lock()
	ok, keys := c.keysOK, c.keys
	c.mu.Unlock()
	if !ok {
		return "", errControlPlan
	}
	return keys.Issue(guest)
}

// revokeKey はゲストのアクセスキーを失効させる（キックとは独立）。
func (c *shareController) revokeKey(guest string) { c.keys.Revoke(guest) }

// setGuestLimit はゲスト単位の上限を設定する（有料プラン機能）。guestIP は当該ゲストのメッシュIP。
func (c *shareController) setGuestLimit(guestIP string, l usage.Limit) error {
	addr, err := netip.ParseAddr(guestIP)
	if err != nil {
		return fmt.Errorf("ゲストのメッシュIP %q: %w", guestIP, err)
	}
	c.mu.Lock()
	ok, tunl := c.limitsOK, c.tun
	c.mu.Unlock()
	if !ok {
		return errControlPlan
	}
	if tunl == nil {
		return errControlUnavailable
	}
	tunl.Usage().SetLimit(addr, l)
	c.publish() // 上限が付いたら L7 で数える必要があるため待受を見直す
	return nil
}

// controlView は統制の表示状態（GUI 向け）。
type controlView struct {
	Available  bool              `json:"available"`  // 有料プランで統制機能を使えるか
	RequireKey bool              `json:"requireKey"` // アクセスキーを要求中か
	Keys       map[string]string `json:"keys"`       // ゲスト公開鍵 → 発行済みキー
}

// control は統制の現在値を返す。キーはホストが帯域外でゲストへ渡すため、そのまま載せる
// （LocalAPI は 127.0.0.1 限定＋originguard 保護下）。
func (c *shareController) control() controlView {
	c.mu.Lock()
	available, reqKey, keys := c.keysOK, c.reqKey, c.keys
	c.mu.Unlock()
	m := make(map[string]string)
	for _, g := range keys.Guests() {
		if k, ok := keys.KeyFor(g); ok {
			m[g] = k
		}
	}
	return controlView{Available: available, RequireKey: reqKey, Keys: m}
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
