package main

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/appstate"
	"github.com/instantmesh/instantmesh/pkg/clientconf"
	"github.com/instantmesh/instantmesh/pkg/localsvc"
	"github.com/instantmesh/instantmesh/pkg/meshname"
	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/signalclient"
	"github.com/instantmesh/instantmesh/pkg/signaling"
)

func TestMeshHostLabel(t *testing.T) {
	if got := meshHostLabel("Tanaka Note"); got != "tanaka-note" {
		t.Errorf("指定ラベル = %q, want tanaka-note", got)
	}
	// 指定が LDH ラベルにならない場合は OS のホスト名から導出し、それも無理なら既定値。
	got := meshHostLabel("")
	if err := meshname.ValidateLabel(got); err != nil {
		t.Errorf("導出したラベル %q が不正: %v", got, err)
	}
	if h, err := os.Hostname(); err == nil {
		if want := meshname.Sanitize(h); want != "" && got != want {
			t.Errorf("ホスト名由来 = %q, want %q", got, want)
		}
	}
	if got := meshHostLabel("日本語のみ"); got == "" {
		t.Error("代替ラベルが空になった")
	}
	// 候補は優先順（-mesh-name > 保存済み設定）に評価し、使える最初のものを採る（付録C.9 D-14）。
	if got := meshHostLabel("", "saved-label"); got != "saved-label" {
		t.Errorf("保存済み設定 = %q, want saved-label", got)
	}
	if got := meshHostLabel("flag", "saved-label"); got != "flag" {
		t.Errorf("フラグ優先 = %q, want flag", got)
	}
}

// hostSession はホストのセッション相当（ゾーン・表示状態・フェイク接続）を組み立てる。
func hostSession(t *testing.T) (*meshname.Zone, *viewStore, *fakeConn, *signalclient.Client) {
	t.Helper()
	store := newViewStore()
	store.update(func(m *appstate.Model) {
		_ = m.StartHosting()
		_ = m.RoomCreated("room-1", "instantmesh://join?x=1", "SAS", "10.9.0.1")
	})
	fc := newFakeConn()
	return meshname.NewZone(), store, fc, signalclient.New(fc)
}

// TestShareControllerPublishes は共有ポートの選択が、ゾーン・表示状態・peer_info の 3 箇所へ
// 反映されることを確かめる（要件 §4.6.1 / §4.6.3）。
func TestShareControllerPublishes(t *testing.T) {
	zone, store, fc, cl := hostSession(t)
	c := newShareController("tanaka", nil, nil)

	// ルーム作成前の選択は保持だけされ、まだ配られない。
	if err := c.setPorts([]int{11434}); err != nil {
		t.Fatalf("setPorts: %v", err)
	}
	if len(zone.Entries()) != 0 || len(fc.sent()) != 0 {
		t.Error("ルーム作成前に配布された")
	}

	c.bind(shareSession{zone: zone, store: store, client: cl, pubKey: "hostPK", hostIP: "10.9.0.1", tier: "free"})

	// ゾーン: 自身の名前とサービス名が自分のメッシュIP へ解決する。
	host := netip.MustParseAddr("10.9.0.1")
	for _, name := range []string{"tanaka.mesh", "ollama.tanaka.mesh"} {
		if addr, ok := zone.Lookup(name); !ok || addr != host {
			t.Errorf("%s = %v, %v", name, addr, ok)
		}
	}
	// 表示状態: 共有中サービスと到達 URL。
	snap := store.snapshot()
	if snap.MeshName != "tanaka.mesh" {
		t.Errorf("MeshName = %q", snap.MeshName)
	}
	if len(snap.Shared) != 1 || snap.Shared[0].URL != "http://ollama.tanaka.mesh:11434" ||
		snap.Shared[0].MeshURL != "http://10.9.0.1:11434" || snap.Shared[0].Label != "Ollama" {
		t.Fatalf("Shared = %+v", snap.Shared)
	}
	// エンドポイント未確定の間は peer_info を送らない（WANEndpoint 必須のため）。
	if len(fc.sent()) != 0 {
		t.Errorf("エンドポイント未確定で送信した: %d 件", len(fc.sent()))
	}

	// エンドポイント確定後に共有を変えると、再広告が飛ぶ。
	c.setEndpoint("203.0.113.7:51820")
	if err := c.setPorts([]int{11434, 3000}); err != nil {
		t.Fatalf("setPorts: %v", err)
	}
	sent := fc.sent()
	if len(sent) != 1 {
		t.Fatalf("送信数 = %d, want 1", len(sent))
	}
	env, err := signaling.Decode(sent[0])
	if err != nil || env.Type != signaling.TypePeerInfo {
		t.Fatalf("envelope = %+v, err = %v", env, err)
	}
	var pi signaling.PeerInfo
	_ = env.Unmarshal(&pi)
	if pi.PubKey != "hostPK" || pi.WANEndpoint != "203.0.113.7:51820" {
		t.Errorf("peer_info = %+v", pi)
	}
	if len(pi.Names) != 3 || pi.Names[0] != "tanaka.mesh" {
		t.Errorf("names = %v", pi.Names)
	}
	if len(pi.Services) != 2 {
		t.Errorf("services = %+v", pi.Services)
	}
	if err := pi.Validate(); err != nil {
		t.Errorf("広告がスキーマ検証を通らない: %v", err)
	}

	// 共有を全て止めると、サービス名はゾーンから消える（自身の名前は残る）。
	if err := c.setPorts(nil); err != nil {
		t.Fatalf("setPorts(nil): %v", err)
	}
	if _, ok := zone.Lookup("ollama.tanaka.mesh"); ok {
		t.Error("共有停止後も名前が残っている")
	}
	if _, ok := zone.Lookup("tanaka.mesh"); !ok {
		t.Error("ホスト自身の名前まで消えた")
	}
	if len(store.snapshot().Shared) != 0 {
		t.Error("共有停止が表示へ反映されていない")
	}
}

func TestShareControllerRejectsInvalidPort(t *testing.T) {
	c := newShareController("tanaka", nil, nil)
	if err := c.setPorts([]int{0}); !errors.Is(err, localsvc.ErrInvalidPort) {
		t.Errorf("err = %v, want ErrInvalidPort", err)
	}
	// 不正な指定は一切反映しない。
	names, _ := c.advert()
	if len(names) != 1 {
		t.Errorf("names = %v, want ホスト名のみ", names)
	}
}

// TestShareControllerReset はセッション終了後の初期化で、セッション固有の状態（IP・接続・
// 発行済みキー）は捨てる一方、メッシュ名と共有の選択は持ち越すことを確かめる（付録C.9 D-14）。
func TestShareControllerReset(t *testing.T) {
	zone, store, fc, cl := hostSession(t)
	c := newShareController("tanaka", nil, nil)
	c.bind(shareSession{zone: zone, store: store, client: cl, pubKey: "hostPK", hostIP: "10.9.0.1", tier: "free"})
	c.setEndpoint("203.0.113.7:51820")
	if err := c.setPorts([]int{11434}); err != nil {
		t.Fatalf("setPorts: %v", err)
	}
	if _, err := c.issueKey("guestPK"); err == nil {
		t.Error("無料プランでキーが発行された")
	}
	sentBefore := len(fc.sent())

	c.reset()

	// 選択とラベルは残る（次のルーム作成で改めて貸し出される）。
	names, svcs := c.advert()
	if len(names) != 2 || len(svcs) != 1 || svcs[0].Port != 11434 {
		t.Errorf("reset 後: names = %v, services = %+v（選択は持ち越すべき）", names, svcs)
	}
	// セッション固有の状態は消えるため、publish は何も配らない（パニックもしない）。
	c.publish()
	if len(fc.sent()) != sentBefore {
		t.Error("reset 後に前セッションの接続へ送信した")
	}
	if c.keys.Len() != 0 {
		t.Error("発行済みキーが残っている")
	}
}

// TestShareControllerSetLabel は GUI からのメッシュ名変更（付録C.9 D-14）が、ゾーン・表示・
// 再広告へ反映され、ローカル設定へ保存されることを確かめる。
func TestShareControllerSetLabel(t *testing.T) {
	zone, store, fc, cl := hostSession(t)
	var saved []clientconf.Config
	c := newShareController("tanaka", []int{11434}, func(cf clientconf.Config) { saved = append(saved, cf) })
	c.bind(shareSession{zone: zone, store: store, client: cl, pubKey: "hostPK", hostIP: "10.9.0.1", tier: "free"})
	c.setEndpoint("203.0.113.7:51820")

	// 入力は LDH ラベルへ落として受け付ける。
	if err := c.setLabel("Tanaka Note"); err != nil {
		t.Fatalf("setLabel: %v", err)
	}
	host := netip.MustParseAddr("10.9.0.1")
	if addr, ok := zone.Lookup("ollama.tanaka-note.mesh"); !ok || addr != host {
		t.Errorf("新しい名前が解決しない: %v, %v", addr, ok)
	}
	// 旧名は解決しなくなる（Zone は当該アドレスの登録を置き換える）。
	if _, ok := zone.Lookup("ollama.tanaka.mesh"); ok {
		t.Error("旧名が残っている")
	}
	if snap := store.snapshot(); snap.MeshName != "tanaka-note.mesh" {
		t.Errorf("MeshName = %q", snap.MeshName)
	}
	if len(fc.sent()) == 0 {
		t.Error("名前の変更が再広告されていない")
	}
	if len(saved) != 1 || saved[0].MeshLabel != "tanaka-note" {
		t.Fatalf("保存内容 = %+v", saved)
	}
	// 復元した共有の選択も一緒に保存される（次回起動でも同じサービスを貸せる）。
	if len(saved[0].SharedPorts) != 1 || saved[0].SharedPorts[0] != 11434 {
		t.Errorf("保存された共有の選択 = %v", saved[0].SharedPorts)
	}

	// ラベルにならない入力は拒否し、現在の名前を変えない。
	for _, bad := range []string{"", "日本語のみ", "---"} {
		if err := c.setLabel(bad); !errors.Is(err, errInvalidMeshLabel) {
			t.Errorf("setLabel(%q) = %v, want errInvalidMeshLabel", bad, err)
		}
	}
	if got := c.settings().MeshLabel; got != "tanaka-note" {
		t.Errorf("拒否後のラベル = %q", got)
	}
	if len(saved) != 1 {
		t.Errorf("拒否された変更が保存された: %+v", saved)
	}
}

// TestShareControllerConcurrentEdits は GUI の操作（名前の変更・共有の更新・設定の閲覧）が
// 並行しても状態が壊れないことを確かめる。排他の検証は CI の `-race` が担う。
func TestShareControllerConcurrentEdits(t *testing.T) {
	zone, store, _, cl := hostSession(t)
	c := newShareController("tanaka", nil, func(clientconf.Config) {})
	c.bind(shareSession{zone: zone, store: store, client: cl, pubKey: "hostPK", hostIP: "10.9.0.1", tier: string(plan.Pro)})

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(3)
		go func(n int) { defer wg.Done(); _ = c.setLabel(fmt.Sprintf("host-%d", n)) }(i)
		go func() { defer wg.Done(); _ = c.setPorts([]int{11434}) }()
		go func() { defer wg.Done(); _ = c.settings() }()
	}
	wg.Wait()

	// どの名前で決着するかは競合次第だが、publish は直列化されるため最後の適用は直近の状態に
	// なる。ゾーンには自分のメッシュIP 向けの登録だけが残り、決着した名前が引ける。
	host := netip.MustParseAddr("10.9.0.1")
	entries := zone.Entries()
	if len(entries) == 0 {
		t.Fatal("ゾーンが空になった")
	}
	for _, e := range entries {
		if e.Addr != host {
			t.Errorf("%s = %v, want %v", e.Name, e.Addr, host)
		}
	}
	got := c.settings()
	if addr, ok := zone.Lookup(got.MeshName); !ok || addr != host {
		t.Errorf("決着した名前 %q がゾーンと不整合: %v, %v", got.MeshName, addr, ok)
	}
}

// TestShareControllerSettings は GUI へ返す設定ビューの内容を確かめる（保存無効時は persisted=false）。
func TestShareControllerSettings(t *testing.T) {
	c := newShareController("tanaka", []int{11434, 3000}, nil)
	got := c.settings()
	if got.MeshLabel != "tanaka" || got.MeshName != "tanaka.mesh" || got.Persisted {
		t.Errorf("settings = %+v", got)
	}
	if len(got.Ports) != 2 || got.Ports[0] != 11434 {
		t.Errorf("Ports = %v", got.Ports)
	}
	// 選択が無い場合も null ではなく空配列（JSON の扱いを揃える）。
	if ports := newShareController("tanaka", nil, nil).settings().Ports; ports == nil {
		t.Error("Ports が null になっている")
	}
	// 保存関数が無ければ persist は何もしない（パニックしない）。
	c.persist()
}

// TestApplyPeerAdvertGuest はホストの広告をゲストが取り込む経路を確かめる（要件 §4.6.3）。
func TestApplyPeerAdvertGuest(t *testing.T) {
	store := newViewStore()
	store.update(func(m *appstate.Model) {
		_ = m.StartJoining("instantmesh://join?server=ws%3A%2F%2Flocalhost%3A8080%2Fws&token=tok&host=hostpk", "alice")
		_ = m.MarkRequested()
		_ = m.Approved("10.9.0.2", "10.9.0.1")
	})
	zone := meshname.NewZone()
	pi := signaling.PeerInfo{
		PubKey:      "hostpk",
		WANEndpoint: "203.0.113.7:51820",
		Names:       []string{"tanaka.mesh", "ollama.tanaka.mesh"},
		Services: []signaling.SharedService{
			{Name: "ollama.tanaka.mesh", Port: 11434},
			{Name: "notadvertised.tanaka.mesh", Port: 9999}, // Names に無い → 表示しない
			{Name: "bad_name.mesh", Port: 8080},             // 構文不正 → 無視
		},
	}
	applyPeerAdvert(zone, store, "10.9.0.1", pi, true, nil)

	if addr, ok := zone.Lookup("ollama.tanaka.mesh"); !ok || addr != netip.MustParseAddr("10.9.0.1") {
		t.Errorf("ゾーン = %v, %v", addr, ok)
	}
	snap := store.snapshot()
	if snap.MeshName != "tanaka.mesh" {
		t.Errorf("MeshName = %q", snap.MeshName)
	}
	if len(snap.Shared) != 1 || snap.Shared[0].URL != "http://ollama.tanaka.mesh:11434" {
		t.Fatalf("Shared = %+v", snap.Shared)
	}
	// 表示ラベルは相手の申告ではなく自前の既知ポート表から導出する。
	if snap.Shared[0].Label != "Ollama" {
		t.Errorf("Label = %q, want Ollama", snap.Shared[0].Label)
	}

	// 名前を空にした再広告は登録を取り消す。
	applyPeerAdvert(zone, store, "10.9.0.1", signaling.PeerInfo{PubKey: "hostpk", WANEndpoint: "x"}, true, nil)
	if _, ok := zone.Lookup("ollama.tanaka.mesh"); ok {
		t.Error("再広告で登録が消えていない")
	}
}

// TestApplyPeerAdvertRejects は不正な入力で状態を壊さないことを確かめる。
func TestApplyPeerAdvertRejects(t *testing.T) {
	zone := meshname.NewZone()
	store := newViewStore()

	// メッシュIP が不正なら何もしない。
	applyPeerAdvert(zone, store, "not-an-ip", signaling.PeerInfo{Names: []string{"a.mesh"}}, true, nil)
	if len(zone.Entries()) != 0 {
		t.Error("不正なIPで登録された")
	}
	// ゾーン外の名前は取り込まない。
	applyPeerAdvert(zone, store, "10.9.0.1", signaling.PeerInfo{Names: []string{"evil.example.com"}}, true, nil)
	if len(zone.Entries()) != 0 {
		t.Error("ゾーン外の名前が登録された")
	}
	// 別ピアが先に使っている名前は奪えない（先着優先）。
	first := netip.MustParseAddr("10.9.0.1")
	if err := zone.Replace(first, []string{"tanaka.mesh"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	applyPeerAdvert(zone, store, "10.9.0.3", signaling.PeerInfo{Names: []string{"tanaka.mesh"}}, false, nil)
	if addr, _ := zone.Lookup("tanaka.mesh"); addr != first {
		t.Errorf("名前が乗っ取られた: %v", addr)
	}
}

// TestShareControllerPlanLimit はプランの同時共有サービス数（§5・付録C.9 D-15）を守ることを確かめる。
func TestShareControllerPlanLimit(t *testing.T) {
	zone, store, _, cl := hostSession(t)
	c := newShareController("tanaka", nil, nil)
	c.bind(shareSession{zone: zone, store: store, client: cl, pubKey: "hostPK", hostIP: "10.9.0.1", tier: string(plan.Free)})

	free := plan.MustLookup(plan.Free).MaxSharedServices
	over := make([]int, free+1)
	for i := range over {
		over[i] = 20000 + i
	}
	if err := c.setPorts(over); !errors.Is(err, errShareLimit) {
		t.Errorf("err = %v, want errShareLimit", err)
	}
	if _, svcs := c.advert(); len(svcs) != 0 {
		t.Errorf("上限超過の選択が反映された: %+v", svcs)
	}
	if err := c.setPorts(over[:free]); err != nil {
		t.Errorf("上限ちょうどは通るべき: %v", err)
	}

	// Pro はより多く貸せる。プラン不明（空文字）は無料プランへフェイルセーフ。
	pro := newShareController("tanaka", nil, nil)
	pro.bind(shareSession{zone: meshname.NewZone(), store: newViewStore(), client: cl, pubKey: "hostPK", hostIP: "10.9.0.1", tier: string(plan.Pro)})
	if err := pro.setPorts(over); err != nil {
		t.Errorf("Pro で %d 件が拒否された: %v", len(over), err)
	}
	unknown := newShareController("tanaka", nil, nil)
	unknown.bind(shareSession{zone: meshname.NewZone(), store: newViewStore(), client: cl, pubKey: "hostPK", hostIP: "10.9.0.1", tier: ""})
	if err := unknown.setPorts(over); !errors.Is(err, errShareLimit) {
		t.Errorf("プラン不明は無料プラン扱いにすべき: %v", err)
	}
}

// TestShareControllerTruncatesOnBind はプラン確定時に、選択済みの超過分を決定的に切り詰めることを
// 確かめる（上位プランで選んだあと無料プランのルームを作った場合など）。
func TestShareControllerTruncatesOnBind(t *testing.T) {
	c := newShareController("tanaka", nil, nil)
	free := plan.MustLookup(plan.Free).MaxSharedServices
	ports := make([]int, free+2)
	for i := range ports {
		ports[i] = 20000 + i
	}

	// まず Pro のセッションで上限より多く選ぶ。
	c.bind(shareSession{zone: meshname.NewZone(), store: newViewStore(), client: nil, pubKey: "hostPK", hostIP: "10.9.0.1", tier: string(plan.Pro)})
	if err := c.setPorts(ports); err != nil {
		t.Fatalf("setPorts: %v", err)
	}
	// 次のセッションが無料プランなら、貸すのは先頭から上限までに絞られる。
	c.bind(shareSession{zone: meshname.NewZone(), store: newViewStore(), client: nil, pubKey: "hostPK", hostIP: "10.9.0.1", tier: string(plan.Free)})
	_, svcs := c.advert()
	if len(svcs) != free {
		t.Fatalf("共有数 = %d, want %d", len(svcs), free)
	}
	for i, sv := range svcs {
		if sv.Port != ports[i] {
			t.Errorf("svcs[%d].Port = %d, want %d（切り詰めは決定的であるべき）", i, sv.Port, ports[i])
		}
	}
	// 選択そのものは保持しているため、再び Pro のセッションになれば全件戻る（保存済みの選択を
	// 無料プランのセッション 1 回で失わせない・付録C.9 D-14）。
	if got := c.settings().Ports; len(got) != len(ports) {
		t.Errorf("保持している選択 = %v, want %d 件", got, len(ports))
	}
	c.bind(shareSession{zone: meshname.NewZone(), store: newViewStore(), client: nil, pubKey: "hostPK", hostIP: "10.9.0.1", tier: string(plan.Pro)})
	if _, svcs := c.advert(); len(svcs) != len(ports) {
		t.Errorf("Pro での共有数 = %d, want %d", len(svcs), len(ports))
	}
}
