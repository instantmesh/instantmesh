package main

import (
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/connmon"
	"github.com/instantmesh/instantmesh/pkg/wgconf"
)

// testBuild はエンドポイントをそのまま載せた最小のピア設定を返す（allowed_ip 検証は本テストの関心外）。
func testBuild(ep string) (wgconf.Config, error) {
	return wgconf.Config{Peers: []wgconf.Peer{{PublicKey: "k", Endpoint: ep}}}, nil
}

// newTestMonitor は run() を使わず tick/track を直接叩けるモニタと、注入した副作用の参照を返す。
func newTestMonitor(cfg connmon.Config, clock *time.Time, hs *time.Time, dial relayDialFunc) (*connMonitor, *[]wgconf.Config) {
	var applied []wgconf.Config
	m := &connMonitor{
		handshake:  func(string) time.Time { return *hs },
		apply:      func(c wgconf.Config) error { applied = append(applied, c); return nil },
		listenPort: 51820,
		dial:       dial,
		cfg:        cfg,
		now:        func() time.Time { return *clock },
		cmds:       make(chan func(), 16),
		peers:      make(map[string]*peerConn),
	}
	return m, &applied
}

func baseConfig() connmon.Config {
	return connmon.Config{ProbeTimeout: 8 * time.Second, AliveTimeout: 180 * time.Second}
}

func TestConnMonitorFallsBackToRelay(t *testing.T) {
	clock := time.Unix(1000, 0)
	hs := time.Time{} // 直通ハンドシェイク成立せず
	ft := newFakeRelayTransport()
	dialCount := 0
	dial := func(func(string, []byte)) (relayTransport, error) { dialCount++; return ft, nil }
	m, applied := newTestMonitor(baseConfig(), &clock, &hs, dial)
	m.track("peerX", "aa", "203.0.113.5:41641", testBuild)
	defer func() {
		if m.proxy != nil {
			_ = m.proxy.Close()
		}
	}()

	// ProbeTimeout 未満: 直通のまま、切替なし。
	m.tick(clock.Add(3 * time.Second))
	if len(*applied) != 0 {
		t.Fatalf("転落前に適用が発生: %d", len(*applied))
	}

	// ProbeTimeout 経過: リレーへ転落し、ループバックエンドポイントで再適用。
	m.tick(clock.Add(8 * time.Second))
	if len(*applied) != 1 {
		t.Fatalf("リレー適用が起きない: %d", len(*applied))
	}
	ep := (*applied)[0].Peers[0].Endpoint
	if !strings.HasPrefix(ep, "127.0.0.1:") {
		t.Errorf("リレーエンドポイントはループバックであるべき: %q", ep)
	}
	if dialCount != 1 {
		t.Errorf("リレーダイヤルは 1 回であるべき: %d", dialCount)
	}
	if m.peers["peerX"].applied != connmon.RouteRelay {
		t.Errorf("applied = %v want Relay", m.peers["peerX"].applied)
	}
}

func TestConnMonitorStaysDirectOnHandshake(t *testing.T) {
	clock := time.Unix(1000, 0)
	hs := time.Time{}
	dial := func(func(string, []byte)) (relayTransport, error) {
		t.Error("直通確立時にリレーダイヤルは不要")
		return nil, errors.New("unexpected")
	}
	m, applied := newTestMonitor(baseConfig(), &clock, &hs, dial)
	m.track("peerX", "aa", "1.2.3.4:5", testBuild)

	// プローブ開始後にハンドシェイク成立 → Direct 維持（経路不変・切替なし）。
	hs = clock.Add(2 * time.Second)
	m.tick(clock.Add(3 * time.Second))
	if len(*applied) != 0 {
		t.Fatalf("直通確立時に切替は不要: %d", len(*applied))
	}
	if m.peers["peerX"].tracker.State() != connmon.Direct {
		t.Errorf("state = %v want Direct", m.peers["peerX"].tracker.State())
	}
}

func TestConnMonitorRelayThenRetryDirect(t *testing.T) {
	cfg := baseConfig()
	cfg.RetryInterval = 30 * time.Second
	clock := time.Unix(1000, 0)
	hs := time.Time{}
	ft := newFakeRelayTransport()
	dial := func(func(string, []byte)) (relayTransport, error) { return ft, nil }
	m, applied := newTestMonitor(cfg, &clock, &hs, dial)
	m.track("peerX", "aa", "1.2.3.4:5", testBuild)
	defer func() { _ = m.proxy.Close() }()

	// 転落（リレー適用）。
	m.tick(clock.Add(8 * time.Second))
	if got := (*applied)[len(*applied)-1].Peers[0].Endpoint; !strings.HasPrefix(got, "127.0.0.1:") {
		t.Fatalf("リレー転落時はループバック: %q", got)
	}

	// RetryInterval 経過で直通へ戻す（directEP を再適用）。
	m.tick(clock.Add(38 * time.Second))
	last := (*applied)[len(*applied)-1].Peers[0].Endpoint
	if last != "1.2.3.4:5" {
		t.Errorf("再試行で直通エンドポイントへ戻すべき: %q", last)
	}
	if m.peers["peerX"].applied != connmon.RouteDirect {
		t.Errorf("applied = %v want Direct", m.peers["peerX"].applied)
	}
}

func TestConnMonitorRelayDialFailureRetries(t *testing.T) {
	clock := time.Unix(1000, 0)
	hs := time.Time{}
	ft := newFakeRelayTransport()
	failing := true
	dial := func(func(string, []byte)) (relayTransport, error) {
		if failing {
			return nil, errors.New("relay down")
		}
		return ft, nil
	}
	m, applied := newTestMonitor(baseConfig(), &clock, &hs, dial)
	m.track("peerX", "aa", "1.2.3.4:5", testBuild)
	defer func() {
		if m.proxy != nil {
			_ = m.proxy.Close()
		}
	}()

	// リレーダイヤル失敗 → 切替せず applied は Direct のまま。
	m.tick(clock.Add(8 * time.Second))
	if len(*applied) != 0 {
		t.Fatalf("ダイヤル失敗時は適用しない: %d", len(*applied))
	}
	if m.peers["peerX"].applied != connmon.RouteDirect {
		t.Errorf("失敗時 applied = %v want Direct", m.peers["peerX"].applied)
	}

	// 次 tick でリレー回復 → 適用される（自己回復）。
	failing = false
	m.tick(clock.Add(9 * time.Second))
	if len(*applied) != 1 {
		t.Fatalf("回復後にリレー適用されるべき: %d", len(*applied))
	}
}

func TestConnMonitorBuildErrorSkipsApply(t *testing.T) {
	clock := time.Unix(1000, 0)
	hs := time.Time{}
	ft := newFakeRelayTransport()
	dial := func(func(string, []byte)) (relayTransport, error) { return ft, nil }
	m, applied := newTestMonitor(baseConfig(), &clock, &hs, dial)
	buildErr := func(string) (wgconf.Config, error) { return wgconf.Config{}, errors.New("build failed") }
	m.track("peerX", "aa", "1.2.3.4:5", buildErr)
	defer func() {
		if m.proxy != nil {
			_ = m.proxy.Close()
		}
	}()

	m.tick(clock.Add(8 * time.Second))
	if len(*applied) != 0 {
		t.Fatalf("build 失敗時は適用しない: %d", len(*applied))
	}
	if m.peers["peerX"].applied != connmon.RouteDirect {
		t.Error("build 失敗時 applied は Direct のまま")
	}
}

func TestConnMonitorApplyErrorSkips(t *testing.T) {
	clock := time.Unix(1000, 0)
	hs := time.Time{}
	ft := newFakeRelayTransport()
	dial := func(func(string, []byte)) (relayTransport, error) { return ft, nil }
	m, _ := newTestMonitor(baseConfig(), &clock, &hs, dial)
	m.apply = func(wgconf.Config) error { return errors.New("apply failed") }
	m.track("peerX", "aa", "1.2.3.4:5", testBuild)
	defer func() {
		if m.proxy != nil {
			_ = m.proxy.Close()
		}
	}()

	m.tick(clock.Add(8 * time.Second))
	if m.peers["peerX"].applied != connmon.RouteDirect {
		t.Error("apply 失敗時 applied は Direct のまま（次 tick で再試行）")
	}
}

func TestConnMonitorTrackUpdateResetsTracker(t *testing.T) {
	clock := time.Unix(1000, 0)
	hs := time.Time{}
	m, _ := newTestMonitor(baseConfig(), &clock, &hs, nil)
	m.track("peerX", "aa", "1.1.1.1:1", testBuild)
	// 同ピアの再 track は directEP を更新し状態機械を初期化する（peer_info 再受信＝再 STUN）。
	m.track("peerX", "bb", "2.2.2.2:2", testBuild)
	pc := m.peers["peerX"]
	if pc.directEP != "2.2.2.2:2" || pc.pubKeyHex != "bb" {
		t.Errorf("再 track で更新されるべき: ep=%q hex=%q", pc.directEP, pc.pubKeyHex)
	}
	if pc.tracker.State() != connmon.Probing || pc.applied != connmon.RouteDirect {
		t.Error("再 track で状態機械は初期化されるべき")
	}
}

func TestConnMonitorTrackUntrackViaCommands(t *testing.T) {
	clock := time.Unix(1000, 0)
	hs := time.Time{}
	m, _ := newTestMonitor(baseConfig(), &clock, &hs, nil)

	m.Track("peerX", "aa", "1.2.3.4:5", testBuild)
	(<-m.cmds)() // キューされたコマンドを実行
	if _, ok := m.peers["peerX"]; !ok {
		t.Fatal("Track で登録されるべき")
	}

	m.Untrack("peerX")
	(<-m.cmds)()
	if _, ok := m.peers["peerX"]; ok {
		t.Fatal("Untrack で削除されるべき")
	}

	// nil モニタでも安全（no-op）。
	var nilM *connMonitor
	nilM.Track("x", "y", "z", testBuild)
	nilM.Untrack("x")
}

func TestPubKeyToHex(t *testing.T) {
	b64 := base64.StdEncoding.EncodeToString(make([]byte, 32))
	hexKey, err := pubKeyToHex(b64)
	if err != nil {
		t.Fatalf("pubKeyToHex: %v", err)
	}
	if hexKey != strings.Repeat("0", 64) {
		t.Errorf("hex = %q want 64 zeros", hexKey)
	}
	if _, err := pubKeyToHex("!!!not-base64!!!"); err == nil {
		t.Error("不正な base64 はエラーになるべき")
	}
}
