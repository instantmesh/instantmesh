package connmon

import (
	"testing"
	"time"
)

func testConfig() Config {
	return Config{
		ProbeTimeout:  8 * time.Second,
		AliveTimeout:  180 * time.Second,
		RetryInterval: 0,
	}
}

func TestNewStartsProbing(t *testing.T) {
	tr := New(testConfig(), time.Unix(0, 0))
	if tr.State() != Probing {
		t.Errorf("初期状態 = %v want Probing", tr.State())
	}
	if tr.Route() != RouteDirect {
		t.Errorf("初期経路 = %v want RouteDirect", tr.Route())
	}
}

func TestStateString(t *testing.T) {
	cases := map[State]string{Probing: "probing", Direct: "direct", Relay: "relay", State(99): "unknown"}
	for s, want := range cases {
		if got := s.String(); got != want {
			t.Errorf("State(%d).String() = %q want %q", int(s), got, want)
		}
	}
}

func TestProbingToDirect(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := New(testConfig(), t0)
	// プローブ開始より新しいハンドシェイクを観測 → Direct。経路は RouteDirect のままで変化なし。
	state, changed := tr.Step(t0.Add(3*time.Second), t0.Add(2*time.Second))
	if state != Direct {
		t.Fatalf("state = %v want Direct", state)
	}
	if changed {
		t.Error("Probing→Direct は経路不変（routeChanged=false）であるべき")
	}
	if tr.Route() != RouteDirect {
		t.Errorf("Route = %v want RouteDirect", tr.Route())
	}
}

func TestProbingStaysWhilePending(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := New(testConfig(), t0)
	// ハンドシェイク未成立・タイムアウト未満 → Probing のまま。
	state, changed := tr.Step(t0.Add(2*time.Second), time.Time{})
	if state != Probing || changed {
		t.Errorf("state=%v changed=%v want Probing,false", state, changed)
	}
}

func TestProbingToRelayOnTimeout(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := New(testConfig(), t0)
	// stale なハンドシェイク（プローブ開始より前）は直通確立とみなさない。タイムアウトで Relay。
	state, changed := tr.Step(t0.Add(8*time.Second), t0.Add(-10*time.Second))
	if state != Relay {
		t.Fatalf("state = %v want Relay", state)
	}
	if !changed {
		t.Error("Probing→Relay は経路変化（routeChanged=true）であるべき")
	}
	if tr.Route() != RouteRelay {
		t.Errorf("Route = %v want RouteRelay", tr.Route())
	}
}

func TestDirectToProbingWhenStale(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := New(testConfig(), t0)
	// まず Direct へ。
	if state, _ := tr.Step(t0.Add(1*time.Second), t0.Add(500*time.Millisecond)); state != Direct {
		t.Fatalf("前提: Direct になるべき, got %v", state)
	}
	// 最終ハンドシェイクが AliveTimeout を超えて古い → 直通が切れたとみなし Probing へ（経路は不変）。
	hs := t0.Add(500 * time.Millisecond)
	state, changed := tr.Step(hs.Add(181*time.Second), hs)
	if state != Probing {
		t.Fatalf("state = %v want Probing", state)
	}
	if changed {
		t.Error("Direct→Probing は経路不変であるべき")
	}
}

func TestDirectStaysWhenAlive(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := New(testConfig(), t0)
	if state, _ := tr.Step(t0.Add(1*time.Second), t0.Add(500*time.Millisecond)); state != Direct {
		t.Fatalf("前提: Direct, got %v", state)
	}
	// 最終ハンドシェイクが新しい → Direct 維持。
	hs := t0.Add(60 * time.Second)
	state, changed := tr.Step(hs.Add(30*time.Second), hs)
	if state != Direct || changed {
		t.Errorf("state=%v changed=%v want Direct,false", state, changed)
	}
}

func TestRelayStaysWithoutRetry(t *testing.T) {
	t0 := time.Unix(1000, 0)
	tr := New(testConfig(), t0) // RetryInterval=0
	// Relay へ転落。
	if state, _ := tr.Step(t0.Add(8*time.Second), time.Time{}); state != Relay {
		t.Fatalf("前提: Relay, got %v", state)
	}
	// RetryInterval=0 なので、いくら時間が経っても Relay に留まる。
	state, changed := tr.Step(t0.Add(1*time.Hour), time.Time{})
	if state != Relay || changed {
		t.Errorf("state=%v changed=%v want Relay,false", state, changed)
	}
}

func TestRelayRetryDirect(t *testing.T) {
	cfg := testConfig()
	cfg.RetryInterval = 30 * time.Second
	t0 := time.Unix(1000, 0)
	tr := New(cfg, t0)
	// Relay へ転落。
	relayAt := t0.Add(8 * time.Second)
	if state, _ := tr.Step(relayAt, time.Time{}); state != Relay {
		t.Fatalf("前提: Relay, got %v", state)
	}
	// RetryInterval 未満は Relay 維持。
	if state, changed := tr.Step(relayAt.Add(10*time.Second), time.Time{}); state != Relay || changed {
		t.Errorf("未満: state=%v changed=%v want Relay,false", state, changed)
	}
	// RetryInterval 経過で直通再試行（Probing へ・経路が RouteDirect に戻る＝変化）。
	state, changed := tr.Step(relayAt.Add(30*time.Second), time.Time{})
	if state != Probing {
		t.Fatalf("state = %v want Probing", state)
	}
	if !changed {
		t.Error("Relay→Probing は経路変化（RouteRelay→RouteDirect）であるべき")
	}
	if tr.Route() != RouteDirect {
		t.Errorf("Route = %v want RouteDirect", tr.Route())
	}
}
