package usage

import (
	"net/netip"
	"testing"
	"time"
)

func TestRecordAndSnapshot(t *testing.T) {
	r := New()
	t0 := time.Date(2026, 7, 28, 10, 0, 0, 0, time.UTC)
	alice := netip.MustParseAddr("10.0.0.2")
	bob := netip.MustParseAddr("10.0.0.3")

	r.AddIn(alice, 11434, 100, t0)
	r.AddOut(alice, 11434, 900, t0.Add(time.Second))
	r.AddIn(alice, 3000, 10, t0.Add(2*time.Second))
	r.AddIn(bob, 11434, 5, t0.Add(3*time.Second))

	got := r.Snapshot()
	if len(got) != 3 {
		t.Fatalf("件数 = %d, want 3", len(got))
	}
	// 並びはピア → ポートの昇順で決定的。
	if got[0].Peer != "10.0.0.2" || got[0].Port != 3000 {
		t.Errorf("got[0] = %+v", got[0])
	}
	if got[1].Port != 11434 || got[1].BytesIn != 100 || got[1].BytesOut != 900 {
		t.Errorf("got[1] = %+v", got[1])
	}
	if !got[1].FirstSeen.Equal(t0) || !got[1].LastSeen.Equal(t0.Add(time.Second)) {
		t.Errorf("時刻 = %v / %v", got[1].FirstSeen, got[1].LastSeen)
	}
	if got[2].Peer != "10.0.0.3" {
		t.Errorf("got[2] = %+v", got[2])
	}

	in, out := r.Totals()
	if in != 115 || out != 900 {
		t.Errorf("Totals = %d / %d, want 115 / 900", in, out)
	}
}

// TestIgnoresUnidentifiable は計上単位を特定できない入力を記録しないことを確かめる。
func TestIgnoresUnidentifiable(t *testing.T) {
	r := New()
	now := time.Now()
	r.AddIn(netip.Addr{}, 11434, 100, now) // アドレス不明
	r.AddIn(netip.MustParseAddr("10.0.0.2"), 0, 100, now)
	if len(r.Snapshot()) != 0 {
		t.Errorf("記録された: %+v", r.Snapshot())
	}
}

func TestForgetAndReset(t *testing.T) {
	r := New()
	now := time.Now()
	alice := netip.MustParseAddr("10.0.0.2")
	bob := netip.MustParseAddr("10.0.0.3")
	r.AddIn(alice, 11434, 1, now)
	r.AddIn(alice, 3000, 1, now)
	r.AddIn(bob, 11434, 1, now)

	r.Forget(alice)
	got := r.Snapshot()
	if len(got) != 1 || got[0].Peer != "10.0.0.3" {
		t.Errorf("Forget 後 = %+v", got)
	}

	r.Reset()
	if len(r.Snapshot()) != 0 {
		t.Error("Reset 後も記録が残っている")
	}
	in, out := r.Totals()
	if in != 0 || out != 0 {
		t.Errorf("Reset 後の合計 = %d / %d", in, out)
	}
}
