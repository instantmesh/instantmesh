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

func TestRequestsAndLimits(t *testing.T) {
	r := New()
	now := time.Now()
	alice := netip.MustParseAddr("10.0.0.2")
	bob := netip.MustParseAddr("10.0.0.3")

	// 上限未設定なら常に通り、そのつど計上される。
	for i := 0; i < 2; i++ {
		if !r.AllowRequest(alice, 11434, now) {
			t.Fatalf("上限未設定で拒否された（%d 回目）", i+1)
		}
	}
	if got := r.Snapshot()[0].Requests; got != 2 {
		t.Errorf("Requests = %d, want 2", got)
	}
	if r.HasLimits() {
		t.Error("上限未設定で HasLimits が真になった")
	}

	// リクエスト数の上限。到達後は拒否し、拒否した分は計上しない。
	r.SetLimit(alice, Limit{MaxRequests: 2})
	if r.AllowRequest(alice, 11434, now) {
		t.Error("リクエスト上限に達したのに通った")
	}
	if got := r.Snapshot()[0].Requests; got != 2 {
		t.Errorf("拒否した要求を計上した: Requests = %d, want 2", got)
	}
	// 上限が 1 件でもあれば HasLimits は真（呼び出し側が L7 で数える判定に使う）。
	if !r.HasLimits() {
		t.Error("上限を設定しても HasLimits が偽")
	}
	if !r.AllowRequest(bob, 11434, now) {
		t.Error("他のゲストまで遮断された（当該ゲストのみを遮断すべき）")
	}
	if got := r.LimitFor(alice); got.MaxRequests != 2 {
		t.Errorf("LimitFor = %+v", got)
	}

	// バイト数の上限（送受信の合計で判定）。
	r.SetLimit(bob, Limit{MaxBytes: 100})
	r.AddIn(bob, 11434, 60, now)
	if !r.AllowRequest(bob, 11434, now) {
		t.Error("上限未達で遮断された")
	}
	r.AddOut(bob, 11434, 40, now)
	if r.AllowRequest(bob, 11434, now) {
		t.Error("送受信合計で上限に達したのに通った")
	}

	// ゼロ値で解除できる。
	r.SetLimit(alice, Limit{})
	if !r.AllowRequest(alice, 11434, now) {
		t.Error("上限を解除しても遮断されたまま")
	}

	// Forget は上限も一緒に消す。
	r.Forget(bob)
	if got := r.LimitFor(bob); got.MaxBytes != 0 {
		t.Errorf("Forget 後も上限が残る: %+v", got)
	}
	// 全ての上限が消えれば HasLimits も偽へ戻る（L7 ゲートを畳める判定になる）。
	if r.HasLimits() {
		t.Error("全ての上限を消しても HasLimits が真")
	}
}
