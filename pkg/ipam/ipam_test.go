package ipam

import (
	"net/netip"
	"testing"
	"time"
)

func newTestAllocator(t *testing.T, cooldown time.Duration) *Allocator {
	t.Helper()
	a, err := New(netip.MustParsePrefix("10.0.0.0/24"), cooldown)
	if err != nil {
		t.Fatalf("New エラー: %v", err)
	}
	return a
}

func TestHostReservedAndSequential(t *testing.T) {
	a := newTestAllocator(t, DefaultReuseCooldown)
	if got := a.HostIP().String(); got != "10.0.0.1" {
		t.Errorf("HostIP = %s, want 10.0.0.1", got)
	}

	now := time.Now()
	for i, want := range []string{"10.0.0.2", "10.0.0.3", "10.0.0.4"} {
		got, err := a.Allocate(now)
		if err != nil {
			t.Fatalf("Allocate[%d] エラー: %v", i, err)
		}
		if got.String() != want {
			t.Errorf("Allocate[%d] = %s, want %s", i, got, want)
		}
	}
}

func TestReleaseRespectsCooldown(t *testing.T) {
	a := newTestAllocator(t, time.Minute)
	now := time.Now()

	a.next = 2
	ip, err := a.Allocate(now) // 10.0.0.2
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Release(ip, now); err != nil {
		t.Fatalf("Release エラー: %v", err)
	}

	// クールダウン中（30 秒）は解放した .2 を返さず次の空きへ。
	a.next = 2
	ip2, err := a.Allocate(now.Add(30 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if ip2 == ip {
		t.Errorf("クールダウン中に解放IP %s が再利用された", ip)
	}
	if ip2.String() != "10.0.0.3" {
		t.Errorf("次の割当 = %s, want 10.0.0.3", ip2)
	}

	// クールダウン経過後（2 分）は .2 が再利用可能。
	a.next = 2
	ip3, err := a.Allocate(now.Add(2 * time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if ip3.String() != "10.0.0.2" {
		t.Errorf("クールダウン後の再利用 = %s, want 10.0.0.2", ip3)
	}
}

func TestReleaseErrors(t *testing.T) {
	a := newTestAllocator(t, time.Minute)
	now := time.Now()

	if err := a.Release(a.HostIP(), now); err != ErrReleaseHost {
		t.Errorf("ホスト解放は ErrReleaseHost を返すべき, got %v", err)
	}
	if err := a.Release(netip.MustParseAddr("10.0.0.9"), now); err != ErrNotAllocated {
		t.Errorf("未割当解放は ErrNotAllocated を返すべき, got %v", err)
	}
}

func TestNewRejectsNonSlash24(t *testing.T) {
	if _, err := New(netip.MustParsePrefix("10.0.0.0/16"), time.Minute); err == nil {
		t.Error("/16 は拒否されるべき")
	}
	if _, err := New(netip.MustParsePrefix("fd00::/24"), time.Minute); err == nil {
		t.Error("IPv6 は拒否されるべき")
	}
}

func TestAllocateExhaustion(t *testing.T) {
	a := newTestAllocator(t, time.Minute) // 10.0.0.0/24 → .2〜.254 = 253 個
	now := time.Now()

	for i := 0; i < 253; i++ {
		if _, err := a.Allocate(now); err != nil {
			t.Fatalf("Allocate[%d] は成功するべき: %v", i, err)
		}
	}
	if _, err := a.Allocate(now); err != ErrExhausted {
		t.Errorf("254 個目は ErrExhausted を返すべき, got %v", err)
	}
}

func TestInUse(t *testing.T) {
	a := newTestAllocator(t, time.Minute)
	now := time.Now()

	ip, err := a.Allocate(now)
	if err != nil {
		t.Fatal(err)
	}
	if !a.InUse(ip) {
		t.Errorf("割当済み %s は InUse=true のはず", ip)
	}
	if !a.InUse(a.HostIP()) {
		t.Error("ホストIPは常に InUse=true のはず")
	}
	if free := netip.MustParseAddr("10.0.0.200"); a.InUse(free) {
		t.Errorf("未割当 %s は InUse=false のはず", free)
	}

	if err := a.Release(ip, now); err != nil {
		t.Fatal(err)
	}
	if a.InUse(ip) {
		t.Errorf("解放後 %s は InUse=false のはず", ip)
	}
}
