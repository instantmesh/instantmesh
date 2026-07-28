package plan

import (
	"testing"
	"time"
)

func TestLookupGuestLimits(t *testing.T) {
	free, ok := Lookup(Free)
	if !ok {
		t.Fatal("Free プランが見つからない")
	}
	if free.MaxGuests != 5 {
		t.Errorf("Free.MaxGuests = %d, want 5", free.MaxGuests)
	}

	pro, ok := Lookup(Pro)
	if !ok {
		t.Fatal("Pro プランが見つからない")
	}
	if pro.MaxGuests != 20 {
		t.Errorf("Pro.MaxGuests = %d, want 20", pro.MaxGuests)
	}

	if _, ok := Lookup(Tier("enterprise")); ok {
		t.Error("未知プランは ok=false を返すべき")
	}
}

func TestDurations(t *testing.T) {
	if got := MustLookup(Free).MaxDuration; got != time.Hour {
		t.Errorf("Free.MaxDuration = %v, want 1h", got)
	}
	if got := MustLookup(Pro).MaxDuration; got != 24*time.Hour {
		t.Errorf("Pro.MaxDuration = %v, want 24h", got)
	}
}

func TestTierForGroups(t *testing.T) {
	tests := []struct {
		name     string
		groups   []string
		proGroup string
		want     Tier
	}{
		{"proグループ所属 → Pro", []string{"admins", "pro"}, "pro", Pro},
		{"proグループ非所属 → Free", []string{"admins"}, "pro", Free},
		{"グループ空 → Free", nil, "pro", Free},
		{"proGroup 未設定は常に Free", []string{"pro"}, "", Free},
		{"proGroup 未設定・グループ空 → Free", nil, "", Free},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := TierForGroups(tt.groups, tt.proGroup); got != tt.want {
				t.Errorf("TierForGroups(%v, %q) = %v, want %v", tt.groups, tt.proGroup, got, tt.want)
			}
		})
	}
}

func TestMustLookupPanicsOnUnknown(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Error("未知プランで panic するべき")
		}
	}()
	MustLookup(Tier("nope"))
}

// TestMaxSharedServices は §5 の表（Free=3 / Pro=10・付録C.9 D-15）と実装値の一致を守る。
func TestMaxSharedServices(t *testing.T) {
	if got := MustLookup(Free).MaxSharedServices; got != 3 {
		t.Errorf("Free.MaxSharedServices = %d, want 3", got)
	}
	if got := MustLookup(Pro).MaxSharedServices; got != 10 {
		t.Errorf("Pro.MaxSharedServices = %d, want 10", got)
	}
}

// TestUsageRecords は利用記録の閲覧が有料プラン限定（§5）であることを守る。
func TestUsageRecords(t *testing.T) {
	if MustLookup(Free).UsageRecords {
		t.Error("Free で利用記録を閲覧可能にしている")
	}
	if !MustLookup(Pro).UsageRecords {
		t.Error("Pro で利用記録を閲覧できない")
	}
}
