package netcfg

import (
	"net/netip"
	"testing"
)

func TestForIPv4(t *testing.T) {
	plan, err := For("10.0.0.5")
	if err != nil {
		t.Fatalf("For: %v", err)
	}
	if want := netip.MustParsePrefix("10.0.0.5/32"); plan.Address != want {
		t.Errorf("Address = %v want %v", plan.Address, want)
	}
	if len(plan.Routes) != 1 {
		t.Fatalf("Routes 件数 = %d want 1", len(plan.Routes))
	}
	if want := netip.MustParsePrefix("10.0.0.0/24"); plan.Routes[0] != want {
		t.Errorf("Routes[0] = %v want %v", plan.Routes[0], want)
	}
}

func TestForHostAndGuestSymmetric(t *testing.T) {
	// ホスト(.1)・ゲスト(.7)いずれも同一メッシュ /24 を経由ルートに載せる（計画は対称）。
	host, err := For("10.9.0.1")
	if err != nil {
		t.Fatalf("For(host): %v", err)
	}
	guest, err := For("10.9.0.7")
	if err != nil {
		t.Fatalf("For(guest): %v", err)
	}
	mesh := netip.MustParsePrefix("10.9.0.0/24")
	if host.Routes[0] != mesh || guest.Routes[0] != mesh {
		t.Errorf("メッシュルートが一致しない: host=%v guest=%v want %v", host.Routes[0], guest.Routes[0], mesh)
	}
	if host.Address != netip.MustParsePrefix("10.9.0.1/32") {
		t.Errorf("host Address = %v", host.Address)
	}
	if guest.Address != netip.MustParsePrefix("10.9.0.7/32") {
		t.Errorf("guest Address = %v", guest.Address)
	}
}

func TestForInvalid(t *testing.T) {
	if _, err := For("not-an-ip"); err == nil {
		t.Error("解析不能なIPはエラーになるべき")
	}
}

func TestConflicts(t *testing.T) {
	plan, err := For("10.0.0.5") // メッシュ 10.0.0.0/24
	if err != nil {
		t.Fatalf("For: %v", err)
	}

	// 重複なし: 空スライス、無関係サブネット、無効プレフィックスは衝突に数えない。
	none := plan.Conflicts(nil)
	if len(none) != 0 {
		t.Errorf("nil は衝突なし: %v", none)
	}
	none = plan.Conflicts([]netip.Prefix{
		netip.MustParsePrefix("192.168.1.0/24"),
		netip.MustParsePrefix("172.16.0.0/16"),
		{}, // 無効プレフィックス → スキップ
	})
	if len(none) != 0 {
		t.Errorf("無関係/無効は衝突なし: %v", none)
	}

	// 完全一致の /24 は衝突。
	got := plan.Conflicts([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")})
	if len(got) != 1 || got[0] != netip.MustParsePrefix("10.0.0.0/24") {
		t.Errorf("同一 /24 は衝突すべき: %v", got)
	}

	// メッシュ /24 を内包するより広いサブネット（/16）も重複。
	got = plan.Conflicts([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/16")})
	if len(got) != 1 {
		t.Errorf("内包する /16 は衝突すべき: %v", got)
	}

	// メッシュ /24 の一部（/25）も重複。無関係サブネットと混在しても重複分のみ返す。
	got = plan.Conflicts([]netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/24"),
		netip.MustParsePrefix("10.0.0.128/25"),
	})
	if len(got) != 1 || got[0].Bits() != 25 {
		t.Errorf("内側 /25 のみ衝突すべき: %v", got)
	}
}

func TestForRejectsIPv6(t *testing.T) {
	if _, err := For("fd00::1"); err == nil {
		t.Error("IPv6 はフェーズ1では非対応でエラーになるべき")
	}
}
