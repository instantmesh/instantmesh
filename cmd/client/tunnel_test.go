package main

import (
	"bytes"
	"errors"
	"log"
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/netcfg"
)

func TestTunnelConfigureAppliesPlan(t *testing.T) {
	var gotName string
	var gotPlan netcfg.Plan
	tun := &Tunnel{name: "wg-test", configureLinkFn: func(ifName string, plan netcfg.Plan) error {
		gotName, gotPlan = ifName, plan
		return nil
	}}

	if err := tun.Configure("10.0.0.5"); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if gotName != "wg-test" {
		t.Errorf("ifName = %q want wg-test", gotName)
	}
	if want := netip.MustParsePrefix("10.0.0.5/32"); gotPlan.Address != want {
		t.Errorf("Address = %v want %v", gotPlan.Address, want)
	}
	if len(gotPlan.Routes) != 1 || gotPlan.Routes[0] != netip.MustParsePrefix("10.0.0.0/24") {
		t.Errorf("Routes = %v want [10.0.0.0/24]", gotPlan.Routes)
	}
}

func TestTunnelConfigureInvalidIP(t *testing.T) {
	called := false
	tun := &Tunnel{name: "wg-test", configureLinkFn: func(string, netcfg.Plan) error {
		called = true
		return nil
	}}
	if err := tun.Configure("bogus"); err == nil {
		t.Error("不正なIPはエラーになるべき")
	}
	if called {
		t.Error("計画算出に失敗したら configureLinkFn を呼ぶべきでない")
	}
}

func TestTunnelConfigureApplierError(t *testing.T) {
	wantErr := errors.New("ip コマンド失敗")
	tun := &Tunnel{name: "wg-test", configureLinkFn: func(string, netcfg.Plan) error {
		return wantErr
	}}
	if err := tun.Configure("10.0.0.5"); !errors.Is(err, wantErr) {
		t.Errorf("configureLinkFn のエラーは伝播すべき: got %v", err)
	}
}

func TestTunnelConfigureAbortsOnSubnetConflict(t *testing.T) {
	applied := false
	tun := &Tunnel{
		name:            "wg-test",
		configureLinkFn: func(string, netcfg.Plan) error { applied = true; return nil },
		localPrefixesFn: func(exclude string) ([]netip.Prefix, error) {
			if exclude != "wg-test" {
				t.Errorf("自インターフェースを除外指定すべき: got %q", exclude)
			}
			// メッシュ 10.0.0.0/24 と重複する既存 LAN。
			return []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}, nil
		},
	}
	err := tun.Configure("10.0.0.5")
	if !errors.Is(err, ErrSubnetConflict) {
		t.Fatalf("Configure err = %v, want ErrSubnetConflict", err)
	}
	if applied {
		t.Error("衝突時は configureLink を呼ばず適用を中止すべき")
	}
	if !strings.Contains(err.Error(), "重複") {
		t.Errorf("衝突エラーは重複を説明すべき: %q", err.Error())
	}
}

func TestTunnelConfigureNoWarnWithoutConflict(t *testing.T) {
	var buf bytes.Buffer
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	tun := &Tunnel{
		name:            "wg-test",
		configureLinkFn: func(string, netcfg.Plan) error { return nil },
		localPrefixesFn: func(string) ([]netip.Prefix, error) {
			return []netip.Prefix{netip.MustParsePrefix("192.168.1.0/24")}, nil
		},
	}
	if err := tun.Configure("10.0.0.5"); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if strings.Contains(buf.String(), "重複") {
		t.Errorf("衝突が無ければ警告を出すべきでない: %q", buf.String())
	}
}

func TestTunnelConfigureContinuesOnEnumError(t *testing.T) {
	applied := false
	tun := &Tunnel{
		name:            "wg-test",
		configureLinkFn: func(string, netcfg.Plan) error { applied = true; return nil },
		localPrefixesFn: func(string) ([]netip.Prefix, error) {
			return nil, errors.New("列挙失敗")
		},
	}
	if err := tun.Configure("10.0.0.5"); err != nil {
		t.Fatalf("Configure: %v", err)
	}
	if !applied {
		t.Error("列挙失敗は検知スキップに留め、適用は続行すべき")
	}
}

func TestConfigureTunnelNil(t *testing.T) {
	configureTunnel(nil, "10.0.0.5") // panic しないこと（no-op）
}

func TestConfigureTunnelWarnsOnError(t *testing.T) {
	// Configure が失敗してもパニックせず警告に留める（戻り値なし・副作用のみ）。
	tun := &Tunnel{name: "wg-test", configureLinkFn: func(string, netcfg.Plan) error {
		return errors.New("設定失敗")
	}}
	configureTunnel(tun, "10.0.0.5")

	// 成功パスも実行してログ分岐を通す。
	ok := &Tunnel{name: "wg-test", configureLinkFn: func(string, netcfg.Plan) error { return nil }}
	configureTunnel(ok, "10.0.0.5")
}
