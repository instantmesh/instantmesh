package main

import (
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/dnsmsg"
	"github.com/instantmesh/instantmesh/pkg/meshname"
)

// dnsQuery は A 問い合わせのバイト列を組み立てる（実リゾルバの代わり）。
func dnsQuery(id uint16, name string) []byte {
	msg := make([]byte, 0, 32)
	msg = binary.BigEndian.AppendUint16(msg, id)
	msg = binary.BigEndian.AppendUint16(msg, 0x0100) // RD=1
	msg = binary.BigEndian.AppendUint16(msg, 1)      // QDCOUNT
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, 0)
	for _, l := range strings.Split(name, ".") {
		msg = append(msg, byte(len(l)))
		msg = append(msg, l...)
	}
	msg = append(msg, 0)
	msg = binary.BigEndian.AppendUint16(msg, uint16(dnsmsg.TypeA))
	msg = binary.BigEndian.AppendUint16(msg, uint16(dnsmsg.ClassIN))
	return msg
}

// TestDNSResponderAnswers は実 UDP ソケット越しに、ゾーンへ登録した名前が引けることを確かめる
// （管理者権限を避けるためループバックの動的ポートで待ち受ける）。
func TestDNSResponderAnswers(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	zone := meshname.NewZone()
	host := netip.MustParseAddr("10.9.0.1")
	if err := zone.Replace(host, []string{"tanaka.mesh", "ollama.tanaka.mesh"}); err != nil {
		t.Fatalf("Replace: %v", err)
	}
	r, err := startDNSResponder(ctx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0), zone)
	if err != nil {
		t.Fatalf("startDNSResponder: %v", err)
	}
	defer r.close()

	conn, err := net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(r.localAddr()))
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	ask := func(name string) []byte {
		t.Helper()
		if _, err := conn.Write(dnsQuery(0x4242, name)); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 512)
		n, err := conn.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		return buf[:n]
	}

	resp := ask("ollama.tanaka.mesh")
	if id := binary.BigEndian.Uint16(resp[0:2]); id != 0x4242 {
		t.Errorf("ID = %#x", id)
	}
	if ancount := binary.BigEndian.Uint16(resp[6:8]); ancount != 1 {
		t.Fatalf("ANCOUNT = %d, want 1", ancount)
	}
	if addr, _ := netip.AddrFromSlice(resp[len(resp)-4:]); addr != host {
		t.Errorf("回答 = %v, want %v", addr, host)
	}

	// 未登録の `.mesh` は NXDOMAIN、ゾーン外は REFUSED。
	if rcode := binary.BigEndian.Uint16(ask("nope.tanaka.mesh")[2:4]) & 0x000F; rcode != uint16(dnsmsg.RCodeNameError) {
		t.Errorf("未登録の rcode = %d, want %d", rcode, dnsmsg.RCodeNameError)
	}
	if rcode := binary.BigEndian.Uint16(ask("example.com")[2:4]) & 0x000F; rcode != uint16(dnsmsg.RCodeRefused) {
		t.Errorf("ゾーン外の rcode = %d, want %d", rcode, dnsmsg.RCodeRefused)
	}
}

// TestDNSResponderClosesWithContext は ctx 終了でソケットが閉じ、受信ループが抜けることを確かめる。
func TestDNSResponderClosesWithContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	zone := meshname.NewZone()
	r, err := startDNSResponder(ctx, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0), zone)
	if err != nil {
		t.Fatalf("startDNSResponder: %v", err)
	}
	addr := r.localAddr()
	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		// 閉じていれば同じアドレスを再び bind できる。
		c, err := net.ListenUDP("udp", net.UDPAddrFromAddrPort(addr))
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Error("ctx 終了後もソケットが閉じられていない")
}

func TestAllowDNSSource(t *testing.T) {
	bound := netip.MustParseAddr("10.9.0.2")
	cases := []struct {
		src  string
		want bool
	}{
		{"127.0.0.1", true},       // ローカルのリゾルバ
		{"::1", true},             // 同上（IPv6）
		{"10.9.0.2", true},        // 自身のメッシュIP 宛は送信元も同じになる
		{"::ffff:10.9.0.2", true}, // IPv4 射影表現でも同一とみなす
		{"10.9.0.3", false},       // 他のメッシュピア
		{"203.0.113.9", false},    // メッシュ外
	}
	for _, c := range cases {
		if got := allowDNSSource(netip.MustParseAddr(c.src), bound); got != c.want {
			t.Errorf("allowDNSSource(%s) = %v, want %v", c.src, got, c.want)
		}
	}
}

// TestStartNameResolutionDisabled は無効時・不正IP時に何も起動せず、stop が安全であることを確かめる。
func TestStartNameResolutionDisabled(t *testing.T) {
	ctx := context.Background()
	zone := meshname.NewZone()
	if n := startNameResolution(ctx, false, "wg-mesh", "10.9.0.1", zone); n != nil {
		t.Errorf("無効時に起動した")
	}
	if n := startNameResolution(ctx, true, "wg-mesh", "not-an-ip", zone); n != nil {
		t.Errorf("不正なIPで起動した")
	}
	var none *nameResolution
	none.stop() // nil レシーバでも安全
}
