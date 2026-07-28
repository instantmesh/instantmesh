package pktfilter

import (
	"encoding/binary"
	"net/netip"
	"testing"
)

// pkt4 は IPv4 パケットを組み立てる（payload は上位ヘッダ以降）。
func pkt4(src, dst string, proto uint8, payload []byte, opts ...func([]byte)) []byte {
	b := make([]byte, ipv4MinHeaderLen+len(payload))
	b[0] = 0x45 // version 4 / IHL 5
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[9] = proto
	copy(b[12:16], netip.MustParseAddr(src).AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	copy(b[ipv4MinHeaderLen:], payload)
	for _, o := range opts {
		o(b)
	}
	return b
}

// pkt6 は IPv6 パケットを組み立てる。
func pkt6(src, dst string, proto uint8, payload []byte) []byte {
	b := make([]byte, ipv6HeaderLen+len(payload))
	b[0] = 0x60 // version 6
	b[6] = proto
	copy(b[8:24], netip.MustParseAddr(src).AsSlice())
	copy(b[24:40], netip.MustParseAddr(dst).AsSlice())
	copy(b[ipv6HeaderLen:], payload)
	return b
}

// tcp はポートとフラグを持つ TCP ヘッダを組み立てる。
func tcp(srcPort, dstPort uint16, flags byte) []byte {
	h := make([]byte, tcpMinHeaderLen)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	h[tcpFlagsOffset] = flags
	return h
}

// udp は UDP ヘッダを組み立てる。
func udp(srcPort, dstPort uint16) []byte {
	h := make([]byte, udpHeaderLen)
	binary.BigEndian.PutUint16(h[0:2], srcPort)
	binary.BigEndian.PutUint16(h[2:4], dstPort)
	return h
}

func TestParseIPv4TCP(t *testing.T) {
	b := pkt4("10.0.0.2", "10.0.0.1", protoTCP, tcp(51000, 11434, tcpFlagSYN))
	p, ok := Parse(b)
	if !ok {
		t.Fatal("解析できない")
	}
	if p.Src != netip.MustParseAddr("10.0.0.2") || p.Dst != netip.MustParseAddr("10.0.0.1") {
		t.Errorf("アドレス = %v → %v", p.Src, p.Dst)
	}
	if p.SrcPort != 51000 || p.DstPort != 11434 || !p.NewConn || p.Size != len(b) {
		t.Errorf("packet = %+v", p)
	}
	// SYN+ACK は「新規接続」ではない（ホスト側から張った接続の戻り）。
	if p, _ := Parse(pkt4("10.0.0.2", "10.0.0.1", protoTCP, tcp(11434, 51000, tcpFlagSYN|tcpFlagACK))); p.NewConn {
		t.Error("SYN+ACK を新規接続と誤判定した")
	}
}

func TestParseIPv6UDP(t *testing.T) {
	p, ok := Parse(pkt6("fd00::2", "fd00::1", protoUDP, udp(5000, 53)))
	if !ok {
		t.Fatal("解析できない")
	}
	if p.Dst != netip.MustParseAddr("fd00::1") || p.DstPort != 53 || p.Proto != protoUDP {
		t.Errorf("packet = %+v", p)
	}
}

func TestParseRejects(t *testing.T) {
	frag := func(b []byte) { binary.BigEndian.PutUint16(b[6:8], 1) } // フラグメントオフセット
	badIHL := func(b []byte) { b[0] = 0x43 }                         // IHL=3（20 バイト未満）
	badTotal := func(b []byte) { binary.BigEndian.PutUint16(b[2:4], 9999) }

	cases := []struct {
		name string
		in   []byte
	}{
		{"空", nil},
		{"未知のバージョン", []byte{0x70, 0, 0, 0}},
		{"IPv4 ヘッダ長不足", []byte{0x45, 0, 0, 0}},
		{"バージョン欠落（ゼロ埋め）", make([]byte, 10)},
		{"IPv4 IHL 不正", pkt4("10.0.0.2", "10.0.0.1", protoTCP, tcp(1, 2, 0), badIHL)},
		{"IPv4 全長がバッファ超過", pkt4("10.0.0.2", "10.0.0.1", protoTCP, tcp(1, 2, 0), badTotal)},
		{"IPv4 フラグメント", pkt4("10.0.0.2", "10.0.0.1", protoTCP, tcp(1, 2, 0), frag)},
		{"IPv6 ヘッダ長不足", []byte{0x60, 0, 0, 0}},
		{"TCP ヘッダ不足", pkt4("10.0.0.2", "10.0.0.1", protoTCP, make([]byte, 4))},
		{"UDP ヘッダ不足", pkt4("10.0.0.2", "10.0.0.1", protoUDP, make([]byte, 2))},
		{"IPv6 UDP ヘッダ不足", pkt6("fd00::2", "fd00::1", protoUDP, make([]byte, 2))},
		{"未対応プロトコル(GRE)", pkt4("10.0.0.2", "10.0.0.1", 47, make([]byte, 20))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, ok := Parse(c.in); ok {
				t.Error("解釈できないパケットを通した（fail-closed であるべき）")
			}
		})
	}
}

func TestPolicyAllow(t *testing.T) {
	self := netip.MustParseAddr("10.0.0.1")
	pol := NewPolicy(self, []int{11434}, []int{53}, true)

	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"共有中ポートへの新規接続は通す", pkt4("10.0.0.2", "10.0.0.1", protoTCP, tcp(51000, 11434, tcpFlagSYN)), true},
		{"共有していないポートへの新規接続は落とす", pkt4("10.0.0.2", "10.0.0.1", protoTCP, tcp(51000, 22, tcpFlagSYN)), false},
		{"確立済み接続は通す", pkt4("10.0.0.2", "10.0.0.1", protoTCP, tcp(51000, 22, tcpFlagACK)), true},
		{"制御用ポート(DNS)は共有していなくても通す", pkt4("10.0.0.2", "10.0.0.1", protoUDP, udp(5000, 53)), true},
		{"共有していない UDP は落とす", pkt4("10.0.0.2", "10.0.0.1", protoUDP, udp(5000, 5353)), false},
		{"共有中ポートへの UDP は通す", pkt4("10.0.0.2", "10.0.0.1", protoUDP, udp(5000, 11434)), true},
		{"ICMP(ping)は通す", pkt4("10.0.0.2", "10.0.0.1", protoICMP, nil), true},
		{"自分宛以外は落とす", pkt4("10.0.0.2", "10.0.0.3", protoTCP, tcp(51000, 11434, tcpFlagSYN)), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, ok := Parse(c.pkt)
			if !ok {
				t.Fatal("解析できない")
			}
			if got := pol.Allow(p); got != c.want {
				t.Errorf("Allow = %v, want %v", got, c.want)
			}
		})
	}
}

// TestPolicyICMPDisabled は ICMP を止める設定も選べることを確かめる。
func TestPolicyICMPDisabled(t *testing.T) {
	pol := NewPolicy(netip.MustParseAddr("10.0.0.1"), nil, nil, false)
	p, _ := Parse(pkt4("10.0.0.2", "10.0.0.1", protoICMP, nil))
	if pol.Allow(p) {
		t.Error("allowICMP=false でも通した")
	}
	p6, _ := Parse(pkt6("fd00::2", "fd00::1", protoICMPv6, nil))
	if NewPolicy(netip.MustParseAddr("fd00::1"), nil, nil, true).Allow(p6) != true {
		t.Error("ICMPv6 が通らない")
	}
}

// TestPolicyFailClosed は自身のアドレスが未確定なら全て落とすことを確かめる（fail-closed）。
func TestPolicyFailClosed(t *testing.T) {
	var pol Policy
	p, _ := Parse(pkt4("10.0.0.2", "10.0.0.1", protoTCP, tcp(51000, 11434, tcpFlagSYN)))
	if pol.Allow(p) {
		t.Error("自身のアドレス未設定で通した")
	}
	// 解釈できないプロトコル（Parse を通さず直接構築した場合）も落とす。
	pol = NewPolicy(netip.MustParseAddr("10.0.0.1"), []int{11434}, nil, true)
	if pol.Allow(Packet{Src: netip.MustParseAddr("10.0.0.2"), Dst: netip.MustParseAddr("10.0.0.1"), Proto: 47}) {
		t.Error("未対応プロトコルを通した")
	}
}

func TestIsShared(t *testing.T) {
	pol := NewPolicy(netip.MustParseAddr("10.0.0.1"), []int{11434}, []int{53}, true)
	if !pol.IsShared(11434) {
		t.Error("共有中ポートが false")
	}
	// 制御用ポートは「通す」が「共有中」ではない（利用記録の対象にしない）。
	if pol.IsShared(53) || pol.IsShared(22) {
		t.Error("共有中でないポートが true")
	}
}

func TestSharedPorts(t *testing.T) {
	pol := NewPolicy(netip.MustParseAddr("10.0.0.1"), []int{11434, 3000, 0, 70000}, nil, true)
	got := pol.SharedPorts()
	if len(got) != 2 || got[0] != 3000 || got[1] != 11434 {
		t.Errorf("SharedPorts = %v, want [3000 11434]（範囲外は無視・昇順）", got)
	}
}

// TestPolicyIPv4In6 は IPv4 射影表現の宛先でも自分宛と判定できることを確かめる。
func TestPolicyIPv4In6(t *testing.T) {
	pol := NewPolicy(netip.MustParseAddr("10.0.0.1"), []int{11434}, nil, true)
	p := Packet{
		Src:     netip.MustParseAddr("10.0.0.2"),
		Dst:     netip.MustParseAddr("::ffff:10.0.0.1"),
		Proto:   protoTCP,
		DstPort: 11434,
		NewConn: true,
	}
	if !pol.Allow(p) {
		t.Error("IPv4 射影表現の自分宛を落とした")
	}
}
