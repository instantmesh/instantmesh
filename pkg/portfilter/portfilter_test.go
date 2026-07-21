package portfilter

import (
	"encoding/binary"
	"testing"

	"github.com/instantmesh/instantmesh/pkg/plan"
)

// ipv4 は指定プロトコル・宛先ポートの最小 IPv4 パケット（IHL 5）を作る。
func ipv4(proto byte, dstPort uint16) []byte {
	p := make([]byte, 24)
	p[0] = 0x45 // version 4, IHL 5(=20B)
	p[9] = proto
	binary.BigEndian.PutUint16(p[22:24], dstPort) // ihl(20)+2
	return p
}

// ipv6 は指定プロトコル・宛先ポートの最小 IPv6 パケットを作る。
func ipv6(proto byte, dstPort uint16) []byte {
	p := make([]byte, 44)
	p[0] = 0x60 // version 6
	p[6] = proto
	binary.BigEndian.PutUint16(p[42:44], dstPort) // 40+2
	return p
}

func TestAllowProUnrestricted(t *testing.T) {
	pro := plan.MustLookup(plan.Pro)
	// ポート制限なしプランは、通常拒否される TCP/UDP でも常に許可。
	if !Allow(ipv4(protoTCP, 22), pro) {
		t.Error("Pro は TCP 22 も許可すべき")
	}
	if !Allow(ipv4(protoUDP, 53), pro) {
		t.Error("Pro は UDP も許可すべき")
	}
}

func TestAllowFree(t *testing.T) {
	free := plan.MustLookup(plan.Free)
	cases := []struct {
		name string
		pkt  []byte
		want bool
	}{
		{"ipv4 tcp 443 (許可)", ipv4(protoTCP, 443), true},
		{"ipv4 tcp 80 (許可)", ipv4(protoTCP, 80), true},
		{"ipv4 tcp 8080 (許可)", ipv4(protoTCP, 8080), true},
		{"ipv4 tcp 22 (拒否)", ipv4(protoTCP, 22), false},
		{"ipv4 udp 53 (拒否)", ipv4(protoUDP, 53), false},
		{"ipv4 icmp (許可)", ipv4(protoICMP, 0), true},
		{"ipv6 tcp 443 (許可)", ipv6(protoTCP, 443), true},
		{"ipv6 tcp 22 (拒否)", ipv6(protoTCP, 22), false},
		{"ipv6 icmpv6 (許可)", ipv6(protoICMPv6, 0), true},
	}
	for _, c := range cases {
		if got := Allow(c.pkt, free); got != c.want {
			t.Errorf("%s: Allow = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestAllowFreeMalformed(t *testing.T) {
	free := plan.MustLookup(plan.Free)

	badIPv4IHL := make([]byte, 20)
	badIPv4IHL[0] = 0x40 // version 4, IHL 0 → ヘッダ長 0(<20)

	shortForIHL := make([]byte, 20)
	shortForIHL[0] = 0x46 // IHL 6(=24B) だが実データ 20B（len<ihl）

	tcpTruncatedV4 := make([]byte, 20)
	tcpTruncatedV4[0] = 0x45
	tcpTruncatedV4[9] = protoTCP // L4 ヘッダが存在しない

	tcpTruncatedV6 := make([]byte, 40)
	tcpTruncatedV6[0] = 0x60
	tcpTruncatedV6[6] = protoTCP

	shortIPv6 := make([]byte, 39) // version 6 だが 40B 未満
	shortIPv6[0] = 0x60

	cases := []struct {
		name string
		pkt  []byte
	}{
		{"空", []byte{}},
		{"未知バージョン", []byte{0x30}},
		{"ipv4 短すぎ", []byte{0x45}},
		{"ipv4 IHL 不正", badIPv4IHL},
		{"ipv4 IHL がデータ長超過", shortForIHL},
		{"ipv4 TCP ヘッダ欠落", tcpTruncatedV4},
		{"ipv6 短すぎ", shortIPv6},
		{"ipv6 TCP ヘッダ欠落", tcpTruncatedV6},
	}
	for _, c := range cases {
		if Allow(c.pkt, free) {
			t.Errorf("%s: 解析不能/不許可パケットは拒否すべき", c.name)
		}
	}
}
