// Package pktfilter は仮想NIC を流れる IP パケットの最小限の解析と、共有していないサービスへの
// 到達を遮断する可否判定を提供する純粋ロジック（要件定義書 §4.6.1・付録C.9 D-11）。
//
// なぜ要るか: メッシュに参加した承認済みゲストは、ホストのメッシュIP の**全ポート**へ到達できる。
// 「共有するサービスを選んで貸す」（§4.6）を到達制御として成立させるには、選ばれていない宛先を
// どこかで落とす必要がある。その判断をここに純粋ロジックとして置き、実際の適用（wireguard-go の
// tun.Device を包んで受信パケットを落とす）は cmd/client が担う（§4.6.5 と同じ分割）。
//
// 判定の方針:
//   - **新規の受信接続だけを止める。** TCP は SYN（ACK 無し）だけを検査対象にし、それ以外は通す。
//     こうすることで、ホスト側から張った接続の戻りパケット（宛先ポートが一時ポートになる）を
//     状態を持たずに通せる。UDP は宛先ポートで判定する。
//   - **ICMP は落とさない。** 疎通確認（ping）はメッシュの基本機能であり、共有の有無とは独立。
//   - **自分宛以外は落とす。** フェーズ1 はスター型でゲスト間の転送を行わないため、自身のメッシュIP
//     以外を宛先とするパケットを仮想NIC へ渡す必要が無い。
//   - **制御用ポートは常に通す。** 名前解決のローカルレスポンダ（自メッシュIP の :53）を落とすと
//     §4.6.3 が機能しなくなるため、共有の有無に関わらず通す。
//
// 本パッケージは製品固有の知識を持たない（設計原則8）。「どのポートが共有中か」は呼び出し側が
// 与えるだけで、Ollama 等のアプリ層プロトコルは解釈しない。
package pktfilter

import (
	"encoding/binary"
	"net/netip"
	"sort"
)

// IP プロトコル番号。
const (
	protoICMP   = 1
	protoTCP    = 6
	protoUDP    = 17
	protoICMPv6 = 58
)

// ヘッダ長の定数。
const (
	ipv4MinHeaderLen = 20
	ipv6HeaderLen    = 40
	tcpMinHeaderLen  = 20
	udpHeaderLen     = 8
	tcpFlagsOffset   = 13
	tcpFlagSYN       = 0x02
	tcpFlagACK       = 0x10
)

// Packet は判定に必要な最小限のヘッダ情報。
type Packet struct {
	// Src / Dst は送信元・宛先アドレス。
	Src, Dst netip.Addr
	// Proto は IP プロトコル番号（TCP=6 / UDP=17 / ICMP=1 / ICMPv6=58）。
	Proto uint8
	// SrcPort / DstPort は TCP・UDP のポート（それ以外は 0）。
	SrcPort, DstPort uint16
	// NewConn は「新規接続の開始」を表す（TCP の SYN かつ ACK 無し）。UDP・ICMP では false。
	NewConn bool
	// Size はパケット全体のバイト数（計上に使う）。
	Size int
}

// Parse は IP パケットの先頭から判定に要る情報を取り出す。解釈できないものは ok=false を返し、
// 呼び出し側は落とす（不明なものを通さない fail-closed）。
//
// IPv4 のフラグメント（先頭以外）はポートを読めないため解釈不能として扱う。断片化された
// 攻撃パケットでフィルタを迂回されないための fail-closed でもある。
func Parse(b []byte) (Packet, bool) {
	if len(b) < 1 {
		return Packet{}, false
	}
	switch b[0] >> 4 {
	case 4:
		return parseIPv4(b)
	case 6:
		return parseIPv6(b)
	}
	return Packet{}, false
}

func parseIPv4(b []byte) (Packet, bool) {
	if len(b) < ipv4MinHeaderLen {
		return Packet{}, false
	}
	ihl := int(b[0]&0x0F) * 4
	total := int(binary.BigEndian.Uint16(b[2:4]))
	if ihl < ipv4MinHeaderLen || len(b) < ihl || total > len(b) {
		return Packet{}, false
	}
	// フラグメントオフセットが 0 でないものは上位ヘッダを読めない。
	if binary.BigEndian.Uint16(b[6:8])&0x1FFF != 0 {
		return Packet{}, false
	}
	p := Packet{
		Src:   netip.AddrFrom4([4]byte(b[12:16])),
		Dst:   netip.AddrFrom4([4]byte(b[16:20])),
		Proto: b[9],
		Size:  len(b),
	}
	if !fillPorts(&p, b[ihl:]) {
		return Packet{}, false
	}
	return p, true
}

func parseIPv6(b []byte) (Packet, bool) {
	if len(b) < ipv6HeaderLen {
		return Packet{}, false
	}
	p := Packet{
		Src:   netip.AddrFrom16([16]byte(b[8:24])),
		Dst:   netip.AddrFrom16([16]byte(b[24:40])),
		Proto: b[6], // 拡張ヘッダは解釈しない（後述のとおり解釈不能として落とす）
		Size:  len(b),
	}
	if !fillPorts(&p, b[ipv6HeaderLen:]) {
		return Packet{}, false
	}
	return p, true
}

// fillPorts は上位プロトコルのヘッダからポートと SYN を取り出す。TCP/UDP/ICMP 以外は
// 解釈不能として false を返す（IPv6 拡張ヘッダ付きもここで落ちる）。
func fillPorts(p *Packet, payload []byte) bool {
	switch p.Proto {
	case protoTCP:
		if len(payload) < tcpMinHeaderLen {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		p.DstPort = binary.BigEndian.Uint16(payload[2:4])
		flags := payload[tcpFlagsOffset]
		p.NewConn = flags&tcpFlagSYN != 0 && flags&tcpFlagACK == 0
		return true
	case protoUDP:
		if len(payload) < udpHeaderLen {
			return false
		}
		p.SrcPort = binary.BigEndian.Uint16(payload[0:2])
		p.DstPort = binary.BigEndian.Uint16(payload[2:4])
		return true
	case protoICMP, protoICMPv6:
		return true
	}
	return false
}

// Policy は受信パケットの可否を決める規則。ゼロ値は「自分宛の ICMP すら通さない」ため、
// 必ず NewPolicy で組み立てる。
type Policy struct {
	self     netip.Addr
	allowed  map[uint16]bool // 共有中サービスのポート
	control  map[uint16]bool // 共有の有無に関わらず通すポート（名前解決の :53 等）
	allowICM bool
}

// NewPolicy は自身のメッシュIP・共有中ポート・制御用ポートから規則を組み立てる。
// allowICMP は疎通確認（ping）を通すかどうかで、通常は true。
func NewPolicy(self netip.Addr, sharedPorts, controlPorts []int, allowICMP bool) Policy {
	return Policy{
		self:     self,
		allowed:  portSet(sharedPorts),
		control:  portSet(controlPorts),
		allowICM: allowICMP,
	}
}

func portSet(ports []int) map[uint16]bool {
	m := make(map[uint16]bool, len(ports))
	for _, p := range ports {
		if p > 0 && p <= 65535 {
			m[uint16(p)] = true
		}
	}
	return m
}

// IsShared は当該ポートが共有中サービスのものかを返す。利用記録（§4.7）の計上対象を
// 共有サービスに限る（制御用ポートや一時ポートを混ぜない）ために使う。
func (p Policy) IsShared(port uint16) bool { return p.allowed[port] }

// SharedPorts は共有中として許可しているポートを昇順で返す（表示・テスト用）。
func (p Policy) SharedPorts() []int {
	out := make([]int, 0, len(p.allowed))
	for port := range p.allowed {
		out = append(out, int(port))
	}
	sort.Ints(out)
	return out
}

// Allow はピアから受信したパケットを仮想NIC へ渡してよいかを返す。
//
// 判定できないパケットは落とす（fail-closed）。自身のメッシュIP が未設定（ゼロ値）の場合、
// 宛先の照合ができないため全て落とす。
func (p Policy) Allow(pkt Packet) bool {
	if !p.self.IsValid() || pkt.Dst.Unmap() != p.self.Unmap() {
		return false // 自分宛以外は転送しない（スター型・ゲスト間転送は行わない）
	}
	switch pkt.Proto {
	case protoICMP, protoICMPv6:
		return p.allowICM
	case protoTCP:
		// 新規の受信接続だけを止める。確立済み接続や、ホスト側から張った接続の戻りは通す。
		if !pkt.NewConn {
			return true
		}
		return p.allowed[pkt.DstPort] || p.control[pkt.DstPort]
	case protoUDP:
		return p.allowed[pkt.DstPort] || p.control[pkt.DstPort]
	}
	return false
}
