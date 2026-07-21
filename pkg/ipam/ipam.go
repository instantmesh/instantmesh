// Package ipam はルーム内の仮想IPアドレス割当を管理する。
//
// ルームごとに /24 レンジを確保し、ホストに .1、ゲストは参加順に .2〜.254 を
// 順次割り当てる。キック・退出で解放されたアドレスは、一定のクールダウンを
// 経てから再利用する（要件定義書 §4.3）。
//
// Allocator はゴルーチンセーフではない。ルーム単位で直列化して使う想定。
package ipam

import (
	"errors"
	"net/netip"
	"time"
)

// DefaultReuseCooldown は解放されたIPが再割当可能になるまでの既定の猶予。
const DefaultReuseCooldown = 5 * time.Minute

var (
	// ErrExhausted は割当可能なアドレスが無い（枯渇またはクールダウン中で埋まっている）場合に返る。
	ErrExhausted = errors.New("ipam: address pool exhausted")
	// ErrNotAllocated は未割当アドレスを解放しようとした場合に返る。
	ErrNotAllocated = errors.New("ipam: address not allocated")
	// ErrReleaseHost はホストアドレスを解放しようとした場合に返る。
	ErrReleaseHost = errors.New("ipam: cannot release host address")
)

// Allocator は単一ルームの /24 レンジからIPを割り当てる。
type Allocator struct {
	base     netip.Addr // ネットワークアドレス .0
	host     netip.Addr // .1（ホスト予約）
	cooldown time.Duration
	inUse    map[netip.Addr]bool
	freeAt   map[netip.Addr]time.Time // 解放時刻（クールダウン判定用）
	next     int                      // 次に試すホストオクテット (2..254)
}

// New は指定の IPv4 /24 プレフィックスで Allocator を生成する。
// ホストアドレス(.1)は予約済みとしてマークする。
func New(prefix netip.Prefix, cooldown time.Duration) (*Allocator, error) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is4() || prefix.Bits() != 24 {
		return nil, errors.New("ipam: prefix must be an IPv4 /24")
	}
	base := prefix.Addr()
	a := &Allocator{
		base:     base,
		host:     addrWithLastOctet(base, 1),
		cooldown: cooldown,
		inUse:    make(map[netip.Addr]bool),
		freeAt:   make(map[netip.Addr]time.Time),
		next:     2,
	}
	a.inUse[a.host] = true
	return a, nil
}

// HostIP はホストに予約されたアドレス(.1)を返す。
func (a *Allocator) HostIP() netip.Addr { return a.host }

// Allocate は未使用かつクールダウンを経過したアドレスを 1 つ割り当てて返す。
// 空きが無い場合は ErrExhausted を返す。now は現在時刻。
func (a *Allocator) Allocate(now time.Time) (netip.Addr, error) {
	// .2 .. .254 の 253 個を一巡走査する。
	for i := 0; i < 253; i++ {
		octet := a.next
		a.next++
		if a.next > 254 {
			a.next = 2
		}

		addr := addrWithLastOctet(a.base, byte(octet))
		if a.inUse[addr] {
			continue
		}
		if freed, ok := a.freeAt[addr]; ok {
			if now.Sub(freed) < a.cooldown {
				continue // クールダウン中
			}
			delete(a.freeAt, addr)
		}
		a.inUse[addr] = true
		return addr, nil
	}
	return netip.Addr{}, ErrExhausted
}

// Release は割当済みアドレスを解放する。解放時刻を記録し、以後クールダウンが
// 経過するまで再割当対象から外す。ホストアドレスは解放できない。
func (a *Allocator) Release(addr netip.Addr, now time.Time) error {
	if addr == a.host {
		return ErrReleaseHost
	}
	if !a.inUse[addr] {
		return ErrNotAllocated
	}
	delete(a.inUse, addr)
	a.freeAt[addr] = now
	return nil
}

// InUse は指定アドレスが現在割当中かを返す。
func (a *Allocator) InUse(addr netip.Addr) bool { return a.inUse[addr] }

func addrWithLastOctet(base netip.Addr, octet byte) netip.Addr {
	b := base.As4()
	b[3] = octet
	return netip.AddrFrom4(b)
}
