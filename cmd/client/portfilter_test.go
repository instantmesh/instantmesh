package main

import (
	"encoding/binary"
	"errors"
	"testing"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/instantmesh/instantmesh/pkg/plan"
)

// fakeTun は tun.Device のフェイク。Read で packets を返す。Read 以外は本テストで呼ばれない
// ため、埋め込んだ nil インターフェースの既定（呼べば panic）に委ねる。
type fakeTun struct {
	tun.Device
	packets [][]byte
	readErr error
}

func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	// packets を詰めたうえで readErr を返す。NativeTun のように n(>0) とエラーを同時返却する
	// ケース（GRO 分割時の ErrTooManySegments 等）を模す（packets が空なら n=0 のエラーになる）。
	n := 0
	for i, p := range f.packets {
		if i >= len(bufs) {
			break
		}
		copy(bufs[i][offset:], p)
		sizes[i] = len(p)
		n++
	}
	return n, f.readErr
}

// ipv4 は proto と（TCP/UDP の場合）宛先ポートを持つ最小の IPv4 パケットを作る。
func ipv4(proto byte, dstPort uint16) []byte {
	p := make([]byte, 24) // 20B IPv4 ヘッダ + 4B（L4 先頭のポート領域）
	p[0] = 0x45           // version=4, IHL=5(=20B)
	p[9] = proto
	binary.BigEndian.PutUint16(p[22:24], dstPort) // 宛先ポート = ihl(20)+2
	return p
}

const (
	protoTCP  = 6
	protoUDP  = 17
	protoICMP = 1
)

// readAll は n 件のバッファを用意して fd.Read を 1 回呼び、保持されたパケット列を返す。
func readAll(t *testing.T, fd *filterDevice, capacity int) [][]byte {
	t.Helper()
	bufs := make([][]byte, capacity)
	sizes := make([]int, capacity)
	for i := range bufs {
		bufs[i] = make([]byte, 64)
	}
	n, err := fd.Read(bufs, sizes, 0)
	if err != nil {
		t.Fatalf("Read エラー: %v", err)
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = append([]byte(nil), bufs[i][:sizes[i]]...)
	}
	return out
}

func TestFilterDevicePassthroughWhenUnset(t *testing.T) {
	// spec 未設定（プラン未確定）なら全て素通し。
	ft := &fakeTun{packets: [][]byte{ipv4(protoUDP, 53), ipv4(protoTCP, 22)}}
	fd := newFilterDevice(ft)
	if got := readAll(t, fd, 4); len(got) != 2 {
		t.Errorf("未設定時は全通し: got %d want 2", len(got))
	}
}

func TestFilterDeviceProPassesAll(t *testing.T) {
	// ポート制限なし（Pro）は全て通す。
	ft := &fakeTun{packets: [][]byte{ipv4(protoUDP, 53), ipv4(protoTCP, 22)}}
	fd := newFilterDevice(ft)
	fd.SetSpec(plan.MustLookup(plan.Pro))
	if got := readAll(t, fd, 4); len(got) != 2 {
		t.Errorf("Pro は全通し: got %d want 2", len(got))
	}
}

func TestFilterDeviceFreeDropsDisallowed(t *testing.T) {
	// Free: ICMP と許可 TCP(443) は通し、許可外 TCP(22)・UDP(53) は破棄する。前詰めも確認する。
	ft := &fakeTun{packets: [][]byte{
		ipv4(protoTCP, 22),   // drop
		ipv4(protoTCP, 443),  // keep
		ipv4(protoUDP, 53),   // drop
		ipv4(protoICMP, 0),   // keep
	}}
	fd := newFilterDevice(ft)
	fd.SetSpec(plan.MustLookup(plan.Free))
	got := readAll(t, fd, 8)
	if len(got) != 2 {
		t.Fatalf("Free は許可分のみ通す: got %d want 2", len(got))
	}
	// 前詰め後、[0]=443(TCP)、[1]=ICMP。
	if got[0][9] != protoTCP || binary.BigEndian.Uint16(got[0][22:24]) != 443 {
		t.Errorf("先頭は TCP/443 のはず: proto=%d port=%d", got[0][9], binary.BigEndian.Uint16(got[0][22:24]))
	}
	if got[1][9] != protoICMP {
		t.Errorf("2 件目は ICMP のはず: proto=%d", got[1][9])
	}
}

func TestFilterDeviceReadError(t *testing.T) {
	sentinel := errors.New("read failed")
	fd := newFilterDevice(&fakeTun{readErr: sentinel})
	bufs := [][]byte{make([]byte, 64)}
	sizes := make([]int, 1)
	if _, err := fd.Read(bufs, sizes, 0); !errors.Is(err, sentinel) {
		t.Errorf("下層 Read のエラーを伝播すべき: %v", err)
	}
}

func TestFilterDeviceFiltersDespitePartialReadError(t *testing.T) {
	// n>0 とエラーを同時返却するケース（GRO 分割時の ErrTooManySegments 等）でも、返された n 件には
	// フィルタが適用され、かつエラーは呼び出し側へ伝播することを確認する（フィルタバイパス防止）。
	sentinel := errors.New("too many segments")
	ft := &fakeTun{
		packets: [][]byte{
			ipv4(protoUDP, 53),  // drop
			ipv4(protoTCP, 443), // keep
		},
		readErr: sentinel,
	}
	fd := newFilterDevice(ft)
	fd.SetSpec(plan.MustLookup(plan.Free))
	bufs := make([][]byte, 4)
	sizes := make([]int, 4)
	for i := range bufs {
		bufs[i] = make([]byte, 64)
	}
	n, err := fd.Read(bufs, sizes, 0)
	if !errors.Is(err, sentinel) {
		t.Errorf("エラーは呼び出し側へ伝播すべき: %v", err)
	}
	if n != 1 {
		t.Fatalf("エラー時も許可分のみ通すべき: got %d want 1", n)
	}
	if bufs[0][9] != protoTCP || binary.BigEndian.Uint16(bufs[0][22:24]) != 443 {
		t.Errorf("残った 1 件は TCP/443 のはず: proto=%d port=%d", bufs[0][9], binary.BigEndian.Uint16(bufs[0][22:24]))
	}
}

func TestTunnelSetPlanNilFilter(t *testing.T) {
	// filter が nil の Tunnel でも SetPlan は panic せず no-op。
	(&Tunnel{}).SetPlan(plan.MustLookup(plan.Free))
}
