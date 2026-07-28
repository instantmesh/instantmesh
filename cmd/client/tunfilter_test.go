package main

import (
	"encoding/binary"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/usage"
	"golang.zx2c4.com/wireguard/tun"
)

// fakeTun は tun.Device を満たすテスト用デバイス。Write されたパケットを記録し、
// Read では queued のパケットを返す。
type fakeTun struct {
	written [][]byte
	queued  [][]byte
	events  chan tun.Event
}

func newFakeTun() *fakeTun { return &fakeTun{events: make(chan tun.Event, 1)} }

func (f *fakeTun) File() *os.File { return nil }
func (f *fakeTun) Write(bufs [][]byte, offset int) (int, error) {
	for _, b := range bufs {
		f.written = append(f.written, append([]byte(nil), b[offset:]...))
	}
	return len(bufs), nil
}
func (f *fakeTun) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n := 0
	for i := range bufs {
		if len(f.queued) == 0 {
			break
		}
		p := f.queued[0]
		f.queued = f.queued[1:]
		copy(bufs[i][offset:], p)
		sizes[i] = len(p)
		n++
	}
	return n, nil
}
func (f *fakeTun) MTU() (int, error)        { return 1420, nil }
func (f *fakeTun) Name() (string, error)    { return "faketun", nil }
func (f *fakeTun) Events() <-chan tun.Event { return f.events }
func (f *fakeTun) Close() error             { close(f.events); return nil }
func (f *fakeTun) BatchSize() int           { return 1 }

// ipv4 はテスト用の IPv4 パケットを組み立てる（TCP は flags、UDP/ICMP は 0 を渡す）。
func ipv4(src, dst string, proto byte, srcPort, dstPort uint16, flags byte, payload int) []byte {
	hdr := 20
	upper := 0
	switch proto {
	case 6:
		upper = 20
	case 17:
		upper = 8
	}
	b := make([]byte, hdr+upper+payload)
	b[0] = 0x45
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)))
	b[9] = proto
	copy(b[12:16], netip.MustParseAddr(src).AsSlice())
	copy(b[16:20], netip.MustParseAddr(dst).AsSlice())
	if upper > 0 {
		binary.BigEndian.PutUint16(b[hdr:hdr+2], srcPort)
		binary.BigEndian.PutUint16(b[hdr+2:hdr+4], dstPort)
	}
	if proto == 6 {
		b[hdr+13] = flags
	}
	return b
}

const (
	protoTCPTest  = 6
	protoUDPTest  = 17
	protoICMPTest = 1
	synFlag       = 0x02
	ackFlag       = 0x10
)

// TestFilterDeviceEnforcesSharedPorts は共有していない宛先への新規接続だけが落ち、共有中の
// サービス・ICMP・名前解決（:53）は通ることを確かめる（付録C.9 D-11）。
func TestFilterDeviceEnforcesSharedPorts(t *testing.T) {
	ft := newFakeTun()
	rec := usage.New()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	d := newFilterDevice(ft, rec, func() time.Time { return now })

	self := netip.MustParseAddr("10.0.0.1")
	guest := "10.0.0.2"
	applyFilterPolicy(d, self, []int{11434})

	cases := []struct {
		name string
		pkt  []byte
		pass bool
	}{
		{"共有中サービスへの新規接続", ipv4(guest, "10.0.0.1", protoTCPTest, 51000, 11434, synFlag, 100), true},
		{"共有していない SSH への新規接続", ipv4(guest, "10.0.0.1", protoTCPTest, 51001, 22, synFlag, 0), false},
		{"確立済み接続（戻り）", ipv4(guest, "10.0.0.1", protoTCPTest, 51002, 40000, ackFlag, 0), true},
		{"名前解決(:53/UDP)", ipv4(guest, "10.0.0.1", protoUDPTest, 5000, 53, 0, 30), true},
		{"共有していない UDP", ipv4(guest, "10.0.0.1", protoUDPTest, 5000, 5353, 0, 30), false},
		{"ICMP(ping)", ipv4(guest, "10.0.0.1", protoICMPTest, 0, 0, 0, 8), true},
		{"他ピア宛の転送", ipv4(guest, "10.0.0.3", protoTCPTest, 51003, 11434, synFlag, 0), false},
		{"解釈できないパケット", []byte{0x00, 0x01}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			before := len(ft.written)
			if _, err := d.Write([][]byte{c.pkt}, 0); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if passed := len(ft.written) > before; passed != c.pass {
				t.Errorf("通過 = %v, want %v", passed, c.pass)
			}
		})
	}
	if d.droppedCount() != 4 {
		t.Errorf("落とした数 = %d, want 4", d.droppedCount())
	}

	// 計上は共有サービス宛だけ（ICMP・DNS・戻りは記録しない）。
	got := rec.Snapshot()
	if len(got) != 1 {
		t.Fatalf("記録 = %+v", got)
	}
	if got[0].Peer != guest || got[0].Port != 11434 || got[0].BytesIn != 140 {
		t.Errorf("記録 = %+v", got[0])
	}
}

// TestFilterDeviceBatch は複数パケットのバッチで、通すものだけが下位デバイスへ渡ることを確かめる
// （wireguard-go が再利用するバッファ列を壊さないこと）。
func TestFilterDeviceBatch(t *testing.T) {
	ft := newFakeTun()
	d := newFilterDevice(ft, usage.New(), time.Now)
	applyFilterPolicy(d, netip.MustParseAddr("10.0.0.1"), []int{11434})

	allow := ipv4("10.0.0.2", "10.0.0.1", protoTCPTest, 51000, 11434, synFlag, 1)
	deny := ipv4("10.0.0.2", "10.0.0.1", protoTCPTest, 51000, 22, synFlag, 2)
	bufs := [][]byte{deny, allow, deny}
	orig := [][]byte{bufs[0], bufs[1], bufs[2]}

	if _, err := d.Write(bufs, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(ft.written) != 1 || len(ft.written[0]) != len(allow) {
		t.Fatalf("下位へ渡ったパケット = %d 件", len(ft.written))
	}
	// 呼び出し側のスライスを書き換えていないこと。
	for i := range bufs {
		if &bufs[i][0] != &orig[i][0] {
			t.Errorf("bufs[%d] が入れ替わっている", i)
		}
	}
}

// TestFilterDevicePassThrough はポリシー未設定・無効時に素通しすることを確かめる。
func TestFilterDevicePassThrough(t *testing.T) {
	ft := newFakeTun()
	d := newFilterDevice(ft, usage.New(), time.Now)
	pkt := ipv4("10.0.0.2", "10.0.0.1", protoTCPTest, 51000, 22, synFlag, 0)

	if _, err := d.Write([][]byte{pkt}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(ft.written) != 1 {
		t.Error("ポリシー未設定で落とした（メッシュIP 確定前は素通しであるべき）")
	}
	applyFilterPolicy(d, netip.MustParseAddr("10.0.0.1"), nil)
	if _, err := d.Write([][]byte{pkt}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(ft.written) != 1 {
		t.Error("ポリシー適用後に落ちていない")
	}
	d.disable()
	if _, err := d.Write([][]byte{pkt}, 0); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if len(ft.written) != 2 {
		t.Error("disable 後は素通しであるべき")
	}
}

// TestFilterDeviceRecordsResponse は共有サービスからの応答（送信方向）を計上することを確かめる。
// 推論の応答はここに乗るため、利用記録（§4.7）の主対象になる。
func TestFilterDeviceRecordsResponse(t *testing.T) {
	ft := newFakeTun()
	rec := usage.New()
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	d := newFilterDevice(ft, rec, func() time.Time { return now })
	applyFilterPolicy(d, netip.MustParseAddr("10.0.0.1"), []int{11434})

	// 共有サービス（11434）からゲストへの応答と、ホスト発の一時ポートからの送信。
	ft.queued = [][]byte{
		ipv4("10.0.0.1", "10.0.0.2", protoTCPTest, 11434, 51000, ackFlag, 500),
		ipv4("10.0.0.1", "10.0.0.2", protoTCPTest, 40000, 8080, synFlag, 10),
	}
	bufs := [][]byte{make([]byte, 2048), make([]byte, 2048)}
	sizes := make([]int, 2)
	n, err := d.Read(bufs, sizes, 0)
	if err != nil || n != 2 {
		t.Fatalf("Read = %d, %v", n, err)
	}

	got := rec.Snapshot()
	if len(got) != 1 {
		t.Fatalf("記録 = %+v（共有サービスの応答だけを数えるべき）", got)
	}
	if got[0].Port != 11434 || got[0].BytesOut != 540 || got[0].Peer != "10.0.0.2" {
		t.Errorf("記録 = %+v", got[0])
	}
}
