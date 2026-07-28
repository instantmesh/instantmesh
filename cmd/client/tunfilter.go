package main

// 本ファイルは共有の選択を到達制御として強制する層（要件定義書 §4.6.1・付録C.9 D-11）。
//
// メッシュに参加した承認済みゲストは、そのままではホストのメッシュIP の全ポートへ到達できる。
// wireguard-go の tun.Device を包み、**ピアから届いて OS へ渡される直前**のパケットを検査して、
// 共有していない宛先への新規接続を落とす。同じ地点で「どのピアが・どの共有サービスへ・何バイト」
// を計上し、§4.7 の利用記録の土台にする。
//
// 可否判定とパケット解析は純粋ロジック（pkg/pktfilter）、計上は pkg/usage にあり、ここは
// wireguard-go のインターフェースへの適合とデータ競合の回避だけを担う（§4.6.5 と同じ分割）。
//
// 方向の対応:
//   - Write … ピア → 自ホスト（復号済み）。ここで落とし、受信バイトを計上する。
//   - Read  … 自ホスト → ピア（暗号化前）。落とさず、応答バイトのみ計上する（推論の応答は
//     こちらに乗るため、記録の主対象になる）。

import (
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/instantmesh/instantmesh/pkg/pktfilter"
	"github.com/instantmesh/instantmesh/pkg/usage"
	"golang.zx2c4.com/wireguard/tun"
)

// maxFilterBatch は 1 回の Write で受け取るパケット数の想定上限（wireguard-go のバッチは
// これより小さい）。超えた場合だけ判定結果の置き場をヒープへ確保する。
const maxFilterBatch = 256

// filterDevice は tun.Device を包み、受信パケットの選別と通信量の計上を行う。
// ポリシーはセッション中に何度も差し替わる（共有の変更のたび）ため atomic で保持し、
// データパス側はロックを取らずに読む。
type filterDevice struct {
	tun.Device

	policy atomic.Pointer[pktfilter.Policy]
	rec    *usage.Recorder
	now    func() time.Time

	// enabled が false の間は素通しする（メッシュIP 確定前など、自分宛の判定ができない時期）。
	enabled atomic.Bool
	// dropped は落としたパケット数（診断用）。
	dropped atomic.Int64
}

// newFilterDevice は素通し状態のフィルタ付きデバイスを返す。ポリシーは setPolicy で与える。
func newFilterDevice(dev tun.Device, rec *usage.Recorder, now func() time.Time) *filterDevice {
	return &filterDevice{Device: dev, rec: rec, now: now}
}

// setPolicy は可否判定の規則を差し替え、以後の受信パケットに適用する。
func (d *filterDevice) setPolicy(p pktfilter.Policy) {
	d.policy.Store(&p)
	d.enabled.Store(true)
}

// disable は選別を止めて素通しに戻す（セッション終了時）。計上は続けない。
func (d *filterDevice) disable() { d.enabled.Store(false) }

// droppedCount は落としたパケット数を返す（診断・テスト用）。
func (d *filterDevice) droppedCount() int64 { return d.dropped.Load() }

// Write はピアから届いたパケットを OS へ渡す。共有していない宛先への新規接続は落とし、
// 通したぶんを受信バイトとして計上する。
//
// 落としたパケットはそのまま黙って捨てる（RST や ICMP unreachable を返さない）。共有して
// いないポートの存在を相手に知らせないため。
func (d *filterDevice) Write(bufs [][]byte, offset int) (int, error) {
	pol := d.policy.Load()
	if !d.enabled.Load() || pol == nil {
		return d.Device.Write(bufs, offset)
	}

	// 判定結果はスタック上の配列へ置き、1 個も落とさない通常時は詰め直しも割当も行わない
	// （bufs は wireguard-go が再利用するバッファ列なので、その場で書き換えてはならない）。
	var stack [maxFilterBatch]bool
	allow := stack[:0]
	if len(bufs) > maxFilterBatch {
		allow = make([]bool, 0, len(bufs))
	}

	now := d.now()
	dropped := 0
	for _, b := range bufs {
		ok := false
		if offset <= len(b) {
			if pkt, parsed := pktfilter.Parse(b[offset:]); parsed && pol.Allow(pkt) {
				ok = true
				// 計上は共有サービス宛だけに限る（制御用ポートや ICMP は利用記録に混ぜない）。
				if pol.IsShared(pkt.DstPort) {
					d.rec.AddIn(pkt.Src, pkt.DstPort, pkt.Size, now)
				}
			}
		}
		if !ok {
			dropped++
		}
		allow = append(allow, ok)
	}
	if dropped == 0 {
		return d.Device.Write(bufs, offset)
	}
	d.dropped.Add(int64(dropped))
	if dropped == len(bufs) {
		return 0, nil
	}

	keep := make([][]byte, 0, len(bufs)-dropped)
	for i, b := range bufs {
		if allow[i] {
			keep = append(keep, b)
		}
	}
	return d.Device.Write(keep, offset)
}

// Read は自ホストからピアへ出ていくパケットを取り出す。選別はせず、共有サービスの応答バイトを
// 計上するだけに留める（出ていく通信を止めるのは本層の役目ではない）。
func (d *filterDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	if n == 0 || !d.enabled.Load() {
		return n, err
	}
	now := d.now()
	for i := 0; i < n; i++ {
		if offset+sizes[i] > len(bufs[i]) {
			continue
		}
		pkt, ok := pktfilter.Parse(bufs[i][offset : offset+sizes[i]])
		if !ok {
			continue
		}
		// 宛先がピア、送信元ポートが共有サービスのポート（＝共有への応答）。ホスト側から
		// 張った接続の送信（送信元が一時ポート）は共有の利用ではないので数えない。
		if pol := d.policy.Load(); pol != nil && pol.IsShared(pkt.SrcPort) {
			d.rec.AddOut(pkt.Dst, pkt.SrcPort, pkt.Size, now)
		}
	}
	return n, err
}

// controlPorts は共有の有無に関わらず通すポート。名前解決のローカルレスポンダ（§4.6.3）を
// 落とすと名前が引けなくなるため常に許可する。
func controlPorts() []int { return []int{dnsPort} }

// applyFilterPolicy は共有中ポートを到達制御へ反映する（dev が nil なら何もしない）。
func applyFilterPolicy(dev *filterDevice, self netip.Addr, sharedPorts []int) {
	if dev == nil {
		return
	}
	// ICMP は疎通確認の基本機能であり共有の有無と独立なので常に通す。
	dev.setPolicy(pktfilter.NewPolicy(self, sharedPorts, controlPorts(), true))
}
