package main

import (
	"sync/atomic"

	"golang.zx2c4.com/wireguard/tun"

	"github.com/instantmesh/instantmesh/pkg/plan"
	"github.com/instantmesh/instantmesh/pkg/portfilter"
)

// filterDevice は wireguard-go の tun.Device をラップし、無料版ポート制限（要件 §4.5）の
// 既定フィルタを適用する。仮想NICから読み出す送出パケット（ローカルアプリ → メッシュ）を検査し、
// プラン仕様で許可されないもの（UDP・許可外 TCP・解析不能）を破棄する（ICMP と許可 TCP ポートは通す）。
//
// プラン仕様はシグナリング（room_created / join_approved の Tier）で確定するため、それまでは未設定
// （＝素通し）で、確定後に SetSpec で設定する。tun.Device の Read は wireguard-go の受信ゴルーチンから、
// SetSpec はシグナリングのゴルーチンから呼ばれるため、spec は atomic で共有する。
//
// これはクライアント側の緩和策であり、クライアント改変でバイパスされうる（強制はリレー量制限・
// レート制限・監査ログで担保する。判定ロジックの正本は pkg/portfilter）。
type filterDevice struct {
	tun.Device
	spec atomic.Pointer[plan.Spec]
}

// newFilterDevice は下層デバイス d をラップした filterDevice を返す（初期状態は素通し）。
func newFilterDevice(d tun.Device) *filterDevice {
	return &filterDevice{Device: d}
}

// SetSpec は適用するプラン仕様を設定する（ポート制限なしプランでは実質何も破棄しない）。
func (d *filterDevice) SetSpec(s plan.Spec) { d.spec.Store(&s) }

// allow はパケット pkt を送出許可するか判定する。プラン未確定（spec 未設定）時は素通しする。
func (d *filterDevice) allow(pkt []byte) bool {
	s := d.spec.Load()
	if s == nil {
		return true
	}
	return portfilter.Allow(pkt, *s)
}

// Read は下層デバイスから読み出したパケットのうち、許可されないものを破棄し、残りを前詰めして返す。
// バッチ API（bufs/sizes/offset）に従い、保持するパケットを先頭スロットへ詰め直して件数を返す。
//
// エラーの有無に関わらず、返された n(>0) 件には必ずフィルタを適用する。Linux の NativeTun は
// GRO 分割時に有効パケット数 n(>0) と tun.ErrTooManySegments を同時返却しうる。wireguard-go は
// このエラーを消化して n 件を処理するため、err!=nil を理由に n 件を素通しさせるとフィルタが
// バイパスされる（Free プランで許可外パケットが送出されうる）。err はそのまま呼び出し側へ返す。
func (d *filterDevice) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	n, err := d.Device.Read(bufs, sizes, offset)
	kept := 0
	for i := 0; i < n; i++ {
		if d.allow(bufs[i][offset : offset+sizes[i]]) {
			if kept != i {
				copy(bufs[kept][offset:], bufs[i][offset:offset+sizes[i]])
				sizes[kept] = sizes[i]
			}
			kept++
		}
	}
	return kept, err
}

// SetPlan はトンネルの既定フィルタへプラン仕様を適用する（tun が仮想NICを持たない場合は no-op）。
func (t *Tunnel) SetPlan(spec plan.Spec) {
	if t.filter != nil {
		t.filter.SetSpec(spec)
	}
}
