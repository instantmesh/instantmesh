// Package usage は共有サービスの利用記録（要件定義書 §4.7）を保持する純粋ロジック。
//
// 記録するのは「どのピアが・どの共有サービス（ポート）へ・いつ・何バイト」だけで、通信内容は
// 一切扱わない（設計原則4 と同じ方針）。**計上はホスト側クライアントで行う** —— サーバーは E2E
// 暗号化された通信を復号できず、してはならないため（設計原則2・§4.7）。
//
// 時刻は now 注入で受け取り、内部に時計を持たない（決定的テストのため）。計上はデータパス
// （仮想NICの読み書き）から、読み出しは GUI から呼ばれるためゴルーチンセーフにする。
package usage

import (
	"net/netip"
	"sort"
	"sync"
	"time"
)

// Key は計上の単位。ピア（ゲスト）のメッシュIP と、共有サービスのポート番号の組。
type Key struct {
	Peer netip.Addr
	Port uint16
}

// Record は 1 単位ぶんの記録。
type Record struct {
	Peer string `json:"peer"`
	Port int    `json:"port"`
	// BytesIn はピアからホストへ流れたバイト数（要求）。
	BytesIn int64 `json:"bytesIn"`
	// BytesOut はホストからピアへ流れたバイト数（応答）。推論の応答はこちらに乗る。
	BytesOut int64 `json:"bytesOut"`
	// FirstSeen / LastSeen は最初と直近の観測時刻。
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// entry は内部の集計値。
type entry struct {
	in, out             int64
	firstSeen, lastSeen time.Time
}

// Recorder は利用記録の集計器。ゼロ値は使わず New で初期化する。
type Recorder struct {
	mu      sync.Mutex
	entries map[Key]*entry
}

// New は空の集計器を返す。
func New() *Recorder {
	return &Recorder{entries: make(map[Key]*entry)}
}

// AddIn はピア → ホスト方向のバイト数を計上する。
func (r *Recorder) AddIn(peer netip.Addr, port uint16, n int, now time.Time) {
	r.add(Key{Peer: peer, Port: port}, int64(n), 0, now)
}

// AddOut はホスト → ピア方向のバイト数を計上する。
func (r *Recorder) AddOut(peer netip.Addr, port uint16, n int, now time.Time) {
	r.add(Key{Peer: peer, Port: port}, 0, int64(n), now)
}

func (r *Recorder) add(k Key, in, out int64, now time.Time) {
	if !k.Peer.IsValid() || k.Port == 0 {
		return // 計上単位を特定できないものは記録しない
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	e, ok := r.entries[k]
	if !ok {
		e = &entry{firstSeen: now}
		r.entries[k] = e
	}
	e.in += in
	e.out += out
	e.lastSeen = now
}

// Snapshot は現在の記録を決定的な順序（ピア → ポートの昇順）で返す。
func (r *Recorder) Snapshot() []Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Record, 0, len(r.entries))
	for k, e := range r.entries {
		out = append(out, Record{
			Peer:      k.Peer.String(),
			Port:      int(k.Port),
			BytesIn:   e.in,
			BytesOut:  e.out,
			FirstSeen: e.firstSeen,
			LastSeen:  e.lastSeen,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Peer != out[j].Peer {
			return out[i].Peer < out[j].Peer
		}
		return out[i].Port < out[j].Port
	})
	return out
}

// Totals は全体の合計（受信・送信バイト）を返す。
func (r *Recorder) Totals() (in, out int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, e := range r.entries {
		in += e.in
		out += e.out
	}
	return in, out
}

// Forget は指定ピアの記録を消す（キック・離脱で記録を残さない運用にする場合に使う）。
func (r *Recorder) Forget(peer netip.Addr) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k := range r.entries {
		if k.Peer == peer {
			delete(r.entries, k)
		}
	}
}

// Reset は全ての記録を消す（セッション終了時）。
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.entries)
}
