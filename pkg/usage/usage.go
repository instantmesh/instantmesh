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
	// Requests は共有サービスへのリクエスト数（L7 で数えた場合のみ。L4 のみの経路では 0）。
	Requests int64 `json:"requests"`
	// FirstSeen / LastSeen は最初と直近の観測時刻。
	FirstSeen time.Time `json:"firstSeen"`
	LastSeen  time.Time `json:"lastSeen"`
}

// Limit はゲスト単位の上限（要件 §4.7・有料プラン機能）。0 は無制限。
// 超過時に遮断するのは**当該ゲストのみ**で、ルーム全体には影響させない。
type Limit struct {
	// MaxBytes は送受信の合計バイト数の上限。
	MaxBytes int64 `json:"maxBytes"`
	// MaxRequests はリクエスト数の上限。
	MaxRequests int64 `json:"maxRequests"`
}

// entry は内部の集計値。
type entry struct {
	in, out             int64
	requests            int64
	firstSeen, lastSeen time.Time
}

// Recorder は利用記録の集計器。ゼロ値は使わず New で初期化する。
type Recorder struct {
	mu      sync.Mutex
	entries map[Key]*entry
	limits  map[netip.Addr]Limit
}

// New は空の集計器を返す。
func New() *Recorder {
	return &Recorder{entries: make(map[Key]*entry), limits: make(map[netip.Addr]Limit)}
}

// AddIn はピア → ホスト方向のバイト数を計上する。
func (r *Recorder) AddIn(peer netip.Addr, port uint16, n int, now time.Time) {
	r.add(Key{Peer: peer, Port: port}, int64(n), 0, 0, now)
}

// AddOut はホスト → ピア方向のバイト数を計上する。
func (r *Recorder) AddOut(peer netip.Addr, port uint16, n int, now time.Time) {
	r.add(Key{Peer: peer, Port: port}, 0, int64(n), 0, now)
}

// AddRequest はリクエスト 1 件を計上する（L7 ゲートを通る共有サービスのみ）。
func (r *Recorder) AddRequest(peer netip.Addr, port uint16, now time.Time) {
	r.add(Key{Peer: peer, Port: port}, 0, 0, 1, now)
}

// SetLimit はゲスト単位の上限を設定する（ゼロ値の Limit で解除）。
func (r *Recorder) SetLimit(peer netip.Addr, l Limit) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if l.MaxBytes <= 0 && l.MaxRequests <= 0 {
		delete(r.limits, peer)
		return
	}
	r.limits[peer] = l
}

// LimitFor はゲストに設定された上限を返す（未設定はゼロ値＝無制限）。
func (r *Recorder) LimitFor(peer netip.Addr) Limit {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.limits[peer]
}

// HasLimits はいずれかのゲストに上限が設定されているかを返す。
//
// 呼び出し側（cmd/client）は「上限を強制するために L7 で数える必要があるか」の判定に使う。
// 上限の集合を持つのは本パッケージなので、外から個々のゲストを列挙して LimitFor を引き直す
// 必要はない（表示状態にまだ現れていないゲストの上限も取りこぼさない）。
func (r *Recorder) HasLimits() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.limits) > 0
}

// Exceeded はゲストが上限に達しているかを返す。上限未設定なら常に false。
// 判定に使うのは当該ゲストの全共有サービスの合計。
func (r *Recorder) Exceeded(peer netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	l, ok := r.limits[peer]
	if !ok {
		return false
	}
	var bytes, reqs int64
	for k, e := range r.entries {
		if k.Peer != peer {
			continue
		}
		bytes += e.in + e.out
		reqs += e.requests
	}
	return (l.MaxBytes > 0 && bytes >= l.MaxBytes) || (l.MaxRequests > 0 && reqs >= l.MaxRequests)
}

// add は計上単位を解決し、集計値へ加算する（全ての Add* の実体）。
func (r *Recorder) add(k Key, in, out, reqs int64, now time.Time) {
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
	e.requests += reqs
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
			Requests:  e.requests,
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
	delete(r.limits, peer)
}

// Reset は全ての記録を消す（セッション終了時）。
func (r *Recorder) Reset() {
	r.mu.Lock()
	defer r.mu.Unlock()
	clear(r.entries)
	clear(r.limits)
}
