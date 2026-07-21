package main

// 本ファイルは pkg/appstate の純粋ビューモデルを、cmd/client の並行文脈でゴルーチンセーフに
// 扱うための薄いアダプタ。シグナリング受信ループ（唯一の書き手）と GUI の localhost HTTP
// サーバー（読み手）が同じ Model を共有するため、更新と読み取りを RWMutex で直列化する。
//
// appstate.Model 自体は時刻・トランスポート非依存の純粋状態機械であり、ロックを持ち込まない
// （設計原則1: UI とコアの分離）。並行制御はこの I/O アダプタ層に閉じる。

import (
	"sync"

	"github.com/instantmesh/instantmesh/pkg/appstate"
)

// viewStore は appstate.Model をゴルーチンセーフに包む。update で状態遷移を適用し、
// snapshot で表示用スナップショットを読み出す。書き手（受信ループ）は 1 本に限定し、
// 読み手（HTTP ハンドラ）は複数でも安全にする。
type viewStore struct {
	mu    sync.RWMutex
	model *appstate.Model
}

// newViewStore は初期状態（Idle・役割未確定）の viewStore を返す。
func newViewStore() *viewStore {
	return &viewStore{model: appstate.New()}
}

// update は排他ロック下で Model へ遷移を適用する。appstate の各メソッドは不正遷移を
// センチネルエラーで返すが、受信ループはサーバー権威の状態を反映するだけなので呼び出し側は
// 通常エラーを無視してよい（従来のヘッドレス実装と同じ挙動）。
func (s *viewStore) update(fn func(m *appstate.Model)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(s.model)
}

// reset は Model を初期状態（Idle）へ置き換える。GUI が前回セッション終了後に新しい
// セッション（ホスト/参加）を開始する際、古い終了状態を引きずらないために使う。
func (s *viewStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.model = appstate.New()
}

// snapshot は共有ロック下で現在の表示用スナップショットを返す。JSON へそのまま符号化できる。
func (s *viewStore) snapshot() appstate.Snapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.model.View()
}

// guestIP は参加確定済みゲストの割当 IP を共有ロック下で返す（ホストが peer_info 受信時に
// 相手ゲストの allowed_ip を引くのに使う）。未確定・不在は ok=false。
func (s *viewStore) guestIP(pubKey string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.model.GuestIP(pubKey)
}

// verifyHostKey はシグナリング経由で受け取ったホスト公開鍵が招待に埋め込まれた鍵と一致するかを
// 共有ロック下で定数時間照合する（ゲストの帯域外 MITM 検知）。
func (s *viewStore) verifyHostKey(received string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.model.VerifyHostKey(received)
}
