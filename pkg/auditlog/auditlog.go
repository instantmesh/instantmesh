// Package auditlog は接続メタデータ監査ログの純粋ロジック（イベント表現・バッチバッファ・
// NDJSON シリアライズ・オブジェクトキー生成）を提供する。
//
// 監査ログは「どのホストが・いつルーム作成／どの IP のゲストが参加」といった接続メタデータ
// のみを扱い、通信ペイロードは一切含めない（要件 §監査ログ）。Event の型がこの契約を体現する。
//
// 本パッケージは I/O を持たない。実際の書き込み先（S3 等）への PUT・並行制御・定期フラッシュ
// のゴルーチンは cmd 側アダプタが担い、時刻は now 引数で注入する（決定的テストのため）。
package auditlog

import (
	"bytes"
	"encoding/json"
	"strings"
	"time"
)

// 監査イベント種別。通信内容は決して含めず、接続メタデータのみを扱う。
const (
	KindConnect    = "connect"     // 接続確立
	KindDisconnect = "disconnect"  // 接続切断
	KindRoomCreate = "room_create" // ルーム作成（どのホストが・いつ・どのルームを）
	KindGuestJoin  = "guest_join"  // ゲスト参加（どの IP が・いつ・どのルームへ）
)

// Event は監査ログ 1 件。接続メタデータのみを保持する（通信ペイロードは含めない）。
type Event struct {
	Time      time.Time `json:"time"`
	Kind      string    `json:"kind"`
	Role      string    `json:"role"`
	AccountID string    `json:"account_id,omitempty"` // ホストのみ
	RemoteIP  string    `json:"remote_ip,omitempty"`
	RoomID    string    `json:"room_id,omitempty"` // 判明している場合
}

// Buffer は監査イベントをためてバッチにする純粋バッファ。並行制御は行わない（呼び出し側が
// 直列化する）。件数上限（maxBatch）または最古イベントの経過時間（maxAge）でフラッシュ要否を
// 判定する。maxBatch<=0 は件数トリガ無効、maxAge<=0 は時間トリガ無効を意味する。
type Buffer struct {
	maxBatch int
	maxAge   time.Duration
	events   []Event
	oldest   time.Time // 現バッチの最古イベント追加時刻
}

// NewBuffer はバッファを構築する。
func NewBuffer(maxBatch int, maxAge time.Duration) *Buffer {
	return &Buffer{maxBatch: maxBatch, maxAge: maxAge}
}

// Add はイベントを追加し、件数トリガでフラッシュすべきなら true を返す。
func (b *Buffer) Add(ev Event, now time.Time) bool {
	if len(b.events) == 0 {
		b.oldest = now
	}
	b.events = append(b.events, ev)
	return b.maxBatch > 0 && len(b.events) >= b.maxBatch
}

// DueByAge は最古イベントが maxAge を超過していればフラッシュ要と判断する（ticker 用）。
func (b *Buffer) DueByAge(now time.Time) bool {
	return len(b.events) > 0 && b.maxAge > 0 && !now.Before(b.oldest.Add(b.maxAge))
}

// Len は現在バッファ中のイベント数。
func (b *Buffer) Len() int { return len(b.events) }

// Flush は現在のイベントを取り出しバッファを空にする（空なら nil）。
func (b *Buffer) Flush() []Event {
	if len(b.events) == 0 {
		return nil
	}
	out := b.events
	b.events = nil
	return out
}

// MarshalNDJSON はイベント群を NDJSON（1 行 1 JSON オブジェクト）へ符号化する。空スライスは
// 空バイト列を返す。Event は string/time のみで構成され符号化に失敗しないため、error は返さない。
func MarshalNDJSON(events []Event) []byte {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	for _, ev := range events {
		// bytes.Buffer への書き込みと Event の符号化はいずれも失敗しないため戻り値は常に nil。
		_ = enc.Encode(ev)
	}
	return buf.Bytes()
}

// ObjectKey は日付パーティション付きの監査オブジェクトキーを返す。suffix は一意性のため呼び出し
// 側が与える（連番やランダム文字列）。例: audit/2026/07/16/20260716T045301Z-000001.ndjson
func ObjectKey(prefix string, t time.Time, suffix string) string {
	u := t.UTC()
	key := u.Format("2006/01/02/20060102T150405Z") + "-" + suffix + ".ndjson"
	prefix = strings.TrimRight(prefix, "/")
	if prefix == "" {
		return key
	}
	return prefix + "/" + key
}
