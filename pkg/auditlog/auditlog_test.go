package auditlog

import (
	"strings"
	"testing"
	"time"
)

func TestBufferAddCountTrigger(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBuffer(3, time.Minute)

	if b.Add(Event{Kind: KindConnect}, now) {
		t.Error("1 件目でフラッシュ要になってはいけない")
	}
	if b.Add(Event{Kind: KindConnect}, now) {
		t.Error("2 件目でフラッシュ要になってはいけない")
	}
	if !b.Add(Event{Kind: KindConnect}, now) {
		t.Error("3 件目（maxBatch 到達）はフラッシュ要になるべき")
	}
	if b.Len() != 3 {
		t.Errorf("Len = %d, want 3", b.Len())
	}
}

func TestBufferNoCountTrigger(t *testing.T) {
	// maxBatch<=0 は件数トリガ無効。
	b := NewBuffer(0, time.Minute)
	for i := 0; i < 5; i++ {
		if b.Add(Event{}, time.Unix(int64(i), 0)) {
			t.Fatalf("maxBatch<=0 では件数フラッシュしないはず (i=%d)", i)
		}
	}
}

func TestBufferDueByAge(t *testing.T) {
	base := time.Unix(1000, 0)

	// 空バッファは age トリガしない。
	b := NewBuffer(100, time.Minute)
	if b.DueByAge(base.Add(time.Hour)) {
		t.Error("空バッファは DueByAge=false であるべき")
	}

	b.Add(Event{}, base)
	if b.DueByAge(base.Add(30 * time.Second)) {
		t.Error("maxAge 未満では DueByAge=false")
	}
	if !b.DueByAge(base.Add(time.Minute)) {
		t.Error("maxAge 到達で DueByAge=true")
	}

	// maxAge<=0 は時間トリガ無効。
	b2 := NewBuffer(100, 0)
	b2.Add(Event{}, base)
	if b2.DueByAge(base.Add(time.Hour)) {
		t.Error("maxAge<=0 では DueByAge=false")
	}
}

func TestBufferFlush(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBuffer(10, time.Minute)

	if b.Flush() != nil {
		t.Error("空バッファの Flush は nil")
	}

	b.Add(Event{Kind: KindRoomCreate, RoomID: "r1"}, now)
	b.Add(Event{Kind: KindGuestJoin, RoomID: "r1"}, now)
	out := b.Flush()
	if len(out) != 2 {
		t.Fatalf("Flush len = %d, want 2", len(out))
	}
	if b.Len() != 0 {
		t.Errorf("Flush 後 Len = %d, want 0", b.Len())
	}

	// Flush 後に再度追加すると oldest がリセットされ、age は新しい起点で判定される。
	later := now.Add(time.Hour)
	b.Add(Event{Kind: KindDisconnect}, later)
	if b.DueByAge(later.Add(30 * time.Second)) {
		t.Error("Flush 後の新バッチは oldest がリセットされるべき")
	}
}

func TestMarshalNDJSON(t *testing.T) {
	if got := MarshalNDJSON(nil); len(got) != 0 {
		t.Errorf("空スライスは空バイト列: got %q", got)
	}

	events := []Event{
		{Time: time.Unix(1000, 0).UTC(), Kind: KindRoomCreate, Role: "host", AccountID: "acc-1", RoomID: "r1"},
		{Time: time.Unix(1001, 0).UTC(), Kind: KindGuestJoin, Role: "guest", RemoteIP: "203.0.113.9", RoomID: "r1"},
	}
	out := string(MarshalNDJSON(events))
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("NDJSON 行数 = %d, want 2\n%s", len(lines), out)
	}
	if !strings.Contains(lines[0], `"kind":"room_create"`) || !strings.Contains(lines[0], `"account_id":"acc-1"`) {
		t.Errorf("1 行目が不正: %s", lines[0])
	}
	// ゲスト行は account_id が omitempty で省略される。
	if strings.Contains(lines[1], "account_id") {
		t.Errorf("ゲスト行に account_id が出てはいけない: %s", lines[1])
	}
	if !strings.Contains(lines[1], `"remote_ip":"203.0.113.9"`) {
		t.Errorf("2 行目に remote_ip が必要: %s", lines[1])
	}
}

func TestObjectKey(t *testing.T) {
	// JST の時刻でも UTC でパーティションされる（越境なし・監査の一貫性）。
	loc := time.FixedZone("JST", 9*3600)
	tm := time.Date(2026, 7, 16, 13, 53, 1, 0, loc) // = 2026-07-16T04:53:01Z

	got := ObjectKey("audit", tm, "000001")
	want := "audit/2026/07/16/20260716T045301Z-000001.ndjson"
	if got != want {
		t.Errorf("ObjectKey = %q, want %q", got, want)
	}

	// 末尾スラッシュは正規化される。
	if got := ObjectKey("audit/", tm, "x"); !strings.HasPrefix(got, "audit/2026/") {
		t.Errorf("prefix 正規化失敗: %q", got)
	}
	// prefix 空はパーティションのみ。
	if got := ObjectKey("", tm, "x"); got != "2026/07/16/20260716T045301Z-x.ndjson" {
		t.Errorf("空 prefix = %q", got)
	}
}
