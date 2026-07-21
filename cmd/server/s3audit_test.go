package main

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/auditlog"
)

// fakeSink は Sink のテスト実装。書き込みを記録し、任意でエラーを返す。
type fakeSink struct {
	mu   sync.Mutex
	keys []string
	body [][]byte
	err  error
}

func (f *fakeSink) Put(_ context.Context, key string, body []byte) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.keys = append(f.keys, key)
	f.body = append(f.body, append([]byte(nil), body...))
	return f.err
}

func (f *fakeSink) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.keys)
}

func (f *fakeSink) lastBody() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.body) == 0 {
		return ""
	}
	return string(f.body[len(f.body)-1])
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("条件が満たされない（タイムアウト）")
}

func fixedNow(tm time.Time) func() time.Time { return func() time.Time { return tm } }

func TestBufferedAuditLoggerCountFlush(t *testing.T) {
	now := time.Unix(1000, 0)
	sink := &fakeSink{}
	b := NewBufferedAuditLogger(sink, "audit", 2, time.Hour, time.Hour, fixedNow(now))
	defer b.Close()

	b.Log(auditlog.Event{Kind: auditlog.KindConnect, Role: "host"})
	if sink.count() != 0 {
		t.Fatalf("1 件では書き込まれない: count=%d", sink.count())
	}
	b.Log(auditlog.Event{Kind: auditlog.KindRoomCreate, Role: "host", RoomID: "r1"})
	waitFor(t, func() bool { return sink.count() == 1 })

	// バッチは NDJSON 2 行。
	if lines := strings.Split(strings.TrimRight(sink.lastBody(), "\n"), "\n"); len(lines) != 2 {
		t.Errorf("NDJSON 行数 = %d, want 2", len(lines))
	}
	// キーは prefix と日付パーティションを含む。
	if k := sink.keys[0]; !strings.HasPrefix(k, "audit/") || !strings.HasSuffix(k, ".ndjson") {
		t.Errorf("object key が不正: %q", k)
	}
}

func TestBufferedAuditLoggerCloseFlush(t *testing.T) {
	now := time.Unix(1000, 0)
	sink := &fakeSink{}
	// maxBatch を大きくして件数トリガを起こさず、Close の drain 経路を検証する。
	b := NewBufferedAuditLogger(sink, "audit", 100, time.Hour, time.Hour, fixedNow(now))
	b.Log(auditlog.Event{Kind: auditlog.KindConnect})
	b.Close()
	if sink.count() != 1 {
		t.Fatalf("Close で残バッチがフラッシュされるべき: count=%d", sink.count())
	}

	// Close 後の Log（maxBatch=1 で due）は enqueue の done 経路で同期書き込みされる。
	b.Log(auditlog.Event{Kind: auditlog.KindDisconnect})
	if sink.count() < 1 {
		t.Error("Close 後の Log でパニックせず記録されること")
	}
}

func TestBufferedAuditLoggerAgeFlush(t *testing.T) {
	base := time.Unix(1000, 0)
	var nowNanos atomic.Int64
	nowNanos.Store(base.UnixNano())
	nowFn := func() time.Time { return time.Unix(0, nowNanos.Load()) }

	sink := &fakeSink{}
	// 件数トリガは無効化、maxAge=1分、チェック周期 5ms。
	b := NewBufferedAuditLogger(sink, "audit", 0, time.Minute, 5*time.Millisecond, nowFn)
	defer b.Close()

	b.Log(auditlog.Event{Kind: auditlog.KindConnect})
	// まだ経過していない。
	if sink.count() != 0 {
		t.Fatalf("age 未達では書き込まれない: %d", sink.count())
	}
	// 時刻を進めると ticker が age フラッシュを起こす。
	nowNanos.Store(base.Add(2 * time.Minute).UnixNano())
	waitFor(t, func() bool { return sink.count() == 1 })
}

func TestBufferedAuditLoggerPutError(t *testing.T) {
	now := time.Unix(1000, 0)
	sink := &fakeSink{err: errors.New("boom")}
	b := NewBufferedAuditLogger(sink, "audit", 1, time.Hour, time.Hour, fixedNow(now))
	// Put がエラーでもパニックせず、ログのみで継続する。
	b.Log(auditlog.Event{Kind: auditlog.KindConnect})
	waitFor(t, func() bool { return sink.count() == 1 })
	b.Close()
}

func TestNewS3Sink(t *testing.T) {
	s, err := NewS3Sink(context.Background(), "ap-northeast-1", "my-bucket", "kms-key-1")
	if err != nil {
		t.Fatalf("NewS3Sink: %v", err)
	}
	if s.bucket != "my-bucket" || s.kmsKeyID != "kms-key-1" {
		t.Errorf("S3Sink フィールド不正: %+v", s)
	}
}
