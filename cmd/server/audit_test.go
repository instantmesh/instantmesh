package main

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/instantmesh/instantmesh/pkg/auditlog"
)

func TestNopAuditLogger(t *testing.T) {
	// パニックしないこと。
	NopAuditLogger{}.Log(auditlog.Event{Kind: auditlog.KindConnect})
}

func TestSlogAuditLogger(t *testing.T) {
	var buf bytes.Buffer
	a := SlogAuditLogger{Logger: slog.New(slog.NewTextHandler(&buf, nil))}
	a.Log(auditlog.Event{
		Time:      time.Now(),
		Kind:      auditlog.KindConnect,
		Role:      "host",
		AccountID: "acc-1",
		RemoteIP:  "203.0.113.9",
		RoomID:    "r1",
	})
	out := buf.String()
	for _, want := range []string{"kind=connect", "role=host", "account_id=acc-1", "remote_ip=203.0.113.9", "room_id=r1"} {
		if !strings.Contains(out, want) {
			t.Errorf("監査出力に %q が含まれるべき: %s", want, out)
		}
	}
}

func TestSlogAuditLoggerNilUsesDefault(t *testing.T) {
	// Logger 未設定でも slog.Default() を用いてパニックしない。
	SlogAuditLogger{}.Log(auditlog.Event{Kind: auditlog.KindDisconnect})
}
