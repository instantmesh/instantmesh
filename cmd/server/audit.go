package main

import (
	"log/slog"

	"github.com/instantmesh/instantmesh/pkg/auditlog"
)

// AuditLogger は接続メタデータの監査出力先。イベント表現・シリアライズの純粋ロジックは
// pkg/auditlog にあり、本 I/F はその Event を受ける。既定は SlogAuditLogger、本番は S3
// （Object Lock + KMS）へバッチ書き込みする BufferedAuditLogger（s3audit.go）へ差し替える。
type AuditLogger interface {
	Log(ev auditlog.Event)
}

// NopAuditLogger は何も記録しない（無効化・テスト用）。
type NopAuditLogger struct{}

// Log は AuditLogger を実装する（何もしない）。
func (NopAuditLogger) Log(auditlog.Event) {}

// SlogAuditLogger は log/slog へ構造化出力する既定実装。接続メタデータのみを出す。
type SlogAuditLogger struct {
	// Logger が nil の場合は slog.Default() を用いる。
	Logger *slog.Logger
}

// Log は AuditLogger を実装する。
func (a SlogAuditLogger) Log(ev auditlog.Event) {
	l := a.Logger
	if l == nil {
		l = slog.Default()
	}
	l.Info("audit",
		"kind", ev.Kind,
		"role", ev.Role,
		"account_id", ev.AccountID,
		"remote_ip", ev.RemoteIP,
		"room_id", ev.RoomID,
		"time", ev.Time,
	)
}
