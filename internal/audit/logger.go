// Package audit records admin/system actions into durable audit_logs.
package audit

import (
	"context"
	"encoding/json"
	"log/slog"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/store"
)

// Logger writes audit entries via the store. Failures are logged but do not
// fail the calling request (best-effort audit).
type Logger struct {
	Store *store.Store
}

// New returns a Logger backed by s.
func New(s *store.Store) *Logger {
	return &Logger{Store: s}
}

// Event describes one admin/system action to record.
type Event struct {
	ActorUserID   *uuid.UUID
	ActorUsername string
	Action        string
	TargetType    string
	TargetID      string
	Summary       string
	Detail        any
	IP            string
}

// Log inserts an audit entry. Returns the stored entry or an error.
// Prefer LogBestEffort from handlers so audit failures never break mutations.
func (l *Logger) Log(ctx context.Context, e Event) (store.AuditEntry, error) {
	if l == nil || l.Store == nil {
		return store.AuditEntry{}, nil
	}
	entry := store.AuditEntry{
		ActorUserID:   e.ActorUserID,
		ActorUsername: e.ActorUsername,
		Action:        e.Action,
		TargetType:    e.TargetType,
		TargetID:      e.TargetID,
		Summary:       e.Summary,
		IP:            e.IP,
	}
	if e.Detail != nil {
		raw, err := json.Marshal(e.Detail)
		if err != nil {
			return store.AuditEntry{}, err
		}
		entry.Detail = raw
	}
	return l.Store.InsertAuditLog(ctx, entry)
}

// LogBestEffort records e and logs any error without returning it.
func (l *Logger) LogBestEffort(ctx context.Context, e Event) {
	if _, err := l.Log(ctx, e); err != nil {
		slog.Warn("audit log failed", "action", e.Action, "err", err)
	}
}
