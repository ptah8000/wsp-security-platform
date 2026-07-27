package store

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"
)

// AuditEntry is a durable admin/system action record.
type AuditEntry struct {
	ID            uuid.UUID       `json:"id"`
	TS            time.Time       `json:"ts"`
	ActorUserID   *uuid.UUID      `json:"actor_user_id,omitempty"`
	ActorUsername string          `json:"actor_username,omitempty"`
	Action        string          `json:"action"`
	TargetType    string          `json:"target_type,omitempty"`
	TargetID      string          `json:"target_id,omitempty"`
	Summary       string          `json:"summary,omitempty"`
	Detail        json.RawMessage `json:"detail,omitempty"`
	IP            string          `json:"ip,omitempty"`
}

// InsertAuditLog appends an audit_logs row and returns the stored entry (with id/ts).
func (s *Store) InsertAuditLog(ctx context.Context, e AuditEntry) (AuditEntry, error) {
	if e.Action == "" {
		return AuditEntry{}, fmt.Errorf("audit action is required")
	}

	var detail any
	if len(e.Detail) > 0 {
		if !json.Valid(e.Detail) {
			return AuditEntry{}, fmt.Errorf("audit detail is not valid JSON")
		}
		detail = []byte(e.Detail)
	}

	const q = `
INSERT INTO audit_logs (
    actor_user_id, actor_username, action, target_type, target_id, summary, detail, ip
) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
RETURNING id, ts, actor_user_id, actor_username, action, target_type, target_id, summary, detail, ip
`
	var (
		out       AuditEntry
		actorUser pgtype.UUID
		actorName pgtype.Text
		targetTyp pgtype.Text
		targetID  pgtype.Text
		summary   pgtype.Text
		detailOut []byte
		ip        pgtype.Text
	)
	err := s.pool.QueryRow(ctx, q,
		e.ActorUserID,
		nullIfEmpty(e.ActorUsername),
		e.Action,
		nullIfEmpty(e.TargetType),
		nullIfEmpty(e.TargetID),
		nullIfEmpty(e.Summary),
		detail,
		nullIfEmpty(e.IP),
	).Scan(
		&out.ID,
		&out.TS,
		&actorUser,
		&actorName,
		&out.Action,
		&targetTyp,
		&targetID,
		&summary,
		&detailOut,
		&ip,
	)
	if err != nil {
		return AuditEntry{}, fmt.Errorf("insert audit log: %w", err)
	}
	if actorUser.Valid {
		id := uuid.UUID(actorUser.Bytes)
		out.ActorUserID = &id
	}
	out.ActorUsername = actorName.String
	out.TargetType = targetTyp.String
	out.TargetID = targetID.String
	out.Summary = summary.String
	out.IP = ip.String
	if len(detailOut) > 0 {
		out.Detail = json.RawMessage(detailOut)
	}
	return out, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
