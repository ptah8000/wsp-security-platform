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

// DeleteAuditLogsBefore deletes up to limit audit_logs rows with ts < before.
// Used by the hourly retention job. Returns rows deleted.
func (s *Store) DeleteAuditLogsBefore(ctx context.Context, before time.Time, limit int) (int64, error) {
	if s == nil || s.pool == nil {
		return 0, fmt.Errorf("store is nil")
	}
	if before.IsZero() {
		return 0, fmt.Errorf("before timestamp is required")
	}
	if limit <= 0 {
		limit = 5000
	}
	const q = `
DELETE FROM audit_logs
WHERE id IN (
    SELECT id FROM audit_logs
    WHERE ts < $1
    ORDER BY ts ASC
    LIMIT $2
)
`
	tag, err := s.pool.Exec(ctx, q, before.UTC(), limit)
	if err != nil {
		return 0, fmt.Errorf("delete audit logs before %s: %w", before.UTC().Format(time.RFC3339), err)
	}
	return tag.RowsAffected(), nil
}

// AuditListFilter constrains ListAuditLogs.
type AuditListFilter struct {
	Action string
	Limit  int
	Offset int
}

// ListAuditLogs returns audit entries newest-first.
func (s *Store) ListAuditLogs(ctx context.Context, f AuditListFilter) ([]AuditEntry, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("store is nil")
	}
	limit := f.Limit
	if limit <= 0 {
		limit = 100
	}
	if limit > 1000 {
		limit = 1000
	}
	offset := f.Offset
	if offset < 0 {
		offset = 0
	}

	const q = `
SELECT id, ts, actor_user_id, actor_username, action, target_type, target_id, summary, detail, ip
FROM audit_logs
WHERE ($1 = '' OR action = $1)
ORDER BY ts DESC
LIMIT $2 OFFSET $3
`
	rows, err := s.pool.Query(ctx, q, f.Action, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	defer rows.Close()

	var out []AuditEntry
	for rows.Next() {
		var (
			e         AuditEntry
			actorUser pgtype.UUID
			actorName pgtype.Text
			targetTyp pgtype.Text
			targetID  pgtype.Text
			summary   pgtype.Text
			detailOut []byte
			ip        pgtype.Text
		)
		if err := rows.Scan(
			&e.ID, &e.TS, &actorUser, &actorName, &e.Action,
			&targetTyp, &targetID, &summary, &detailOut, &ip,
		); err != nil {
			return nil, fmt.Errorf("scan audit log: %w", err)
		}
		if actorUser.Valid {
			id := uuid.UUID(actorUser.Bytes)
			e.ActorUserID = &id
		}
		e.ActorUsername = actorName.String
		e.TargetType = targetTyp.String
		e.TargetID = targetID.String
		e.Summary = summary.String
		e.IP = ip.String
		if len(detailOut) > 0 {
			e.Detail = json.RawMessage(detailOut)
		}
		out = append(out, e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list audit logs: %w", err)
	}
	if out == nil {
		out = []AuditEntry{}
	}
	return out, nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}
