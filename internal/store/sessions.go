package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// BrowsingSession groups related proxy requests from one client identity.
type BrowsingSession struct {
	ID        uuid.UUID       `json:"id"`
	StartedAt time.Time       `json:"started_at"`
	EndedAt   *time.Time      `json:"ended_at,omitempty"`
	ClientIP  string          `json:"client_ip,omitempty"`
	Username  string          `json:"username,omitempty"`
	UserAgent string          `json:"user_agent,omitempty"`
	Summary   json.RawMessage `json:"summary,omitempty"`
}

// CreateBrowsingSession inserts a sessions row and returns it with generated id/timestamps.
func (s *Store) CreateBrowsingSession(ctx context.Context, sess BrowsingSession) (BrowsingSession, error) {
	if s == nil || s.pool == nil {
		return BrowsingSession{}, fmt.Errorf("store is nil")
	}

	var summary any
	if len(sess.Summary) > 0 {
		if !json.Valid(sess.Summary) {
			return BrowsingSession{}, fmt.Errorf("session summary is not valid JSON")
		}
		summary = []byte(sess.Summary)
	}

	const q = `
INSERT INTO sessions (client_ip, username, user_agent, summary)
VALUES ($1, $2, $3, $4)
RETURNING id, started_at, ended_at, client_ip, username, user_agent, summary
`
	var (
		out        BrowsingSession
		endedAt    pgtype.Timestamptz
		clientIP   pgtype.Text
		username   pgtype.Text
		userAgent  pgtype.Text
		summaryOut []byte
	)
	err := s.pool.QueryRow(ctx, q,
		nullIfEmpty(sess.ClientIP),
		nullIfEmpty(sess.Username),
		nullIfEmpty(sess.UserAgent),
		summary,
	).Scan(
		&out.ID,
		&out.StartedAt,
		&endedAt,
		&clientIP,
		&username,
		&userAgent,
		&summaryOut,
	)
	if err != nil {
		return BrowsingSession{}, fmt.Errorf("create browsing session: %w", err)
	}
	if endedAt.Valid {
		t := endedAt.Time
		out.EndedAt = &t
	}
	out.ClientIP = clientIP.String
	out.Username = username.String
	out.UserAgent = userAgent.String
	if len(summaryOut) > 0 {
		out.Summary = json.RawMessage(summaryOut)
	}
	return out, nil
}

// EndBrowsingSession sets ended_at on the session if not already ended.
func (s *Store) EndBrowsingSession(ctx context.Context, id uuid.UUID) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("store is nil")
	}
	const q = `
UPDATE sessions
SET ended_at = COALESCE(ended_at, now())
WHERE id = $1
`
	tag, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("end browsing session: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("browsing session %s: %w", id, pgx.ErrNoRows)
	}
	return nil
}

// GetBrowsingSession returns a sessions row by id.
func (s *Store) GetBrowsingSession(ctx context.Context, id uuid.UUID) (BrowsingSession, error) {
	if s == nil || s.pool == nil {
		return BrowsingSession{}, fmt.Errorf("store is nil")
	}
	const q = `
SELECT id, started_at, ended_at, client_ip, username, user_agent, summary
FROM sessions
WHERE id = $1
`
	var (
		out        BrowsingSession
		endedAt    pgtype.Timestamptz
		clientIP   pgtype.Text
		username   pgtype.Text
		userAgent  pgtype.Text
		summaryOut []byte
	)
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&out.ID,
		&out.StartedAt,
		&endedAt,
		&clientIP,
		&username,
		&userAgent,
		&summaryOut,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BrowsingSession{}, fmt.Errorf("browsing session %s: %w", id, err)
		}
		return BrowsingSession{}, fmt.Errorf("get browsing session: %w", err)
	}
	if endedAt.Valid {
		t := endedAt.Time
		out.EndedAt = &t
	}
	out.ClientIP = clientIP.String
	out.Username = username.String
	out.UserAgent = userAgent.String
	if len(summaryOut) > 0 {
		out.Summary = json.RawMessage(summaryOut)
	}
	return out, nil
}
