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

// RequestLog is one data-plane request observation (request_logs table).
type RequestLog struct {
	ID               uuid.UUID       `json:"id"`
	SessionID        *uuid.UUID      `json:"session_id,omitempty"`
	RequestID        uuid.UUID       `json:"request_id"`
	TS               time.Time       `json:"ts"`
	ClientIP         string          `json:"client_ip,omitempty"`
	Username         string          `json:"username,omitempty"`
	UserAgent        string          `json:"user_agent,omitempty"`
	Method           string          `json:"method,omitempty"`
	Scheme           string          `json:"scheme,omitempty"`
	Host             string          `json:"host,omitempty"`
	Path             string          `json:"path,omitempty"`
	Query            string          `json:"query,omitempty"`
	URL              string          `json:"url,omitempty"`
	Protocol         string          `json:"protocol,omitempty"`
	RequestSize      *int64          `json:"request_size,omitempty"`
	ResponseSize     *int64          `json:"response_size,omitempty"`
	Decision         string          `json:"decision,omitempty"`
	MatchedRuleIDs   []uuid.UUID     `json:"matched_rule_ids"`
	EvaluatedRuleIDs []uuid.UUID     `json:"evaluated_rule_ids"`
	Actions          json.RawMessage `json:"actions,omitempty"`
	Timings          json.RawMessage `json:"timings,omitempty"`
	BlockReason      string          `json:"block_reason,omitempty"`
	BlockPageID      *uuid.UUID      `json:"block_page_id,omitempty"`
	Error            string          `json:"error,omitempty"`
}

// EnsureRequestLogsPartition ensures a monthly partition exists for ts (UTC month).
func (s *Store) EnsureRequestLogsPartition(ctx context.Context, ts time.Time) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("store is nil")
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	_, err := s.pool.Exec(ctx, `SELECT ensure_request_logs_partition($1)`, ts.UTC())
	if err != nil {
		return fmt.Errorf("ensure request_logs partition: %w", err)
	}
	return nil
}

// InsertRequestLog appends a request_logs row. Ensures the partition for rec.TS exists.
// Generates RequestID when zero; TS defaults to now UTC.
func (s *Store) InsertRequestLog(ctx context.Context, rec RequestLog) (RequestLog, error) {
	if s == nil || s.pool == nil {
		return RequestLog{}, fmt.Errorf("store is nil")
	}
	if rec.RequestID == uuid.Nil {
		rec.RequestID = uuid.New()
	}
	if rec.TS.IsZero() {
		rec.TS = time.Now().UTC()
	}
	if rec.MatchedRuleIDs == nil {
		rec.MatchedRuleIDs = []uuid.UUID{}
	}
	if rec.EvaluatedRuleIDs == nil {
		rec.EvaluatedRuleIDs = []uuid.UUID{}
	}

	if err := s.EnsureRequestLogsPartition(ctx, rec.TS); err != nil {
		return RequestLog{}, err
	}

	actions := jsonOrEmptyObject(rec.Actions)
	timings := jsonOrEmptyObject(rec.Timings)

	const q = `
INSERT INTO request_logs (
    session_id, request_id, ts,
    client_ip, username, user_agent,
    method, scheme, host, path, query, url, protocol,
    request_size, response_size,
    decision, matched_rule_ids, evaluated_rule_ids,
    actions, timings, block_reason, block_page_id, error
) VALUES (
    $1, $2, $3,
    $4, $5, $6,
    $7, $8, $9, $10, $11, $12, $13,
    $14, $15,
    $16, $17, $18,
    $19::jsonb, $20::jsonb, $21, $22, $23
)
RETURNING id, session_id, request_id, ts,
    client_ip, username, user_agent,
    method, scheme, host, path, query, url, protocol,
    request_size, response_size,
    decision, matched_rule_ids, evaluated_rule_ids,
    actions, timings, block_reason, block_page_id, error
`
	var (
		out          RequestLog
		sessionID    pgtype.UUID
		clientIP     pgtype.Text
		username     pgtype.Text
		userAgent    pgtype.Text
		method       pgtype.Text
		scheme       pgtype.Text
		host         pgtype.Text
		path         pgtype.Text
		query        pgtype.Text
		url          pgtype.Text
		protocol     pgtype.Text
		reqSize      pgtype.Int8
		respSize     pgtype.Int8
		decision     pgtype.Text
		actionsOut   []byte
		timingsOut   []byte
		blockReason  pgtype.Text
		blockPageID  pgtype.UUID
		errText      pgtype.Text
	)

	err := s.pool.QueryRow(ctx, q,
		rec.SessionID,
		rec.RequestID,
		rec.TS.UTC(),
		nullIfEmpty(rec.ClientIP),
		nullIfEmpty(rec.Username),
		nullIfEmpty(rec.UserAgent),
		nullIfEmpty(rec.Method),
		nullIfEmpty(rec.Scheme),
		nullIfEmpty(rec.Host),
		nullIfEmpty(rec.Path),
		nullIfEmpty(rec.Query),
		nullIfEmpty(rec.URL),
		nullIfEmpty(rec.Protocol),
		rec.RequestSize,
		rec.ResponseSize,
		nullIfEmpty(rec.Decision),
		rec.MatchedRuleIDs,
		rec.EvaluatedRuleIDs,
		[]byte(actions),
		[]byte(timings),
		nullIfEmpty(rec.BlockReason),
		rec.BlockPageID,
		nullIfEmpty(rec.Error),
	).Scan(
		&out.ID,
		&sessionID,
		&out.RequestID,
		&out.TS,
		&clientIP,
		&username,
		&userAgent,
		&method,
		&scheme,
		&host,
		&path,
		&query,
		&url,
		&protocol,
		&reqSize,
		&respSize,
		&decision,
		&out.MatchedRuleIDs,
		&out.EvaluatedRuleIDs,
		&actionsOut,
		&timingsOut,
		&blockReason,
		&blockPageID,
		&errText,
	)
	if err != nil {
		return RequestLog{}, fmt.Errorf("insert request log: %w", err)
	}

	if sessionID.Valid {
		id := uuid.UUID(sessionID.Bytes)
		out.SessionID = &id
	}
	out.ClientIP = clientIP.String
	out.Username = username.String
	out.UserAgent = userAgent.String
	out.Method = method.String
	out.Scheme = scheme.String
	out.Host = host.String
	out.Path = path.String
	out.Query = query.String
	out.URL = url.String
	out.Protocol = protocol.String
	if reqSize.Valid {
		v := reqSize.Int64
		out.RequestSize = &v
	}
	if respSize.Valid {
		v := respSize.Int64
		out.ResponseSize = &v
	}
	out.Decision = decision.String
	if out.MatchedRuleIDs == nil {
		out.MatchedRuleIDs = []uuid.UUID{}
	}
	if out.EvaluatedRuleIDs == nil {
		out.EvaluatedRuleIDs = []uuid.UUID{}
	}
	if len(actionsOut) > 0 {
		out.Actions = json.RawMessage(actionsOut)
	}
	if len(timingsOut) > 0 {
		out.Timings = json.RawMessage(timingsOut)
	}
	out.BlockReason = blockReason.String
	if blockPageID.Valid {
		id := uuid.UUID(blockPageID.Bytes)
		out.BlockPageID = &id
	}
	out.Error = errText.String
	return out, nil
}

// GetRequestLogByRequestID returns the most recent request_logs row for requestID.
func (s *Store) GetRequestLogByRequestID(ctx context.Context, requestID uuid.UUID) (RequestLog, error) {
	if s == nil || s.pool == nil {
		return RequestLog{}, fmt.Errorf("store is nil")
	}
	const q = `
SELECT id, session_id, request_id, ts,
    client_ip, username, user_agent,
    method, scheme, host, path, query, url, protocol,
    request_size, response_size,
    decision, matched_rule_ids, evaluated_rule_ids,
    actions, timings, block_reason, block_page_id, error
FROM request_logs
WHERE request_id = $1
ORDER BY ts DESC
LIMIT 1
`
	var (
		out         RequestLog
		sessionID   pgtype.UUID
		clientIP    pgtype.Text
		username    pgtype.Text
		userAgent   pgtype.Text
		method      pgtype.Text
		scheme      pgtype.Text
		host        pgtype.Text
		path        pgtype.Text
		query       pgtype.Text
		url         pgtype.Text
		protocol    pgtype.Text
		reqSize     pgtype.Int8
		respSize    pgtype.Int8
		decision    pgtype.Text
		actionsOut  []byte
		timingsOut  []byte
		blockReason pgtype.Text
		blockPageID pgtype.UUID
		errText     pgtype.Text
	)
	err := s.pool.QueryRow(ctx, q, requestID).Scan(
		&out.ID,
		&sessionID,
		&out.RequestID,
		&out.TS,
		&clientIP,
		&username,
		&userAgent,
		&method,
		&scheme,
		&host,
		&path,
		&query,
		&url,
		&protocol,
		&reqSize,
		&respSize,
		&decision,
		&out.MatchedRuleIDs,
		&out.EvaluatedRuleIDs,
		&actionsOut,
		&timingsOut,
		&blockReason,
		&blockPageID,
		&errText,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return RequestLog{}, fmt.Errorf("request log %s: %w", requestID, err)
		}
		return RequestLog{}, fmt.Errorf("get request log: %w", err)
	}
	if sessionID.Valid {
		id := uuid.UUID(sessionID.Bytes)
		out.SessionID = &id
	}
	out.ClientIP = clientIP.String
	out.Username = username.String
	out.UserAgent = userAgent.String
	out.Method = method.String
	out.Scheme = scheme.String
	out.Host = host.String
	out.Path = path.String
	out.Query = query.String
	out.URL = url.String
	out.Protocol = protocol.String
	if reqSize.Valid {
		v := reqSize.Int64
		out.RequestSize = &v
	}
	if respSize.Valid {
		v := respSize.Int64
		out.ResponseSize = &v
	}
	out.Decision = decision.String
	if out.MatchedRuleIDs == nil {
		out.MatchedRuleIDs = []uuid.UUID{}
	}
	if out.EvaluatedRuleIDs == nil {
		out.EvaluatedRuleIDs = []uuid.UUID{}
	}
	if len(actionsOut) > 0 {
		out.Actions = json.RawMessage(actionsOut)
	}
	if len(timingsOut) > 0 {
		out.Timings = json.RawMessage(timingsOut)
	}
	out.BlockReason = blockReason.String
	if blockPageID.Valid {
		id := uuid.UUID(blockPageID.Bytes)
		out.BlockPageID = &id
	}
	out.Error = errText.String
	return out, nil
}

func jsonOrEmptyObject(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage(`{}`)
	}
	if !json.Valid(raw) {
		return json.RawMessage(`{}`)
	}
	return raw
}
