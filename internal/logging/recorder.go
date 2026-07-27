// Package logging records data-plane sessions and request observations.
package logging

import (
	"context"
	"encoding/json"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/store"
)

// DefaultMemCap is the max in-memory records retained when Store is nil or for tests.
const DefaultMemCap = 256

// RequestRecord is one proxy pipeline observation (maps to request_logs).
type RequestRecord struct {
	SessionID        *uuid.UUID
	RequestID        uuid.UUID
	TS               time.Time
	ClientIP         string
	Username         string
	UserAgent        string
	Method           string
	Scheme           string
	Host             string
	Path             string
	Query            string
	URL              string
	Protocol         string
	RequestSize      int64
	ResponseSize     int64
	Decision         string
	MatchedRuleIDs   []uuid.UUID
	EvaluatedRuleIDs []uuid.UUID
	Actions          map[string]any
	Timings          map[string]any
	BlockReason      string
	BlockPageID      *uuid.UUID
	Error            string
}

// Recorder writes request logs to PostgreSQL when a Store is configured, and
// always retains a bounded in-memory ring for tests and local debugging.
type Recorder struct {
	store  *store.Store
	memCap int

	mu  sync.Mutex
	mem []RequestRecord
}

// NewRecorder builds a Recorder. store may be nil (memory-only).
func NewRecorder(s *store.Store) *Recorder {
	return &Recorder{
		store:  s,
		memCap: DefaultMemCap,
		mem:    make([]RequestRecord, 0, 32),
	}
}

// Record persists rec (async-safe). Missing RequestID/TS are filled in.
// Failures against the database are logged but do not return to the caller so
// the data plane is not blocked by log sink issues; in-memory always succeeds.
func (r *Recorder) Record(ctx context.Context, rec RequestRecord) {
	if r == nil {
		return
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

	r.pushMem(rec)

	if r.store == nil {
		return
	}

	row := store.RequestLog{
		SessionID:        rec.SessionID,
		RequestID:        rec.RequestID,
		TS:               rec.TS,
		ClientIP:         rec.ClientIP,
		Username:         rec.Username,
		UserAgent:        rec.UserAgent,
		Method:           rec.Method,
		Scheme:           rec.Scheme,
		Host:             rec.Host,
		Path:             rec.Path,
		Query:            rec.Query,
		URL:              rec.URL,
		Protocol:         rec.Protocol,
		Decision:         rec.Decision,
		MatchedRuleIDs:   rec.MatchedRuleIDs,
		EvaluatedRuleIDs: rec.EvaluatedRuleIDs,
		BlockReason:      rec.BlockReason,
		BlockPageID:      rec.BlockPageID,
		Error:            rec.Error,
	}
	if rec.RequestSize != 0 {
		v := rec.RequestSize
		row.RequestSize = &v
	}
	if rec.ResponseSize != 0 {
		v := rec.ResponseSize
		row.ResponseSize = &v
	}
	if rec.Actions != nil {
		if b, err := json.Marshal(rec.Actions); err == nil {
			row.Actions = b
		}
	}
	if rec.Timings != nil {
		if b, err := json.Marshal(rec.Timings); err == nil {
			row.Timings = b
		}
	}

	if _, err := r.store.InsertRequestLog(ctx, row); err != nil {
		slog.Warn("request log insert failed", "err", err, "request_id", rec.RequestID)
	}
}

// Recent returns a copy of the in-memory ring (oldest first).
func (r *Recorder) Recent() []RequestRecord {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]RequestRecord, len(r.mem))
	copy(out, r.mem)
	return out
}

// Last returns the most recent in-memory record, if any.
func (r *Recorder) Last() (RequestRecord, bool) {
	if r == nil {
		return RequestRecord{}, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.mem) == 0 {
		return RequestRecord{}, false
	}
	return r.mem[len(r.mem)-1], true
}

// ClearMem drops in-memory records (tests).
func (r *Recorder) ClearMem() {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.mem = r.mem[:0]
}

func (r *Recorder) pushMem(rec RequestRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	capN := r.memCap
	if capN <= 0 {
		capN = DefaultMemCap
	}
	if len(r.mem) >= capN {
		// Drop oldest.
		copy(r.mem, r.mem[1:])
		r.mem[len(r.mem)-1] = rec
		return
	}
	r.mem = append(r.mem, rec)
}
