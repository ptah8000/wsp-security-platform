// Package logging records data-plane sessions and request observations.
package logging

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/wsp-security/wsp/internal/store"
)

// DefaultRetentionBatchSize is the max rows deleted per DELETE statement.
const DefaultRetentionBatchSize = 5000

// DefaultRetentionInterval is how often the job runs when started via Start.
const DefaultRetentionInterval = time.Hour

// DefaultLogRetentionDays matches migrations seed (log_retention_days).
const DefaultLogRetentionDays = 30

// DefaultAuditRetentionDays matches migrations seed (audit_retention_days).
const DefaultAuditRetentionDays = 365

// RetentionJob deletes expired request_logs (and audit_logs) in batches.
type RetentionJob struct {
	Store     *store.Store
	BatchSize int
	Interval  time.Duration
	// MaxBatches caps how many batch DELETEs run per table per cycle (0 = unlimited).
	// Prevents a single cycle from monopolizing the DB when retention is shortened.
	MaxBatches int
	// Now overrides time.Now for tests (UTC).
	Now func() time.Time
}

// NewRetentionJob builds a job with defaults (5000-row batches, hourly).
func NewRetentionJob(st *store.Store) *RetentionJob {
	return &RetentionJob{
		Store:      st,
		BatchSize:  DefaultRetentionBatchSize,
		Interval:   DefaultRetentionInterval,
		MaxBatches: 100,
	}
}

// Start runs RunOnce immediately, then on Interval until ctx is cancelled.
// Blocks until ctx is done; call from a goroutine.
func (j *RetentionJob) Start(ctx context.Context) {
	if j == nil || j.Store == nil {
		slog.Warn("retention job not started: nil job or store")
		return
	}
	interval := j.Interval
	if interval <= 0 {
		interval = DefaultRetentionInterval
	}

	// Run once promptly so short-lived lab processes still prune.
	if err := j.RunOnce(ctx); err != nil && ctx.Err() == nil {
		slog.Warn("retention job cycle failed", "err", err)
	}

	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			slog.Info("retention job stopped")
			return
		case <-t.C:
			if err := j.RunOnce(ctx); err != nil && ctx.Err() == nil {
				slog.Warn("retention job cycle failed", "err", err)
			}
		}
	}
}

// RunOnce loads retention settings and deletes expired rows in batches of BatchSize.
func (j *RetentionJob) RunOnce(ctx context.Context) error {
	if j == nil || j.Store == nil {
		return fmt.Errorf("retention job: store is nil")
	}
	now := j.now()
	batch := j.BatchSize
	if batch <= 0 {
		batch = DefaultRetentionBatchSize
	}
	maxBatches := j.MaxBatches
	if maxBatches < 0 {
		maxBatches = 0
	}

	logDays, err := j.settingInt(ctx, store.SettingLogRetentionDays, DefaultLogRetentionDays)
	if err != nil {
		return err
	}
	auditDays, err := j.settingInt(ctx, store.SettingAuditRetentionDays, DefaultAuditRetentionDays)
	if err != nil {
		return err
	}

	// Ensure current/next month partitions exist so inserts never fail mid-month.
	if err := j.Store.EnsureRequestLogsPartition(ctx, now); err != nil {
		slog.Warn("retention: ensure current partition", "err", err)
	}
	if err := j.Store.EnsureRequestLogsPartition(ctx, now.AddDate(0, 1, 0)); err != nil {
		slog.Warn("retention: ensure next partition", "err", err)
	}

	logCutoff := now.AddDate(0, 0, -logDays)
	auditCutoff := now.AddDate(0, 0, -auditDays)

	reqDeleted, err := j.purgeRequestLogs(ctx, logCutoff, batch, maxBatches)
	if err != nil {
		return err
	}
	auditDeleted, err := j.purgeAuditLogs(ctx, auditCutoff, batch, maxBatches)
	if err != nil {
		return err
	}

	if reqDeleted > 0 || auditDeleted > 0 {
		slog.Info("retention job cycle complete",
			"log_retention_days", logDays,
			"audit_retention_days", auditDays,
			"request_logs_deleted", reqDeleted,
			"audit_logs_deleted", auditDeleted,
			"request_cutoff", logCutoff.Format(time.RFC3339),
			"audit_cutoff", auditCutoff.Format(time.RFC3339),
		)
	} else {
		slog.Debug("retention job cycle complete; nothing to delete",
			"log_retention_days", logDays,
			"audit_retention_days", auditDays,
		)
	}
	return nil
}

func (j *RetentionJob) purgeRequestLogs(ctx context.Context, cutoff time.Time, batch, maxBatches int) (int64, error) {
	var total int64
	for n := 0; maxBatches == 0 || n < maxBatches; n++ {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		deleted, err := j.Store.DeleteRequestLogsBefore(ctx, cutoff, batch)
		if err != nil {
			return total, fmt.Errorf("delete request_logs: %w", err)
		}
		total += deleted
		if deleted < int64(batch) {
			break
		}
	}
	return total, nil
}

func (j *RetentionJob) purgeAuditLogs(ctx context.Context, cutoff time.Time, batch, maxBatches int) (int64, error) {
	var total int64
	for n := 0; maxBatches == 0 || n < maxBatches; n++ {
		if err := ctx.Err(); err != nil {
			return total, err
		}
		deleted, err := j.Store.DeleteAuditLogsBefore(ctx, cutoff, batch)
		if err != nil {
			return total, fmt.Errorf("delete audit_logs: %w", err)
		}
		total += deleted
		if deleted < int64(batch) {
			break
		}
	}
	return total, nil
}

func (j *RetentionJob) settingInt(ctx context.Context, key string, def int) (int, error) {
	raw, err := j.Store.GetSetting(ctx, key)
	if err != nil {
		// Missing key → defaults (fresh DB without seed should still work).
		slog.Debug("retention: using default for setting", "key", key, "default", def, "err", err)
		return def, nil
	}
	days, ok := parseRetentionDays(raw)
	if !ok {
		slog.Warn("retention: invalid setting value; using default", "key", key, "default", def, "value", string(raw))
		return def, nil
	}
	return days, nil
}

func (j *RetentionJob) now() time.Time {
	if j != nil && j.Now != nil {
		return j.Now().UTC()
	}
	return time.Now().UTC()
}

// parseRetentionDays accepts a JSON number (e.g. 30) and clamps to a sane range.
// Returns ok=false when the value cannot be used.
func parseRetentionDays(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var n int
	if err := json.Unmarshal(raw, &n); err != nil {
		// Also accept stringified numbers from ad-hoc edits.
		var s string
		if err2 := json.Unmarshal(raw, &s); err2 != nil {
			return 0, false
		}
		var n2 int
		if _, err3 := fmt.Sscanf(s, "%d", &n2); err3 != nil {
			return 0, false
		}
		n = n2
	}
	if n < 1 {
		return 0, false
	}
	if n > 3650 {
		n = 3650
	}
	return n, true
}
