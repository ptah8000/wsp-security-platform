package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
)

// Setting keys seeded by 001_init (and used by later tasks).
const (
	SettingSetupCompleted     = "setup_completed"
	SettingLogRetentionDays   = "log_retention_days"
	SettingAuditRetentionDays = "audit_retention_days"
	SettingDNSServers         = "dns_servers"
	SettingProxyListen        = "proxy_listen"
	SettingAdminListen        = "admin_listen"
	SettingPlatform           = "platform"
)

// Setting is a key/JSONB value row from the settings table.
type Setting struct {
	Key       string          `json:"key"`
	Value     json.RawMessage `json:"value"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// IsSetupComplete reports whether the first-run wizard finished
// (settings.setup_completed JSON boolean true).
func (s *Store) IsSetupComplete(ctx context.Context) (bool, error) {
	raw, err := s.GetSetting(ctx, SettingSetupCompleted)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	var v bool
	if err := json.Unmarshal(raw, &v); err != nil {
		return false, fmt.Errorf("parse setup_completed: %w", err)
	}
	return v, nil
}

// GetSetting returns the JSON value for key.
func (s *Store) GetSetting(ctx context.Context, key string) (json.RawMessage, error) {
	const q = `SELECT value FROM settings WHERE key = $1`
	var raw []byte
	err := s.pool.QueryRow(ctx, q, key).Scan(&raw)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("setting %q: %w", key, err)
		}
		return nil, fmt.Errorf("get setting %q: %w", key, err)
	}
	return json.RawMessage(raw), nil
}

// SetSetting upserts a JSON value for key.
func (s *Store) SetSetting(ctx context.Context, key string, value json.RawMessage) error {
	if key == "" {
		return fmt.Errorf("setting key is required")
	}
	if !json.Valid(value) {
		return fmt.Errorf("setting value is not valid JSON")
	}
	const q = `
INSERT INTO settings (key, value, updated_at)
VALUES ($1, $2::jsonb, now())
ON CONFLICT (key) DO UPDATE
SET value = EXCLUDED.value, updated_at = now()
`
	if _, err := s.pool.Exec(ctx, q, key, []byte(value)); err != nil {
		return fmt.Errorf("set setting %q: %w", key, err)
	}
	return nil
}

// GetSettingRow returns the full settings row for key.
func (s *Store) GetSettingRow(ctx context.Context, key string) (Setting, error) {
	const q = `SELECT key, value, updated_at FROM settings WHERE key = $1`
	var st Setting
	var raw []byte
	err := s.pool.QueryRow(ctx, q, key).Scan(&st.Key, &raw, &st.UpdatedAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Setting{}, fmt.Errorf("setting %q: %w", key, err)
		}
		return Setting{}, fmt.Errorf("get setting row %q: %w", key, err)
	}
	st.Value = json.RawMessage(raw)
	return st, nil
}
