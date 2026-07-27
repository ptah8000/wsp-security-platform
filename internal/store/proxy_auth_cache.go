package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// ProxyAuthCacheEntry is a row in proxy_auth_cache (IP → user for proxy auth).
type ProxyAuthCacheEntry struct {
	IP        string    `json:"ip"`
	UserID    uuid.UUID `json:"user_id"`
	Username  string    `json:"username"`
	ExpiresAt time.Time `json:"expires_at"`
}

// GetProxyAuthCache returns a non-expired cache entry for ip.
// Expired or missing rows yield ok=false with a zero entry (and nil error for miss/expired).
func (s *Store) GetProxyAuthCache(ctx context.Context, ip string) (ProxyAuthCacheEntry, bool, error) {
	if ip == "" {
		return ProxyAuthCacheEntry{}, false, fmt.Errorf("ip is required")
	}
	const q = `
SELECT ip, user_id, username, expires_at
FROM proxy_auth_cache
WHERE ip = $1 AND expires_at > now()
`
	var out ProxyAuthCacheEntry
	var userID *uuid.UUID
	err := s.pool.QueryRow(ctx, q, ip).Scan(&out.IP, &userID, &out.Username, &out.ExpiresAt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ProxyAuthCacheEntry{}, false, nil
		}
		return ProxyAuthCacheEntry{}, false, fmt.Errorf("get proxy auth cache: %w", err)
	}
	if userID != nil {
		out.UserID = *userID
	}
	return out, true, nil
}

// UpsertProxyAuthCache inserts or refreshes the IP auth cache entry.
func (s *Store) UpsertProxyAuthCache(ctx context.Context, ip string, userID uuid.UUID, username string, expiresAt time.Time) error {
	if ip == "" {
		return fmt.Errorf("ip is required")
	}
	if username == "" {
		return fmt.Errorf("username is required")
	}
	if expiresAt.IsZero() {
		return fmt.Errorf("expires_at is required")
	}

	const q = `
INSERT INTO proxy_auth_cache (ip, user_id, username, expires_at)
VALUES ($1, $2, $3, $4)
ON CONFLICT (ip) DO UPDATE
SET user_id = EXCLUDED.user_id,
    username = EXCLUDED.username,
    expires_at = EXCLUDED.expires_at
`
	var uid any
	if userID != uuid.Nil {
		uid = userID
	}
	if _, err := s.pool.Exec(ctx, q, ip, uid, username, expiresAt); err != nil {
		return fmt.Errorf("upsert proxy auth cache: %w", err)
	}
	return nil
}

// DeleteProxyAuthCache removes the cache entry for ip (idempotent).
func (s *Store) DeleteProxyAuthCache(ctx context.Context, ip string) error {
	if ip == "" {
		return fmt.Errorf("ip is required")
	}
	const q = `DELETE FROM proxy_auth_cache WHERE ip = $1`
	if _, err := s.pool.Exec(ctx, q, ip); err != nil {
		return fmt.Errorf("delete proxy auth cache: %w", err)
	}
	return nil
}
