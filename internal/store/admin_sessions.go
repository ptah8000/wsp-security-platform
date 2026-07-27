package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// AdminSession is a row in admin_sessions (token material is never stored raw).
type AdminSession struct {
	ID        uuid.UUID `json:"id"`
	UserID    uuid.UUID `json:"user_id"`
	TokenHash string    `json:"-"`
	ExpiresAt time.Time `json:"expires_at"`
	IP        string    `json:"ip,omitempty"`
	UserAgent string    `json:"user_agent,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// CreateAdminSession inserts a session row identified by tokenHash (SHA-256 hex of the cookie token).
func (s *Store) CreateAdminSession(ctx context.Context, userID uuid.UUID, tokenHash, ip, userAgent string, expiresAt time.Time) (AdminSession, error) {
	if userID == uuid.Nil {
		return AdminSession{}, fmt.Errorf("user_id is required")
	}
	if tokenHash == "" {
		return AdminSession{}, fmt.Errorf("token_hash is required")
	}
	if expiresAt.IsZero() {
		return AdminSession{}, fmt.Errorf("expires_at is required")
	}

	const q = `
INSERT INTO admin_sessions (user_id, token_hash, expires_at, ip, user_agent)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, user_id, token_hash, expires_at, ip, user_agent, created_at
`
	var out AdminSession
	var ipOut, uaOut *string
	err := s.pool.QueryRow(ctx, q,
		userID,
		tokenHash,
		expiresAt,
		nullIfEmpty(ip),
		nullIfEmpty(userAgent),
	).Scan(
		&out.ID,
		&out.UserID,
		&out.TokenHash,
		&out.ExpiresAt,
		&ipOut,
		&uaOut,
		&out.CreatedAt,
	)
	if err != nil {
		return AdminSession{}, fmt.Errorf("create admin session: %w", err)
	}
	if ipOut != nil {
		out.IP = *ipOut
	}
	if uaOut != nil {
		out.UserAgent = *uaOut
	}
	return out, nil
}

// GetUserByAdminTokenHash returns the user for a non-expired admin session token hash.
// Expired sessions yield pgx.ErrNoRows (wrapped).
func (s *Store) GetUserByAdminTokenHash(ctx context.Context, tokenHash string) (User, error) {
	if tokenHash == "" {
		return User{}, fmt.Errorf("token_hash is required")
	}
	const q = `
SELECT u.id, u.username, u.password_hash, u.display_name, u.role, u.enabled,
       u.created_at, u.updated_at, u.last_login_at
FROM admin_sessions s
JOIN users u ON u.id = s.user_id
WHERE s.token_hash = $1
  AND s.expires_at > now()
`
	var out User
	err := s.pool.QueryRow(ctx, q, tokenHash).Scan(
		&out.ID,
		&out.Username,
		&out.PasswordHash,
		&out.DisplayName,
		&out.Role,
		&out.Enabled,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.LastLoginAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, fmt.Errorf("admin session: %w", err)
		}
		return User{}, fmt.Errorf("get user by admin token hash: %w", err)
	}
	return out, nil
}

// DeleteAdminSessionByTokenHash removes the session row for tokenHash.
// Missing rows are not an error (idempotent revoke).
func (s *Store) DeleteAdminSessionByTokenHash(ctx context.Context, tokenHash string) error {
	if tokenHash == "" {
		return fmt.Errorf("token_hash is required")
	}
	const q = `DELETE FROM admin_sessions WHERE token_hash = $1`
	if _, err := s.pool.Exec(ctx, q, tokenHash); err != nil {
		return fmt.Errorf("delete admin session: %w", err)
	}
	return nil
}

// GetUserByID returns the user with the given id.
func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
	if id == uuid.Nil {
		return User{}, fmt.Errorf("user id is required")
	}
	const q = `
SELECT id, username, password_hash, display_name, role, enabled, created_at, updated_at, last_login_at
FROM users
WHERE id = $1
`
	var out User
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&out.ID,
		&out.Username,
		&out.PasswordHash,
		&out.DisplayName,
		&out.Role,
		&out.Enabled,
		&out.CreatedAt,
		&out.UpdatedAt,
		&out.LastLoginAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, fmt.Errorf("user %s: %w", id, err)
		}
		return User{}, fmt.Errorf("get user by id: %w", err)
	}
	return out, nil
}
