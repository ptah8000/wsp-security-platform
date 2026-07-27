package store

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// User roles stored in the users.role column.
const (
	RoleAdmin = "admin"
	RoleUser  = "user"
)

// User is a platform account (admin UI and/or proxy identity).
type User struct {
	ID           uuid.UUID  `json:"id"`
	Username     string     `json:"username"`
	PasswordHash string     `json:"-"`
	DisplayName  string     `json:"display_name"`
	Role         string     `json:"role"`
	Enabled      bool       `json:"enabled"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
}

// CreateUser inserts a new user and returns the row as stored (including generated id/timestamps).
// Callers must set Username and PasswordHash; Role defaults to "user" when empty.
// New accounts are always created enabled (u.Enabled is ignored). Use a dedicated
// SetUserEnabled later if disable-on-create is needed.
func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
	if u.Username == "" {
		return User{}, fmt.Errorf("username is required")
	}
	if u.PasswordHash == "" {
		return User{}, fmt.Errorf("password_hash is required")
	}
	if u.Role == "" {
		u.Role = RoleUser
	}
	if u.Role != RoleAdmin && u.Role != RoleUser {
		return User{}, fmt.Errorf("invalid role %q", u.Role)
	}

	// v1: always create active users (avoids bool zero-value footgun).
	const enabled = true

	const q = `
INSERT INTO users (username, password_hash, display_name, role, enabled)
VALUES ($1, $2, $3, $4, $5)
RETURNING id, username, password_hash, display_name, role, enabled, created_at, updated_at, last_login_at
`
	var out User
	err := s.pool.QueryRow(ctx, q,
		u.Username,
		u.PasswordHash,
		u.DisplayName,
		u.Role,
		enabled,
	).Scan(
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
		return User{}, fmt.Errorf("create user: %w", err)
	}
	return out, nil
}

// GetUserByUsername returns the user with the given username.
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
	const q = `
SELECT id, username, password_hash, display_name, role, enabled, created_at, updated_at, last_login_at
FROM users
WHERE username = $1
`
	var out User
	err := s.pool.QueryRow(ctx, q, username).Scan(
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
			return User{}, fmt.Errorf("user %q: %w", username, err)
		}
		return User{}, fmt.Errorf("get user by username: %w", err)
	}
	return out, nil
}

// ListUsers returns all users ordered by username.
// PasswordHash is not selected (always empty on returned rows).
func (s *Store) ListUsers(ctx context.Context) ([]User, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("store is nil")
	}
	const q = `
SELECT id, username, display_name, role, enabled, created_at, updated_at, last_login_at
FROM users
ORDER BY username ASC, id ASC
`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	defer rows.Close()

	var out []User
	for rows.Next() {
		var u User
		if err := rows.Scan(
			&u.ID, &u.Username, &u.DisplayName, &u.Role, &u.Enabled,
			&u.CreatedAt, &u.UpdatedAt, &u.LastLoginAt,
		); err != nil {
			return nil, fmt.Errorf("scan user: %w", err)
		}
		out = append(out, u)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list users: %w", err)
	}
	if out == nil {
		out = []User{}
	}
	return out, nil
}

// UpdateUser updates mutable user fields. PasswordHash is only updated when non-empty.
// Username cannot change. Returns the updated row without password_hash.
func (s *Store) UpdateUser(ctx context.Context, id uuid.UUID, displayName, role string, enabled bool, passwordHash string) (User, error) {
	if s == nil || s.pool == nil {
		return User{}, fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return User{}, fmt.Errorf("user id is required")
	}
	if role != "" && role != RoleAdmin && role != RoleUser {
		return User{}, fmt.Errorf("invalid role %q", role)
	}

	// When role is empty, keep existing; when passwordHash empty, keep existing.
	const q = `
UPDATE users SET
  display_name = $2,
  role = CASE WHEN $3 = '' THEN role ELSE $3 END,
  enabled = $4,
  password_hash = CASE WHEN $5 = '' THEN password_hash ELSE $5 END,
  updated_at = now()
WHERE id = $1
RETURNING id, username, display_name, role, enabled, created_at, updated_at, last_login_at
`
	var out User
	err := s.pool.QueryRow(ctx, q, id, displayName, role, enabled, passwordHash).Scan(
		&out.ID, &out.Username, &out.DisplayName, &out.Role, &out.Enabled,
		&out.CreatedAt, &out.UpdatedAt, &out.LastLoginAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return User{}, fmt.Errorf("user %s: %w", id, err)
		}
		return User{}, fmt.Errorf("update user: %w", err)
	}
	return out, nil
}

// DeleteUser removes a user by id. Cascades admin_sessions via FK.
func (s *Store) DeleteUser(ctx context.Context, id uuid.UUID) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return fmt.Errorf("user id is required")
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete user: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", id, pgx.ErrNoRows)
	}
	return nil
}

// TouchUserLastLogin sets last_login_at to now for the user.
func (s *Store) TouchUserLastLogin(ctx context.Context, id uuid.UUID) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return fmt.Errorf("user id is required")
	}
	const q = `UPDATE users SET last_login_at = now(), updated_at = now() WHERE id = $1`
	tag, err := s.pool.Exec(ctx, q, id)
	if err != nil {
		return fmt.Errorf("touch last login: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user %s: %w", id, pgx.ErrNoRows)
	}
	return nil
}

// CountUsersByRole returns how many users have the given role.
func (s *Store) CountUsersByRole(ctx context.Context, role string) (int, error) {
	if s == nil || s.pool == nil {
		return 0, fmt.Errorf("store is nil")
	}
	var n int
	err := s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE role = $1`, role).Scan(&n)
	if err != nil {
		return 0, fmt.Errorf("count users by role: %w", err)
	}
	return n, nil
}
