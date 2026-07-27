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
// Enabled is stored as provided (set true for normal accounts).
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
		u.Enabled,
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
