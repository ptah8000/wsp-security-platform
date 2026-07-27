package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wsp-security/wsp/internal/store"
)

// DefaultAdminSessionTTL is used when SessionManager is constructed with a non-positive TTL.
const DefaultAdminSessionTTL = 24 * time.Hour

// SessionManager issues and validates admin UI session cookies.
// Only SHA-256 hashes of tokens are persisted; the raw token is returned once from Create.
type SessionManager struct {
	store *store.Store
	ttl   time.Duration
}

// NewSessionManager returns a SessionManager. Non-positive ttl uses DefaultAdminSessionTTL.
func NewSessionManager(s *store.Store, ttl time.Duration) *SessionManager {
	if ttl <= 0 {
		ttl = DefaultAdminSessionTTL
	}
	return &SessionManager{store: s, ttl: ttl}
}

// Create issues a new session for userID, stores only the token hash, and returns the raw token
// (cookie value). The token is 32 random bytes, base64url-encoded without padding.
func (m *SessionManager) Create(ctx context.Context, userID uuid.UUID, ip, ua string) (token string, err error) {
	if m == nil || m.store == nil {
		return "", errors.New("session manager is not configured")
	}
	if userID == uuid.Nil {
		return "", errors.New("user_id is required")
	}

	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate session token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(raw)
	tokenHash := hashToken(token)
	expiresAt := time.Now().UTC().Add(m.ttl)

	if _, err := m.store.CreateAdminSession(ctx, userID, tokenHash, ip, ua, expiresAt); err != nil {
		return "", err
	}
	return token, nil
}

// UserFromToken resolves a valid, non-expired session token to its user.
// Disabled users and unknown/expired tokens return an error.
func (m *SessionManager) UserFromToken(ctx context.Context, token string) (*store.User, error) {
	if m == nil || m.store == nil {
		return nil, errors.New("session manager is not configured")
	}
	if token == "" {
		return nil, errors.New("session token is required")
	}

	user, err := m.store.GetUserByAdminTokenHash(ctx, hashToken(token))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("invalid or expired session: %w", err)
		}
		return nil, err
	}
	if !user.Enabled {
		return nil, errors.New("user is disabled")
	}
	return &user, nil
}

// Revoke deletes the session identified by token (idempotent when already absent).
func (m *SessionManager) Revoke(ctx context.Context, token string) error {
	if m == nil || m.store == nil {
		return errors.New("session manager is not configured")
	}
	if token == "" {
		return errors.New("session token is required")
	}
	return m.store.DeleteAdminSessionByTokenHash(ctx, hashToken(token))
}

// hashToken returns the hex-encoded SHA-256 of token (what is stored in admin_sessions.token_hash).
func hashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
