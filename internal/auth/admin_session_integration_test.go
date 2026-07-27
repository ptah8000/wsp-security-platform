//go:build integration

package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wsp-security/wsp/internal/auth"
	"github.com/wsp-security/wsp/internal/store"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("WSP_DATABASE_URL")
	if url == "" {
		t.Skip("WSP_DATABASE_URL not set; skipping auth integration tests")
	}
	return url
}

func openMigratedStore(t *testing.T) *store.Store {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	s, err := store.New(ctx, testDatabaseURL(t))
	if err != nil {
		t.Fatalf("store.New: %v", err)
	}
	t.Cleanup(s.Close)
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate: %v", err)
	}
	return s
}

func hashTokenHex(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func TestIntegration_AdminSessionLifecycle(t *testing.T) {
	s := openMigratedStore(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, store.User{
		Username:     "sess_" + uuid.NewString()[:8],
		PasswordHash: "argon2id$test-not-real",
		Role:         store.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	sm := auth.NewSessionManager(s, time.Hour)
	token, err := sm.Create(ctx, user.ID, "203.0.113.10", "test-agent/1.0")
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if token == "" {
		t.Fatal("Create returned empty token")
	}

	got, err := sm.UserFromToken(ctx, token)
	if err != nil {
		t.Fatalf("UserFromToken: %v", err)
	}
	if got.ID != user.ID || got.Username != user.Username {
		t.Fatalf("user = %+v, want id=%s username=%s", got, user.ID, user.Username)
	}
	if got.PasswordHash != "" {
		t.Error("UserFromToken must not load password_hash")
	}

	_, err = sm.UserFromToken(ctx, token+"x")
	if err == nil {
		t.Fatal("UserFromToken wrong token: want error")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("wrong token error = %v, want wrapped pgx.ErrNoRows", err)
	}

	if err := sm.Revoke(ctx, token); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	_, err = sm.UserFromToken(ctx, token)
	if err == nil {
		t.Fatal("UserFromToken after revoke: want error")
	}
	if err := sm.Revoke(ctx, token); err != nil {
		t.Fatalf("second Revoke: %v", err)
	}
}

func TestIntegration_ProxyAuthCache(t *testing.T) {
	s := openMigratedStore(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, store.User{
		Username:     "proxy_" + uuid.NewString()[:8],
		PasswordHash: "argon2id$test-not-real",
		Role:         store.RoleUser,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	cache := auth.NewProxyAuthCache(s, time.Hour)
	// Unique IP per run to avoid collisions on reused DBs.
	ip := "198.51.100." + uuid.NewString()[:8]

	if _, _, ok := cache.Get(ctx, ip); ok {
		t.Fatal("Get before Put: want ok=false")
	}

	if err := cache.Put(ctx, ip, user.ID, user.Username); err != nil {
		t.Fatalf("Put: %v", err)
	}

	username, userID, ok := cache.Get(ctx, ip)
	if !ok {
		t.Fatal("Get after Put: want ok=true")
	}
	if username != user.Username || userID != user.ID {
		t.Fatalf("got username=%q id=%s, want %q %s", username, userID, user.Username, user.ID)
	}

	if err := cache.Put(ctx, ip, user.ID, user.Username); err != nil {
		t.Fatalf("Put refresh: %v", err)
	}
}

func TestIntegration_ExpiredAdminSession(t *testing.T) {
	s := openMigratedStore(t)
	ctx := context.Background()

	user, err := s.CreateUser(ctx, store.User{
		Username:     "exp_" + uuid.NewString()[:8],
		PasswordHash: "argon2id$test-not-real",
		Role:         store.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	tokenRaw := "expired-token-" + uuid.NewString()
	_, err = s.CreateAdminSession(ctx, user.ID, hashTokenHex(tokenRaw), "127.0.0.1", "ua", time.Now().UTC().Add(-time.Minute))
	if err != nil {
		t.Fatalf("CreateAdminSession expired: %v", err)
	}

	sm := auth.NewSessionManager(s, time.Hour)
	_, err = sm.UserFromToken(ctx, tokenRaw)
	if err == nil {
		t.Fatal("UserFromToken expired: want error")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("expired session error = %v, want pgx.ErrNoRows", err)
	}
}
