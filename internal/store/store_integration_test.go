//go:build integration

package store_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wsp-security/wsp/internal/store"
)

func testDatabaseURL(t *testing.T) string {
	t.Helper()
	url := os.Getenv("WSP_DATABASE_URL")
	if url == "" {
		t.Skip("WSP_DATABASE_URL not set; skipping store integration tests")
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
	// Idempotent second pass.
	if err := s.Migrate(ctx); err != nil {
		t.Fatalf("Migrate (second): %v", err)
	}
	return s
}

func TestIntegration_MigratePingAndSettings(t *testing.T) {
	s := openMigratedStore(t)
	ctx := context.Background()

	if err := s.Ping(ctx); err != nil {
		t.Fatalf("Ping: %v", err)
	}

	complete, err := s.IsSetupComplete(ctx)
	if err != nil {
		t.Fatalf("IsSetupComplete: %v", err)
	}
	if complete {
		t.Fatalf("IsSetupComplete = true, want false after fresh seed")
	}

	raw, err := s.GetSetting(ctx, store.SettingLogRetentionDays)
	if err != nil {
		t.Fatalf("GetSetting log_retention_days: %v", err)
	}
	var days int
	if err := json.Unmarshal(raw, &days); err != nil {
		t.Fatalf("unmarshal retention: %v", err)
	}
	if days != 30 {
		t.Errorf("log_retention_days = %d, want 30", days)
	}
}

func TestIntegration_CreateAndGetUser(t *testing.T) {
	s := openMigratedStore(t)
	ctx := context.Background()

	username := "itest_" + uuid.NewString()[:8]
	created, err := s.CreateUser(ctx, store.User{
		Username:     username,
		PasswordHash: "argon2id$test-hash-not-real",
		DisplayName:  "Integration Tester",
		Role:         store.RoleAdmin,
		Enabled:      true,
	})
	if err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	if created.ID == uuid.Nil {
		t.Fatal("CreateUser returned nil id")
	}
	if created.Username != username {
		t.Errorf("username = %q, want %q", created.Username, username)
	}
	if created.Role != store.RoleAdmin {
		t.Errorf("role = %q, want admin", created.Role)
	}
	if !created.Enabled {
		t.Error("enabled = false, want true")
	}
	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
		t.Error("expected non-zero timestamps")
	}

	got, err := s.GetUserByUsername(ctx, username)
	if err != nil {
		t.Fatalf("GetUserByUsername: %v", err)
	}
	if got.ID != created.ID {
		t.Errorf("id = %v, want %v", got.ID, created.ID)
	}
	if got.PasswordHash != "argon2id$test-hash-not-real" {
		t.Errorf("password_hash mismatch")
	}

	_, err = s.GetUserByUsername(ctx, "does-not-exist-"+uuid.NewString())
	if err == nil {
		t.Fatal("expected error for missing user")
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		t.Errorf("missing user error = %v, want wrapped pgx.ErrNoRows", err)
	}
}

func TestIntegration_AuditLog(t *testing.T) {
	s := openMigratedStore(t)
	ctx := context.Background()

	entry, err := s.InsertAuditLog(ctx, store.AuditEntry{
		Action:     "test.integration",
		TargetType: "settings",
		TargetID:   "setup_completed",
		Summary:    "integration test audit row",
		Detail:     json.RawMessage(`{"ok":true}`),
		IP:         "127.0.0.1",
	})
	if err != nil {
		t.Fatalf("InsertAuditLog: %v", err)
	}
	if entry.ID == uuid.Nil {
		t.Fatal("audit id is nil")
	}
	if entry.TS.IsZero() {
		t.Fatal("audit ts is zero")
	}
	if entry.Action != "test.integration" {
		t.Errorf("action = %q", entry.Action)
	}
}
