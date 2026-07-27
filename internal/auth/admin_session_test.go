package auth

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashTokenDeterministicAndUnique(t *testing.T) {
	a := hashToken("session-token-one")
	b := hashToken("session-token-one")
	c := hashToken("session-token-two")

	if a != b {
		t.Fatalf("hashToken not deterministic: %q vs %q", a, b)
	}
	if a == c {
		t.Fatal("different tokens must not produce the same hash")
	}
	if len(a) != 64 { // sha256 hex
		t.Fatalf("hash length = %d, want 64 hex chars", len(a))
	}
	// Must not equal the raw token (we only store hashes).
	if a == "session-token-one" {
		t.Fatal("hash must not equal plaintext token")
	}
}

func TestSessionManagerRequiresConfig(t *testing.T) {
	ctx := context.Background()
	var m *SessionManager
	if _, err := m.Create(ctx, uuid.New(), "", ""); err == nil {
		t.Error("nil SessionManager.Create: want error")
	}
	if _, err := m.UserFromToken(ctx, "tok"); err == nil {
		t.Error("nil SessionManager.UserFromToken: want error")
	}
	if err := m.Revoke(ctx, "tok"); err == nil {
		t.Error("nil SessionManager.Revoke: want error")
	}

	m = NewSessionManager(nil, time.Hour)
	if _, err := m.Create(ctx, uuid.New(), "1.2.3.4", "ua"); err == nil {
		t.Error("nil store Create: want error")
	}
	if _, err := m.UserFromToken(ctx, "abc"); err == nil {
		t.Error("nil store UserFromToken: want error")
	}
	if err := m.Revoke(ctx, "abc"); err == nil {
		t.Error("nil store Revoke: want error")
	}
}

func TestSessionManagerValidation(t *testing.T) {
	ctx := context.Background()
	m := NewSessionManager(nil, time.Hour)

	if _, err := m.Create(ctx, uuid.Nil, "", ""); err == nil {
		t.Error("Create with nil user id: want error")
	}
	// Empty token is rejected before store use.
	if _, err := m.UserFromToken(ctx, ""); err == nil {
		t.Error("UserFromToken(\"\"): want error")
	}
	if err := m.Revoke(ctx, ""); err == nil {
		t.Error("Revoke(\"\"): want error")
	}
}

func TestNewSessionManagerDefaultTTL(t *testing.T) {
	m := NewSessionManager(nil, 0)
	if m.ttl != DefaultAdminSessionTTL {
		t.Fatalf("ttl = %v, want default %v", m.ttl, DefaultAdminSessionTTL)
	}
	m = NewSessionManager(nil, -time.Minute)
	if m.ttl != DefaultAdminSessionTTL {
		t.Fatalf("negative ttl = %v, want default", m.ttl)
	}
	m = NewSessionManager(nil, 2*time.Hour)
	if m.ttl != 2*time.Hour {
		t.Fatalf("ttl = %v, want 2h", m.ttl)
	}
}

func TestTokenEncodingShape(t *testing.T) {
	// 32 random bytes → raw URL encoding without padding is 43 chars.
	raw := make([]byte, 32)
	for i := range raw {
		raw[i] = byte(i)
	}
	tok := base64.RawURLEncoding.EncodeToString(raw)
	if len(tok) != 43 {
		t.Fatalf("encoded length = %d, want 43", len(tok))
	}
	if _, err := base64.RawURLEncoding.DecodeString(tok); err != nil {
		t.Fatalf("decode token: %v", err)
	}
	// Ensure hashToken never stores the cookie material itself.
	if hashToken(tok) == tok {
		t.Fatal("token hash equals token")
	}
}

