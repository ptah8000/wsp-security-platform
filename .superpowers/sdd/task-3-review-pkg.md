BASE ec3bec85e87e6995a1346bdce249361a93a73d33
HEAD 1daf8c4b1a73e02e50ee04ceb462590e33b7bdd4

 go.mod                                          |   3 +-  go.sum                                          |   2 +  internal/auth/admin_session.go                  |  99 ++++++++++++++  internal/auth/admin_session_integration_test.go | 166 ++++++++++++++++++++++++  internal/auth/admin_session_test.go             | 106 +++++++++++++++  internal/auth/password.go                       | 114 ++++++++++++++++  internal/auth/password_test.go                  |  79 +++++++++++  internal/auth/proxy_auth.go                     |  55 ++++++++  internal/auth/proxy_auth_test.go                |  48 +++++++  internal/store/admin_sessions.go                | 147 +++++++++++++++++++++  internal/store/proxy_auth_cache.go              |  87 +++++++++++++  11 files changed, 905 insertions(+), 1 deletion(-)

diff --git a/go.mod b/go.mod
index 2c26006..da08b49 100644
--- a/go.mod
+++ b/go.mod
@@ -2,16 +2,17 @@ module github.com/wsp-security/wsp
 
 go 1.22
 
 require (
 	github.com/google/uuid v1.6.0
 	github.com/jackc/pgx/v5 v5.7.4
+	golang.org/x/crypto v0.31.0
 )
 
 require (
 	github.com/jackc/pgpassfile v1.0.0 // indirect
 	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
 	github.com/jackc/puddle/v2 v2.2.2 // indirect
-	golang.org/x/crypto v0.31.0 // indirect
 	golang.org/x/sync v0.10.0 // indirect
+	golang.org/x/sys v0.28.0 // indirect
 	golang.org/x/text v0.21.0 // indirect
 )
diff --git a/go.sum b/go.sum
index d95dea0..5fae489 100644
--- a/go.sum
+++ b/go.sum
@@ -19,12 +19,14 @@ github.com/stretchr/testify v1.7.0/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/
 github.com/stretchr/testify v1.8.1 h1:w7B6lhMri9wdJUVmEZPGGhZzrYTPvgJArz7wNPgYKsk=
 github.com/stretchr/testify v1.8.1/go.mod h1:w2LPCIKwWwSfY2zedu0+kehJoqGctiVI29o6fzry7u4=
 golang.org/x/crypto v0.31.0 h1:ihbySMvVjLAeSH1IbfcRTkD/iNscyz8rGzjF/E5hV6U=
 golang.org/x/crypto v0.31.0/go.mod h1:kDsLvtWBEx7MV9tJOj9bnXsPbxwJQ6csT/x4KIN4Ssk=
 golang.org/x/sync v0.10.0 h1:3NQrjDixjgGwUOCaF8w2+VYHv0Ve/vGYSbdkTa98gmQ=
 golang.org/x/sync v0.10.0/go.mod h1:Czt+wKu1gCyEFDUtn0jG5QVvpJ6rzVqr5aXyt9drQfk=
+golang.org/x/sys v0.28.0 h1:Fksou7UEQUWlKvIdsqzJmUmCX3cZuD2+P3XyyzwMhlA=
+golang.org/x/sys v0.28.0/go.mod h1:/VUhepiaJMQUp4+oa/7Zr1D23ma6VTLIYjOOTFZPUcA=
 golang.org/x/text v0.21.0 h1:zyQAAkrwaneQ066sspRyJaG9VNi/YJ1NfzcGB3hZ/qo=
 golang.org/x/text v0.21.0/go.mod h1:4IBbMaMmOPCJ8SecivzSH54+73PCFmPWxNTLm+vZkEQ=
 gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
 gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
 gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
 gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
diff --git a/internal/auth/admin_session.go b/internal/auth/admin_session.go
new file mode 100644
index 0000000..27fd54a
--- /dev/null
+++ b/internal/auth/admin_session.go
@@ -0,0 +1,99 @@
+package auth
+
+import (
+	"context"
+	"crypto/rand"
+	"crypto/sha256"
+	"encoding/base64"
+	"encoding/hex"
+	"errors"
+	"fmt"
+	"time"
+
+	"github.com/google/uuid"
+	"github.com/jackc/pgx/v5"
+
+	"github.com/wsp-security/wsp/internal/store"
+)
+
+// DefaultAdminSessionTTL is used when SessionManager is constructed with a non-positive TTL.
+const DefaultAdminSessionTTL = 24 * time.Hour
+
+// SessionManager issues and validates admin UI session cookies.
+// Only SHA-256 hashes of tokens are persisted; the raw token is returned once from Create.
+type SessionManager struct {
+	store *store.Store
+	ttl   time.Duration
+}
+
+// NewSessionManager returns a SessionManager. Non-positive ttl uses DefaultAdminSessionTTL.
+func NewSessionManager(s *store.Store, ttl time.Duration) *SessionManager {
+	if ttl <= 0 {
+		ttl = DefaultAdminSessionTTL
+	}
+	return &SessionManager{store: s, ttl: ttl}
+}
+
+// Create issues a new session for userID, stores only the token hash, and returns the raw token
+// (cookie value). The token is 32 random bytes, base64url-encoded without padding.
+func (m *SessionManager) Create(ctx context.Context, userID uuid.UUID, ip, ua string) (token string, err error) {
+	if m == nil || m.store == nil {
+		return "", errors.New("session manager is not configured")
+	}
+	if userID == uuid.Nil {
+		return "", errors.New("user_id is required")
+	}
+
+	raw := make([]byte, 32)
+	if _, err := rand.Read(raw); err != nil {
+		return "", fmt.Errorf("generate session token: %w", err)
+	}
+	token = base64.RawURLEncoding.EncodeToString(raw)
+	tokenHash := hashToken(token)
+	expiresAt := time.Now().UTC().Add(m.ttl)
+
+	if _, err := m.store.CreateAdminSession(ctx, userID, tokenHash, ip, ua, expiresAt); err != nil {
+		return "", err
+	}
+	return token, nil
+}
+
+// UserFromToken resolves a valid, non-expired session token to its user.
+// Disabled users and unknown/expired tokens return an error.
+func (m *SessionManager) UserFromToken(ctx context.Context, token string) (*store.User, error) {
+	if m == nil || m.store == nil {
+		return nil, errors.New("session manager is not configured")
+	}
+	if token == "" {
+		return nil, errors.New("session token is required")
+	}
+
+	user, err := m.store.GetUserByAdminTokenHash(ctx, hashToken(token))
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return nil, fmt.Errorf("invalid or expired session: %w", err)
+		}
+		return nil, err
+	}
+	if !user.Enabled {
+		return nil, errors.New("user is disabled")
+	}
+	return &user, nil
+}
+
+// Revoke deletes the session identified by token (idempotent when already absent).
+func (m *SessionManager) Revoke(ctx context.Context, token string) error {
+	if m == nil || m.store == nil {
+		return errors.New("session manager is not configured")
+	}
+	if token == "" {
+		return errors.New("session token is required")
+	}
+	return m.store.DeleteAdminSessionByTokenHash(ctx, hashToken(token))
+}
+
+// hashToken returns the hex-encoded SHA-256 of token (what is stored in admin_sessions.token_hash).
+func hashToken(token string) string {
+	sum := sha256.Sum256([]byte(token))
+	return hex.EncodeToString(sum[:])
+}
diff --git a/internal/auth/admin_session_integration_test.go b/internal/auth/admin_session_integration_test.go
new file mode 100644
index 0000000..9bca0f0
--- /dev/null
+++ b/internal/auth/admin_session_integration_test.go
@@ -0,0 +1,166 @@
+//go:build integration
+
+package auth_test
+
+import (
+	"context"
+	"crypto/sha256"
+	"encoding/hex"
+	"errors"
+	"os"
+	"testing"
+	"time"
+
+	"github.com/google/uuid"
+	"github.com/jackc/pgx/v5"
+
+	"github.com/wsp-security/wsp/internal/auth"
+	"github.com/wsp-security/wsp/internal/store"
+)
+
+func testDatabaseURL(t *testing.T) string {
+	t.Helper()
+	url := os.Getenv("WSP_DATABASE_URL")
+	if url == "" {
+		t.Skip("WSP_DATABASE_URL not set; skipping auth integration tests")
+	}
+	return url
+}
+
+func openMigratedStore(t *testing.T) *store.Store {
+	t.Helper()
+	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
+	t.Cleanup(cancel)
+
+	s, err := store.New(ctx, testDatabaseURL(t))
+	if err != nil {
+		t.Fatalf("store.New: %v", err)
+	}
+	t.Cleanup(s.Close)
+	if err := s.Migrate(ctx); err != nil {
+		t.Fatalf("Migrate: %v", err)
+	}
+	return s
+}
+
+func hashTokenHex(token string) string {
+	sum := sha256.Sum256([]byte(token))
+	return hex.EncodeToString(sum[:])
+}
+
+func TestIntegration_AdminSessionLifecycle(t *testing.T) {
+	s := openMigratedStore(t)
+	ctx := context.Background()
+
+	user, err := s.CreateUser(ctx, store.User{
+		Username:     "sess_" + uuid.NewString()[:8],
+		PasswordHash: "argon2id$test-not-real",
+		Role:         store.RoleAdmin,
+	})
+	if err != nil {
+		t.Fatalf("CreateUser: %v", err)
+	}
+
+	sm := auth.NewSessionManager(s, time.Hour)
+	token, err := sm.Create(ctx, user.ID, "203.0.113.10", "test-agent/1.0")
+	if err != nil {
+		t.Fatalf("Create: %v", err)
+	}
+	if token == "" {
+		t.Fatal("Create returned empty token")
+	}
+
+	got, err := sm.UserFromToken(ctx, token)
+	if err != nil {
+		t.Fatalf("UserFromToken: %v", err)
+	}
+	if got.ID != user.ID || got.Username != user.Username {
+		t.Fatalf("user = %+v, want id=%s username=%s", got, user.ID, user.Username)
+	}
+
+	_, err = sm.UserFromToken(ctx, token+"x")
+	if err == nil {
+		t.Fatal("UserFromToken wrong token: want error")
+	}
+	if !errors.Is(err, pgx.ErrNoRows) {
+		t.Errorf("wrong token error = %v, want wrapped pgx.ErrNoRows", err)
+	}
+
+	if err := sm.Revoke(ctx, token); err != nil {
+		t.Fatalf("Revoke: %v", err)
+	}
+	_, err = sm.UserFromToken(ctx, token)
+	if err == nil {
+		t.Fatal("UserFromToken after revoke: want error")
+	}
+	if err := sm.Revoke(ctx, token); err != nil {
+		t.Fatalf("second Revoke: %v", err)
+	}
+}
+
+func TestIntegration_ProxyAuthCache(t *testing.T) {
+	s := openMigratedStore(t)
+	ctx := context.Background()
+
+	user, err := s.CreateUser(ctx, store.User{
+		Username:     "proxy_" + uuid.NewString()[:8],
+		PasswordHash: "argon2id$test-not-real",
+		Role:         store.RoleUser,
+	})
+	if err != nil {
+		t.Fatalf("CreateUser: %v", err)
+	}
+
+	cache := auth.NewProxyAuthCache(s, time.Hour)
+	// Unique IP per run to avoid collisions on reused DBs.
+	ip := "198.51.100." + uuid.NewString()[:8]
+
+	if _, _, ok := cache.Get(ctx, ip); ok {
+		t.Fatal("Get before Put: want ok=false")
+	}
+
+	if err := cache.Put(ctx, ip, user.ID, user.Username); err != nil {
+		t.Fatalf("Put: %v", err)
+	}
+
+	username, userID, ok := cache.Get(ctx, ip)
+	if !ok {
+		t.Fatal("Get after Put: want ok=true")
+	}
+	if username != user.Username || userID != user.ID {
+		t.Fatalf("got username=%q id=%s, want %q %s", username, userID, user.Username, user.ID)
+	}
+
+	if err := cache.Put(ctx, ip, user.ID, user.Username); err != nil {
+		t.Fatalf("Put refresh: %v", err)
+	}
+}
+
+func TestIntegration_ExpiredAdminSession(t *testing.T) {
+	s := openMigratedStore(t)
+	ctx := context.Background()
+
+	user, err := s.CreateUser(ctx, store.User{
+		Username:     "exp_" + uuid.NewString()[:8],
+		PasswordHash: "argon2id$test-not-real",
+		Role:         store.RoleAdmin,
+	})
+	if err != nil {
+		t.Fatalf("CreateUser: %v", err)
+	}
+
+	tokenRaw := "expired-token-" + uuid.NewString()
+	_, err = s.CreateAdminSession(ctx, user.ID, hashTokenHex(tokenRaw), "127.0.0.1", "ua", time.Now().UTC().Add(-time.Minute))
+	if err != nil {
+		t.Fatalf("CreateAdminSession expired: %v", err)
+	}
+
+	sm := auth.NewSessionManager(s, time.Hour)
+	_, err = sm.UserFromToken(ctx, tokenRaw)
+	if err == nil {
+		t.Fatal("UserFromToken expired: want error")
+	}
+	if !errors.Is(err, pgx.ErrNoRows) {
+		t.Errorf("expired session error = %v, want pgx.ErrNoRows", err)
+	}
+}
diff --git a/internal/auth/admin_session_test.go b/internal/auth/admin_session_test.go
new file mode 100644
index 0000000..8088e4a
--- /dev/null
+++ b/internal/auth/admin_session_test.go
@@ -0,0 +1,106 @@
+package auth
+
+import (
+	"context"
+	"encoding/base64"
+	"testing"
+	"time"
+
+	"github.com/google/uuid"
+)
+
+func TestHashTokenDeterministicAndUnique(t *testing.T) {
+	a := hashToken("session-token-one")
+	b := hashToken("session-token-one")
+	c := hashToken("session-token-two")
+
+	if a != b {
+		t.Fatalf("hashToken not deterministic: %q vs %q", a, b)
+	}
+	if a == c {
+		t.Fatal("different tokens must not produce the same hash")
+	}
+	if len(a) != 64 { // sha256 hex
+		t.Fatalf("hash length = %d, want 64 hex chars", len(a))
+	}
+	// Must not equal the raw token (we only store hashes).
+	if a == "session-token-one" {
+		t.Fatal("hash must not equal plaintext token")
+	}
+}
+
+func TestSessionManagerRequiresConfig(t *testing.T) {
+	ctx := context.Background()
+	var m *SessionManager
+	if _, err := m.Create(ctx, uuid.New(), "", ""); err == nil {
+		t.Error("nil SessionManager.Create: want error")
+	}
+	if _, err := m.UserFromToken(ctx, "tok"); err == nil {
+		t.Error("nil SessionManager.UserFromToken: want error")
+	}
+	if err := m.Revoke(ctx, "tok"); err == nil {
+		t.Error("nil SessionManager.Revoke: want error")
+	}
+
+	m = NewSessionManager(nil, time.Hour)
+	if _, err := m.Create(ctx, uuid.New(), "1.2.3.4", "ua"); err == nil {
+		t.Error("nil store Create: want error")
+	}
+	if _, err := m.UserFromToken(ctx, "abc"); err == nil {
+		t.Error("nil store UserFromToken: want error")
+	}
+	if err := m.Revoke(ctx, "abc"); err == nil {
+		t.Error("nil store Revoke: want error")
+	}
+}
+
+func TestSessionManagerValidation(t *testing.T) {
+	ctx := context.Background()
+	m := NewSessionManager(nil, time.Hour)
+
+	if _, err := m.Create(ctx, uuid.Nil, "", ""); err == nil {
+		t.Error("Create with nil user id: want error")
+	}
+	// Empty token is rejected before store use.
+	if _, err := m.UserFromToken(ctx, ""); err == nil {
+		t.Error("UserFromToken(\"\"): want error")
+	}
+	if err := m.Revoke(ctx, ""); err == nil {
+		t.Error("Revoke(\"\"): want error")
+	}
+}
+
+func TestNewSessionManagerDefaultTTL(t *testing.T) {
+	m := NewSessionManager(nil, 0)
+	if m.ttl != DefaultAdminSessionTTL {
+		t.Fatalf("ttl = %v, want default %v", m.ttl, DefaultAdminSessionTTL)
+	}
+	m = NewSessionManager(nil, -time.Minute)
+	if m.ttl != DefaultAdminSessionTTL {
+		t.Fatalf("negative ttl = %v, want default", m.ttl)
+	}
+	m = NewSessionManager(nil, 2*time.Hour)
+	if m.ttl != 2*time.Hour {
+		t.Fatalf("ttl = %v, want 2h", m.ttl)
+	}
+}
+
+func TestTokenEncodingShape(t *testing.T) {
+	// 32 random bytes ΓåÆ raw URL encoding without padding is 43 chars.
+	raw := make([]byte, 32)
+	for i := range raw {
+		raw[i] = byte(i)
+	}
+	tok := base64.RawURLEncoding.EncodeToString(raw)
+	if len(tok) != 43 {
+		t.Fatalf("encoded length = %d, want 43", len(tok))
+	}
+	if _, err := base64.RawURLEncoding.DecodeString(tok); err != nil {
+		t.Fatalf("decode token: %v", err)
+	}
+	// Ensure hashToken never stores the cookie material itself.
+	if hashToken(tok) == tok {
+		t.Fatal("token hash equals token")
+	}
+}
+
diff --git a/internal/auth/password.go b/internal/auth/password.go
new file mode 100644
index 0000000..e0fe9ca
--- /dev/null
+++ b/internal/auth/password.go
@@ -0,0 +1,114 @@
+// Package auth provides password hashing, admin session tokens, and proxy IP auth cache.
+package auth
+
+import (
+	"crypto/rand"
+	"crypto/subtle"
+	"encoding/base64"
+	"errors"
+	"fmt"
+	"strings"
+
+	"golang.org/x/crypto/argon2"
+)
+
+// Argon2id parameters (OWASP-aligned interactive login defaults).
+const (
+	argonTime    = 3
+	argonMemory  = 64 * 1024 // KiB ΓåÆ 64 MiB
+	argonThreads = 2
+	argonKeyLen  = 32
+	argonSaltLen = 16
+)
+
+// HashPassword returns a PHC-formatted argon2id hash of password.
+// Empty passwords are rejected.
+func HashPassword(password string) (string, error) {
+	if password == "" {
+		return "", errors.New("password must not be empty")
+	}
+
+	salt := make([]byte, argonSaltLen)
+	if _, err := rand.Read(salt); err != nil {
+		return "", fmt.Errorf("generate salt: %w", err)
+	}
+
+	hash := argon2.IDKey([]byte(password), salt, argonTime, argonMemory, argonThreads, argonKeyLen)
+
+	// $argon2id$v=19$m=65536,t=3,p=2$<salt>$<hash>
+	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
+	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
+	encoded := fmt.Sprintf(
+		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
+		argon2.Version, argonMemory, argonTime, argonThreads, b64Salt, b64Hash,
+	)
+	return encoded, nil
+}
+
+// CheckPassword reports whether password matches a PHC argon2id hash.
+// Invalid or unsupported hashes return false (never panics).
+func CheckPassword(hash, password string) bool {
+	if hash == "" || password == "" {
+		return false
+	}
+
+	salt, expected, time, memory, threads, keyLen, err := parseArgon2idHash(hash)
+	if err != nil {
+		return false
+	}
+
+	got := argon2.IDKey([]byte(password), salt, time, memory, threads, keyLen)
+	if len(got) != len(expected) {
+		return false
+	}
+	return subtle.ConstantTimeCompare(got, expected) == 1
+}
+
+func parseArgon2idHash(encoded string) (salt, hash []byte, time, memory uint32, threads uint8, keyLen uint32, err error) {
+	// $argon2id$v=19$m=65536,t=3,p=2$salt$hash
+	parts := strings.Split(encoded, "$")
+	// Split yields leading empty element before first $.
+	if len(parts) != 6 {
+		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid hash format")
+	}
+	if parts[1] != "argon2id" {
+		return nil, nil, 0, 0, 0, 0, fmt.Errorf("unsupported algorithm %q", parts[1])
+	}
+	var version int
+	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil {
+		return nil, nil, 0, 0, 0, 0, fmt.Errorf("parse version: %w", err)
+	}
+	if version != argon2.Version {
+		return nil, nil, 0, 0, 0, 0, fmt.Errorf("unsupported argon2 version %d", version)
+	}
+
+	var t, m uint32
+	var p uint32
+	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &m, &t, &p); err != nil {
+		return nil, nil, 0, 0, 0, 0, fmt.Errorf("parse params: %w", err)
+	}
+	if t == 0 || m == 0 || p == 0 || p > 255 {
+		return nil, nil, 0, 0, 0, 0, fmt.Errorf("invalid argon2 params")
+	}
+
+	salt, err = base64.RawStdEncoding.DecodeString(parts[4])
+	if err != nil {
+		// Some encoders pad; accept standard encoding too.
+		salt, err = base64.StdEncoding.DecodeString(parts[4])
+		if err != nil {
+			return nil, nil, 0, 0, 0, 0, fmt.Errorf("decode salt: %w", err)
+		}
+	}
+	hash, err = base64.RawStdEncoding.DecodeString(parts[5])
+	if err != nil {
+		hash, err = base64.StdEncoding.DecodeString(parts[5])
+		if err != nil {
+			return nil, nil, 0, 0, 0, 0, fmt.Errorf("decode hash: %w", err)
+		}
+	}
+	if len(salt) == 0 || len(hash) == 0 {
+		return nil, nil, 0, 0, 0, 0, fmt.Errorf("empty salt or hash")
+	}
+
+	return salt, hash, t, m, uint8(p), uint32(len(hash)), nil
+}
diff --git a/internal/auth/password_test.go b/internal/auth/password_test.go
new file mode 100644
index 0000000..2f1fd98
--- /dev/null
+++ b/internal/auth/password_test.go
@@ -0,0 +1,79 @@
+package auth
+
+import (
+	"strings"
+	"testing"
+)
+
+func TestHashPasswordAndCheck(t *testing.T) {
+	const password = "correct horse battery staple"
+
+	hash, err := HashPassword(password)
+	if err != nil {
+		t.Fatalf("HashPassword: %v", err)
+	}
+	if hash == "" {
+		t.Fatal("HashPassword returned empty hash")
+	}
+	if hash == password {
+		t.Fatal("hash must not equal plaintext password")
+	}
+	if !strings.HasPrefix(hash, "$argon2id$") {
+		t.Fatalf("hash prefix = %q, want $argon2id$", hash[:min(20, len(hash))])
+	}
+	if !CheckPassword(hash, password) {
+		t.Error("CheckPassword(hash, correct) = false, want true")
+	}
+	if CheckPassword(hash, "wrong-password") {
+		t.Error("CheckPassword(hash, wrong) = true, want false")
+	}
+}
+
+func TestHashPasswordUniqueSalts(t *testing.T) {
+	const password = "same-password-twice"
+	h1, err := HashPassword(password)
+	if err != nil {
+		t.Fatalf("HashPassword #1: %v", err)
+	}
+	h2, err := HashPassword(password)
+	if err != nil {
+		t.Fatalf("HashPassword #2: %v", err)
+	}
+	if h1 == h2 {
+		t.Error("expected different hashes for independent salts")
+	}
+	if !CheckPassword(h1, password) || !CheckPassword(h2, password) {
+		t.Error("both hashes should verify the original password")
+	}
+}
+
+func TestHashPasswordEmpty(t *testing.T) {
+	_, err := HashPassword("")
+	if err == nil {
+		t.Fatal("HashPassword(\"\") = nil error, want error")
+	}
+}
+
+func TestCheckPasswordInvalidHash(t *testing.T) {
+	if CheckPassword("", "password") {
+		t.Error("empty hash should not verify")
+	}
+	if CheckPassword("not-a-valid-hash", "password") {
+		t.Error("garbage hash should not verify")
+	}
+	if CheckPassword("$argon2id$v=19$m=65536,t=1,p=1$YWFh$YmJi", "password") {
+		t.Error("malformed/short argon2 params should not verify")
+	}
+	// bcrypt-looking string is not supported for HashPassword output; Check returns false.
+	if CheckPassword("$2a$10$abcdefghijklmnopqrstuuABCDEFGHIJKLMNOPQRSTUVWXYZ012", "password") {
+		t.Error("bcrypt-looking hash should not verify via argon2 path")
+	}
+}
+
+func TestCheckPasswordRejectsArgon2i(t *testing.T) {
+	// Only argon2id is accepted (variant string must be argon2id).
+	fake := "$argon2i$v=19$m=65536,t=1,p=1$c2FsdHNhbHRzYWx0$aGFzaGhhc2hoYXNoaGFzaGhhc2hoYXNoaGFz"
+	if CheckPassword(fake, "anything") {
+		t.Error("argon2i hash must be rejected")
+	}
+}
diff --git a/internal/auth/proxy_auth.go b/internal/auth/proxy_auth.go
new file mode 100644
index 0000000..05b42d2
--- /dev/null
+++ b/internal/auth/proxy_auth.go
@@ -0,0 +1,55 @@
+package auth
+
+import (
+	"context"
+	"errors"
+	"time"
+
+	"github.com/google/uuid"
+
+	"github.com/wsp-security/wsp/internal/store"
+)
+
+// DefaultProxyAuthCacheTTL is used when ProxyAuthCache is constructed with a non-positive TTL.
+const DefaultProxyAuthCacheTTL = time.Hour
+
+// ProxyAuthCache persists short-lived IP ΓåÆ user mappings for proxy authentication.
+type ProxyAuthCache struct {
+	store *store.Store
+	ttl   time.Duration
+}
+
+// NewProxyAuthCache returns a ProxyAuthCache. Non-positive ttl uses DefaultProxyAuthCacheTTL.
+func NewProxyAuthCache(s *store.Store, ttl time.Duration) *ProxyAuthCache {
+	if ttl <= 0 {
+		ttl = DefaultProxyAuthCacheTTL
+	}
+	return &ProxyAuthCache{store: s, ttl: ttl}
+}
+
+// Get returns a cached username/userID for ip when a non-expired entry exists.
+func (c *ProxyAuthCache) Get(ctx context.Context, ip string) (username string, userID uuid.UUID, ok bool) {
+	if c == nil || c.store == nil || ip == "" {
+		return "", uuid.Nil, false
+	}
+	entry, found, err := c.store.GetProxyAuthCache(ctx, ip)
+	if err != nil || !found {
+		return "", uuid.Nil, false
+	}
+	return entry.Username, entry.UserID, true
+}
+
+// Put stores or refreshes the IP auth cache entry with the manager TTL.
+func (c *ProxyAuthCache) Put(ctx context.Context, ip string, userID uuid.UUID, username string) error {
+	if c == nil || c.store == nil {
+		return errors.New("proxy auth cache is not configured")
+	}
+	if ip == "" {
+		return errors.New("ip is required")
+	}
+	if username == "" {
+		return errors.New("username is required")
+	}
+	expiresAt := time.Now().UTC().Add(c.ttl)
+	return c.store.UpsertProxyAuthCache(ctx, ip, userID, username, expiresAt)
+}
diff --git a/internal/auth/proxy_auth_test.go b/internal/auth/proxy_auth_test.go
new file mode 100644
index 0000000..f0a2a6b
--- /dev/null
+++ b/internal/auth/proxy_auth_test.go
@@ -0,0 +1,48 @@
+package auth
+
+import (
+	"context"
+	"testing"
+	"time"
+
+	"github.com/google/uuid"
+)
+
+func TestNewProxyAuthCacheDefaultTTL(t *testing.T) {
+	c := NewProxyAuthCache(nil, 0)
+	if c.ttl != DefaultProxyAuthCacheTTL {
+		t.Fatalf("ttl = %v, want default %v", c.ttl, DefaultProxyAuthCacheTTL)
+	}
+	c = NewProxyAuthCache(nil, 5*time.Minute)
+	if c.ttl != 5*time.Minute {
+		t.Fatalf("ttl = %v, want 5m", c.ttl)
+	}
+}
+
+func TestProxyAuthCacheGetWithoutStore(t *testing.T) {
+	ctx := context.Background()
+	var c *ProxyAuthCache
+	if _, _, ok := c.Get(ctx, "1.2.3.4"); ok {
+		t.Error("nil cache Get: want ok=false")
+	}
+	c = NewProxyAuthCache(nil, time.Hour)
+	if _, _, ok := c.Get(ctx, "1.2.3.4"); ok {
+		t.Error("nil store Get: want ok=false")
+	}
+	if _, _, ok := c.Get(ctx, ""); ok {
+		t.Error("empty ip Get: want ok=false")
+	}
+}
+
+func TestProxyAuthCachePutValidation(t *testing.T) {
+	ctx := context.Background()
+	c := NewProxyAuthCache(nil, time.Hour)
+	if err := c.Put(ctx, "1.2.3.4", uuid.New(), "alice"); err == nil {
+		t.Error("Put with nil store: want error")
+	}
+	// Even with a store pointer nil path already covered; empty fields:
+	var nilCache *ProxyAuthCache
+	if err := nilCache.Put(ctx, "1.2.3.4", uuid.New(), "alice"); err == nil {
+		t.Error("nil ProxyAuthCache.Put: want error")
+	}
+}
diff --git a/internal/store/admin_sessions.go b/internal/store/admin_sessions.go
new file mode 100644
index 0000000..56a6fb6
--- /dev/null
+++ b/internal/store/admin_sessions.go
@@ -0,0 +1,147 @@
+package store
+
+import (
+	"context"
+	"errors"
+	"fmt"
+	"time"
+
+	"github.com/google/uuid"
+	"github.com/jackc/pgx/v5"
+)
+
+// AdminSession is a row in admin_sessions (token material is never stored raw).
+type AdminSession struct {
+	ID        uuid.UUID `json:"id"`
+	UserID    uuid.UUID `json:"user_id"`
+	TokenHash string    `json:"-"`
+	ExpiresAt time.Time `json:"expires_at"`
+	IP        string    `json:"ip,omitempty"`
+	UserAgent string    `json:"user_agent,omitempty"`
+	CreatedAt time.Time `json:"created_at"`
+}
+
+// CreateAdminSession inserts a session row identified by tokenHash (SHA-256 hex of the cookie token).
+func (s *Store) CreateAdminSession(ctx context.Context, userID uuid.UUID, tokenHash, ip, userAgent string, expiresAt time.Time) (AdminSession, error) {
+	if userID == uuid.Nil {
+		return AdminSession{}, fmt.Errorf("user_id is required")
+	}
+	if tokenHash == "" {
+		return AdminSession{}, fmt.Errorf("token_hash is required")
+	}
+	if expiresAt.IsZero() {
+		return AdminSession{}, fmt.Errorf("expires_at is required")
+	}
+
+	const q = `
+INSERT INTO admin_sessions (user_id, token_hash, expires_at, ip, user_agent)
+VALUES ($1, $2, $3, $4, $5)
+RETURNING id, user_id, token_hash, expires_at, ip, user_agent, created_at
+`
+	var out AdminSession
+	var ipOut, uaOut *string
+	err := s.pool.QueryRow(ctx, q,
+		userID,
+		tokenHash,
+		expiresAt,
+		nullIfEmpty(ip),
+		nullIfEmpty(userAgent),
+	).Scan(
+		&out.ID,
+		&out.UserID,
+		&out.TokenHash,
+		&out.ExpiresAt,
+		&ipOut,
+		&uaOut,
+		&out.CreatedAt,
+	)
+	if err != nil {
+		return AdminSession{}, fmt.Errorf("create admin session: %w", err)
+	}
+	if ipOut != nil {
+		out.IP = *ipOut
+	}
+	if uaOut != nil {
+		out.UserAgent = *uaOut
+	}
+	return out, nil
+}
+
+// GetUserByAdminTokenHash returns the user for a non-expired admin session token hash.
+// Expired sessions yield pgx.ErrNoRows (wrapped).
+func (s *Store) GetUserByAdminTokenHash(ctx context.Context, tokenHash string) (User, error) {
+	if tokenHash == "" {
+		return User{}, fmt.Errorf("token_hash is required")
+	}
+	const q = `
+SELECT u.id, u.username, u.password_hash, u.display_name, u.role, u.enabled,
+       u.created_at, u.updated_at, u.last_login_at
+FROM admin_sessions s
+JOIN users u ON u.id = s.user_id
+WHERE s.token_hash = $1
+  AND s.expires_at > now()
+`
+	var out User
+	err := s.pool.QueryRow(ctx, q, tokenHash).Scan(
+		&out.ID,
+		&out.Username,
+		&out.PasswordHash,
+		&out.DisplayName,
+		&out.Role,
+		&out.Enabled,
+		&out.CreatedAt,
+		&out.UpdatedAt,
+		&out.LastLoginAt,
+	)
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return User{}, fmt.Errorf("admin session: %w", err)
+		}
+		return User{}, fmt.Errorf("get user by admin token hash: %w", err)
+	}
+	return out, nil
+}
+
+// DeleteAdminSessionByTokenHash removes the session row for tokenHash.
+// Missing rows are not an error (idempotent revoke).
+func (s *Store) DeleteAdminSessionByTokenHash(ctx context.Context, tokenHash string) error {
+	if tokenHash == "" {
+		return fmt.Errorf("token_hash is required")
+	}
+	const q = `DELETE FROM admin_sessions WHERE token_hash = $1`
+	if _, err := s.pool.Exec(ctx, q, tokenHash); err != nil {
+		return fmt.Errorf("delete admin session: %w", err)
+	}
+	return nil
+}
+
+// GetUserByID returns the user with the given id.
+func (s *Store) GetUserByID(ctx context.Context, id uuid.UUID) (User, error) {
+	if id == uuid.Nil {
+		return User{}, fmt.Errorf("user id is required")
+	}
+	const q = `
+SELECT id, username, password_hash, display_name, role, enabled, created_at, updated_at, last_login_at
+FROM users
+WHERE id = $1
+`
+	var out User
+	err := s.pool.QueryRow(ctx, q, id).Scan(
+		&out.ID,
+		&out.Username,
+		&out.PasswordHash,
+		&out.DisplayName,
+		&out.Role,
+		&out.Enabled,
+		&out.CreatedAt,
+		&out.UpdatedAt,
+		&out.LastLoginAt,
+	)
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return User{}, fmt.Errorf("user %s: %w", id, err)
+		}
+		return User{}, fmt.Errorf("get user by id: %w", err)
+	}
+	return out, nil
+}
diff --git a/internal/store/proxy_auth_cache.go b/internal/store/proxy_auth_cache.go
new file mode 100644
index 0000000..e3d3503
--- /dev/null
+++ b/internal/store/proxy_auth_cache.go
@@ -0,0 +1,87 @@
+package store
+
+import (
+	"context"
+	"errors"
+	"fmt"
+	"time"
+
+	"github.com/google/uuid"
+	"github.com/jackc/pgx/v5"
+)
+
+// ProxyAuthCacheEntry is a row in proxy_auth_cache (IP ΓåÆ user for proxy auth).
+type ProxyAuthCacheEntry struct {
+	IP        string    `json:"ip"`
+	UserID    uuid.UUID `json:"user_id"`
+	Username  string    `json:"username"`
+	ExpiresAt time.Time `json:"expires_at"`
+}
+
+// GetProxyAuthCache returns a non-expired cache entry for ip.
+// Expired or missing rows yield ok=false with a zero entry (and nil error for miss/expired).
+func (s *Store) GetProxyAuthCache(ctx context.Context, ip string) (ProxyAuthCacheEntry, bool, error) {
+	if ip == "" {
+		return ProxyAuthCacheEntry{}, false, fmt.Errorf("ip is required")
+	}
+	const q = `
+SELECT ip, user_id, username, expires_at
+FROM proxy_auth_cache
+WHERE ip = $1 AND expires_at > now()
+`
+	var out ProxyAuthCacheEntry
+	var userID *uuid.UUID
+	err := s.pool.QueryRow(ctx, q, ip).Scan(&out.IP, &userID, &out.Username, &out.ExpiresAt)
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return ProxyAuthCacheEntry{}, false, nil
+		}
+		return ProxyAuthCacheEntry{}, false, fmt.Errorf("get proxy auth cache: %w", err)
+	}
+	if userID != nil {
+		out.UserID = *userID
+	}
+	return out, true, nil
+}
+
+// UpsertProxyAuthCache inserts or refreshes the IP auth cache entry.
+func (s *Store) UpsertProxyAuthCache(ctx context.Context, ip string, userID uuid.UUID, username string, expiresAt time.Time) error {
+	if ip == "" {
+		return fmt.Errorf("ip is required")
+	}
+	if username == "" {
+		return fmt.Errorf("username is required")
+	}
+	if expiresAt.IsZero() {
+		return fmt.Errorf("expires_at is required")
+	}
+
+	const q = `
+INSERT INTO proxy_auth_cache (ip, user_id, username, expires_at)
+VALUES ($1, $2, $3, $4)
+ON CONFLICT (ip) DO UPDATE
+SET user_id = EXCLUDED.user_id,
+    username = EXCLUDED.username,
+    expires_at = EXCLUDED.expires_at
+`
+	var uid any
+	if userID != uuid.Nil {
+		uid = userID
+	}
+	if _, err := s.pool.Exec(ctx, q, ip, uid, username, expiresAt); err != nil {
+		return fmt.Errorf("upsert proxy auth cache: %w", err)
+	}
+	return nil
+}
+
+// DeleteProxyAuthCache removes the cache entry for ip (idempotent).
+func (s *Store) DeleteProxyAuthCache(ctx context.Context, ip string) error {
+	if ip == "" {
+		return fmt.Errorf("ip is required")
+	}
+	const q = `DELETE FROM proxy_auth_cache WHERE ip = $1`
+	if _, err := s.pool.Exec(ctx, q, ip); err != nil {
+		return fmt.Errorf("delete proxy auth cache: %w", err)
+	}
+	return nil
+}
