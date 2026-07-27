# Task 3 Report: Auth (passwords, admin sessions, proxy auth cache)

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `1daf8c4` — `feat: add argon2id passwords and admin sessions`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Implemented `internal/auth` with argon2id password hashing (PHC string format), admin session manager (32-byte random tokens, SHA-256 hex stored only), and proxy IP auth cache. Added store methods for `admin_sessions` and `proxy_auth_cache`, plus `GetUserByID`.

---

## Deliverables

| Path | Purpose |
|------|---------|
| `internal/auth/password.go` | `HashPassword` / `CheckPassword` (argon2id) |
| `internal/auth/password_test.go` | TDD unit tests for hashing |
| `internal/auth/admin_session.go` | `SessionManager` Create / UserFromToken / Revoke |
| `internal/auth/admin_session_test.go` | Unit tests (token hash, validation, defaults) |
| `internal/auth/admin_session_integration_test.go` | Integration tests (`//go:build integration`) |
| `internal/auth/proxy_auth.go` | `ProxyAuthCache` Get / Put |
| `internal/auth/proxy_auth_test.go` | Unit tests for defaults / nil safety |
| `internal/store/admin_sessions.go` | Admin session CRUD + `GetUserByID` |
| `internal/store/proxy_auth_cache.go` | Proxy auth cache get/upsert/delete |
| `go.mod` / `go.sum` | direct `golang.org/x/crypto` |

---

## Auth API

```go
func HashPassword(password string) (string, error)
func CheckPassword(hash, password string) bool

func NewSessionManager(s *store.Store, ttl time.Duration) *SessionManager
func (m *SessionManager) Create(ctx, userID, ip, ua) (token string, err error)
func (m *SessionManager) UserFromToken(ctx, token) (*store.User, error)
func (m *SessionManager) Revoke(ctx, token) error

func NewProxyAuthCache(s *store.Store, ttl time.Duration) *ProxyAuthCache
func (c *ProxyAuthCache) Get(ctx, ip) (username string, userID uuid.UUID, ok bool)
func (c *ProxyAuthCache) Put(ctx, ip, userID, username) error
```

### Password details
- Algorithm: **argon2id** (`golang.org/x/crypto/argon2`)
- Params: time=3, memory=64 MiB, parallelism=2, keyLen=32, saltLen=16
- Encoding: PHC `$argon2id$v=19$m=...,t=...,p=...$salt$hash` (base64 raw)
- Empty password rejected; invalid hashes → `CheckPassword` false (no panic)
- Constant-time compare of derived key

### Session details
- Token: 32 cryptographically random bytes, **base64.RawURLEncoding** (cookie value)
- Storage: **SHA-256 hex** of token string only (`admin_sessions.token_hash`)
- Default TTL: 24h; non-positive ctor TTL uses default
- `UserFromToken` requires non-expired session + enabled user
- `Revoke` is idempotent

### Proxy auth cache
- Default TTL: 1h
- `Get` returns `ok=false` on miss/expired/errors (no error channel)
- `Put` upserts by IP with `expires_at = now + ttl`

---

## Store methods added

| Method | Table |
|--------|--------|
| `CreateAdminSession` | admin_sessions |
| `GetUserByAdminTokenHash` | admin_sessions ⋈ users (expires_at > now()) |
| `DeleteAdminSessionByTokenHash` | admin_sessions |
| `GetUserByID` | users |
| `GetProxyAuthCache` | proxy_auth_cache (non-expired) |
| `UpsertProxyAuthCache` | proxy_auth_cache |
| `DeleteProxyAuthCache` | proxy_auth_cache |

---

## Verification

| Check | Result |
|-------|--------|
| `go test ./internal/auth/` | PASS (password + session unit + proxy unit) |
| `go test ./...` | PASS |
| `go test -tags=integration ./internal/auth/` without `WSP_DATABASE_URL` | PASS (integration tests SKIP) |
| Live Postgres integration | **Not run** — no `WSP_DATABASE_URL` / Docker this pass |

### Integration coverage (when DB available)

```bash
export WSP_DATABASE_URL='postgres://wsp:wsp@localhost:5432/wsp?sslmode=disable'
go test -tags=integration ./internal/auth/ -count=1 -v
```

- Admin session create → resolve → wrong token → revoke → resolve fails  
- Expired session rejected (`pgx.ErrNoRows`)  
- Proxy auth cache Put/Get refresh  

---

## Self-review

### Matches task brief
- [x] `internal/auth/password.go`, `admin_session.go`, `proxy_auth.go`
- [x] Tests: `password_test.go`, `admin_session_test.go` (+ integration + proxy unit)
- [x] HashPassword / CheckPassword (argon2id)
- [x] SessionManager Create / UserFromToken / Revoke (SHA-256 of token only)
- [x] ProxyAuthCache Get / Put
- [x] Store methods for admin_sessions + proxy_auth_cache
- [x] Commit message `feat: add argon2id passwords and admin sessions`
- [x] Author WSP Dev \<dev@wsp.local\>
- [x] No Task 4+ (certs, etc.)

### Concerns / follow-ups
1. **No live DB verification** — re-run integration tests when Postgres is up.
2. **bcrypt fallback** mentioned in design as constant/preference — not implemented; only argon2id (sufficient for v1 HashPassword path).
3. **Disabled users** still have valid DB session rows until revoke/expiry; `UserFromToken` rejects them.
4. **No session cleanup job** for expired `admin_sessions` / `proxy_auth_cache` rows (indexes exist; retention can come later).
5. **Argon2 params are fixed** in code (not settings) — intentional for v1.

---

## Out of scope (not done)

- Management login handlers / cookies (later mgmt task)
- Certificate / CA work (Task 4)
- Wire auth into `cmd/wsp` or Echo middleware

---

## Review fix pass (Important findings)

**Commit:** `fix: auth session safe user load, enabled proxy cache, max password length`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

### Changes

1. **Session-safe user load** — `GetUserByAdminTokenHash` no longer SELECTs `password_hash`; `PasswordHash` is forced empty. `UserFromToken` also clears `PasswordHash` after load.
2. **Proxy auth cache enabled check** — `ProxyAuthCache.Get` looks up the user via `GetUserByID` after a cache hit; returns miss if missing/disabled.
3. **Max password length** — `HashPassword` / `CheckPassword` reject passwords longer than 1024 bytes (`MaxPasswordBytes`); empty already rejected. Unit tests cover oversize + boundary.

### Verification

| Check | Result |
|-------|--------|
| `go test ./internal/auth/...` | PASS |
| `go test ./...` | PASS |
