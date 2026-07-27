### Task 3: Auth (passwords, admin sessions, proxy auth cache)

**Files:**
- Create: `internal/auth/password.go`, `admin_session.go`, `proxy_auth.go`
- Test: `internal/auth/password_test.go`, `admin_session_test.go`

**Interfaces:**
```go
func HashPassword(password string) (string, error)
func CheckPassword(hash, password string) bool

type SessionManager struct { store *store.Store; ttl time.Duration }
func (m *SessionManager) Create(ctx context.Context, userID uuid.UUID, ip, ua string) (token string, err error)
func (m *SessionManager) UserFromToken(ctx context.Context, token string) (*store.User, error)
func (m *SessionManager) Revoke(ctx context.Context, token string) error

type ProxyAuthCache struct { store *store.Store; ttl time.Duration }
func (c *ProxyAuthCache) Get(ctx context.Context, ip string) (username string, userID uuid.UUID, ok bool)
func (c *ProxyAuthCache) Put(ctx context.Context, ip string, userID uuid.UUID, username string) error
```

- [ ] **Step 1: TDD password hashing with argon2id** (`golang.org/x/crypto/argon2`)

- [ ] **Step 2: Session tokens** — generate 32 random bytes, store SHA-256 hash only, return raw token once (cookie value)

- [ ] **Step 3: Commit** `feat: add argon2id passwords and admin sessions`

---
