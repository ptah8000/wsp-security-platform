### Task 2: Store layer + migrations runner

**Files:**
- Create: `internal/store/store.go`, `migrate.go`, `users.go`, `settings.go`, `audit.go`, repository files as needed
- Test: `internal/store/store_integration_test.go` (tag `integration`, skip without `WSP_DATABASE_URL`)

**Interfaces:**
- Produces:
```go
type Store struct { pool *pgxpool.Pool }
func New(ctx context.Context, databaseURL string) (*Store, error)
func (s *Store) Close()
func (s *Store) Migrate(ctx context.Context) error
func (s *Store) Ping(ctx context.Context) error
func (s *Store) IsSetupComplete(ctx context.Context) (bool, error)
func (s *Store) CreateUser(ctx context.Context, u User) (User, error)
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error)
// ... additional methods added in later tasks when needed
```

- [ ] **Step 1: Implement `New` + `Migrate`** using embed of `migrations/*.sql` or reading from filesystem in dev; production uses embed.

- [ ] **Step 2: Integration test** — start against Compose postgres or skip; create user, read settings.

- [ ] **Step 3: Wire main to migrate on startup**

- [ ] **Step 4: Commit** `feat: add postgres store and migrations`

---
