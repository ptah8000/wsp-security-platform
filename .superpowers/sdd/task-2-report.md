# Task 2 Report: Store layer + migrations runner

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `97e4ea2` — `feat: add postgres store and migrations`  
**Date:** 2026-07-27

---

## Summary

Implemented the PostgreSQL store package (`internal/store`) with pgx/v5 pool, embedded SQL migration runner, user/settings/audit repository methods required for Task 2, integration tests (build tag `integration`, skip without `WSP_DATABASE_URL`), and wired `cmd/wsp` to open the store and migrate on startup.

---

## Deliverables

| Path | Purpose |
|------|---------|
| `migrations/embed.go` | `//go:embed *.sql` → `migrations.FS` for production |
| `internal/store/store.go` | `Store`, `New`, `Close`, `Ping`, `Pool` |
| `internal/store/migrate.go` | Ordered `*.up.sql` runner + `schema_migrations` table |
| `internal/store/users.go` | `User`, `CreateUser`, `GetUserByUsername` |
| `internal/store/settings.go` | `IsSetupComplete`, `GetSetting`, `SetSetting`, `GetSettingRow` |
| `internal/store/audit.go` | `AuditEntry`, `InsertAuditLog` |
| `internal/store/migrate_test.go` | Unit tests for migration filename listing |
| `internal/store/store_integration_test.go` | Integration tests (`//go:build integration`) |
| `cmd/wsp/main.go` | Real migrate-on-startup (replaces stub) |
| `go.mod` / `go.sum` | `pgx/v5`, `google/uuid` |

---

## Store API

```go
type Store struct { pool *pgxpool.Pool }

func New(ctx context.Context, databaseURL string) (*Store, error)
func (s *Store) Close()
func (s *Store) Migrate(ctx context.Context) error
func (s *Store) Ping(ctx context.Context) error
func (s *Store) IsSetupComplete(ctx context.Context) (bool, error)
func (s *Store) CreateUser(ctx context.Context, u User) (User, error)
func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error)
```

**Also provided (needed by integration / later tasks, still store-layer only):**

- `GetSetting` / `SetSetting` / `GetSettingRow`
- `InsertAuditLog`
- Setting key constants (`setup_completed`, retention, DNS, listen, platform)

---

## Migration runner design

1. Ensure `schema_migrations (version TEXT PK, applied_at TIMESTAMPTZ)`.
2. Discover `NNN_name.up.sql` from embedded `migrations.FS` (sorted by version).
3. Skip versions already recorded.
4. Apply each pending file via **simple query protocol** (`pgconn.Exec`) so multi-statement SQL (functions, many statements) works.
5. Wrap apply + version insert in `BEGIN`/`COMMIT` (rollback on failure).

Production path uses embed only (no filesystem fallback required for Task 2). Down migrations are present in the FS but not auto-applied.

---

## Main wiring

On process start (after config + logger):

1. `store.New(ctx, cfg.DatabaseURL)` with 60s timeout  
2. `s.Migrate(ctx)`  
3. Log `setup_complete` from `IsSetupComplete`  
4. `s.Close()` (long-lived store ownership lands with later listener tasks)

`--version` still prints `0.1.0` and exits before DB access.

**Note:** Default run now requires a reachable Postgres (`WSP_DATABASE_URL` or default localhost URL). Without DB, process exits non-zero after logging migration failure — expected for this task.

---

## Dependencies

| Module | Version |
|--------|---------|
| `github.com/jackc/pgx/v5` | v5.7.4 |
| `github.com/google/uuid` | v1.6.0 |

Go module still declares `go 1.22` (compatible with toolchain 1.26.5 used locally).

---

## Verification

| Check | Result |
|-------|--------|
| `go test ./internal/store/` (unit) | PASS — `TestListUpMigrations`, `TestListUpMigrationsEmpty` |
| `go test ./internal/config/` | PASS |
| `go test ./...` | PASS (store unit + config) |
| `go test -tags=integration ./internal/store/` without `WSP_DATABASE_URL` | PASS with SKIP on three integration tests |
| `go build -o bin/wsp.exe ./cmd/wsp` | PASS |
| `wsp --version` | `0.1.0` |
| Integration against live Postgres | **Not run** — Docker daemon unavailable (`dockerDesktopLinuxEngine` pipe missing). Tests correctly skip when `WSP_DATABASE_URL` unset. |

### Integration tests (when DB available)

```bash
# example
export WSP_DATABASE_URL='postgres://wsp:wsp@localhost:5432/wsp?sslmode=disable'
go test -tags=integration ./internal/store/ -count=1 -v
```

Coverage: migrate (+idempotent second pass), ping, `IsSetupComplete` false after seed, read `log_retention_days`, create/get user, audit insert, missing-user `pgx.ErrNoRows`.

---

## Self-review

### Matches task brief
- [x] `internal/store` with store/migrate/users/settings/audit
- [x] Interfaces: New, Close, Migrate, Ping, IsSetupComplete, CreateUser, GetUserByUsername
- [x] Embed of `migrations/*.sql` for production
- [x] Integration test tag + skip without `WSP_DATABASE_URL`
- [x] Main wired to migrate on startup
- [x] Commit message `feat: add postgres store and migrations`
- [x] No Task 3+ (auth, sessions, proxy, etc.)

### Concerns / follow-ups
1. **No live DB verification this run** — Docker engine was down; re-run integration tests when Postgres is up.
2. **Startup hard-depends on Postgres** — acceptable post-Task-2; health/retry policy may be refined when gateway/management split lands.
3. **`CreateUser` stores `Enabled` as provided** — zero value is `false`; wizard/callers must set `Enabled: true`.
4. **Migration version key is numeric prefix only** (`001`), matching one file per version convention.
5. **Transaction wrapping** around full init SQL assumes migrations do not open nested transactions or require `CONCURRENTLY` — true for `001_init`.

---

## Out of scope (not done)

- Auth package (Task 3)
- Long-lived store shared with HTTP/proxy listeners
- Down-migration CLI
- golang-migrate library (custom embed runner used instead)

---

## Review fix (post Task 2 review)

**Status:** DONE  
**Commit:** `2d18051` — `fix: store CreateUser defaults enabled; harden integration asserts`  
**Date:** 2026-07-27

### Findings addressed

1. **CreateUser Enabled footgun** — `CreateUser` always inserts `enabled = true` and ignores `u.Enabled` (bool zero-value was silently creating disabled users). Comment documents that disable-on-create is deferred to a future `SetUserEnabled`.
2. **Integration test dirty DB** — `TestIntegration_MigratePingAndSettings` now re-seeds `setup_completed=false` and `log_retention_days=30` via `SetSetting` before asserts, so reused Postgres instances do not fail on mutated seed rows.
3. **Embedded migration list unit test** — `TestListUpMigrationsEmbeddedFS` asserts `listUpMigrations(migrations.FS)` finds version `001` / name `init`.

### Files touched

| Path | Change |
|------|--------|
| `internal/store/users.go` | Force `enabled=true` on create |
| `internal/store/store_integration_test.go` | Reset seed settings; omit Enabled on CreateUser (assert still true) |
| `internal/store/migrate_test.go` | `TestListUpMigrationsEmbeddedFS` |

### Verification (this fix)

| Check | Result |
|-------|--------|
| `go test ./...` | PASS — store unit tests include new embed FS test; config cached OK |
| Integration (`-tags=integration`) | Not re-run (no `WSP_DATABASE_URL` / Docker this pass); code path hardened for dirty DB |
