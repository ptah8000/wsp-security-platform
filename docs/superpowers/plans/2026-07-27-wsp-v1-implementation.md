# Web Security Platform v1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a complete single-host on-prem web security suite (explicit MITM proxy, policy engine, RBI, CASB, ClamAV, management UI) as a modular Go monolith with Docker Compose.

**Architecture:** One `wsp` binary exposes proxy `:8080` and management `:3000` (embedded React SPA). PostgreSQL stores config/logs; ClamAV via clamd INSTREAM; RBI via ephemeral Chromium containers + go-rod/CDP. Policy evaluation is pure; side effects run in the proxy pipeline. Interfaces at every seam enable later split/cluster.

**Tech Stack:** Go 1.22+, Echo, pgx/v5, elazarl/goproxy patterns / custom MITM, go-rod, argon2id, React+TS+Vite+Tailwind+shadcn/ui, PostgreSQL 16, ClamAV, Docker Compose on Linux only.

**Spec:** `docs/superpowers/specs/2026-07-27-web-security-platform-v1-design.md`  
**Product requirements:** `SECURITY_SUITE_V1_DEVELOPMENT_PROMPT.md`

## Global Constraints

- Open source components only.
- Linux Docker Compose is the only supported run path.
- Single binary default mode `WSP_MODE=all` (optional `gateway` | `management` for future).
- Policy engine must be pure (no I/O during evaluate).
- RBI path must never send origin HTML/JS/binaries to the user.
- CA private keys encrypted at rest with `WSP_DATA_KEY`; never exportable via API.
- Request logs partitioned (or time-keyed for drop); retention job required.
- CASB: full framework + solid ChatGPT + Google Drive; Slack/M365/WhatsApp partial.
- RBI: real create/destroy + basic stream/input (UX may be rough).
- Passwords: argon2id.
- Management API: Echo under `/api/v1`.
- Frontend: React+TS+Vite+Tailwind+shadcn, embedded with `go:embed`.
- Frequent commits; TDD where unit-testable (policy, certs, casb matchers, auth).
- Work only under `D:\Grok\WSP` (repo root).

---

## File structure (create as tasks progress)

```
D:\Grok\WSP\
  cmd/wsp/main.go
  internal/
    config/config.go
    store/
      store.go
      migrate.go
      users.go
      sessions_admin.go
      certificates.go
      settings.go
      policies.go
      objects.go
      blockpages.go
      requestlogs.go
      audit.go
    auth/
      password.go
      admin_session.go
      proxy_auth.go
    certs/
      ca.go
      leaf_cache.go
      crypto_box.go
    policy/
      types.go
      engine.go
      compile.go
      match.go
      simulate.go
    proxy/
      server.go
      mitm.go
      pipeline.go
      session.go
    casb/
      inspector.go
      types.go
      chatgpt.go
      google_drive.go
      slack.go
      m365.go
      whatsapp.go
    malware/
      clamd.go
    rbi/
      orchestrator.go
      docker.go
      session.go
      viewer_ws.go
    logging/
      recorder.go
      retention.go
    audit/
      logger.go
    blockpage/
      render.go
    export/
      export.go
    health/
      health.go
    mgmt/
      server.go
      middleware.go
      setup.go
      handlers_*.go
  web/                     # Vite React app
  migrations/
    001_init.up.sql
    001_init.down.sql
  deploy/
    Dockerfile
    docker-compose.yml
    env.example
  README.md
  go.mod
```

---

### Task 1: Repository skeleton, module, Compose, migrations

**Files:**
- Create: `go.mod`, `cmd/wsp/main.go`, `internal/config/config.go`, `migrations/001_init.up.sql`, `migrations/001_init.down.sql`, `deploy/Dockerfile`, `deploy/docker-compose.yml`, `deploy/env.example`, `.gitignore`, `README.md` (stub), `web/package.json` (minimal placeholder page)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Config` loaded from env; empty `main` that prints version and exits 0 if `--version`; Compose that builds/runs placeholders later

- [ ] **Step 1: Create `.gitignore` and `go.mod`**

```gitignore
bin/
dist/
web/dist/
web/node_modules/
.env
*.pem
*.key
.idea/
.vscode/
```

```bash
cd /path/to/WSP   # D:\Grok\WSP or Linux checkout
go mod init github.com/wsp-security/wsp
```

- [ ] **Step 2: Write `internal/config/config.go` and test**

```go
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Mode            string // all | gateway | management
	ProxyAddr       string
	AdminAddr       string
	DatabaseURL     string
	DataKey         string // 32-byte key, base64 or raw hex preferred
	ClamdAddr       string
	DockerHost      string
	RBIImage        string
	MaxRBISessions  int
	LogLevel        string
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	c := Config{
		Mode:            getenv("WSP_MODE", "all"),
		ProxyAddr:       getenv("WSP_PROXY_ADDR", ":8080"),
		AdminAddr:       getenv("WSP_ADMIN_ADDR", ":3000"),
		DatabaseURL:     getenv("WSP_DATABASE_URL", "postgres://wsp:wsp@localhost:5432/wsp?sslmode=disable"),
		DataKey:         os.Getenv("WSP_DATA_KEY"),
		ClamdAddr:       getenv("WSP_CLAMD_ADDR", "clamav:3310"),
		DockerHost:      getenv("DOCKER_HOST", "unix:///var/run/docker.sock"),
		RBIImage:        getenv("WSP_RBI_IMAGE", "browserless/chrome:latest"),
		MaxRBISessions:  getenvInt("WSP_MAX_RBI_SESSIONS", 10),
		LogLevel:        getenv("WSP_LOG_LEVEL", "info"),
		ShutdownTimeout: time.Duration(getenvInt("WSP_SHUTDOWN_TIMEOUT_SEC", 15)) * time.Second,
	}
	if c.Mode != "all" && c.Mode != "gateway" && c.Mode != "management" {
		return c, fmt.Errorf("invalid WSP_MODE %q", c.Mode)
	}
	return c, nil
}
// helpers getenv, getenvInt omitted in plan — implement standard versions
```

Test: invalid mode returns error; defaults apply when env empty.

- [ ] **Step 3: Write `migrations/001_init.up.sql`** covering tables from design §4:
  - users, admin_sessions, proxy_auth_cache
  - certificates, settings, block_pages, reusable_objects, policies
  - sessions, request_logs (with `PARTITION BY RANGE (ts)` if using PG native partitions — include parent + first partitions for current/next month, or use single table + `ts` index if partition automation deferred; **prefer parent partitioned table + function to ensure monthly partitions**)
  - audit_logs
  - seed: system block page, CASB app objects, default policies, `setup_completed=false`

- [ ] **Step 4: `deploy/docker-compose.yml`**

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: wsp
      POSTGRES_PASSWORD: wsp
      POSTGRES_DB: wsp
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U wsp"]
      interval: 5s
      timeout: 5s
      retries: 10
  clamav:
    image: clamav/clamav:stable
    # expose 3310 internally
  wsp:
    build:
      context: ..
      dockerfile: deploy/Dockerfile
    env_file: .env
    ports:
      - "8080:8080"
      - "3000:3000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - wsp_data:/var/lib/wsp
    depends_on:
      postgres:
        condition: service_healthy
    # clamav may take long to start — wsp must retry clamd
volumes:
  pgdata:
  wsp_data:
```

- [ ] **Step 5: Multi-stage `deploy/Dockerfile`**

1. `node:20` build `web/` → `web/dist`
2. `golang:1.22` build `cmd/wsp` with CGO disabled, embed UI
3. Distroless or `gcr.io/distroless/static` / alpine with ca-certs — note: RBI uses Docker API so `wsp` does not need Chromium in its image

- [ ] **Step 6: Minimal `cmd/wsp/main.go`** loads config, slog, `--version` flag `0.1.0`, listen nothing yet but exit cleanly after migrate hook stub.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: scaffold wsp module, compose, and initial migration"
```

---

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

### Task 4: Certificate CA + encrypted key storage + leaf cache

**Files:**
- Create: `internal/certs/crypto_box.go`, `ca.go`, `leaf_cache.go`
- Test: `internal/certs/ca_test.go`, `leaf_cache_test.go`

**Interfaces:**
```go
type Provider struct { store *store.Store; dataKey []byte; cache *LeafCache }
func NewProvider(store *store.Store, dataKey string) (*Provider, error)
func (p *Provider) GenerateSelfSignedCA(ctx context.Context, name string) (CertMeta, error)
func (p *Provider) ActiveCA(ctx context.Context) (certPEM []byte, ok bool, err error)
func (p *Provider) SignHost(host string) (*tls.Certificate, error) // uses in-memory active CA key
```

- [ ] **Step 1: AES-GCM box for CA private key** using key derived from `WSP_DATA_KEY` (require min 16 chars; hash with SHA-256 to 32 bytes)

- [ ] **Step 2: Generate CA RSA 4096 or ECDSA P-256** (prefer ECDSA P-256 for perf) valid 10 years; store PEM cert + encrypted key

- [ ] **Step 3: Leaf cache LRU** max 1024 hosts; generate leaf with SAN DNS=host, 48h validity

- [ ] **Step 4: Unit test** generate CA → SignHost(`example.com`) → verify chain

- [ ] **Step 5: Commit** `feat: self-signed CA generation and MITM leaf cache`

---

### Task 5: Policy types, compiler, pure engine, simulator

**Files:**
- Create: `internal/policy/types.go`, `compile.go`, `match.go`, `engine.go`, `simulate.go`
- Test: `internal/policy/engine_test.go`, `simulate_test.go`

**Interfaces:**
```go
type Action string // allow, block
type Decision struct {
    FinalAction Action
    BlockPageID *uuid.UUID
    BlockReason string
    TLSIntercept bool
    AuthMode string // disable | ip_cached | per_request
    RBI Isolated bool
    RBIBlockCopyFrom bool
    RBIBlockCopyTo bool
    CASB []CASBRestriction
    MalwareScan bool
    HeaderMods []HeaderMod
    MatchedRuleIDs []uuid.UUID
    EvaluatedRuleIDs []uuid.UUID
}

type RequestInput struct {
    ClientIP net.IP
    Username string
    UserAgent string
    Method string
    URL *url.URL
    Now time.Time
}

type Engine struct { snap atomic.Pointer[Snapshot] }
func (e *Engine) Swap(s *Snapshot)
func (e *Engine) Evaluate(in RequestInput) Decision
func Compile(rules []Rule, objects map[uuid.UUID]Object) (*Snapshot, error)
func Simulate(rules []Rule, objects map[uuid.UUID]Object, in RequestInput) Decision // same as evaluate with full trace
```

- [ ] **Step 1: Write failing tests** for ordered Block stop; Allow continues; domain suffix match; CIDR match; time window; disabled rules skipped

- [ ] **Step 2: Implement compiler + engine** until tests pass

- [ ] **Step 3: Commit** `feat: pure ordered policy engine and simulator`

---

### Task 6: Explicit proxy + MITM + pipeline skeleton + request logging

**Files:**
- Create: `internal/proxy/server.go`, `mitm.go`, `pipeline.go`, `session.go`
- Create: `internal/logging/recorder.go`
- Create: `internal/blockpage/render.go`
- Test: `internal/proxy/proxy_integration_test.go` (local listener)

**Interfaces:**
```go
type Server struct {
    Addr string
    Engine *policy.Engine
    Certs *certs.Provider
    Store *store.Store
    Recorder *logging.Recorder
    // CASB, Malware, RBI injected later via interfaces
}
func (s *Server) Start(ctx context.Context) error
```

Pipeline order (implement stubs for CASB/malware/RBI that no-op until later tasks):
1. Build RequestInput  
2. Evaluate policy  
3. Auth if required  
4. Block → block page  
5. CONNECT tunnel or MITM  
6. Forward  
7. Record log  

- [ ] **Step 1: HTTP proxy for plain HTTP absolute-form** with Allow policy

- [ ] **Step 2: CONNECT + MITM** using `http.Hijacker` / custom dial; inject `certs.SignHost`

- [ ] **Step 3: Session IDs** — map client IP+username → session row with 30m idle

- [ ] **Step 4: Recorder writes request_logs** with required fields from design §6.9 (minimum set)

- [ ] **Step 5: Integration test** — spin TLS origin, MITM fetch, assert log row

- [ ] **Step 6: Commit** `feat: explicit MITM proxy with policy and request logs`

---

### Task 7: ClamAV client + pipeline integration

**Files:**
- Create: `internal/malware/clamd.go`
- Test: `internal/malware/clamd_test.go` (mock conn)

**Interfaces:**
```go
type Scanner interface {
    Ping(ctx context.Context) error
    Scan(ctx context.Context, r io.Reader, maxBytes int64) (Result, error)
}
type Result struct {
    Infected bool
    Signature string
    Skipped bool
    Error error
}
func NewClamd(addr string) *Clamd
```

- [ ] **Step 1: Implement INSTREAM protocol** (zINSTREAM chunks + end)

- [ ] **Step 2: Pipeline** — if `Decision.MalwareScan`, buffer up to maxBytes, scan request/response; on infected serve malware block page

- [ ] **Step 3: Config `WSP_MALWARE_FAIL_CLOSED` bool default false

- [ ] **Step 4: Commit** `feat: clamd malware scanning on policy-enabled traffic`

---

### Task 8: CASB framework + ChatGPT + Google Drive (+ stubs)

**Files:**
- Create: all `internal/casb/*`
- Test: `internal/casb/chatgpt_test.go`, `google_drive_test.go`

**Interfaces:**
```go
type Inspector interface {
    InspectRequest(ctx context.Context, req *http.Request, restrictions []CASBRestriction) *Hit
    InspectResponse(ctx context.Context, req *http.Request, resp *http.Response, restrictions []CASBRestriction) *Hit
}
type Hit struct {
    App string
    Action string
    Message string
}
```

- [ ] **Step 1: Catalog detectors by host suffix**

- [ ] **Step 2: ChatGPT** — block multipart uploads / known file endpoints when restriction says block_upload

- [ ] **Step 3: Google Drive** — block upload/download URL patterns + content-disposition

- [ ] **Step 4: Register Slack, M365, WhatsApp** with host lists and partial path rules; document coverage in detector `Coverage() string`

- [ ] **Step 5: Pipeline returns targeted block page on Hit**

- [ ] **Step 6: Commit** `feat: inline CASB detectors and enforcement hooks`

---

### Task 9: RBI orchestrator + viewer WebSocket

**Files:**
- Create: `internal/rbi/orchestrator.go`, `docker.go`, `session.go`, `viewer_ws.go`
- Create: static viewer route served by management or proxy special path `/rbi/session/:id`
- Test: unit test docker client mock for create/remove; manual Compose test documented

**Interfaces:**
```go
type Orchestrator interface {
    Start(ctx context.Context, targetURL string, opts SessionOpts) (Session, error)
    Get(id string) (Session, bool)
    Stop(ctx context.Context, id string) error
    ActiveCount() int
}
type Session interface {
    ID() string
    Attach(ws interface{}) error // websocket conn
}
```

- [ ] **Step 1: Docker client create container** from `WSP_RBI_IMAGE`, publish/debug port, memory limit 1g, auto-remove false then ForceRemove on stop

- [ ] **Step 2: go-rod connect, Navigate, StartScreencast**

- [ ] **Step 3: WebSocket protocol** JSON messages: `{type:frame,data:base64}`, `{type:input,event:...}`

- [ ] **Step 4: Proxy on RBI decision** — do not forward origin body; return redirect HTML to viewer with session token

- [ ] **Step 5: Enforce max sessions; copy-paste flags best-effort via CDP

- [ ] **Step 6: Commit** `feat: RBI ephemeral chromium sessions with CDP viewer`

---

### Task 10: Management API (Echo) — setup, auth, CRUD, health, export, simulate

**Files:**
- Create: `internal/mgmt/server.go`, `middleware.go`, `setup.go`, `handlers_auth.go`, `handlers_users.go`, `handlers_certs.go`, `handlers_policies.go`, `handlers_objects.go`, `handlers_logs.go`, `handlers_audit.go`, `handlers_settings.go`, `handlers_export.go`, `handlers_health.go`, `handlers_clientsetup.go`, `handlers_blockpages.go`
- Create: `internal/health/health.go`, `internal/export/export.go`, `internal/audit/logger.go`
- Test: `internal/mgmt/setup_test.go` (httptest)

**Interfaces:**
- Produces REST as design §10.2
- Middleware: load session cookie `wsp_session`; require auth except setup + `/healthz` + login
- On policy write: recompile + `engine.Swap`

- [ ] **Step 1: Echo server + embed placeholder `index.html`** if web dist missing

- [ ] **Step 2: Setup wizard endpoints** — create first admin, generate CA, save DNS settings, mark setup complete

- [ ] **Step 3: Auth login/logout/me**

- [ ] **Step 4: CRUD handlers** for users, certs (generate/download PEM public), policies reorder, objects, block pages, settings (retention)

- [ ] **Step 5: Logs search + session detail; audit list**

- [ ] **Step 6: Simulate + export + client-setup + health**

- [ ] **Step 7: Audit every mutating admin action**

- [ ] **Step 8: Commit** `feat: management REST API with setup wizard and operability endpoints`

---

### Task 11: React admin SPA

**Files:**
- Create: `web/` full Vite React TS app with Tailwind + shadcn components as needed
- Routes: `/setup`, `/login`, `/`, `/health`, `/settings/*`, `/policy/*`, `/objects`, `/logs`, `/audit`, `/client-setup`
- API client: `web/src/api.ts` fetch credentials include

**UX requirements (design §10):**
- Progressive disclosure on policy editor (tabs: General, Web, RBI, CASB, Malware)
- Policy list drag reorder or up/down
- Simulation form
- Log filters + session expand
- Health status badges
- Empty states with guidance

- [ ] **Step 1: Scaffold Vite React-TS + Tailwind**

- [ ] **Step 2: Auth gate + setup redirect if `GET /api/v1/setup/status` incomplete**

- [ ] **Step 3: Implement all main pages** (functional, clean, not dark-mode)

- [ ] **Step 4: Build into `web/dist`; Go embed `//go:embed all:web/dist`**

- [ ] **Step 5: Commit** `feat: embed React admin UI for all main sections`

---

### Task 12: Retention job, default policy seed polish, health metrics

**Files:**
- Modify: `internal/logging/retention.go`, `migrations` seed if needed, `internal/health/health.go`
- Wire ticker in `main` (hourly)

- [ ] **Step 1: Delete request_logs older than retention_days in batches of 5000**

- [ ] **Step 2: Health collects** DB, clamd ping, docker ping, active RBI, goroutine/mem optional, version, uptime

- [ ] **Step 3: Commit** `feat: log retention job and richer health checks`

---

### Task 13: End-to-end Compose hardening + README

**Files:**
- Modify: `deploy/*`, `README.md`, `deploy/env.example`
- Create: `docs/architecture.md` short notes

**README sections:**
1. What is WSP  
2. Architecture diagram (text)  
3. Requirements (Linux, Docker)  
4. Quick start `docker compose up -d --build`  
5. First-run wizard  
6. Client proxy + CA install  
7. Default ports  
8. CASB coverage matrix  
9. RBI limitations  
10. Security notes (Docker socket, data key, fail_open)  
11. Config env reference  
12. Future roadmap hooks  

- [ ] **Step 1: Generate strong default `WSP_DATA_KEY` instructions** (must set in `.env`)

- [ ] **Step 2: Smoke script** `deploy/smoke.sh` — healthz, setup status

- [ ] **Step 3: Full manual test checklist in README**

- [ ] **Step 4: Commit** `docs: README and compose production-ready defaults`

---

### Task 14: Final verification pass

- [ ] **Step 1: `go test ./...`**

- [ ] **Step 2: `docker compose -f deploy/docker-compose.yml up -d --build`** on Linux

- [ ] **Step 3: Wizard → CA download → curl via proxy HTTP and HTTPS**

- [ ] **Step 4: Policy block rule visible in logs**

- [ ] **Step 5: EICAR download blocked when malware enabled**

- [ ] **Step 6: RBI rule for one test domain opens viewer**

- [ ] **Step 7: Export config JSON downloads**

- [ ] **Step 8: Fix gaps; final commit** `chore: v1 verification fixes`

---

## Spec coverage checklist (self-review)

| Spec area | Task(s) |
|-----------|---------|
| Explicit MITM proxy | 6 |
| Policy engine + objects + default + simulate | 5, 10, 11, migrations |
| Local auth + modes | 3, 6 |
| Self-signed CA one-click | 4, 10, 11 |
| RBI | 9 |
| CASB | 8 |
| ClamAV | 7 |
| Rich request/session logs + retention | 6, 12 |
| Audit log | 10 |
| Setup wizard | 10, 11 |
| Health page | 10, 11, 12 |
| Config export | 10, 11 |
| Client guidance | 10, 11 |
| Compose + README | 1, 13 |
| Modular seams / WSP_MODE | 1, main wiring |
| Security (encryption, isolation) | 3, 4, 9 |

## Type/name consistency notes

- Package import root: `github.com/wsp-security/wsp`
- Binary name: `wsp`
- Cookie: `wsp_session`
- Env prefix: `WSP_`
- API prefix: `/api/v1`
- Policy `Engine.Evaluate` / `Swap` / `Compile` names fixed above — do not rename in later tasks

---

## Execution handoff

Plan saved to `docs/superpowers/plans/2026-07-27-wsp-v1-implementation.md`.

**Two execution options:**

1. **Subagent-Driven (recommended)** — fresh subagent per task, review between tasks  
2. **Inline Execution** — same session with executing-plans and checkpoints  

Which approach?
