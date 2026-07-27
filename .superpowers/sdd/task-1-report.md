# Task 1 Report: Repository skeleton, module, Compose, migrations

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `cc1675c` — `chore: scaffold wsp module, compose, and initial migration`  
**Date:** 2026-07-27

---

## Summary

Implemented the WSP v1 repository scaffold end-to-end: Go module, config package with tests, `cmd/wsp` binary (`--version` → `0.1.0`), PostgreSQL init migration (tables + monthly partitions + seeds), multi-stage Dockerfile, Compose stack, env example, web UI placeholder with `go:embed`, README stub, and `.gitignore`.

---

## Deliverables

| Path | Purpose |
|------|---------|
| `go.mod` | Module `github.com/wsp-security/wsp`, Go 1.22 |
| `.gitignore` | bin/dist/node_modules/.env/keys/IDE |
| `cmd/wsp/main.go` | Version flag, config load, slog JSON, migrate stub |
| `internal/config/config.go` | Env-based `Config` + defaults |
| `internal/config/config_test.go` | Defaults, invalid mode, valid modes, overrides |
| `migrations/001_init.up.sql` | Full §4 schema, partition helper, seeds |
| `migrations/001_init.down.sql` | Drop tables/function in reverse order |
| `deploy/Dockerfile` | node:20 UI → golang:1.22 static binary → distroless |
| `deploy/docker-compose.yml` | postgres, clamav, wsp (socket + volumes) |
| `deploy/env.example` | All `WSP_*` / Docker env vars |
| `web/package.json`, `web/index.html`, `web/scripts/build.mjs` | Placeholder SPA build |
| `web/embed.go` + `web/dist/index.html` | `//go:embed` assets (placeholder force-tracked) |
| `README.md` | Stub: run, layout, version |

---

## Config (`internal/config`)

`config.Load()` reads:

| Env | Default |
|-----|---------|
| `WSP_MODE` | `all` (also `gateway`, `management`) |
| `WSP_PROXY_ADDR` | `:8080` |
| `WSP_ADMIN_ADDR` | `:3000` |
| `WSP_DATABASE_URL` | `postgres://wsp:wsp@localhost:5432/wsp?sslmode=disable` |
| `WSP_DATA_KEY` | empty (no default secret) |
| `WSP_CLAMD_ADDR` | `clamav:3310` |
| `DOCKER_HOST` | `unix:///var/run/docker.sock` |
| `WSP_RBI_IMAGE` | `browserless/chrome:latest` |
| `WSP_MAX_RBI_SESSIONS` | `10` |
| `WSP_LOG_LEVEL` | `info` |
| `WSP_SHUTDOWN_TIMEOUT_SEC` | `15` |

Invalid `WSP_MODE` returns an error.

---

## Migration schema (`001_init`)

**Tables:** `users`, `admin_sessions`, `proxy_auth_cache`, `certificates`, `settings`, `block_pages`, `reusable_objects`, `policies`, `sessions`, `request_logs` (RANGE partition on `ts`), `audit_logs`.

**Partitioning:** parent `request_logs` + function `ensure_request_logs_partition(timestamptz)` creates `request_logs_YYYY_MM`; migration calls it for current and next UTC months. Indexes match design (ts, client_ip, username, host, decision, session_id).

**Seeds:**
- `setup_completed=false`, retention 30/365, DNS, listen, platform metadata
- System default block page HTML
- Five CASB system objects (ChatGPT, Google Drive, M365, Slack, WhatsApp Web)
- Default policies: local exceptions (prio 100), anti-malware broad web (500), default allow+log (900), sample RBI disabled (400)
- No admin user (wizard later)

---

## Binary behavior

```
wsp --version  →  0.1.0  (exit 0)
wsp            →  load config, slog start, migrate stub, exit 0 (no listeners yet)
```

Blank-import of `github.com/wsp-security/wsp/web` ensures embedded UI is linked at build time.

---

## Verification

| Check | Result |
|-------|--------|
| `go test ./internal/config/...` | PASS (`ok … 0.19s`) |
| `go build -o bin/wsp.exe ./cmd/wsp` | PASS |
| `./bin/wsp.exe --version` | `0.1.0` |
| Docker Compose up | Not run (daemon may be unavailable; files written per plan) |

---

## Self-review

### Matches task brief
- [x] All listed files created
- [x] Config API and defaults verbatim from plan
- [x] Migration covers design §4 tables + seeds
- [x] Compose topology matches plan (postgres healthcheck, clamav, wsp ports/volumes)
- [x] Multi-stage Dockerfile (Node → Go CGO=0 → distroless)
- [x] `--version` = `0.1.0`
- [x] Commit message as specified

### Intentional notes / minor concerns
1. **`web/dist/index.html` force-added** while `web/dist/` is gitignored so `go:embed` and local `go build` work without npm. Rebuild via `node web/scripts/build.mjs` or Docker UI stage.
2. **`go.mod` uses `go 1.22`** (design + Dockerfile) even though the host toolchain is go1.26.5 — correct for Compose image compatibility.
3. **Compose `env_file: .env`** — operators must `cp env.example .env` before `docker compose up` (documented in README).
4. **`.superpowers/sdd/*.md` included in commit** because the task `.gitignore` does not exclude `.superpowers/`; harmless for this worktree workflow.
5. **Migrations not executed** against a live Postgres in this task (store/migrate runner is Task 2). SQL is ready for that runner.
6. **Dockerfile not built** in this environment (Docker optional). Structure follows the multi-stage plan.

### No blockers
Scaffold is complete and verified for unit tests and local binary build.

---

## Out of scope (correctly deferred)

- Store layer / migration runner (Task 2+)
- Proxy/listeners, policy engine, RBI, CASB, full React SPA
- Compose smoke against real Postgres/ClamAV

---

## Review fixes (compose restart + partition UTC)

**Commit:** `faa8b7b` — `fix: task1 compose restart and partition UTC bounds`  
**Author:** WSP Dev <dev@wsp.local>

### Changes

1. **`deploy/docker-compose.yml`:** set `wsp` service `restart: "no"` (removed thrash-prone `unless-stopped`). Kept `restart: unless-stopped` on `postgres` and `clamav`.
2. **`migrations/001_init.up.sql`:**
   - `start_ts := (date_trunc('month', target AT TIME ZONE 'UTC')) AT TIME ZONE 'UTC';` so partition bounds are true UTC `TIMESTAMPTZ`
   - Seed calls: `ensure_request_logs_partition(now())` and `now() + INTERVAL '1 month'` (no `now() AT TIME ZONE 'UTC'` coercion)
   - Partition name uses `to_char(start_ts AT TIME ZONE 'UTC', 'YYYY_MM')`

### Re-verification

```
$ go test ./internal/config/...
ok  	github.com/wsp-security/wsp/internal/config	(cached)

$ go build ./cmd/wsp
# exit 0
```

Both checks PASS.
