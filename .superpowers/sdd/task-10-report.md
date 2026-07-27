# Task 10 Report: Management API (Echo) — setup, auth, CRUD, health, export, simulate

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `3a8d5d8` — `feat: management REST API with setup wizard and operability endpoints`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Implemented the full management plane REST API with Echo:

1. **Setup wizard** (`/api/v1/setup/*`) — gated when incomplete; creates first admin, generates CA, saves DNS, marks complete.
2. **Auth** — `login` / `logout` / `me` with HttpOnly `wsp_session` cookie via existing `auth.SessionManager`.
3. **CRUD** — users, certificates (public PEM only — **never private keys**), policies + reorder, reusable objects, block pages, settings (retention/DNS).
4. **Operability** — request log search, session detail, audit list, policy simulate, config export, client-setup guidance, detailed health.
5. **Liveness** — unauthenticated `GET /healthz`.
6. **Policy hot reload** — on policy/object write: recompile from store + `engine.Swap` on the shared engine used by the proxy.
7. **Audit** — mutating admin actions recorded best-effort via `internal/audit.Logger`.
8. **Process wiring** — management server starts for `WSP_MODE=all` and `management`; proxy for `all` and `gateway`.

---

## Deliverables

| Path | Purpose |
|------|---------|
| `internal/mgmt/server.go` | Echo app, routes, SPA mount, audit helpers |
| `internal/mgmt/middleware.go` | Session cookie load, requireAuth, setup gates |
| `internal/mgmt/setup.go` | First-run wizard handlers |
| `internal/mgmt/handlers_auth.go` | login / logout / me + session cookie |
| `internal/mgmt/handlers_users.go` | User CRUD |
| `internal/mgmt/handlers_certs.go` | CA generate + public PEM download |
| `internal/mgmt/handlers_policies.go` | Policy CRUD, reorder, simulate, engine reload |
| `internal/mgmt/handlers_objects.go` | Reusable object CRUD |
| `internal/mgmt/handlers_blockpages.go` | Block page CRUD |
| `internal/mgmt/handlers_settings.go` | Settings list/get/put |
| `internal/mgmt/handlers_logs.go` | Request log search + session detail |
| `internal/mgmt/handlers_audit.go` | Audit list |
| `internal/mgmt/handlers_export.go` | Config export |
| `internal/mgmt/handlers_health.go` | `/healthz` + `/api/v1/health` |
| `internal/mgmt/handlers_clientsetup.go` | PAC, CA download URL, trust notes |
| `internal/mgmt/setup_test.go` | httptest setup/auth/gating tests |
| `internal/audit/logger.go` | Best-effort audit writer |
| `internal/health/health.go` | Component health aggregation |
| `internal/export/export.go` | Secret-free config bundle |
| `internal/store/*` | Extended CRUD/list/search methods |
| `cmd/wsp/main.go` | Wire mgmt for `all` / `management` modes |

---

## API surface (design §10.2)

| Group | Routes |
|-------|--------|
| Setup | `GET /api/v1/setup/status`, `POST .../admin|ca|network|complete` (mutations only if incomplete) |
| Auth | `POST /api/v1/auth/login`, `POST .../logout`, `GET .../me` |
| Health | `GET /healthz` (no auth), `GET /api/v1/health` (auth) |
| Users | `GET/POST /api/v1/users`, `GET/PUT/DELETE /api/v1/users/:id` |
| Certs | `GET /api/v1/certificates`, `POST .../generate`, `GET .../:id`, `GET .../:id/pem` |
| Settings | `GET /api/v1/settings`, `GET/PUT .../:key` |
| Block pages | CRUD `/api/v1/block-pages` |
| Objects | CRUD `/api/v1/objects` |
| Policies | CRUD + `POST /policies/reorder` + `POST /policies/simulate` |
| Logs | `GET /api/v1/logs/requests`, `GET /api/v1/logs/sessions/:id` |
| Audit | `GET /api/v1/audit` |
| Export | `GET /api/v1/export/config` |
| Client setup | `GET /api/v1/client-setup` |

**Middleware rules**

- Load `wsp_session` on every request (optional).
- Auth required except: setup endpoints, `POST /auth/login`, `/healthz`, SPA static.
- Admin role required for management API (proxy `user` role forbidden).
- Admin CRUD requires setup complete (409 if wizard unfinished).
- Setup mutations require setup incomplete (409 if already done).

---

## Security notes

- Certificate download serves **public PEM only**; refuses body containing `PRIVATE KEY`.
- Config export includes certificate **metadata** and users **without password hashes**.
- Passwords hashed with argon2id via existing `auth.HashPassword`.
- Session tokens stored as SHA-256 hashes only (existing `SessionManager`).
- Login errors uniform (`invalid username or password`) to reduce enumeration.

---

## Tests

```text
go test ./internal/mgmt/ -count=1
# PASS — setup status, setup mutation gate, auth required, login blocked pre-setup,
#        admin validation, SPA placeholder, non-admin forbidden, healthz

go test ./... -count=1
# PASS (unit tests; integration tests still skip without WSP_DATABASE_URL)

go build -o bin/wsp.exe ./cmd/wsp
# OK
```

---

## Wiring (`cmd/wsp`)

- Shared `*policy.Engine` loaded once; proxy and mgmt share it for Swap.
- `auth.NewSessionManager`, `audit.New`, `health.Checker` (DB / ClamAV / Docker / RBI count / gateway flag).
- Modes: `all` → proxy + mgmt; `gateway` → proxy only; `management` → mgmt only.

---

## Store methods added

Users: `ListUsers`, `UpdateUser`, `DeleteUser`, `TouchUserLastLogin`, `CountUsersByRole`  
Certs: `ListCertificates`, `GetCertificatePublicPEM`  
Policies/objects/block pages: full CRUD + `ReorderPolicies`  
Settings: `ListSettings`, `MarkSetupComplete`  
Logs: `SearchRequestLogs`, `ListRequestLogsBySession`  
Audit: `ListAuditLogs`
