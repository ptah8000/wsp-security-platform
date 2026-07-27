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
