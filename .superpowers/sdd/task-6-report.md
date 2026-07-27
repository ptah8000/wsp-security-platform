# Task 6 Report: Explicit proxy + MITM + pipeline skeleton + request logging

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `fcf01b0` — `feat: explicit MITM proxy with policy and request logs`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Implemented the explicit forward proxy data plane: absolute-form HTTP, CONNECT tunnel, TLS MITM via `certs.SignHost`, ordered policy evaluation, optional proxy Basic auth (per-request / IP-cached), block pages, browsing session tracking (30m idle), and request logging (`logging.Recorder` → in-memory ring + `request_logs` when Store is configured).

CASB / malware / RBI are **stub no-ops** injected via interfaces for later tasks.

`cmd/wsp` modes `all` and `gateway` start the proxy after migrations; management API remains unwired.

---

## Deliverables

| Path | Purpose |
|------|---------|
| `internal/proxy/server.go` | `Server`, `Start`/`Shutdown`, `ServeHTTP` |
| `internal/proxy/mitm.go` | CONNECT tunnel + MITM TLS + per-request forward |
| `internal/proxy/pipeline.go` | RequestInput build, auth, block page, hooks, record |
| `internal/proxy/session.go` | IP+username → session ID, 30m idle |
| `internal/proxy/policyload.go` | Load/compile policies+objects from DB |
| `internal/proxy/proxy_integration_test.go` | HTTP allow, HTTPS MITM, block page, session reuse |
| `internal/logging/recorder.go` | `Recorder.Record` + memory ring |
| `internal/logging/recorder_test.go` | Memory ring capacity |
| `internal/blockpage/render.go` | Placeholder HTML render + defaults |
| `internal/blockpage/render_test.go` | Escape/substitute tests |
| `internal/store/sessions.go` | `CreateBrowsingSession`, `EndBrowsingSession`, `GetBrowsingSession` |
| `internal/store/request_logs.go` | Partition ensure + insert/get request logs |
| `internal/store/policies.go` | List policies/objects, get block pages |
| `cmd/wsp/main.go` | Wire store, certs (`WSP_DATA_KEY`), engine, proxy |

---

## Pipeline order (design §5)

1. Build `policy.RequestInput` (client IP, UA, method, URL, time; username when known)
2. `Engine.Evaluate` (pure; nil engine → allow)
3. Auth if `AuthMode` is `ip_cached` / `per_request` → 407 Basic `realm="WSP"`
4. Block → HTML block page (HTTP) or MITM-then-block / CONNECT 403 short body
5. CONNECT: tunnel when `!TLSIntercept`; MITM when intercept (needs CA)
6. Forward origin (HTTP RoundTrip / MITM decrypted requests)
7. `Recorder.Record` with decision, rule IDs, actions, timings, sizes

Stub hooks:
- `CASBInspector` — always allow
- `MalwareScanner` — always clean
- `RBIOrchestrator` — never isolates

---

## Public API

```go
type Server struct {
    Addr string
    Engine *policy.Engine
    Certs *certs.Provider
    Store *store.Store
    Recorder *logging.Recorder
    AuthCache *auth.ProxyAuthCache
    Sessions *SessionTracker
    CASB CASBInspector
    Malware MalwareScanner
    RBI RBIOrchestrator
    // Dialer, Transport, IdleTimeout optional
}
func (s *Server) Start(ctx context.Context) error
func (s *Server) Shutdown(ctx context.Context) error
func LoadEngineFromStore(ctx context.Context, s *store.Store) (*policy.Engine, error)

type Recorder struct { /* store + mem ring */ }
func NewRecorder(s *store.Store) *Recorder
func (r *Recorder) Record(ctx context.Context, rec RequestRecord)
func (r *Recorder) Recent() []RequestRecord
func (r *Recorder) Last() (RequestRecord, bool)
```

---

## Tests

```
go test ./internal/... -count=1
```

All packages pass (no Postgres required for proxy tests):

| Test | Asserts |
|------|---------|
| `TestIntegration_HTTPAbsoluteFormAllow` | plain HTTP via proxy; allow log + session_id |
| `TestIntegration_HTTPS_MITM_AndLog` | TLS origin, MITM with test CA trust, body `mitm-ok`, allow log for `/secure` |
| `TestIntegration_HTTPBlockPage` | 403 HTML block; decision=block |
| `TestIntegration_SessionIdleReuse` | two requests share session ID |
| `blockpage` / `logging` unit tests | escaping, memory ring |

Store request_log / session persistence paths need `WSP_DATABASE_URL` + `//go:build integration` tests (not added in this task; insert path is exercised only when Store is non-nil in production).

---

## Wiring notes (`cmd/wsp`)

- `WSP_MODE=all|gateway` → start proxy on `WSP_PROXY_ADDR`
- `WSP_MODE=management` → no proxy (admin API later)
- Loads policies from DB via `LoadEngineFromStore`
- `WSP_DATA_KEY` required for `certs.Provider` / MITM; warns and continues without MITM if missing
- Active CA warmed from store when present
- Graceful shutdown on SIGINT/SIGTERM (`WSP_SHUTDOWN_TIMEOUT_SEC`)

---

## Concerns / follow-ups

1. **Origin TLS verification** uses system roots by default; lab origins with private certs need transport injection (tests use `InsecureSkipVerify` on origin side only).
2. **Malware scan** is a no-op stub — bodies are not buffered; real ClamAV wiring is Task 7.
3. **RBI / CASB** stubs do not alter traffic; isolated rules currently still forward until RBI task.
4. **CONNECT block without MITM** returns short text 403 (cannot render HTML inside CONNECT).
5. **Policy hot-reload** not implemented — engine loaded once at startup.
6. **HTTP/2 to client** on MITM is not negotiated (HTTP/1.1 over MITM TLS).
7. **Proxy auth** needs users in DB; no default lab user until wizard.
8. Management listener still not started in `all` mode (later task).

---

## Checklist

- [x] Step 1: HTTP absolute-form with Allow policy  
- [x] Step 2: CONNECT + MITM (`Hijacker` + `certs.SignHost`)  
- [x] Step 3: Session IDs (IP+username, 30m idle)  
- [x] Step 4: Recorder → request_logs fields (minimum set + actions/timings)  
- [x] Step 5: Integration test TLS origin + MITM + log assert  
- [x] Step 6: Commit `feat: explicit MITM proxy with policy and request logs`  
