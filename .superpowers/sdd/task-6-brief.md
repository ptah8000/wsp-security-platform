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
