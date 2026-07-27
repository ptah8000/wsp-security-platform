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
