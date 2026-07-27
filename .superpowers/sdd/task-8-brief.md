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
