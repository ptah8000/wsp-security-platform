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
