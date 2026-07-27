# Task 9 Report: RBI orchestrator + viewer WebSocket

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `d19e7a8` — `feat: RBI ephemeral chromium sessions with CDP viewer`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Replaced the proxy RBI no-op stub with a real orchestrator that:

1. Creates/destroys ephemeral Chromium containers via the Docker Engine HTTP API (`WSP_RBI_IMAGE`, 1 GiB memory, published debug port, `ForceRemove` on stop).
2. Connects with **go-rod** (CDP), navigates to the target URL, starts **Page.startScreencast**.
3. Serves an inline isolation **viewer** (HTML + canvas) and streams frames / accepts input over **WebSocket** (`{type:frame,data:base64}`, `{type:input,event:…}`).
4. Enforces **max concurrent sessions** (`WSP_MAX_RBI_SESSIONS`).
5. On policy isolate: `HandleIsolation` returns **true** when a session starts (viewer HTML); returns **false** when Docker/CDP fails so the proxy **fail-closed** block path runs.

---

## Deliverables

| Path | Purpose |
|------|---------|
| `internal/rbi/docker.go` | `ContainerRuntime` + thin Docker Engine HTTP client (create/start/inspect/remove/pull/ping) |
| `internal/rbi/docker_host_*.go` | Default DOCKER_HOST (unix socket / Windows npipe) |
| `internal/rbi/docker_npipe_*.go` | Windows named-pipe dial via go-winio |
| `internal/rbi/session.go` | Session lifecycle, go-rod connect/navigate/screencast/input, clipboard guards |
| `internal/rbi/viewer_ws.go` | `/rbi/session/:id` HTML, `/rbi/ws/:id` WebSocket protocol |
| `internal/rbi/orchestrator.go` | Start/Get/Stop/ActiveCount + `proxy.RBIOrchestrator` adapter |
| `internal/rbi/docker_test.go` | Mock DockerAPI create/remove/ping tests |
| `internal/rbi/orchestrator_test.go` | Max sessions, fail-closed, HandleIsolation success |
| `internal/proxy/{server,mitm,pipeline}.go` | Wire `/rbi/*` routes + MITM Hijacker for WS |
| `cmd/wsp/main.go` | `initRBI` + shutdown `StopAll` |

---

## Public API

```go
// internal/rbi
type ContainerRuntime interface {
    Ping(ctx context.Context) error
    CreateAndStart(ctx context.Context, opts CreateOpts) (ContainerInfo, error)
    Remove(ctx context.Context, id string, force bool) error
}

type Orchestrator struct { /* Runtime, Image, MaxSessions, … */ }
func NewOrchestrator(cfg Config) *Orchestrator
func NewDockerRuntime(dockerHost string) (*DockerRuntime, error)

func (o *Orchestrator) Start(ctx, targetURL, opts) (Session, error)
func (o *Orchestrator) Get(id string) (Session, bool)
func (o *Orchestrator) Stop(ctx, id) error
func (o *Orchestrator) ActiveCount() int
func (o *Orchestrator) StopAll(ctx)

// Implements proxy.RBIOrchestrator:
func (o *Orchestrator) ShouldIsolate(d policy.Decision) bool
func (o *Orchestrator) HandleIsolation(w, req, d) bool // true ⇒ viewer served

// Optional path server (proxy type-asserts):
func (o *Orchestrator) ServeRBIPath(w, req) bool
```

---

## Pipeline behavior

1. Policy sets `Decision.RBIIsolated` (OR accumulation from rules).
2. Proxy `needsIsolation` → never forwards origin bytes.
3. `HandleIsolation`:
   - Starts container + CDP navigate.
   - Writes viewer HTML (relative WS to `/rbi/ws/{id}`).
   - Returns **true** on success.
   - Returns **false** on Docker/max-sessions/CDP failure → existing `rbi_unavailable` block page.
4. Subsequent `/rbi/session/*` and `/rbi/ws/*` on the same MITM origin (or absolute-form proxy) are short-circuited before re-isolation.
5. Viewer disconnect → session Stop → `ForceRemove` container.

---

## WebSocket protocol

**Server → client**

```json
{"type":"frame","data":"<base64-jpeg>"}
```

**Client → server**

```json
{"type":"input","event":{"kind":"mouse|key|wheel","type":"mouseMoved|…","x":0,"y":0,…}}
```

Copy/paste: best-effort CDP page listeners + viewer-side preventDefault when `RBIBlockCopyFrom` / `RBIBlockCopyTo` set.

---

## Tests

```text
go test ./internal/rbi/ ./internal/proxy/ -count=1
# + full suite: go test ./... -count=1  (all pass)
```

Unit coverage:

- Mock Docker create/start/remove + memory limit + force-remove on start failure.
- Orchestrator max sessions, Docker unavailable fail-closed, HandleIsolation HTML success.
- Proxy: isolation fail-closed (existing) + isolation success without origin hit (new).

### Manual Compose test (Linux host)

1. `docker compose -f deploy/docker-compose.yml up -d --build`
2. Ensure socket mount: `/var/run/docker.sock` (already in compose).
3. Pull/cache RBI image: `docker pull browserless/chrome:latest` (or set `WSP_RBI_IMAGE`).
4. Enable a policy rule with RBI mode **isolated** for a test host (UI/task 10–11, or SQL seed).
5. Point a browser at the proxy; navigate to the isolated host.
6. Expect isolation viewer (RBI badge), interactive screencast; origin HTML/JS must not appear in DevTools as navigated document source from the site.
7. Close tab → container should disappear (`docker ps` / labels `wsp.rbi=1`).
8. With Docker stopped: isolated rule → block page *Remote browser isolation required but unavailable*.

---

## Config

| Env | Default | Role |
|-----|---------|------|
| `WSP_RBI_IMAGE` | `browserless/chrome:latest` | Container image |
| `WSP_MAX_RBI_SESSIONS` | `10` | Cap concurrent sessions |
| `DOCKER_HOST` | unix socket / npipe | Engine API endpoint |
| `WSP_RBI_CDP_HOST` | (unset) | Optional: force CDP via published ports on this host (Docker Desktop). Prefer container IP when unset. |

Note: `WSP_RBI_CDP_HOST` is supported as `DockerRuntime.CDPHost` field; wire from env in a later polish if needed. Compose-on-Linux uses container IP by default.

---

## Concerns / limitations (v1)

- Screencast FPS/quality is basic (JPEG q=60, every 2nd frame); not production UX polish.
- One viewer attachment per session; disconnect destroys the container.
- No pre-warm pool; cold start includes image pull on first use if missing.
- Clipboard controls are best-effort (DOM events + viewer shortcuts), not a hardened CDP sandbox.
- MITM WebSocket depends on `mitmResponseWriter.Hijack` + buffered reader; pipelined HTTP before upgrade is not supported (normal for WS).
- Full Engine SDK avoided (thin HTTP API) to keep module graph small and avoid docker client build issues.

---

## Wiring

`cmd/wsp/main.go` always installs `*rbi.Orchestrator` on the gateway. If Docker client init or ping fails at startup, orchestrator remains installed with Runtime nil/unreachable so isolation still **fail-closed** per request rather than silently allowing origin traffic.
