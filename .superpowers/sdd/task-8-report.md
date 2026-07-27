# Task 8 Report: CASB framework + ChatGPT + Google Drive (+ stubs)

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `b31ba73` — `feat: inline CASB detectors and enforcement hooks`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Implemented the inline CASB package: pluggable `Detector` catalog, deep **ChatGPT** and **Google Drive** upload/download (and ChatGPT send) enforcement, and **partial** Slack / Microsoft 365 / WhatsApp Web detectors with `Coverage()` documentation. Wired into the proxy HTTP and MITM pipelines via `casb.ProxyAdapter`, replacing the CASB no-op when `Decision.CASB` has restrictions. Hits produce a **targeted block page** reason (`CASB: <App> — <action> …`).

---

## Deliverables

| Path | Purpose |
|------|---------|
| `internal/casb/types.go` | `Hit`, action constants, `Detector` interface, message formatting |
| `internal/casb/match.go` | Host suffix match, multipart/CD/MIME/extension helpers, type filters |
| `internal/casb/inspector.go` | `Inspector` catalog, `Default()`, `ProxyAdapter` (Decision → reason) |
| `internal/casb/chatgpt.go` | Full-depth ChatGPT detector |
| `internal/casb/google_drive.go` | Full-depth Google Drive / Docs / googleapis detector |
| `internal/casb/slack.go` | Partial Slack detector + `Coverage()` |
| `internal/casb/m365.go` | Partial M365/OWA/OneDrive/SharePoint detector + `Coverage()` |
| `internal/casb/whatsapp.go` | Partial WhatsApp Web detector + `Coverage()` |
| `internal/casb/chatgpt_test.go` | Upload/send/download/MIME/adapter unit tests |
| `internal/casb/google_drive_test.go` | Upload/download/CD/extension/catalog unit tests |
| `internal/proxy/pipeline.go` | Default hook → `casb.NewProxyAdapter()` |
| `internal/proxy/server.go` | CASB request/response enforcement (plain HTTP) logs `casb` |
| `internal/proxy/mitm.go` | Same for MITM path via `writeMITMBlock` |
| `cmd/wsp/main.go` | Wires `casb.NewProxyAdapter()` on gateway start |

---

## Public API

```go
// internal/casb
type Hit struct {
    App     string
    Action  string
    Message string
}

type Detector interface {
    App() string
    HostSuffixes() []string
    Coverage() string
    InspectRequest(ctx context.Context, req *http.Request, r policy.CASBRestriction) *Hit
    InspectResponse(ctx context.Context, req *http.Request, resp *http.Response, r policy.CASBRestriction) *Hit
}

type Inspector struct { /* catalog */ }
func NewInspector(detectors ...Detector) *Inspector
func Default() *Inspector
func (in *Inspector) InspectRequest(ctx, req, restrictions []policy.CASBRestriction) *Hit
func (in *Inspector) InspectResponse(ctx, req, resp, restrictions []policy.CASBRestriction) *Hit
func (in *Inspector) Detectors() []Detector

type ProxyAdapter struct { Inner *Inspector }
func NewProxyAdapter() *ProxyAdapter
// Implements proxy.CASBInspector:
func (a *ProxyAdapter) InspectRequest(ctx, req, d policy.Decision) (string, error)
func (a *ProxyAdapter) InspectResponse(ctx, req, resp, d policy.Decision) (string, error)

const (
    ActionBlockUpload   = "block_upload"
    ActionBlockDownload = "block_download"
    ActionBlockSend     = "block_send"
    ActionBlockMessage  = "block_message"
)
```

---

## Detector coverage matrix

| App id | Depth | Hosts (representative) | Actions enforced |
|--------|-------|------------------------|------------------|
| `chatgpt` | **full** | chat.openai.com, chatgpt.com | upload (multipart + `/backend-api/files*`), send (conversation POST), download (attachment / file content) |
| `google_drive` | **full** | drive.google.com, docs.google.com, googleapis.com, usercontent | upload (resumable/upload paths), download (export/uc, alt=media, Content-Disposition) |
| `slack` | **partial** | app.slack.com, files.slack.com, … | upload / download / message heuristics — see `Coverage()` |
| `m365` | **partial** | outlook.office.com, onedrive.live.com, sharepoint.com, graph… | upload / download path heuristics — see `Coverage()` |
| `whatsapp_web` | **partial** | web.whatsapp.com, mmg/pps media hosts | best-effort media upload/download — E2E limits documented |

Optional `MIMETypes` / `Extensions` on `policy.CASBRestriction` narrow which uploads/downloads fire (empty = all).

---

## Pipeline behavior

1. Policy engine accumulates `Decision.CASB` from matched rules (unchanged).
2. After allow + RBI checks, **request-side** CASB runs before malware/header mods.
3. After origin response, **response-side** CASB runs before malware scan.
4. On `Hit`: `FinalAction=block`, `BlockReason=hit.Message` (targeted), HTML block page 403, log error tag `casb`.
5. Empty `Decision.CASB` → adapter returns immediately (no detector work).

---

## Tests

```
go test ./internal/casb/ ./internal/proxy/ ./internal/... -count=1
```

All packages pass.

| Package | Coverage focus |
|---------|----------------|
| `internal/casb` | ChatGPT multipart/files/send/download; Drive upload/export/CD/extensions; host routing; ProxyAdapter no-op; five-app catalog; partial Coverage() |
| `internal/proxy` | Existing malware/pipeline tests still green with default CASB adapter |

---

## Notes / limits

- Detection is signature-based on decrypted HTTP only (no SaaS API calls).
- Partial apps intentionally incomplete; completeness is self-documented via `Coverage()`.
- Adding an app = new `Detector` + `Default()` registration (+ system object seed if needed).
