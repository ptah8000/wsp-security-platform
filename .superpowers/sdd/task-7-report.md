# Task 7 Report: ClamAV client + pipeline integration

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `75d36b2` — `feat: clamd malware scanning on policy-enabled traffic`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Implemented a clamd TCP client using the null-terminated **zINSTREAM** / **zPING** protocol, wired it into the proxy data plane when `Decision.MalwareScan` is set, and added global **fail-open / fail-closed** control via `WSP_MALWARE_FAIL_CLOSED` (default **false** = fail-open).

On infected bodies the gateway serves the HTML block page with reason `Malware detected: <signature>`. Scan transport/protocol errors log loudly and either allow (fail-open) or block with `Malware scan unavailable` (fail-closed). Oversized bodies (Content-Length or streamed length above the cap) skip scanning and pass through.

---

## Deliverables

| Path | Purpose |
|------|---------|
| `internal/malware/clamd.go` | `Scanner`, `Result`, `Clamd` (INSTREAM/PING), `Nop`, `DefaultMaxScanBytes` (25 MiB) |
| `internal/malware/clamd_test.go` | Mock `net.Conn` protocol tests (clean, EICAR FOUND, empty skip, dial error, maxBytes) |
| `internal/config/config.go` | `MalwareFailClosed` + `getenvBool` / `WSP_MALWARE_FAIL_CLOSED` |
| `internal/config/config_test.go` | Default false + truthy/falsey env parsing |
| `internal/proxy/pipeline.go` | `scanHTTPBody`, size cap, fail mode, `malware.Nop` default hook |
| `internal/proxy/server.go` | Request + response body scan on plain HTTP path |
| `internal/proxy/mitm.go` | Same scan on MITM path + `writeMITMBlock` |
| `internal/proxy/pipeline_test.go` | Infected block, fail-open, fail-closed, policy-off |
| `cmd/wsp/main.go` | `malware.NewClamd(cfg.ClamdAddr)`, startup ping, fail-closed flag |
| `deploy/env.example` | Documents `WSP_MALWARE_FAIL_CLOSED` |

---

## Public API

```go
// internal/malware
type Scanner interface {
    Ping(ctx context.Context) error
    Scan(ctx context.Context, r io.Reader, maxBytes int64) (Result, error)
}
type Result struct {
    Infected  bool
    Signature string
    Skipped   bool
    Error     error
}
func NewClamd(addr string) *Clamd
type Nop struct{}
const DefaultMaxScanBytes int64 = 25 << 20

// internal/config
MalwareFailClosed bool // WSP_MALWARE_FAIL_CLOSED, default false

// internal/proxy.Server
Malware           malware.Scanner
MalwareFailClosed bool
MalwareMaxBytes   int64 // 0 → DefaultMaxScanBytes
```

### Clamd protocol

1. Dial TCP `addr`
2. Write `zINSTREAM\0`
3. For each chunk: 4-byte big-endian length + data
4. End with length `0`
5. Read null-terminated reply: `stream: OK` | `stream: <sig> FOUND` | `… ERROR`

`Ping` sends `zPING\0` and expects `PONG`.

---

## Pipeline behavior

When `Decision.MalwareScan`:

1. **Request body** (if present): buffer up to max, scan, restore body for origin `RoundTrip`
2. **Response body**: buffer up to max, scan; on clean, forward buffered body
3. **Infected** → 403 block page (`Malware detected: …`), log `malware_detected`
4. **Scan error** → fail-open allow + error log, or fail-closed block page
5. **Oversize** → skip scan, pass through (`malware_skipped_oversize`)

Empty bodies do not dial clamd (`Result.Skipped`).

---

## Tests

```
go test ./internal/... -count=1
```

All packages pass.

| Package | Coverage focus |
|---------|----------------|
| `internal/malware` | INSTREAM framing, FOUND/OK/ERROR, empty skip, maxBytes, Ping |
| `internal/config` | `WSP_MALWARE_FAIL_CLOSED` default + values |
| `internal/proxy` | Infected response block, fail-open/closed, no scan when policy off |

---

## Out of scope (later tasks)

- CASB detectors (Task 8)
- RBI orchestrator (Task 9)
- Per-rule `fail_mode` / `max_scan_bytes` accumulation into `Decision` (policy fields exist; global config used for fail mode; fixed 25 MiB default for size)
- Health endpoint clamd status (Task 10+)
- Live EICAR Compose demo (Task 14)

---

## Security notes

- Default **fail-open** prioritizes availability when clamd is slow/down (design §9); set `WSP_MALWARE_FAIL_CLOSED=true` for stricter orgs.
- Bodies are buffered up to 25 MiB for scan+replay; very large transfers skip scanning rather than partial-scan.
