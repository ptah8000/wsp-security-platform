# Task 14 Final Verification

Date: 2026-07-27
Branch: feature/wsp-v1
Worktree: D:\Grok\WSP\.worktrees\wsp-v1

## Automated (executed)

- go test ./... -count=1 → PASS (all packages)
- go build -o bin/wsp.exe ./cmd/wsp → OK
- wsp --version → 0.1.0

## Not executed (environment)

- Docker daemon unavailable on Windows host — Compose smoke, wizard live, MITM via real stack, EICAR, RBI live not run
- Integration tests with -tags=integration require WSP_DATABASE_URL + Postgres

## Manual checklist for Linux host

1. cd deploy && cp env.example .env && set strong WSP_DATA_KEY
2. docker compose up -d --build
3. Open :3000 → wizard
4. Download CA, set proxy :8080
5. Policy block test + logs
6. EICAR with malware enabled
7. RBI rule + viewer
8. Config export

## Status

Foundation complete for v1 code delivery; full Compose E2E deferred to Linux Docker environment.

## Critical fix: CONNECT + RBI isolation (2026-07-27)

**Finding:** `handleCONNECT` served a transparent tunnel when `TLSIntercept=false` even if `RBIIsolated` was true, delivering origin bytes and bypassing isolation.

**Fix:**
1. CONNECT path: if `needsIsolation` / `RBIIsolated`, never `serveTunnel`. Force MITM (`serveMITM`); if CA unavailable, fail-closed 403 block.
2. Policy accumulate: when `RBIIsolated`, set `TLSIntercept=true` automatically.
3. Unit tests:
   - `TestRBIIsolatedImpliesTLSIntercept` (policy)
   - `TestCONNECT_RBIIsolated_NoTLSIntercept_DoesNotDialOrigin` (mock dialer; origin never contacted)
   - `TestCONNECT_RBIIsolated_WithCA_ForcesMITMNotTunnel` (MITM 200, dial count 0)

**Verification:**
- `go test ./internal/proxy/... ./internal/policy/... -count=1` → PASS
- `go test ./... -count=1` → PASS
- Commit: `fix: force MITM or fail-closed when RBI isolates CONNECT`
