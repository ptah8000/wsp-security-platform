# Task 11 Report: React admin SPA

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `a7b9a88` — `feat: embed React admin UI for all main sections`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Implemented the full management admin SPA as a **Vite + React + TypeScript + Tailwind v4** application under `web/`, built into `web/dist` and embedded via existing `//go:embed all:dist` (`web/embed.go`).

1. **Auth gate + setup redirect** — bootstrap via `GET /api/v1/setup/status`; incomplete setup forces `/setup`; unauthenticated users go to `/login`; session cookie via `credentials: "include"`.
2. **All main sections** — functional pages calling the management REST API.
3. **UX** — light theme, progressive policy editor tabs, policy up/down reorder, simulation form, log filters + session expand, health status badges, empty states with guidance.
4. **Docker** — `deploy/Dockerfile` UI stage updated from placeholder `build.mjs` to `npm ci && npm run build`.

---

## Routes

| Path | Page |
|------|------|
| `/setup` | First-run wizard (admin → CA → network → complete) |
| `/login` | Admin session login |
| `/` | Dashboard (health snapshot, policy counts, recent logs) |
| `/health` | Component health badges + process metrics |
| `/settings` | DNS + retention |
| `/settings/users` | User CRUD |
| `/settings/certificates` | CA generate + PEM download links |
| `/settings/block-pages` | Block page CRUD |
| `/settings/export` | Config JSON export download |
| `/policy` | Policy list + up/down reorder |
| `/policy/new`, `/policy/:id` | Editor tabs: General, Web, RBI, CASB, Malware |
| `/policy/simulate` | Synthetic request simulation |
| `/objects` | Reusable object CRUD |
| `/logs` | Request log filters + session expand |
| `/audit` | Audit list with action filter |
| `/client-setup` | CA download, PAC, trust/MDM/troubleshooting |

---

## Deliverables

| Path | Purpose |
|------|---------|
| `web/package.json` | Vite React TS + Tailwind deps & scripts |
| `web/vite.config.ts` | Vite build → `dist/`, dev API proxy |
| `web/src/api.ts` | Typed fetch client, `credentials: "include"` |
| `web/src/auth.tsx` | AuthProvider, RequireAuth, SetupOnly, PublicOnly |
| `web/src/App.tsx` | React Router routes |
| `web/src/components/ui.tsx` | shadcn-style primitives (Button, Card, Badge, …) |
| `web/src/components/Layout.tsx` | Sidebar shell |
| `web/src/pages/*` | All functional screens |
| `web/dist/*` | Production build (embedded) |
| `web/embed.go` | Unchanged embed path `all:dist` |
| `deploy/Dockerfile` | Multi-stage UI build via Vite |

---

## Build / tests

```text
cd web && npm install && npm run build   # SUCCESS
  dist/index.html
  dist/assets/index-*.css
  dist/assets/index-*.js

go test ./web/... ./internal/mgmt/...    # web: no tests; mgmt: ok
go build -o bin/wsp.exe ./cmd/wsp        # SUCCESS (embed resolves)
```

Node was available (v24 / npm 11). Go embed verified by successful package compile and binary build.

---

## Notes

- UI is **light mode** (not dark), clean functional styling without full shadcn CLI.
- CSP on the management server already allows `'self'` scripts/styles used by the Vite build.
- SPA fallback remains in `mountSPA` (paths without file extension → `index.html`).
- `web/dist/` is tracked so `go:embed` works without Node; Docker still rebuilds UI in stage 1.
- Private keys remain never exposed; CA download uses public PEM endpoint only.

---

## Checklist

- [x] Scaffold Vite React-TS + Tailwind  
- [x] Auth gate + setup redirect  
- [x] All main pages functional  
- [x] Build into `web/dist`; go:embed works  
- [x] Commit `feat: embed React admin UI for all main sections`  
