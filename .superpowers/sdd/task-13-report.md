# Task 13 Report: Compose hardening + README

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `a2a64f3` — `docs: README and compose production-ready defaults`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Production-oriented docs and deploy polish for single-host Compose:

1. **Full README** — product overview, architecture diagram, requirements, quick start, wizard, client/CA setup, ports, CASB matrix, RBI limits, security notes, env reference, roadmap, manual test checklist.
2. **`deploy/env.example`** — strong `WSP_DATA_KEY` generation instructions (`openssl rand -base64 32`); must set in `.env`.
3. **`deploy/smoke.sh`** — waits for `GET /healthz`, then checks `GET /api/v1/setup/status` for `setup_completed`.
4. **`docs/architecture.md`** — short process/data/control plane and failure-mode notes.
5. **Compose** — comments for production defaults, postgres health start_period, restart policy, RBI socket security notes.

---

## Deliverables

| Path | Purpose |
|------|---------|
| `README.md` | Operator-facing full documentation |
| `docs/architecture.md` | Condensed architecture notes |
| `deploy/env.example` | Env template + data key instructions |
| `deploy/smoke.sh` | healthz + setup status smoke |
| `deploy/docker-compose.yml` | Comments / production-ready defaults polish |

---

## Smoke usage

```bash
cd deploy
cp env.example .env
# set WSP_DATA_KEY
docker compose up -d --build
./smoke.sh
# ADMIN_BASE=http://host:3000 ./smoke.sh
```

---

## Tests

```text
go test ./... -count=1   # PASS (docs-only change; suite still green)
```

---

## Notes

- Compose still mounts Docker socket for RBI; README documents the privilege risk.
- Distroless image has no curl — smoke runs on the host against published `:3000`.
