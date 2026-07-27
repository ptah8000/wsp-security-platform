# WSP architecture notes (v1)

Short companion to the full design in `docs/superpowers/specs/`.

## Process model

One Go binary (`wsp`) can run:

| `WSP_MODE` | Listeners |
|------------|-----------|
| `all` (default) | Proxy `:8080` + management `:3000` |
| `gateway` | Proxy only |
| `management` | Admin API/UI only |

Shared components in `all` mode: policy engine (hot-swapped from management writes), cert provider, store, RBI orchestrator, ClamAV client, hourly log retention job.

## Data plane (proxy)

1. Accept explicit HTTP or `CONNECT`
2. Build request context (IP, user, URL, method)
3. Evaluate ordered policy (pure engine, no I/O)
4. Auth / block / tunnel vs MITM
5. On intercept: leaf cert from active CA → decrypt
6. CASB (request/response) → malware (size-capped) → optional RBI handoff
7. Forward and log decision + timings to `request_logs` (monthly partitions)

## Control plane (management)

- Echo REST under `/api/v1/*`, session cookie `wsp_session`
- Unauthenticated: `/healthz`, setup routes (while incomplete), login
- Authenticated: CRUD, simulate, logs, audit, export, full health
- Embedded SPA from `web/dist` (Vite/React)

## Persistence

- PostgreSQL 16: users, sessions, certificates (encrypted keys), policies, objects, settings, audit, partitioned request logs
- Retention: settings `log_retention_days` / `audit_retention_days`; background batches of 5000 deletes/hour

## Sidecars

| Service | Purpose |
|---------|---------|
| `postgres` | System of record |
| `clamav` | clamd TCP for anti-malware |
| Docker engine | Ephemeral Chromium for RBI |

## Failure modes (summary)

| Dependency | Effect |
|------------|--------|
| Postgres down | Admin + new policy load fail; health **critical** |
| ClamAV down | Per rule/fail mode (default **fail-open**); health **degraded** |
| Docker down | RBI rules fail closed; other traffic continues; health **degraded** |
| No `WSP_DATA_KEY` / CA | MITM unavailable |

## Trust boundaries

- Clients trust the org CA for intercepted TLS
- Operators with Docker socket access are effectively host-privileged
- Management plane should sit behind TLS in production; lab defaults are plain HTTP
