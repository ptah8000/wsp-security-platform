# Web Security Platform (WSP) v1

On-premises web security suite: explicit HTTP/HTTPS proxy with TLS interception, ordered policy, Remote Browser Isolation (RBI), inline CASB, ClamAV anti-malware, and a management plane with first-run wizard, health, audit, and config export.

**Module:** `github.com/wsp-security/wsp`  
**Binary version:** `0.1.0`  
**Target runtime:** Linux + Docker Compose (WSL2/VM OK for development)

---

## 1. What is WSP

WSP is a modular monolith that sits between browsers and the internet as an **explicit proxy**. Policy rules decide allow/block, TLS interception (MITM), authentication, RBI isolation, CASB controls, and malware scanning. Operators manage everything from an embedded admin SPA on port **3000**.

Typical lab or branch-office deployment: one Compose stack (WSP + PostgreSQL + ClamAV), Docker socket for RBI, and clients pointed at the proxy with the WSP CA trusted.

---

## 2. Architecture

```
                    ┌─────────────────────────────────────────┐
  Browser ─────────►│  wsp :8080  explicit HTTP/HTTPS proxy   │
                    │    policy → MITM → CASB → malware → RBI │
  Admin SPA ───────►│  wsp :3000  REST API + embedded UI      │
                    └───────────┬─────────────┬───────────────┘
                                │             │
                     ┌──────────▼──┐   ┌──────▼──────┐
                     │  postgres   │   │   clamav    │
                     │  :5432      │   │   :3310     │
                     └─────────────┘   └─────────────┘
                                │
                     Docker socket (optional RBI)
                                │
                     ephemeral Chromium containers
```

| Package | Role |
|---------|------|
| `cmd/wsp` | Single binary entrypoint (`all` / `gateway` / `management`) |
| `internal/proxy` | Explicit proxy, CONNECT, MITM, request pipeline |
| `internal/policy` | Ordered pure evaluation engine + simulate |
| `internal/casb` | Inline host/path detectors (no SaaS APIs) |
| `internal/malware` | clamd INSTREAM client |
| `internal/rbi` | Docker + CDP viewer sessions |
| `internal/mgmt` | Echo management API + SPA |
| `internal/logging` | Request/session recorder + hourly retention job |
| `internal/health` | Aggregate readiness (DB, clam, docker, process) |
| `migrations/` | PostgreSQL 16 schema (partitioned `request_logs`) |
| `web/` | React + TypeScript + Vite + Tailwind admin UI |
| `deploy/` | Dockerfile, Compose, env example, smoke script |

See [docs/architecture.md](docs/architecture.md) for short notes on data/control planes and failure modes.

---

## 3. Requirements

- **Linux host** (or WSL2/VM) with Docker Engine and Docker Compose v2
- ~2+ CPU / 4+ GB RAM recommended if RBI is used (Chromium containers)
- Outbound network for image pulls and (optional) ClamAV signature updates
- Clients that can use an explicit HTTP proxy and install a private CA

> Windows can build/test Go packages; **production Compose + RBI Docker socket is Linux-oriented**.

---

## 4. Quick start

```bash
cd deploy
cp env.example .env

# REQUIRED: set a 32-byte data key (encrypts CA private keys at rest)
# openssl rand -base64 32
# paste into WSP_DATA_KEY=... in .env

docker compose up -d --build
```

Wait until Postgres is healthy and WSP has migrated:

```bash
./smoke.sh
# or: bash smoke.sh
```

Open the admin UI: **http://\<host\>:3000**

---

## 5. First-run wizard

On first boot, `setup_completed` is false. The SPA redirects to `/setup`:

1. **Admin user** — create the first local admin (username + password)
2. **Certificate authority** — generate self-signed CA (requires `WSP_DATA_KEY`)
3. **Network** — DNS resolvers used by the platform
4. **Complete** — marks setup done; login with the admin you created

API equivalents (unauthenticated only while setup is incomplete):

| Step | Endpoint |
|------|----------|
| Status | `GET /api/v1/setup/status` |
| Admin | `POST /api/v1/setup/admin` |
| CA | `POST /api/v1/setup/ca` |
| Network | `POST /api/v1/setup/network` |
| Finish | `POST /api/v1/setup/complete` |

Liveness (orchestrators): `GET /healthz` → `{"status":"ok"}`.

---

## 6. Client proxy + CA install

1. Download the **public CA PEM** from **Client setup** in the UI (or `GET /api/v1/certificates/{id}/pem` after login).  
   Private keys are **never** exported.
2. Trust the CA in the OS (and Firefox if not using enterprise roots).
3. Point the browser/OS at the explicit proxy:

   | Setting | Value |
   |---------|-------|
   | Proxy type | HTTP |
   | Host | Compose host IP/DNS |
   | Port | **8080** |

4. Optional PAC (lab) from Client setup — `PROXY host:8080` with DIRECT for RFC1918/localhost.

**Common issues**

| Symptom | Likely cause |
|---------|----------------|
| `NET::ERR_CERT_AUTHORITY_INVALID` | CA not trusted on client |
| Proxy connection failed | Firewall / wrong host:port |
| HTTPS without inspection | Policy `tls_intercept=false` for that destination |
| MITM disabled | Missing `WSP_DATA_KEY` or no active CA |

---

## 7. Default ports

| Port | Service | Notes |
|------|---------|--------|
| **8080** | Explicit proxy | Client traffic |
| **3000** | Management API + SPA | Put TLS reverse proxy in front for production |
| **5432** | PostgreSQL | Compose-internal (not published by default) |
| **3310** | clamd | Compose-internal |

---

## 8. CASB coverage matrix

Inline detectors match **decrypted** HTTP after MITM. No SaaS admin APIs.

| App | Completeness | Hosts (examples) | Actions |
|-----|--------------|------------------|---------|
| ChatGPT | **full** | `chat.openai.com`, `chatgpt.com` | block upload / download / send |
| Google Drive | **full** | `drive.google.com`, `docs.google.com` | block upload / download |
| Microsoft 365 | **partial** | OWA / OneDrive / SharePoint patterns | block upload / download |
| Slack | **partial** | `app.slack.com`, `files.slack.com` | upload / download / message |
| WhatsApp Web | **partial** | `web.whatsapp.com` | best-effort upload / download |

Enable CASB per policy rule; system reusable objects seed the five apps.

---

## 9. RBI limitations (v1)

- One ephemeral Chromium container ≈ one isolated session
- Default max concurrent sessions: **`WSP_MAX_RBI_SESSIONS=10`**
- Requires Docker socket mount on the `wsp` service
- Viewer is CDP/WebSocket-based — expect limited FPS vs native browsing
- Clipboard / file-upload UX is partial
- No pre-warm pool in v1 (interface allows later)
- Sample isolation policy ships **disabled** (enable and set destinations when ready)
- If Docker is down, isolation **fails closed** for matching rules (block/error page); non-RBI traffic continues

---

## 10. Security notes

| Topic | Guidance |
|-------|----------|
| **`WSP_DATA_KEY`** | **Required** for CA private-key encryption. Generate with `openssl rand -base64 32`. Never commit `.env`. Losing the key loses ability to use stored encrypted keys. |
| **Docker socket** | Mounted for RBI only. Treat as root-equivalent on the host. Restrict who can reach the host; future: dedicated RBI agent without socket on the edge. |
| **Malware fail-open** | Default `WSP_MALWARE_FAIL_CLOSED=false`: if clamd is unreachable, traffic is **allowed** (logged). Stricter orgs should set `true` so scan errors block when malware is enabled. |
| **Admin TLS** | Lab default is plain HTTP on `:3000`. Production: terminate TLS (Caddy/nginx) and set secure cookies when terminating TLS. |
| **Postgres password** | Compose example uses `wsp`/`wsp` for labs — change for real deployments. |
| **Single node** | No clustering/HA in v1; back up the Postgres volume. |
| **CA trust** | Clients must trust only the org CA you distribute; rotate carefully. |

---

## 11. Config env reference

Copy `deploy/env.example` → `deploy/.env`.

| Variable | Default | Description |
|----------|---------|-------------|
| `WSP_MODE` | `all` | `all` \| `gateway` \| `management` |
| `WSP_PROXY_ADDR` | `:8080` | Proxy listen address |
| `WSP_ADMIN_ADDR` | `:3000` | Management listen address |
| `WSP_DATABASE_URL` | `postgres://wsp:wsp@postgres:5432/wsp?sslmode=disable` | PostgreSQL DSN |
| `WSP_DATA_KEY` | _(empty)_ | **Must set** — 32-byte secret (base64 or hex) for encrypting CA keys |
| `WSP_CLAMD_ADDR` | `clamav:3310` | clamd TCP address |
| `WSP_MALWARE_FAIL_CLOSED` | `false` | `true` = block on scan errors |
| `DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker API for RBI |
| `WSP_RBI_IMAGE` | `browserless/chrome:latest` | Isolation browser image |
| `WSP_MAX_RBI_SESSIONS` | `10` | Concurrent RBI cap |
| `WSP_LOG_LEVEL` | `info` | `debug` \| `info` \| `warn` \| `error` |
| `WSP_SHUTDOWN_TIMEOUT_SEC` | `15` | Graceful shutdown budget |

**Settings in DB** (UI → Settings): `log_retention_days` (default 30), `audit_retention_days` (default 365), DNS servers. An hourly job deletes expired `request_logs` / `audit_logs` in batches of 5000.

---

## 12. Future roadmap hooks

Architecture intentionally leaves room for:

- Clustering / multi-node gateways and shared policy store
- AD / Kerberos / NTLM authentication
- Transparent proxy mode
- Customer intermediate CAs
- ClickHouse (or similar) for high-volume analytics logs
- Process split (gateway vs management) already supported via `WSP_MODE`
- Dedicated RBI agent (no Docker socket on the edge node)
- Pre-warm RBI pools, richer CASB parity, advanced dashboards

---

## Manual test checklist

Use after `docker compose up -d --build` on Linux:

- [ ] `./deploy/smoke.sh` — healthz OK, setup status JSON
- [ ] Wizard creates admin + CA; login works
- [ ] Download CA PEM; configure client proxy to `:8080`
- [ ] HTTP and HTTPS browse via proxy; request appears in **Logs**
- [ ] Create/enable a block rule; confirm block page + log decision
- [ ] With malware policy on, download EICAR test file → blocked when clamd ready
- [ ] Enable sample RBI rule for a test domain → isolation viewer opens
- [ ] **Health** page shows DB healthy; clam/docker may be degraded until ready
- [ ] **Export** config JSON downloads (no private keys)
- [ ] Change retention days; confirm settings persist

---

## Development (local Go)

```bash
# requires Go 1.22+ (module targets current toolchain)
go test ./...
go build -o bin/wsp ./cmd/wsp
./bin/wsp --version   # 0.1.0

# UI
cd web && npm ci && npm run build
```

Admin UI is embedded from `web/dist` at binary build time.

---

## License

Open source — license file TBD.
