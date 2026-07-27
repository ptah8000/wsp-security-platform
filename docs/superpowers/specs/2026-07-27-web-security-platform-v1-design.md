# Web Security Platform (WSP) v1 — Design Specification

**Date:** 2026-07-27  
**Status:** Ready for user review  
**Source of truth for product requirements:** `SECURITY_SUITE_V1_DEVELOPMENT_PROMPT.md`  
**Working directory:** `D:\Grok\WSP`

---

## 1. Goals and non-goals

### 1.1 Product vision
An open-source, on-premises web security suite that protects users while browsing: explicit HTTP/HTTPS proxy with TLS interception, ordered policy, Remote Browser Isolation (RBI), inline CASB, anti-malware, and a clean management plane with rich logging.

### 1.2 Version 1 success criteria
Deliver a **complete, operable single-host product foundation**:

- Clients can browse through the explicit proxy with TLS interception.
- Ordered firewall-style policy drives Allow/Block, MITM, auth mode, RBI, CASB, and malware scan.
- RBI can isolate a session end-to-end (container + CDP stream + input), even if UX is not polished.
- CASB enforces real upload/download (and selected action) blocks for a subset of apps; remaining apps have clear extension points.
- ClamAV scans size-capped bodies via clamd when policy enables it.
- Management UI covers: first-run wizard, health, users, certificates, policy, objects, simulation, logs, audit, retention, config export, client setup guidance.
- One-command Docker Compose deploy on Linux.
- Architecture does **not** block later clustering, AD auth, multi-tenancy, ClickHouse logs, or process split.

### 1.3 Explicit non-goals (v1)
- Clustering, HA, load balancing, multi-tenancy
- AD / Kerberos / NTLM
- Transparent proxy
- Customer-provided intermediate CAs
- Advanced analytics dashboards
- Live connection monitoring
- Dark mode / heavy UI polish
- Full CASB parity for every action on all five apps
- Pixel-perfect RBI performance at scale

### 1.4 Design principles
1. **Performance first** on the data plane (minimal allocations, streaming where possible).
2. **Security by design** (isolation, least privilege, no real DOM to user in RBI).
3. **Observability** (every request tells a full story).
4. **Operability** (wizard, health, audit, export, single Compose).
5. **Modular monolith now, distributed later** — hard package boundaries, interfaces at seams.
6. **Open source only**.

---

## 2. Decisions locked with stakeholder

| Decision | Choice |
|----------|--------|
| Delivery scope | Full v1 foundation in one arc |
| Process model | Single Go binary: gateway + management API + embedded UI |
| Repo location | `D:\Grok\WSP` with git |
| RBI/CASB/ClamAV depth | Real plumbing, controlled depth (see §6–§8) |
| Runtime | Docker Compose on Linux only (WSL2/VM OK for dev) |
| Architecture style | Modular monolith (Approach 1) |

---

## 3. High-level architecture

### 3.1 Process and listeners
One binary: **`wsp`**.

| Listener | Default | Role |
|----------|---------|------|
| Proxy | `:8080` | Explicit HTTP/HTTPS proxy (data plane) |
| Management | `:3000` | REST API + SPA (control plane) |

Internal TLS termination for the admin UI is optional in v1 lab deployments; production docs recommend placing a reverse proxy (Caddy/nginx) with TLS in front of `:3000`. The proxy listener remains plain TCP for CONNECT/HTTP as is standard for explicit proxies.

### 3.2 Compose topology

```
Client → wsp:8080 (proxy)
Admin  → wsp:3000 (API + UI)

wsp ──TCP──► postgres:5432
wsp ──TCP──► clamav:3310
wsp ──unix──► /var/run/docker.sock  (RBI only; optional mount)
wsp ──creates/destroys──► ephemeral chromium containers
```

Services:

| Service | Image / build | Notes |
|---------|---------------|-------|
| `wsp` | Multi-stage Dockerfile (Node build UI → Go build embed) | Needs Docker socket if RBI enabled |
| `postgres` | `postgres:16-alpine` | Persistent volume |
| `clamav` | Official ClamAV image | Signature updates; TCP 3310 |

### 3.3 Go module layout

```
cmd/wsp/main.go
internal/
  config/          # env bootstrap + settings loaded from DB
  store/           # pgx pool, repositories, migrations runner
  auth/            # local users, password hashing, admin sessions, proxy auth cache
  certs/           # CA lifecycle, leaf cert cache (MITM)
  proxy/           # explicit proxy, CONNECT, MITM, pipeline
  policy/          # pure evaluation engine + simulator
  casb/            # detectors and enforcement
  malware/         # clamd client
  rbi/             # docker + rod/CDP + websocket bridge
  logging/         # session/request log writers + retention
  audit/           # admin audit events
  mgmt/            # Echo HTTP API + middleware
  health/          # aggregate health checks
  blockpage/       # default + custom block HTML rendering
  export/          # configuration export
web/               # React + TypeScript + Vite + Tailwind + shadcn/ui
migrations/        # ordered SQL migrations
deploy/
  docker-compose.yml
  Dockerfile
  env.example
docs/
```

### 3.4 Modular seams (for large-org evolution)

Each domain exposes interfaces consumed by the pipeline; concrete implementations live in the same binary for v1.

| Seam | Interface responsibility | Future split |
|------|--------------------------|--------------|
| `store.Store` | All persistence | Shared DB / config service |
| `policy.Engine` | Evaluate request → decision | Shared policy service + cache |
| `certs.Provider` | CA + SignHost(host) | HSM / external PKI |
| `malware.Scanner` | Scan(stream) → result | Dedicated scan workers |
| `rbi.Orchestrator` | Start/Stop/Attach session | RBI node pool across hosts |
| `casb.Inspector` | Inspect request/response | Pluggable detector packages |
| `logging.Recorder` | Record session/request | ClickHouse / Kafka sink |
| `audit.Logger` | Record admin actions | SIEM export |

**Rule:** Policy evaluation is pure (no I/O). Side effects (block page, RBI, scan, header rewrite, log) happen only in the proxy pipeline after evaluation.

### 3.5 Technology choices

| Area | Choice | Rationale |
|------|--------|-----------|
| Language | Go 1.22+ | Concurrency, static binary, ops simplicity |
| Proxy MITM | Custom CONNECT + MITM helpers; `elazarl/goproxy` patterns / thin wrapper | Full control; mature MITM cert caching patterns |
| Management API | Echo | `net/http` compatible, clean middleware, mature |
| Frontend | React + TS + Vite + Tailwind + shadcn/ui | Simple-yet-powerful admin UX |
| DB driver | pgx/v5 | Performance, pool, JSON support |
| Passwords | argon2id (prefer) with bcrypt fallback constant | Modern default |
| RBI control | go-rod + CDP screencast | Strong CDP DX in Go |
| Malware | clamd INSTREAM over TCP | Simpler/faster than ICAP for custom gateway |
| Migrations | golang-migrate or embed SQL runner | Deterministic schema |
| Logging (app) | slog JSON | Structured operational logs |

---

## 4. Data model (PostgreSQL)

### 4.1 Principles
- UUID primary keys (`gen_random_uuid()`).
- `created_at` / `updated_at` timestamptz where relevant.
- Request logs **partitioned by month** (or week) from day one for high insert volume and retention drops.
- Config tables stay small and transactional; log tables are append-heavy.
- Schema avoids tenant_id for v1 but keeps namespaced tables so multi-tenancy can add `org_id` later without rewriting core logic.

### 4.2 Core tables

**users**
- `id`, `username` (unique), `password_hash`, `display_name`, `role` (`admin` | `user`), `enabled`, `created_at`, `updated_at`, `last_login_at`

**admin_sessions**
- `id`, `user_id`, `token_hash`, `expires_at`, `ip`, `user_agent`, `created_at`

**proxy_auth_cache** (IP-cached auth)
- `ip`, `user_id`, `username`, `expires_at`

**certificates**
- `id`, `name`, `kind` (`self_signed_ca`), `cert_pem`, `key_pem_encrypted` or filesystem path reference, `fingerprint_sha256`, `not_before`, `not_after`, `is_active`, `created_at`
- v1: private key stored encrypted at rest with a master key from env (`WSP_DATA_KEY`), never returned via API in plaintext after creation (download CA **public** cert only).

**settings**
- key/value JSONB document or typed rows: DNS servers, proxy listen (informational), log retention days, setup_completed, platform metadata.

**block_pages**
- `id`, `name`, `html`, `is_system`, `created_at`, `updated_at`

**reusable_objects**
- `id`, `name`, `type` (enum: source_ip, source_user, user_agent, destination_domain, destination_url, destination_regex, time_window, header_mod, casb_app_ref, …), `definition` JSONB, `is_system`, `created_at`, `updated_at`

**policies** (ordered rules)
- `id`, `name`, `description`, `enabled`, `priority` (integer order; lower = higher priority / evaluated first), `sections` JSONB (general, web_filtering, rbi, casb, antimalware), `created_at`, `updated_at`

**sessions** (browsing sessions)
- `id`, `started_at`, `ended_at`, `client_ip`, `username`, `user_agent`, `summary` JSONB optional

**request_logs** (partitioned)
- `id`, `session_id`, `request_id`, `ts`, source fields, destination fields, method, sizes, decision, matched_rule_ids, evaluated_rule_ids, actions JSONB, timings JSONB, block_reason, error, etc.
- Indexes: `(ts DESC)`, `(client_ip, ts)`, `(username, ts)`, `(host, ts)`, `(decision, ts)`, `(session_id, ts)`

**audit_logs**
- `id`, `ts`, `actor_user_id`, `actor_username`, `action`, `target_type`, `target_id`, `summary`, `detail` JSONB, `ip`

**schema_migrations**
- standard migration tracking

### 4.3 Default seed data
- System block page (clean default HTML)
- System reusable objects for the five CASB applications
- Default policy pack (enabled after setup):
  1. Allow local/management exceptions if needed
  2. Enable anti-malware for broad web (or high-risk destinations as defined)
  3. Sensible allow/log baseline so product is useful immediately
  4. Optional sample RBI rule **disabled** by default (document how to enable)
- No admin user until wizard creates one (`setup_completed = false`)

### 4.4 Log retention
- Setting: `log_retention_days` (7 / 14 / 30 / 90; default 30)
- Background job in `wsp` drops old partitions or `DELETE` with limit batches for non-partition path; prefer `DROP PARTITION` for speed.
- Audit logs: longer default (e.g. 365 days) or separate setting; v1 uses same UI section with distinct field `audit_retention_days` default 365.

---

## 5. Data-plane request pipeline

### 5.1 Explicit proxy behavior
1. Accept client connection on proxy port.
2. Parse absolute-form HTTP request or `CONNECT host:port`.
3. Build **RequestContext**: client IP, User-Agent, username (if auth), method, URL parts, time.
4. **Policy evaluate (pre-MITM / connect stage)** for destination host and auth/TLS requirements.
5. If auth required and missing → 407 Proxy Authentication Required (local Basic for v1).
6. If Block → serve block page (HTTP) or MITM-then-block for HTTPS when interception is required to show page; for non-intercept CONNECT block, return 403 with short reason body where possible.
7. If TLS interception disabled → tunnel CONNECT bytes end-to-end (no inspection, limited CASB/malware/RBI).
8. If TLS interception enabled → MITM: generate/cache leaf cert for host signed by active CA; decrypt.
9. For each HTTP request on the channel:
   - Re-evaluate or apply cached rule set for full URL/method/path.
   - Apply CASB request-side checks.
   - Optionally scan request body (uploads) via malware scanner with size cap.
   - If RBI isolated → hand off to RBI flow (client receives isolation viewer, not origin bytes).
   - Else forward to origin; stream response.
   - CASB response-side checks; malware scan response body when enabled and `Content-Length`/read budget allows.
   - Header modifications from policy.
   - Record rich request log; associate session ID (derived from client IP + auth + time window or explicit proxy connection id).

### 5.2 TLS / certificates
- One-click **Generate Self-Signed CA** in UI (and wizard step).
- CA cert downloadable as PEM for client trust stores.
- Leaf certs: on-demand, cached in memory (LRU) by hostname; short-lived validity (e.g. 24h–7d).
- Private keys never leave the server via API.
- Future: `certs.Provider` can wrap customer subordinate CA without pipeline changes.

### 5.3 Authentication modes (proxy)
| Mode | Behavior |
|------|----------|
| Disable | No proxy auth |
| IP-cached | 407 once; success caches username for IP for TTL (setting, default 8h) |
| Per-request | 407 every new connection/request as configured |

Local users only; passwords argon2id.

### 5.4 Session model for logging
- **Session** groups related requests from the same client identity over a sliding/idle window (e.g. 30 minutes idle close) or until proxy connection cluster ends.
- Each request gets unique `request_id` (ULID/UUID).
- UI: search requests; drill into session chronological list.

### 5.5 Performance notes
- Stream bodies; only buffer when CASB/malware/header-rewrite requires it.
- Configurable max scan size (default 10–25 MB); oversize → skip scan + log `scan_skipped_size`.
- Connection-level goroutine model standard for Go; avoid global locks on policy (atomic swap of compiled policy snapshot).

---

## 6. Policy engine

### 6.1 Evaluation order
Strict top-to-bottom by `priority` / list order.

On match:
- **Block** → stop; return selected block page / reason.
- **Allow** and additive actions → accumulate actions; continue as specified.
- RBI / CASB restrictions may produce **targeted** block outcomes for that restriction without being a generic “web block” rule.

### 6.2 Rule sections (stored as structured JSON)
- **General:** sources, destinations, action Allow/Block + block page, TLS intercept on/off + CA, auth mode
- **Web filtering:** optional override src/dst, time conditions, protocols/methods, header mods on allow
- **RBI:** isolated / not isolated; block copy from/to site (enforced in RBI viewer/CDP where possible)
- **CASB:** apps list + actions (block upload/download by type; block specific actions)
- **Anti-malware:** enable/disable scan

### 6.3 Reusable objects
Any condition/action created is savable as a named object; picker in rule editor. System objects (CASB apps) are not deletable.

### 6.4 Policy simulation tool
API + UI: input source IP, optional username, full URL, method, User-Agent, timestamp → output:
- Rules evaluated (in order)
- Matches
- Final decision
- Accumulated actions
- Optional audit entry when used by admin

### 6.5 Compilation
On policy change: build immutable **PolicySnapshot** (compiled matchers: CIDR trees, domain suffix maps, regexes) and atomic-swap into the proxy. Avoids DB hits on the hot path.

---

## 7. Remote Browser Isolation (v1 depth)

### 7.1 Trigger
Policy action **Isolated** for the matched request/navigation.

### 7.2 Flow
1. Gateway creates ephemeral container from pinned image (Chromium + remote debugging port, no privileged mode if possible; drop caps; read-only root where feasible; memory/CPU limits).
2. Connect via go-rod/CDP; navigate to target URL.
3. Start screencast (`Page.startScreencast`) or equivalent frame pipeline.
4. Client is redirected or instructed to open **RBI viewer** page (management origin or proxy-served special host) with session token over WebSocket.
5. Forward mouse/keyboard/wheel to CDP Input domain.
6. On WS close / timeout / user end → stop container (`ForceRemove`), purge session.

### 7.3 Security properties
- User never receives origin HTML/JS/binary objects for isolated sessions.
- Containers have no host network if avoidable; egress via defined network; no mount of host secrets.
- One container ≈ one tab/session.
- Resource limits + max concurrent RBI sessions (setting, default e.g. 10) to protect the host.
- Session tokens: unguessable, short-lived, bound to client IP optional.

### 7.4 v1 UX honesty
Interactive isolation works but may have limited FPS, clipboard controls partial, file upload UX limited. Document limitations. Pre-warm pool is a v1.x optimization (interface allows it).

---

## 8. CASB (inline, controlled depth)

### 8.1 Mechanism
After MITM decryption, match host/path/method/headers/body signatures for supported apps. No SaaS API calls.

### 8.2 Applications
| App | v1 enforcement target |
|-----|------------------------|
| ChatGPT | Upload/file attach patterns; selected send endpoints where reliable |
| Google Drive / Gmail | Upload/download MIME/extension blocks |
| Microsoft 365 (OWA/OneDrive) | Upload/download blocks |
| Slack | Upload/download; message post if reliably detectable |
| WhatsApp Web | Best-effort upload/download; document detection limits |

**v1 commitment:** fully wired framework + **solid detectors for ChatGPT and Google Drive** upload/download; other three apps registered with host patterns and partial rules, clearly marked completeness in code/docs.

### 8.3 Actions
- Block file upload (all or by MIME/extension)
- Block file download (all or by MIME/extension)
- Block specific actions when signatures are reliable
- Targeted block page explaining which CASB control fired

### 8.4 Extensibility
Each app is a `casb.Detector` implementation registered in a catalog. Adding apps = new package + system object seed — no pipeline rewrite.

---

## 9. Anti-malware

- Client: clamd `INSTREAM` over TCP to `clamav:3310`.
- Policy enables/disables per rule.
- Scan request and/or response bodies with size cap and content-type filters (skip obviously non-file types optional).
- On hit: block page with threat name (if provided), URL, timestamp, user.
- Health: clamd ping + last signature update time if obtainable from container/logs/stats.
- Failure mode: configurable `fail_open` vs `fail_closed` (default **fail_open** with loud log for v1 availability; document security tradeoff). Default recommendation for stricter orgs: fail_closed on scan errors for matched rules.

---

## 10. Management plane

### 10.1 API (Echo)
- JSON REST under `/api/v1/...`
- Auth: session cookie (HttpOnly, Secure when TLS, SameSite=Lax) for SPA; CSRF strategy: double-submit or same-site + careful CORS (admin is same origin via embedded SPA).
- Role: v1 all management users are admins (or single `admin` role); proxy users may exist with `role=user` for browsing auth only.

### 10.2 Major API groups
- `/api/v1/setup/*` — wizard (open only when setup incomplete)
- `/api/v1/auth/login|logout|me`
- `/api/v1/health`
- `/api/v1/users`
- `/api/v1/certificates`
- `/api/v1/settings`
- `/api/v1/block-pages`
- `/api/v1/objects`
- `/api/v1/policies` + reorder
- `/api/v1/policies/simulate`
- `/api/v1/logs/requests` + `/api/v1/logs/sessions/:id`
- `/api/v1/audit`
- `/api/v1/export/config`
- `/api/v1/client-setup` (CA download link metadata, PAC snippet)

### 10.3 UI sections
1. Dashboard / Health  
2. Settings (certs, users, DNS, block pages, retention, export)  
3. Policy (list, editor, simulation, defaults)  
4. Reusable Objects  
5. Logs / Audit  
6. Client Setup  

### 10.4 First-run wizard
Linear:
1. Create admin account  
2. Generate self-signed CA  
3. Basic network settings (DNS, show proxy port)  
4. Done → client configuration guidance  

Hard gate: if no admin / setup incomplete, only setup + health endpoints work.

### 10.5 System health page
- Overall status: healthy / degraded / critical  
- Gateway listening, DB ping, ClamAV, RBI (docker ping + active container count), disk/CPU/mem best-effort from `/proc` or cgroup, versions, uptime  

### 10.6 Configuration export
JSON bundle: policies, objects, users (no password hashes or redacted), settings, certificate **metadata** (not private keys), block pages. Audit the export action. Import is out of scope for v1.

### 10.7 Client configuration guidance
- Download CA  
- Browser trust instructions (Chrome/Edge/Firefox)  
- Example PAC  
- GPO/MDM notes  
- Common cert error troubleshooting  

---

## 11. Security considerations

### 11.1 Threat model (summary)
| Threat | Mitigation |
|--------|------------|
| Untrusted web content | MITM inspection, malware scan, optional RBI (no origin code on endpoint) |
| Malicious admin client | Session auth, audit log, argon2id passwords |
| RBI escape | Ephemeral containers, limits, no privileged, minimal mounts |
| MITM key theft | Encrypt CA key at rest; restrict volume perms; no key export API |
| Log injection / XSS in admin | JSON APIs, React escaping, CSP headers on admin |
| SSRF via proxy | Standard forward proxy behavior; block private destinations optional setting (v1: configurable deny RFC1918 for clients — default off for lab, document) |
| Docker socket abuse | Only `wsp` mounts socket; document risk; future: dedicated RBI agent |
| Supply chain | Pin image digests in Compose where practical; Go module sumdb |

### 11.2 Secrets
- `WSP_DATA_KEY` — encrypts CA private key material at rest  
- `POSTGRES_PASSWORD` — DB  
- Admin passwords — argon2id hashes only  
- Never log secrets or full `Authorization` headers (redact)

### 11.3 RBI “never real source” guarantee
Isolated path must not stream origin response bytes to the user-agent; only the viewer protocol (frames + input). Enforced by separate code path after policy decision.

### 11.4 Hardening checklist (docs)
- Run Compose as dedicated user; restrict Docker socket  
- Firewall admin port to management networks  
- Distribute CA only via trusted channels  
- Backup Postgres volumes; protect exports  

---

## 12. Observability and operability

### 12.1 Logs
- **Application logs:** slog JSON to stdout (container-friendly)  
- **Request/session logs:** PostgreSQL + UI  
- **Audit logs:** PostgreSQL + UI  

### 12.2 Health endpoints
- `GET /api/v1/health` — full aggregate (auth optional for local monitoring token later; v1 may allow unauthenticated shallow health on localhost only — decision: **authenticated full health**, **unauthenticated** `GET /healthz` liveness for orchestrators)

### 12.3 Deploy
```bash
docker compose up -d --build
```
Open admin `http://<host>:3000` → wizard → download CA → point clients at `http://<host>:8080`.

### 12.4 README must include
Architecture, run steps, wizard, client setup, limitations (RBI performance, CASB coverage matrix, single-node), security notes, roadmap hooks.

---

## 13. Error handling and failure modes

| Failure | Behavior |
|---------|----------|
| Postgres down | Proxy fails closed for new policy loads; existing snapshot may serve briefly; admin unavailable; health critical |
| ClamAV down | Per `fail_open`/`fail_closed`; health degraded |
| Docker unavailable | RBI actions fail → targeted error/block page; non-RBI traffic continues |
| Origin TLS errors | Log + error page to client |
| Policy empty | Safe default: allow with MITM if CA present? **Safer v1:** ship default policy; if all disabled, allow tunnel with warning in health |

---

## 14. Testing strategy

- **Unit:** policy matching, CASB signature helpers, cert generation, password hashing  
- **Integration:** proxy MITM with test CA + httptest; policy simulation; store migrations  
- **Compose smoke:** healthz, wizard API, one CONNECT MITM request logged  
- **Manual:** RBI one-site demo; ClamAV EICAR download block  

CI (later): Go test + UI typecheck/build; optional Compose smoke on Linux runners.

---

## 15. Implementation phasing (within this arc)

Order optimized for always-bootable product:

1. Repo skeleton, Dockerfile, Compose, migrations, config  
2. Store + auth + setup wizard API  
3. Certs + proxy MITM + basic allow/forward + request logging  
4. Policy engine + default policy + simulation API  
5. Block pages + malware integration  
6. CASB framework + ChatGPT/Google Drive  
7. RBI orchestrator + viewer  
8. React SPA for all main sections  
9. Health, audit, retention job, config export, client guidance  
10. README, hardening notes, seed polish  

---

## 16. Future modularization map (not built now)

| Capability | Path |
|------------|------|
| Multiple gateway nodes | Shared Postgres + atomic policy version; sticky sessions for RBI; move RBI off gateway |
| Split control/data plane | Run same binary with `WSP_MODE=gateway|management` (flag optional even in v1 as hidden footgun-prevention for later) |
| AD/Kerberos | New `auth.Provider` implementation |
| ClickHouse logs | `logging.Recorder` dual-write/migrate |
| Multi-tenancy | `org_id` on config tables + request isolation |
| Customer CA | New cert provider; UI flow |
| Transparent proxy | New listener mode in `proxy` package |

Hidden config (optional in v1 for smoother future): `WSP_MODE=all|gateway|management` defaults to `all`. Document as experimental.

---

## 17. Deliverables checklist (maps to product prompt §9)

1. Complete project structure and Go module  
2. Working `docker-compose.yml`  
3. Gateway: explicit proxy, TLS interception, policy, structured request logs  
4. RBI orchestration skeleton with real create/destroy + basic stream  
5. Management API + React frontend with main navigation and key screens  
6. PostgreSQL schema as above  
7. First-run setup wizard  
8. System Health page  
9. One-click self-signed CA  
10. Policy simulation tool  
11. Configuration export  
12. Client configuration guidance page  
13. ClamAV integration path  
14. README  
15. Architecture notes / meaningful comments  

---

## 18. Open points resolved by recommendation

| Topic | Resolution |
|-------|------------|
| Fiber vs Echo | Echo |
| chromedp vs rod | go-rod |
| ICAP vs clamd | clamd INSTREAM |
| Admin TLS | Optional reverse proxy; lab HTTP OK |
| Malware fail mode | Default fail_open + log; configurable fail_closed |
| CASB coverage | Full framework; deep ChatGPT + Google Drive; others partial |
| RBI | Real e2e path, not mock-only |
| Process split flag | Optional `WSP_MODE`, default `all` |

---

**End of design.**  
Next step after approval: implementation plan via writing-plans skill, then build.
