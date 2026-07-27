# On-Prem Web Security Suite – Version 1 Development Prompt

**Document purpose:**  
This is a complete, self-contained specification for building the first version of an on-premises web security platform. Give this entire document to a development AI.

---

## 1. Project Vision

Build a modern, high-performance, open-source on-premises security suite that protects users while they browse the web.  

The platform provides:
- HTTP/HTTPS proxy with TLS interception and URL filtering
- Remote Browser Isolation (RBI)
- Inline Cloud Access Security Broker (CASB)
- Anti-malware scanning
- Centralized management, policy, and rich logging

The product must be designed from the first line of code to eventually serve large corporations (high throughput, low resource usage, clean architecture for future clustering and multi-tenancy). At the same time, Version 1 must be simple to deploy and operate on a single Linux machine.

---

## 2. Core Principles for Version 1

- **Performance first**: High throughput, low latency, low memory and CPU usage.
- **Simple but granular**: The management interface must feel clean and intuitive, yet expose every important option without clutter.
- **Observability**: Extremely rich logging of every browsing session and every individual request so administrators can fully troubleshoot what happened.
- **Operability**: The system must be easy to install, configure, monitor, and maintain in daily use.
- **Open source only**: All components must be open-source.
- **Growth-oriented architecture**: Design decisions must not block future clustering, high availability, Active Directory integration, or horizontal scaling.
- **Security by design**: Users never receive real website source code or executable objects when RBI is active.

---

## 3. Scope of Version 1 (MVP)

### Included
- Single-instance deployment (no clustering)
- Explicit HTTP/HTTPS proxy with full TLS interception
- Ordered firewall-style policy engine
- Local user authentication only
- One-click self-signed CA certificate generation
- Remote Browser Isolation using Docker + Chromium
- Inline CASB for a limited set of popular web applications
- Anti-malware with ClamAV
- Rich per-request and per-session logging
- Clean web-based management interface
- **First-run setup wizard**
- **System Health / Status page**
- **Administrative audit log**
- **Log retention settings**
- **Policy simulation / test tool**
- **Sensible default policy out of the box**
- **Configuration backup / export**
- **Client configuration guidance page**

### Explicitly Out of Scope for v1
- Clustering / load balancing / automatic failover
- Active Directory, Kerberos, or NTLM authentication
- Transparent proxy mode
- Customer-provided subordinate CA / intermediate certificates
- Advanced analytics dashboards and reporting
- Multi-tenancy
- Real-time live connection monitoring (can come later)
- Dark mode and advanced UI polish features

---

## 4. Recommended Technology Stack

| Area                        | Choice                                      | Reason |
|----------------------------|---------------------------------------------|--------|
| Primary language           | **Go**                                      | Excellent concurrency model, very high networking performance, low resource usage, single static binary, easy future scaling |
| Proxy + Policy + Logging   | Custom Go                                   | Full control over TLS interception, policy evaluation order, and structured logging |
| RBI                        | Docker + Chromium + CDP (`chromedp` or `go-rod/rod`) | Simplest reliable way to achieve true isolation with interactive experience |
| Management API             | Go (Fiber or Echo recommended)              | Same language as the core for consistency and easier maintenance |
| Management Frontend        | React + TypeScript + Tailwind CSS + **shadcn/ui** | Modern, clean, highly customizable, excellent for building simple-yet-powerful admin interfaces |
| Database                   | **PostgreSQL**                              | Open source, fast, reliable, excellent JSON support, proven at scale. Schema should allow heavy request logs to be moved to ClickHouse later if needed |
| Anti-malware               | ClamAV (official Docker image)              | Mature and widely used open-source engine |
| Deployment                 | Docker Compose on Linux                     | Simple, reproducible foundation that can later evolve into Kubernetes |

Everything must remain open-source.

---

## 5. High-Level Architecture (v1)

Single Linux host running Docker Compose with the following logical services:

- **gateway** (Go)  
  The core process. Handles incoming proxy connections, TLS interception, policy evaluation, CASB inspection, ClamAV scanning, RBI orchestration, and structured logging.

- **management** (Go API + React frontend)  
  Web-based administration interface and REST/JSON API. Can be served by the same binary or a separate service.

- **postgres**  
  Stores users, certificates metadata, policies, reusable objects, request/session logs, and administrative audit logs.

- **clamav**  
  Official ClamAV container used by the gateway for malware scanning.

RBI containers are **ephemeral**. The gateway creates a new Docker container running Chromium only when a policy rule requires isolation. The container is destroyed when the isolated session ends.

Traffic flow (simplified):

```
Client → Gateway (TLS interception + policy) → [optional RBI container] → Internet
```

---

## 6. Detailed Functional Requirements

### 6.1 HTTP/HTTPS Proxy
- Explicit proxy only (clients must be configured to use the proxy).
- Full TLS interception using a CA certificate managed by the system.
- Support for HTTP and HTTPS.
- After decryption the proxy must be able to inspect, modify, block, or redirect requests and responses.
- Must support modern TLS versions and cipher suites.
- High connection and request throughput with low memory per connection.

### 6.2 Policy Engine
Rules are evaluated strictly from top to bottom (firewall style).

When a rule matches:
- If the action is **Block** → stop processing, return the chosen block page.
- If the action is **Allow** (or other non-blocking actions) → continue to the next rule / section, applying any additive actions.
- Special handling for RBI and CASB restrictions (they can produce a targeted block page for that specific restriction only).

Each rule contains these sections:

#### General
- Source conditions (IP single/range/CIDR, Username, User-Agent) – multiple objects allowed
- Destination conditions (domain, domain+path, regex, wildcards) – multiple objects allowed
- Action: Allow / Block (select block page)
- TLS Interception: Enable (choose CA) / Disable
- Authentication mode: Disable / IP-cached / Per-request (local users only)

#### Web Filtering
- Can inherit or override source/destination from General
- Time conditions: absolute date-time range **or** recurring (days of week + time window)
- Protocol: HTTP / HTTPS + HTTP methods
- On Allow: ability to append / edit / remove headers in request and response

#### RBI
- Source / Destination (inherit or override)
- Action: Isolated / Not Isolated
- Additional actions: Block copy-paste **from** the website, Block copy-paste **to** the website

#### CASB
- Source (inherit or override)
- Destination: list of supported applications only (not free-form URLs)
- Time conditions (same capabilities as Web Filtering)
- Actions:
  - Block file upload (all files or specific MIME types / extensions)
  - Block file download (all or specific types)
  - Block specific application actions that we support

#### Anti-Malware
- Source / Destination (inherit or override)
- Action: Enable / Disable scanning

**Reusable Objects**  
Any condition or action the administrator creates must be saved as a named reusable object so it can be selected again in future rules. There must be a management screen to view, edit, and delete these objects.  
System-provided objects (e.g. the list of CASB applications) cannot be deleted by the user.

**Default Policy**  
The system must ship with a sensible default policy that is active after first setup. This policy should provide basic protection (e.g. block known dangerous categories if applicable, enable anti-malware, etc.) so the product is immediately useful.

**Policy Simulation / Test Tool**  
Administrators must be able to test a hypothetical request (source IP or username + full URL) and see:
- Which rules would be evaluated
- Which rule(s) match
- Final decision (Allow/Block)
- Which actions would be applied (RBI, CASB restrictions, malware scan, etc.)

This tool is critical for policy troubleshooting and confidence.

### 6.3 Remote Browser Isolation (RBI)
- Triggered only when a matching policy rule sets the action to “Isolated”.
- The gateway starts a new ephemeral Docker container running a recent Chromium browser.
- The real website is loaded **inside** the container.
- The end user receives only a safe graphical representation of the page (pixel stream or equivalent). The user must **never** receive the real DOM, JavaScript, or original objects.
- Mouse movements, clicks, scrolling, and keyboard input from the user are forwarded and emulated inside the container.
- One container = one browser tab/session.
- When the user closes the tab/session the container is immediately destroyed.
- Startup of the isolated session must be as fast as possible.
- The experience should feel close to normal browsing while remaining fully isolated.

Recommended implementation approach for v1 (simplest reliable path):
- Gateway controls Chromium via Chrome DevTools Protocol (CDP) using `chromedp` or `go-rod/rod`.
- Visual output and input events are delivered to the client over WebSocket.
- Client side is a dedicated page that renders the remote view and captures user input.

### 6.4 CASB (Inline Only)
In Version 1, implement real detection and enforcement for the following applications by inspecting decrypted traffic only (no direct calls to the SaaS APIs):

- ChatGPT
- WhatsApp Web
- Microsoft 365 (Outlook Web App / OneDrive)
- Google Drive / Gmail
- Slack

Supported actions (examples):
- Block file upload (all or by type)
- Block file download (all or by type)
- Block specific high-value actions (send message, create post, share, etc.) where they can be reliably detected from URL, method, headers, and body patterns.

When a CASB restriction is triggered, return a targeted block page that explains the specific restriction (not a generic block).

### 6.5 Anti-Malware
- Optional scanning of request and/or response bodies using ClamAV.
- When malware is detected, return a block page that includes basic incident details (name of threat if available, URL, timestamp, user).

### 6.6 Certificate Management
- One prominent button in the UI: “Generate Self-Signed CA”.
- The generated CA is used for TLS interception.
- Ability to download the CA certificate so administrators can distribute it to clients.
- (Future versions will add support for customer-provided subordinate CAs.)

### 6.7 Authentication (v1)
- Local users only (username + password).
- Stored securely in PostgreSQL (bcrypt or better).
- Support for the authentication modes defined in the General policy section (Disable / IP-cached / Per-request).

### 6.8 Block Pages
- System provides a clean default block page.
- Administrator can upload or paste custom HTML for block pages.
- Different block pages can be selected per rule.
- CASB and RBI restrictions should use targeted messaging when possible.

### 6.9 Rich Logging & Troubleshooting (Critical Requirement)

Every browsing **session** is composed of multiple **requests**.

Each individual request log record must capture (at minimum):

- Timestamp (with timezone)
- Session ID
- Request ID
- Source: IP address, username (if authenticated), User-Agent
- Destination: full URL, scheme, host, path, query
- Protocol and HTTP method
- Request size / response size (approximate)
- Which policy rules were evaluated and which one(s) matched
- Final decision (Allow / Block)
- All actions performed by the system:
  - TLS interception performed (yes/no + which CA)
  - RBI used (yes/no + container ID if useful)
  - CASB checks performed and any action blocked
  - Anti-malware scan result
  - Header modifications
  - Any other relevant action
- Timing information (time to first byte, total duration, etc.)
- Block reason and which block page was served (if blocked)
- Error messages if something failed internally

The logging UI must allow an administrator to:
- Search and filter by time range, user, IP, domain, URL, action, decision, etc.
- View a session and expand it to see every request in chronological order
- Quickly understand the full story of what happened to a user’s browsing activity

**Log Retention**  
Administrators must be able to configure how long detailed request logs are kept (e.g. 7 / 14 / 30 / 90 days). Older logs should be automatically purged or archived according to the setting.

Logs are stored in PostgreSQL. The schema should be designed for high insert rates (consider partitioning by time from the beginning).

### 6.10 Administrative Audit Log
A separate audit trail must record all significant administrative actions, including:
- User login / logout
- Creation, modification, deletion, or reordering of policies
- Changes to users, certificates, DNS, block pages, or system settings
- Configuration export
- Use of the policy simulation tool (optional but useful)

Each audit entry should contain: timestamp, acting administrator, action type, target object, and a short description or before/after summary where relevant.

### 6.11 First-Run Setup Wizard
When the system is started for the first time (or when no admin user exists), the management interface must present a guided setup wizard that covers:

1. Creation of the first administrator account
2. Generation of the self-signed CA certificate
3. Basic network settings (DNS servers, proxy listening port if configurable)
4. Confirmation and link to the Client Configuration Guidance page

The wizard should be simple, linear, and hard to get wrong.

### 6.12 System Health / Status Page
A clear status page showing at least:

- Overall system health (healthy / degraded / critical)
- Gateway process status
- PostgreSQL connectivity and status
- ClamAV status and last signature update time
- Number of currently active RBI containers
- Basic resource indicators (CPU, memory, disk usage of the host or containers)
- Platform version and component versions
- Uptime

This page is the first place an administrator should look when something feels wrong.

### 6.13 Configuration Backup / Export
Administrators must be able to export the current configuration (policies, reusable objects, users, settings, certificates metadata) in a portable format (JSON or similar).  

This export is important for backup and for moving configuration between environments. Import can be added later if needed; export is required in v1.

### 6.14 Client Configuration Guidance Page
A dedicated page (or section) that helps administrators deploy the proxy to end users. It should include:

- Download link for the current CA certificate
- Clear instructions for major browsers (Chrome, Edge, Firefox)
- Example PAC file content
- Notes about distributing the CA certificate (GPO, mobile device management, manual install, etc.)
- Troubleshooting tips for common certificate errors

---

## 7. Management Interface Requirements

The UI must feel **simple and intuitive** while still giving access to all granular options.

Main sections:
1. **Dashboard / Health** – System status + recent important activity
2. **Settings**
   - Certificates (generate self-signed CA, download)
   - Local Users
   - DNS servers
   - Block Pages
   - Log Retention
   - Configuration Export
3. **Policy**
   - Ordered list of rules (with enable/disable and reordering)
   - Create / edit rules with full section editor
   - Policy Simulation / Test tool
   - Default policy handling
4. **Reusable Objects**
   - Library of conditions and actions
5. **Logs / Troubleshooting**
   - Powerful search and session drill-down for traffic logs
   - Administrative Audit Log
6. **Client Setup** – Guidance page for distributing the proxy and CA certificate

**UX Principles**
- Progressive disclosure: advanced options are available but not overwhelming on first view.
- Good defaults everywhere.
- Clear empty states with guidance.
- Searchable selectors for objects (users, groups of conditions, etc.).
- Consistent visual language and feedback for success/error states.
- The first-run wizard must feel polished and trustworthy.

---

## 8. Non-Functional Requirements

- Written primarily in Go for the core and API.
- Clean, modular, well-documented code.
- Configuration and all persistent state in PostgreSQL.
- Structured logging (JSON) in addition to the rich request logs and audit log.
- Health endpoints ready for future monitoring integration.
- Docker Compose file that brings up the entire stack with a single command.
- Clear separation between the data plane (gateway) and control plane (management).
- Code and schema designed so that clustering can be added later without a complete rewrite.
- Sensible resource limits and cleanup for ephemeral RBI containers.

---

## 9. Expected Deliverables

The development AI should produce:

1. Complete project structure and Go module layout
2. Working `docker-compose.yml` that starts all required services
3. Core gateway skeleton with:
   - Explicit proxy listener
   - TLS interception using a managed CA
   - Basic policy evaluation engine
   - Structured request logging into PostgreSQL
4. RBI orchestration skeleton (create/destroy Chromium containers via Docker API + CDP control)
5. Management API (Go) + React frontend skeleton with the main navigation and key screens
6. PostgreSQL schema covering:
   - Users
   - Certificates
   - Policies and reusable objects
   - Sessions and detailed request logs
   - Administrative audit log
   - System settings (including log retention)
7. First-run setup wizard
8. System Health / Status page
9. One-click self-signed CA generation
10. Policy simulation / test tool
11. Configuration export functionality
12. Client configuration guidance page
13. ClamAV integration point
14. Clear README explaining architecture, how to run, first-time setup, and current limitations of v1
15. Meaningful code comments and short architecture notes for major decisions

Prioritize a solid, correct foundation over implementing every advanced UI option perfectly on the first pass. Correct request flow, policy evaluation order, isolation model, logging quality, and basic operability (wizard, health, audit, retention) are more important than visual polish in the first iteration.

---

## 10. Future Considerations (Design for These)

Even though they are out of scope for v1, the architecture should not make the following difficult later:

- Adding a load-balancer / cluster of gateway nodes with session stickiness
- Active Directory integration (Kerberos primary, NTLM fallback)
- Support for customer-provided subordinate CAs
- Transparent proxy mode
- Moving high-volume request logs to ClickHouse while keeping PostgreSQL as the system of record for configuration
- Horizontal scaling of RBI containers across multiple hosts
- Multi-tenancy
- Real-time connection monitoring and advanced alerting

---

**End of Specification**

This document is the single source of truth for Version 1 development. Any ambiguity should be resolved in favor of simplicity, performance, security, operability, and clean architecture.