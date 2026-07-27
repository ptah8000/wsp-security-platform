### Task 1: Repository skeleton, module, Compose, migrations

**Files:**
- Create: `go.mod`, `cmd/wsp/main.go`, `internal/config/config.go`, `migrations/001_init.up.sql`, `migrations/001_init.down.sql`, `deploy/Dockerfile`, `deploy/docker-compose.yml`, `deploy/env.example`, `.gitignore`, `README.md` (stub), `web/package.json` (minimal placeholder page)
- Test: `internal/config/config_test.go`

**Interfaces:**
- Produces: `config.Config` loaded from env; empty `main` that prints version and exits 0 if `--version`; Compose that builds/runs placeholders later

- [ ] **Step 1: Create `.gitignore` and `go.mod`**

```gitignore
bin/
dist/
web/dist/
web/node_modules/
.env
*.pem
*.key
.idea/
.vscode/
```

```bash
cd /path/to/WSP   # D:\Grok\WSP or Linux checkout
go mod init github.com/wsp-security/wsp
```

- [ ] **Step 2: Write `internal/config/config.go` and test**

```go
package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Mode            string // all | gateway | management
	ProxyAddr       string
	AdminAddr       string
	DatabaseURL     string
	DataKey         string // 32-byte key, base64 or raw hex preferred
	ClamdAddr       string
	DockerHost      string
	RBIImage        string
	MaxRBISessions  int
	LogLevel        string
	ShutdownTimeout time.Duration
}

func Load() (Config, error) {
	c := Config{
		Mode:            getenv("WSP_MODE", "all"),
		ProxyAddr:       getenv("WSP_PROXY_ADDR", ":8080"),
		AdminAddr:       getenv("WSP_ADMIN_ADDR", ":3000"),
		DatabaseURL:     getenv("WSP_DATABASE_URL", "postgres://wsp:wsp@localhost:5432/wsp?sslmode=disable"),
		DataKey:         os.Getenv("WSP_DATA_KEY"),
		ClamdAddr:       getenv("WSP_CLAMD_ADDR", "clamav:3310"),
		DockerHost:      getenv("DOCKER_HOST", "unix:///var/run/docker.sock"),
		RBIImage:        getenv("WSP_RBI_IMAGE", "browserless/chrome:latest"),
		MaxRBISessions:  getenvInt("WSP_MAX_RBI_SESSIONS", 10),
		LogLevel:        getenv("WSP_LOG_LEVEL", "info"),
		ShutdownTimeout: time.Duration(getenvInt("WSP_SHUTDOWN_TIMEOUT_SEC", 15)) * time.Second,
	}
	if c.Mode != "all" && c.Mode != "gateway" && c.Mode != "management" {
		return c, fmt.Errorf("invalid WSP_MODE %q", c.Mode)
	}
	return c, nil
}
// helpers getenv, getenvInt omitted in plan — implement standard versions
```

Test: invalid mode returns error; defaults apply when env empty.

- [ ] **Step 3: Write `migrations/001_init.up.sql`** covering tables from design §4:
  - users, admin_sessions, proxy_auth_cache
  - certificates, settings, block_pages, reusable_objects, policies
  - sessions, request_logs (with `PARTITION BY RANGE (ts)` if using PG native partitions — include parent + first partitions for current/next month, or use single table + `ts` index if partition automation deferred; **prefer parent partitioned table + function to ensure monthly partitions**)
  - audit_logs
  - seed: system block page, CASB app objects, default policies, `setup_completed=false`

- [ ] **Step 4: `deploy/docker-compose.yml`**

```yaml
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: wsp
      POSTGRES_PASSWORD: wsp
      POSTGRES_DB: wsp
    volumes: [pgdata:/var/lib/postgresql/data]
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U wsp"]
      interval: 5s
      timeout: 5s
      retries: 10
  clamav:
    image: clamav/clamav:stable
    # expose 3310 internally
  wsp:
    build:
      context: ..
      dockerfile: deploy/Dockerfile
    env_file: .env
    ports:
      - "8080:8080"
      - "3000:3000"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - wsp_data:/var/lib/wsp
    depends_on:
      postgres:
        condition: service_healthy
    # clamav may take long to start — wsp must retry clamd
volumes:
  pgdata:
  wsp_data:
```

- [ ] **Step 5: Multi-stage `deploy/Dockerfile`**

1. `node:20` build `web/` → `web/dist`
2. `golang:1.22` build `cmd/wsp` with CGO disabled, embed UI
3. Distroless or `gcr.io/distroless/static` / alpine with ca-certs — note: RBI uses Docker API so `wsp` does not need Chromium in its image

- [ ] **Step 6: Minimal `cmd/wsp/main.go`** loads config, slog, `--version` flag `0.1.0`, listen nothing yet but exit cleanly after migrate hook stub.

- [ ] **Step 7: Commit**

```bash
git add -A
git commit -m "chore: scaffold wsp module, compose, and initial migration"
```

---
