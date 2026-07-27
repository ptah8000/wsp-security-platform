### Task 12: Retention job, default policy seed polish, health metrics

**Files:**
- Modify: `internal/logging/retention.go`, `migrations` seed if needed, `internal/health/health.go`
- Wire ticker in `main` (hourly)

- [ ] **Step 1: Delete request_logs older than retention_days in batches of 5000**

- [ ] **Step 2: Health collects** DB, clamd ping, docker ping, active RBI, goroutine/mem optional, version, uptime

- [ ] **Step 3: Commit** `feat: log retention job and richer health checks`

---
