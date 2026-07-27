# Task 12 Report: Retention job + health metrics

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `b8f45df` — `feat: log retention job and richer health checks`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

1. **Hourly retention job** — `internal/logging/retention.go` reads `log_retention_days` / `audit_retention_days` from settings and deletes expired rows in batches of **5000**. Wired in `cmd/wsp/main.go` via `go retention.Start(ctx)` (immediate first cycle + hourly ticker).
2. **Store purge APIs** — `DeleteRequestLogsBefore` (partition-safe on `(id, ts)`) and `DeleteAuditLogsBefore`.
3. **Richer health** — existing DB / clamd / docker / RBI / version / uptime kept; process component expanded with heap stats, GOMAXPROCS, best-effort Linux `/proc` load average + RSS; unit tests for healthy / critical / degraded paths.

---

## Deliverables

| Path | Purpose |
|------|---------|
| `internal/logging/retention.go` | RetentionJob: RunOnce + Start (hourly) |
| `internal/logging/retention_test.go` | Parse days, defaults, nil-store |
| `internal/store/request_logs.go` | `DeleteRequestLogsBefore` batch delete |
| `internal/store/audit.go` | `DeleteAuditLogsBefore` batch delete |
| `internal/health/health.go` | Process/host best-effort metrics |
| `internal/health/health_test.go` | Checker unit tests |
| `cmd/wsp/main.go` | Start retention goroutine |

---

## Behavior

- Defaults: log **30** days, audit **365** days (migration seed); batch **5000**; max **100** batches per table per cycle; interval **1h**.
- Also ensures current + next month `request_logs` partitions on each cycle.
- Health overall: `critical` if DB fails; `degraded` for clam/docker/gateway issues; process always informational `healthy`.

---

## Tests

```text
go test ./... -count=1   # PASS (all packages)
```

---

## Notes

- No migration change required; retention settings already seeded in `001_init.up.sql`.
- Partition DROP for fully-expired months left as future optimization; v1 uses batch DELETE as specified.
