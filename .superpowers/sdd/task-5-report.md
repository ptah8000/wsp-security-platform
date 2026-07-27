# Task 5 Report: Policy types, compiler, pure engine, simulator

**Status:** DONE  
**Branch:** `feature/wsp-v1`  
**Commit:** `53523b4` — `feat: pure ordered policy engine and simulator`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

---

## Summary

Implemented pure ordered policy evaluation under `internal/policy`: typed rules/sections aligned with `policies.sections` JSONB seed shape, `Compile` → immutable `Snapshot`, atomic `Engine.Swap` / `Evaluate`, and `Simulate` (compile + full trace). Evaluation performs **no I/O and no DB access**.

Semantics (design §6.1):
- Rules ordered by ascending `priority` (lower first).
- **Block** on match → stop.
- **Allow** on match → accumulate additive actions; continue.
- Disabled rules omitted at compile time (never evaluated).
- Empty sources/destinations = match-all.
- Domain conditions use **suffix** match (`example.com` matches `www.example.com`, not `notexample.com`).
- Source IP accepts CIDR or bare IP.
- Time windows: absolute range and/or recurring days + `HH:MM` clock (timezone-aware).

---

## Deliverables

| Path | Purpose |
|------|---------|
| `internal/policy/types.go` | `Action`, `Decision`, `RequestInput`, `Rule`, sections, objects, CASB/HeaderMod |
| `internal/policy/match.go` | Domain suffix, CIDR, time window, method/protocol matchers |
| `internal/policy/compile.go` | `Compile` → `Snapshot` / `compiledRule` (immutable hot path) |
| `internal/policy/engine.go` | `Engine` with `atomic.Pointer[Snapshot]`, `Swap`, `Evaluate` |
| `internal/policy/simulate.go` | `Simulate(rules, objects, in)` full-trace evaluation |
| `internal/policy/engine_test.go` | Ordered block, allow accumulate, domain, CIDR, time, disabled, objects |
| `internal/policy/simulate_test.go` | Simulate vs Evaluate parity, combo conditions |

---

## Public API

```go
type Action string // allow | block

type Decision struct {
    FinalAction      Action
    BlockPageID      *uuid.UUID
    BlockReason      string
    TLSIntercept     bool
    AuthMode         string // disable | ip_cached | per_request
    RBIIsolated      bool
    RBIBlockCopyFrom bool
    RBIBlockCopyTo   bool
    CASB             []CASBRestriction
    MalwareScan      bool
    HeaderMods       []HeaderMod
    MatchedRuleIDs   []uuid.UUID
    EvaluatedRuleIDs []uuid.UUID
}

type RequestInput struct {
    ClientIP  net.IP
    Username  string
    UserAgent string
    Method    string
    URL       *url.URL
    Now       time.Time
}

type Engine struct { /* atomic.Pointer[Snapshot] */ }

func (e *Engine) Swap(s *Snapshot)
func (e *Engine) Evaluate(in RequestInput) Decision
func Compile(rules []Rule, objects map[uuid.UUID]Object) (*Snapshot, error)
func Simulate(rules []Rule, objects map[uuid.UUID]Object, in RequestInput) Decision
```

Note: design sketch field `RBI Isolated` is implemented as `RBIIsolated` (valid Go identifier).

---

## Evaluation / accumulation rules

| Event | Behavior |
|-------|----------|
| Rule disabled | Skipped by `Compile`; absent from `EvaluatedRuleIDs` |
| No match | Counted in `EvaluatedRuleIDs` only; continue |
| Match + Allow | Append to `MatchedRuleIDs`; OR booleans (TLS/RBI/malware); last non-`disable` AuthMode; append CASB + HeaderMods; continue |
| Match + Block | Same accumulation of prior allows + set block fields; **stop** (later rules not evaluated) |
| Nil/empty snapshot | `FinalAction=allow`, `AuthMode=disable` |

---

## TDD evidence

### RED

Tests written first (`engine_test.go`, `simulate_test.go`) before production code. Initial `go test ./internal/policy/` failed to build with undefined types/symbols:

```
# github.com/wsp-security/wsp/internal/policy
internal\policy\engine_test.go:25:30: undefined: RequestInput
internal\policy\engine_test.go:39:13: undefined: Rule
internal\policy\engine_test.go:47:19: undefined: ActionBlock
internal\policy\engine_test.go:51:14: undefined: CondDestinationDomain
...
FAIL
```

Required cases encoded as failing tests:
- `TestOrderedBlockStops`
- `TestAllowContinuesAndAccumulates`
- `TestDomainSuffixMatch`
- `TestCIDRMatch`
- `TestTimeWindow`
- `TestDisabledRulesSkipped`
- (+ simulate parity / combo / object ref)

### GREEN

After implementing `types.go`, `match.go`, `compile.go`, `engine.go`, `simulate.go`:

```
=== RUN   TestOrderedBlockStops
--- PASS: TestOrderedBlockStops
=== RUN   TestAllowContinuesAndAccumulates
--- PASS: TestAllowContinuesAndAccumulates
=== RUN   TestDomainSuffixMatch
--- PASS: TestDomainSuffixMatch
=== RUN   TestCIDRMatch
--- PASS: TestCIDRMatch
=== RUN   TestTimeWindow
--- PASS: TestTimeWindow
=== RUN   TestDisabledRulesSkipped
--- PASS: TestDisabledRulesSkipped
=== RUN   TestCompileOrdersByPriority
--- PASS: TestCompileOrdersByPriority
=== RUN   TestEmptySourcesAndDestinationsMatchAll
--- PASS: TestEmptySourcesAndDestinationsMatchAll
=== RUN   TestNilSnapshotAllows
--- PASS: TestNilSnapshotAllows
=== RUN   TestObjectRefSourceIP
--- PASS: TestObjectRefSourceIP
=== RUN   TestSimulateMatchesEvaluateTrace
--- PASS: TestSimulateMatchesEvaluateTrace
=== RUN   TestSimulateDisabledSkipped
--- PASS: TestSimulateDisabledSkipped
=== RUN   TestSimulateCIDRAndDomainAndTime
--- PASS: TestSimulateCIDRAndDomainAndTime
PASS
ok  github.com/wsp-security/wsp/internal/policy
```

Also: `gofmt` clean, `go vet ./internal/policy/` clean.

---

## Purity guarantee

- `Evaluate` / `evaluateRules` / matchers only read `RequestInput` + compiled snapshot memory.
- `Compile` / `Simulate` accept in-memory `[]Rule` and `map[uuid.UUID]Object` only.
- No `store`, `context`, network, filesystem, or time.Now() inside the engine (caller supplies `RequestInput.Now`).

---

## Out of scope (Task 6+)

- Proxy pipeline integration
- DB load / recompile on policy write
- Simulation HTTP API / UI
- Default policy seed changes

---

## Verification

| Check | Result |
|-------|--------|
| `go test ./internal/policy/` | PASS |
| `go vet ./internal/policy/` | PASS |
| Commit | `53523b4` |

---

## Follow-up: overnight time window matching

**Status:** DONE  
**Commit:** `db47375` — `fix: policy overnight time window matching`  
**Author:** WSP Dev \<dev@wsp.local\>  
**Date:** 2026-07-27

### Bug

`compiledTimeWindow.contains` applied same-day clock bounds (`mins < startMin` / `mins >= endMin`) **before** the overnight branch. For windows with `startMin > endMin` (e.g. `22:00`–`06:00`), valid times failed incorrectly:

- `23:30` → rejected by `mins >= endMin` (1380 ≥ 360)
- `03:00` → rejected by `mins < startMin` (180 < 1320)

### Fix

In `internal/policy/match.go`, when both clock bounds are set and `startMin > endMin`, match with:

```text
mins >= startMin || mins < endMin
```

(end exclusive, same as same-day windows). Same-day windows keep the previous inclusive-start / exclusive-end logic.

### Regression test

`TestOvernightTimeWindow` in `internal/policy/engine_test.go` covers:

| Local time (UTC) | Expected |
|------------------|----------|
| 22:00 (start) | in window (block) |
| 23:30 | in window (block) |
| 03:00 | in window (block) |
| 06:00 (end exclusive) | out (allow) |
| 12:00 | out (allow) |
| 21:59 | out (allow) |

### Verification

| Check | Result |
|-------|--------|
| `go test ./internal/policy/...` | PASS |
| Commit | `db47375` |
