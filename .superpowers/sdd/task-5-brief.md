### Task 5: Policy types, compiler, pure engine, simulator

**Files:**
- Create: `internal/policy/types.go`, `compile.go`, `match.go`, `engine.go`, `simulate.go`
- Test: `internal/policy/engine_test.go`, `simulate_test.go`

**Interfaces:**
```go
type Action string // allow, block
type Decision struct {
    FinalAction Action
    BlockPageID *uuid.UUID
    BlockReason string
    TLSIntercept bool
    AuthMode string // disable | ip_cached | per_request
    RBI Isolated bool
    RBIBlockCopyFrom bool
    RBIBlockCopyTo bool
    CASB []CASBRestriction
    MalwareScan bool
    HeaderMods []HeaderMod
    MatchedRuleIDs []uuid.UUID
    EvaluatedRuleIDs []uuid.UUID
}

type RequestInput struct {
    ClientIP net.IP
    Username string
    UserAgent string
    Method string
    URL *url.URL
    Now time.Time
}

type Engine struct { snap atomic.Pointer[Snapshot] }
func (e *Engine) Swap(s *Snapshot)
func (e *Engine) Evaluate(in RequestInput) Decision
func Compile(rules []Rule, objects map[uuid.UUID]Object) (*Snapshot, error)
func Simulate(rules []Rule, objects map[uuid.UUID]Object, in RequestInput) Decision // same as evaluate with full trace
```

- [ ] **Step 1: Write failing tests** for ordered Block stop; Allow continues; domain suffix match; CIDR match; time window; disabled rules skipped

- [ ] **Step 2: Implement compiler + engine** until tests pass

- [ ] **Step 3: Commit** `feat: pure ordered policy engine and simulator`

---
