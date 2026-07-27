package policy

import (
	"sync/atomic"

	"github.com/google/uuid"
)

// Engine holds an atomically swappable compiled policy snapshot.
// Evaluate is pure with respect to external I/O: it only reads the snapshot
// and the RequestInput.
type Engine struct {
	snap atomic.Pointer[Snapshot]
}

// Swap publishes a new compiled snapshot for subsequent Evaluate calls.
// Passing nil clears the snapshot (Evaluate returns the safe default allow).
func (e *Engine) Swap(s *Snapshot) {
	e.snap.Store(s)
}

// Load returns the current snapshot (may be nil).
func (e *Engine) Load() *Snapshot {
	return e.snap.Load()
}

// Evaluate applies ordered policy to in and returns an accumulated Decision.
// No I/O is performed. Nil or empty snapshots yield default allow.
func (e *Engine) Evaluate(in RequestInput) Decision {
	s := e.snap.Load()
	if s == nil {
		return defaultDecision()
	}
	return evaluateRules(s.rules, in)
}

// evaluateRules is the pure core used by Engine.Evaluate and Simulate.
func evaluateRules(rules []compiledRule, in RequestInput) Decision {
	d := defaultDecision()
	if len(rules) == 0 {
		return d
	}

	// Pre-size lightly; append grows as needed.
	d.EvaluatedRuleIDs = make([]uuid.UUID, 0, len(rules))
	d.MatchedRuleIDs = make([]uuid.UUID, 0, 4)

	for i := range rules {
		r := &rules[i]
		d.EvaluatedRuleIDs = append(d.EvaluatedRuleIDs, r.id)

		if !r.matches(in) {
			continue
		}

		d.MatchedRuleIDs = append(d.MatchedRuleIDs, r.id)
		// Record URL categories for this host (for logs / simulation UX).
		if in.URL != nil {
			for _, cat := range CategoriesForHost(hostname(in.URL)) {
				d.URLCategories = appendUnique(d.URLCategories, cat)
			}
		}
		accumulateAllowActions(&d, r)

		if r.action == ActionBlock {
			d.FinalAction = ActionBlock
			d.BlockReason = r.blockReason
			if d.BlockReason == "" {
				d.BlockReason = "Blocked by web filter policy"
			}
			d.BlockPageID = cloneUUID(r.blockPageID)
			// Stop on first matching Block (firewall-style).
			return d
		}
		// Allow: keep FinalAction allow and continue (malware/CASB may still accumulate).
		d.FinalAction = ActionAllow
	}
	return d
}

// accumulateAllowActions merges additive actions from a matched rule.
// TLSIntercept / malware use OR; AuthMode last non-disable wins; CASB/header mods append.
//
// RBI uses first-explicit-wins: a rule with rbi.mode=isolated or not_isolated locks
// the isolation decision so trusted allow rules (not_isolated) are not overridden by
// a later “isolate uncategorized” rule — RBI sits behind URL filtering.
func accumulateAllowActions(d *Decision, r *compiledRule) {
	if r.tlsIntercept {
		d.TLSIntercept = true
	}
	if r.authMode != "" && r.authMode != AuthDisable {
		d.AuthMode = r.authMode
	} else if r.authMode == AuthDisable && d.AuthMode == "" {
		d.AuthMode = AuthDisable
	}

	if r.rbiExplicit && !d.rbiDecided {
		d.RBIIsolated = r.rbiIsolated
		d.rbiDecided = true
		if d.RBIIsolated {
			// Isolation requires decrypt.
			d.TLSIntercept = true
		}
	}
	// Clipboard controls still accumulate if isolation is (or becomes) active.
	if r.rbiBlockCopyFrom {
		d.RBIBlockCopyFrom = true
	}
	if r.rbiBlockCopyTo {
		d.RBIBlockCopyTo = true
	}

	if r.malwareScan {
		d.MalwareScan = true
		if r.malwareFailClosed {
			d.MalwareFailClosed = true
		}
		if r.malwareMaxBytes > 0 {
			if d.MalwareMaxBytes == 0 || r.malwareMaxBytes < d.MalwareMaxBytes {
				d.MalwareMaxBytes = r.malwareMaxBytes
			}
		}
	}
	if len(r.casb) > 0 {
		d.CASB = append(d.CASB, r.casb...)
	}
	if len(r.headerMods) > 0 {
		d.HeaderMods = append(d.HeaderMods, r.headerMods...)
	}
}

func appendUnique(slice []string, v string) []string {
	for _, s := range slice {
		if s == v {
			return slice
		}
	}
	return append(slice, v)
}
