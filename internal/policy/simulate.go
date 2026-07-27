package policy

import "github.com/google/uuid"

// Simulate compiles rules (skipping disabled) and evaluates in with full trace
// fields (MatchedRuleIDs / EvaluatedRuleIDs). Same semantics as
// Compile + Engine.Evaluate; intended for the admin simulation tool.
// Pure: no I/O. Compile errors yield a default allow decision with empty trace
// (callers that need compile errors should call Compile directly).
func Simulate(rules []Rule, objects map[uuid.UUID]Object, in RequestInput) Decision {
	snap, err := Compile(rules, objects)
	if err != nil {
		// Simulation of invalid policy: fail soft to allow for UI debugging
		// of matchers; production loads should use Compile and surface errors.
		d := defaultDecision()
		d.BlockReason = "compile error: " + err.Error()
		return d
	}
	return evaluateRules(snap.rules, in)
}
