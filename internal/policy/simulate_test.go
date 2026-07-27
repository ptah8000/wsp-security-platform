package policy

import (
	"net"
	"testing"
	"time"
)

func TestSimulateMatchesEvaluateTrace(t *testing.T) {
	blockPage := ruleID(0xB2)
	rules := []Rule{
		{
			ID:       ruleID(1),
			Name:     "allow-scan",
			Enabled:  true,
			Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:       ActionAllow,
					TLSIntercept: true,
					Destinations: []Condition{
						{Type: CondDestinationDomain, Value: "example.com"},
					},
				},
				Antimalware: AntimalwareSection{Enabled: true},
			},
		},
		{
			ID:       ruleID(2),
			Name:     "block-host",
			Enabled:  true,
			Priority: 20,
			Sections: RuleSections{
				General: GeneralSection{
					Action:      ActionBlock,
					BlockPageID: &blockPage,
					BlockReason: "blocked",
					Destinations: []Condition{
						{Type: CondDestinationDomain, Value: "example.com"},
					},
				},
			},
		},
		{
			ID:       ruleID(3),
			Name:     "never-reached",
			Enabled:  true,
			Priority: 30,
			Sections: RuleSections{
				General: GeneralSection{Action: ActionAllow},
			},
		},
	}

	in := baseInput(t)
	sim := Simulate(rules, nil, in)

	if sim.FinalAction != ActionBlock {
		t.Fatalf("Simulate FinalAction = %q, want block", sim.FinalAction)
	}
	if sim.BlockReason != "blocked" {
		t.Fatalf("BlockReason = %q", sim.BlockReason)
	}
	// Full trace: allow matched, then block matched and stopped.
	if len(sim.MatchedRuleIDs) != 2 {
		t.Fatalf("MatchedRuleIDs = %v, want allow+block", sim.MatchedRuleIDs)
	}
	if sim.MatchedRuleIDs[0] != ruleID(1) || sim.MatchedRuleIDs[1] != ruleID(2) {
		t.Fatalf("MatchedRuleIDs order = %v", sim.MatchedRuleIDs)
	}
	if len(sim.EvaluatedRuleIDs) != 2 {
		t.Fatalf("EvaluatedRuleIDs = %v, rule 3 must not run after block", sim.EvaluatedRuleIDs)
	}
	if !sim.TLSIntercept || !sim.MalwareScan {
		t.Fatal("accumulated allow actions should remain visible on final block decision")
	}

	// Engine with compiled snapshot must agree on final decision fields.
	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)
	ev := eng.Evaluate(in)

	if ev.FinalAction != sim.FinalAction ||
		ev.BlockReason != sim.BlockReason ||
		ev.TLSIntercept != sim.TLSIntercept ||
		ev.MalwareScan != sim.MalwareScan {
		t.Fatalf("Evaluate vs Simulate mismatch:\n  eval=%+v\n  sim=%+v", ev, sim)
	}
	if len(ev.MatchedRuleIDs) != len(sim.MatchedRuleIDs) {
		t.Fatalf("MatchedRuleIDs eval=%v sim=%v", ev.MatchedRuleIDs, sim.MatchedRuleIDs)
	}
	if len(ev.EvaluatedRuleIDs) != len(sim.EvaluatedRuleIDs) {
		t.Fatalf("EvaluatedRuleIDs eval=%v sim=%v", ev.EvaluatedRuleIDs, sim.EvaluatedRuleIDs)
	}
}

func TestSimulateDisabledSkipped(t *testing.T) {
	rules := []Rule{
		{
			ID: ruleID(1), Name: "off", Enabled: false, Priority: 1,
			Sections: RuleSections{General: GeneralSection{Action: ActionBlock, BlockReason: "off"}},
		},
		{
			ID: ruleID(2), Name: "on", Enabled: true, Priority: 2,
			Sections: RuleSections{General: GeneralSection{Action: ActionAllow, AuthMode: AuthIPCached}},
		},
	}
	d := Simulate(rules, nil, baseInput(t))
	if d.FinalAction != ActionAllow {
		t.Fatalf("FinalAction = %q", d.FinalAction)
	}
	if d.AuthMode != AuthIPCached {
		t.Fatalf("AuthMode = %q", d.AuthMode)
	}
	if len(d.EvaluatedRuleIDs) != 1 || d.EvaluatedRuleIDs[0] != ruleID(2) {
		t.Fatalf("EvaluatedRuleIDs = %v", d.EvaluatedRuleIDs)
	}
}

func TestSimulateCIDRAndDomainAndTime(t *testing.T) {
	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 7, 31, 23, 59, 59, 0, time.UTC)
	rules := []Rule{
		{
			ID: ruleID(1), Name: "combo", Enabled: true, Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:      ActionBlock,
					BlockReason: "combo",
					Sources: []Condition{
						{Type: CondSourceIP, Value: "192.168.0.0/16"},
					},
					Destinations: []Condition{
						{Type: CondDestinationDomain, Value: "blocked.example"},
					},
				},
				WebFiltering: WebFilteringSection{
					TimeWindows: []TimeWindow{{Start: &start, End: &end}},
					Methods:     []string{"POST", "PUT"},
				},
			},
		},
	}

	// All conditions match
	in := RequestInput{
		ClientIP: net.ParseIP("192.168.10.5"),
		Method:   "POST",
		URL:      mustURL(t, "https://api.blocked.example/upload"),
		Now:      time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC),
	}
	d := Simulate(rules, nil, in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("all match: FinalAction = %q, want block", d.FinalAction)
	}

	// Wrong method
	in.Method = "GET"
	d = Simulate(rules, nil, in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("method miss: FinalAction = %q, want allow", d.FinalAction)
	}

	// Wrong domain
	in.Method = "POST"
	in.URL = mustURL(t, "https://other.example/")
	d = Simulate(rules, nil, in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("domain miss: FinalAction = %q, want allow", d.FinalAction)
	}
}
