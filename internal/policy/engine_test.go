package policy

import (
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/google/uuid"
)

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	return u
}

func ruleID(n byte) uuid.UUID {
	return uuid.UUID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, n}
}

func baseInput(t *testing.T) RequestInput {
	t.Helper()
	return RequestInput{
		ClientIP:  net.ParseIP("10.1.2.3"),
		Username:  "alice",
		UserAgent: "TestAgent/1.0",
		Method:    "GET",
		URL:       mustURL(t, "https://www.example.com/path"),
		Now:       time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
	}
}

func TestOrderedBlockStops(t *testing.T) {
	blockPage := ruleID(0xB1)
	rules := []Rule{
		{
			ID:       ruleID(1),
			Name:     "block-first",
			Enabled:  true,
			Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:      ActionBlock,
					BlockPageID: &blockPage,
					BlockReason: "blocked by rule 1",
					Destinations: []Condition{
						{Type: CondDestinationDomain, Value: "example.com"},
					},
				},
			},
		},
		{
			ID:       ruleID(2),
			Name:     "allow-malware",
			Enabled:  true,
			Priority: 20,
			Sections: RuleSections{
				General: GeneralSection{
					Action:       ActionAllow,
					TLSIntercept: true,
				},
				Antimalware: AntimalwareSection{Enabled: true},
			},
		},
	}

	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)

	d := eng.Evaluate(baseInput(t))
	if d.FinalAction != ActionBlock {
		t.Fatalf("FinalAction = %q, want block", d.FinalAction)
	}
	if d.BlockReason != "blocked by rule 1" {
		t.Fatalf("BlockReason = %q", d.BlockReason)
	}
	if d.BlockPageID == nil || *d.BlockPageID != blockPage {
		t.Fatalf("BlockPageID = %v, want %v", d.BlockPageID, blockPage)
	}
	// Block stops: second rule must not be evaluated or matched.
	if len(d.MatchedRuleIDs) != 1 || d.MatchedRuleIDs[0] != ruleID(1) {
		t.Fatalf("MatchedRuleIDs = %v", d.MatchedRuleIDs)
	}
	if len(d.EvaluatedRuleIDs) != 1 || d.EvaluatedRuleIDs[0] != ruleID(1) {
		t.Fatalf("EvaluatedRuleIDs = %v, want only first rule", d.EvaluatedRuleIDs)
	}
	if d.MalwareScan {
		t.Fatal("MalwareScan should not accumulate after block stop")
	}
}

func TestAllowContinuesAndAccumulates(t *testing.T) {
	rules := []Rule{
		{
			ID:       ruleID(1),
			Name:     "allow-mitm-rbi",
			Enabled:  true,
			Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:       ActionAllow,
					TLSIntercept: true,
					AuthMode:     AuthIPCached,
					Destinations: []Condition{
						{Type: CondDestinationDomain, Value: "example.com"},
					},
				},
				RBI: RBISection{
					Mode:              RBIIsolated,
					BlockCopyFromSite: true,
				},
				Antimalware: AntimalwareSection{Enabled: true},
			},
		},
		{
			ID:       ruleID(2),
			Name:     "allow-casb-headers",
			Enabled:  true,
			Priority: 20,
			Sections: RuleSections{
				General: GeneralSection{
					Action:       ActionAllow,
					TLSIntercept: false, // should not clear prior true
					AuthMode:     AuthPerRequest,
				},
				RBI: RBISection{
					Mode:            RBINotIsolated,
					BlockCopyToSite: true,
				},
				CASB: CASBSection{
					Restrictions: []CASBRestriction{
						{App: "chatgpt", Actions: []string{"block_upload"}},
					},
				},
				WebFiltering: WebFilteringSection{
					HeaderMods: []HeaderMod{
						{Op: HeaderSet, Target: HeaderRequest, Name: "X-WSP", Value: "1"},
					},
				},
			},
		},
		{
			ID:       ruleID(3),
			Name:     "no-match-later",
			Enabled:  true,
			Priority: 30,
			Sections: RuleSections{
				General: GeneralSection{
					Action: ActionAllow,
					Destinations: []Condition{
						{Type: CondDestinationDomain, Value: "other.example"},
					},
				},
				Antimalware: AntimalwareSection{Enabled: true},
			},
		},
	}

	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)

	d := eng.Evaluate(baseInput(t))
	if d.FinalAction != ActionAllow {
		t.Fatalf("FinalAction = %q, want allow", d.FinalAction)
	}
	if !d.TLSIntercept {
		t.Fatal("TLSIntercept should stay true after accumulation")
	}
	if d.AuthMode != AuthPerRequest {
		t.Fatalf("AuthMode = %q, want last matching allow's mode", d.AuthMode)
	}
	if !d.RBIIsolated {
		t.Fatal("RBIIsolated should remain true once set")
	}
	if !d.RBIBlockCopyFrom {
		t.Fatal("RBIBlockCopyFrom should accumulate")
	}
	if !d.RBIBlockCopyTo {
		t.Fatal("RBIBlockCopyTo should accumulate from later allow")
	}
	if !d.MalwareScan {
		t.Fatal("MalwareScan should accumulate from first allow")
	}
	if len(d.CASB) != 1 || d.CASB[0].App != "chatgpt" {
		t.Fatalf("CASB = %+v", d.CASB)
	}
	if len(d.HeaderMods) != 1 || d.HeaderMods[0].Name != "X-WSP" {
		t.Fatalf("HeaderMods = %+v", d.HeaderMods)
	}
	// Rules 1 and 2 match; rule 3 evaluated but not matched.
	if len(d.MatchedRuleIDs) != 2 {
		t.Fatalf("MatchedRuleIDs = %v", d.MatchedRuleIDs)
	}
	if len(d.EvaluatedRuleIDs) != 3 {
		t.Fatalf("EvaluatedRuleIDs = %v, want all three", d.EvaluatedRuleIDs)
	}
}

func TestDomainSuffixMatch(t *testing.T) {
	rules := []Rule{
		{
			ID:       ruleID(1),
			Name:     "suffix",
			Enabled:  true,
			Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:      ActionBlock,
					BlockReason: "domain match",
					Destinations: []Condition{
						{Type: CondDestinationDomain, Value: "example.com"},
					},
				},
			},
		},
	}
	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)

	// Suffix: www.example.com matches example.com
	in := baseInput(t)
	in.URL = mustURL(t, "https://www.example.com/")
	d := eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("www.example.com: FinalAction = %q, want block", d.FinalAction)
	}

	// Exact apex
	in.URL = mustURL(t, "https://example.com/")
	d = eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("example.com: FinalAction = %q, want block", d.FinalAction)
	}

	// Non-suffix sibling must not match
	in.URL = mustURL(t, "https://notexample.com/")
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("notexample.com: FinalAction = %q, want allow (no match)", d.FinalAction)
	}

	// Different TLD
	in.URL = mustURL(t, "https://example.org/")
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("example.org: FinalAction = %q, want allow", d.FinalAction)
	}
}

func TestCIDRMatch(t *testing.T) {
	rules := []Rule{
		{
			ID:       ruleID(1),
			Name:     "src-cidr",
			Enabled:  true,
			Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:      ActionBlock,
					BlockReason: "src cidr",
					Sources: []Condition{
						{Type: CondSourceIP, Value: "10.0.0.0/8"},
					},
				},
			},
		},
	}
	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)

	in := baseInput(t)
	in.ClientIP = net.ParseIP("10.9.9.9")
	d := eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("10.9.9.9 in 10/8: FinalAction = %q, want block", d.FinalAction)
	}

	in.ClientIP = net.ParseIP("192.168.1.1")
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("192.168.1.1 outside 10/8: FinalAction = %q, want allow", d.FinalAction)
	}

	// Single host as CIDR /32
	rules[0].Sections.General.Sources = []Condition{
		{Type: CondSourceIP, Value: "203.0.113.50"},
	}
	snap, err = Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile single IP: %v", err)
	}
	eng.Swap(snap)

	in.ClientIP = net.ParseIP("203.0.113.50")
	d = eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("exact IP: FinalAction = %q, want block", d.FinalAction)
	}
	in.ClientIP = net.ParseIP("203.0.113.51")
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("other IP: FinalAction = %q, want allow", d.FinalAction)
	}
}

func TestTimeWindow(t *testing.T) {
	// Monday 12:00 UTC — inside weekday window Mon–Fri 09:00–17:00
	rules := []Rule{
		{
			ID:       ruleID(1),
			Name:     "business-hours-block",
			Enabled:  true,
			Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:      ActionBlock,
					BlockReason: "after hours only allow",
				},
				WebFiltering: WebFilteringSection{
					TimeWindows: []TimeWindow{
						{
							DaysOfWeek: []int{1, 2, 3, 4, 5}, // Mon-Fri
							StartTime:  "09:00",
							EndTime:    "17:00",
							Timezone:   "UTC",
						},
					},
				},
			},
		},
	}
	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)

	// 2026-07-27 is a Monday
	in := baseInput(t)
	in.Now = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	d := eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("Mon 12:00 in window: FinalAction = %q, want block", d.FinalAction)
	}

	// Outside hours same day
	in.Now = time.Date(2026, 7, 27, 20, 0, 0, 0, time.UTC)
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("Mon 20:00 outside window: FinalAction = %q, want allow", d.FinalAction)
	}

	// Weekend inside clock window
	in.Now = time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC) // Saturday
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("Sat 12:00 not in days: FinalAction = %q, want allow", d.FinalAction)
	}

	// Absolute range
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	end := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)
	rules[0].Sections.WebFiltering.TimeWindows = []TimeWindow{
		{Start: &start, End: &end},
	}
	snap, err = Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile absolute: %v", err)
	}
	eng.Swap(snap)

	in.Now = time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
	d = eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("inside absolute range: FinalAction = %q, want block", d.FinalAction)
	}
	in.Now = time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("outside absolute range: FinalAction = %q, want allow", d.FinalAction)
	}
}

// TestOvernightTimeWindow covers startMin > endMin (e.g. 22:00–06:00):
// match when mins >= startMin || mins < endMin.
func TestOvernightTimeWindow(t *testing.T) {
	rules := []Rule{
		{
			ID:       ruleID(1),
			Name:     "overnight-block",
			Enabled:  true,
			Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:      ActionBlock,
					BlockReason: "overnight window",
				},
				WebFiltering: WebFilteringSection{
					TimeWindows: []TimeWindow{
						{
							StartTime: "22:00",
							EndTime:   "06:00",
							Timezone:  "UTC",
						},
					},
				},
			},
		},
	}
	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)

	in := baseInput(t)

	// Inside: late night (mins >= startMin)
	in.Now = time.Date(2026, 7, 27, 23, 30, 0, 0, time.UTC)
	d := eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("23:30 in overnight window: FinalAction = %q, want block", d.FinalAction)
	}

	// Inside: exactly at start
	in.Now = time.Date(2026, 7, 27, 22, 0, 0, 0, time.UTC)
	d = eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("22:00 at overnight start: FinalAction = %q, want block", d.FinalAction)
	}

	// Inside: early morning (mins < endMin)
	in.Now = time.Date(2026, 7, 28, 3, 0, 0, 0, time.UTC)
	d = eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("03:00 in overnight window: FinalAction = %q, want block", d.FinalAction)
	}

	// Outside: end is exclusive
	in.Now = time.Date(2026, 7, 28, 6, 0, 0, 0, time.UTC)
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("06:00 at overnight end (exclusive): FinalAction = %q, want allow", d.FinalAction)
	}

	// Outside: midday
	in.Now = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("12:00 outside overnight window: FinalAction = %q, want allow", d.FinalAction)
	}

	// Outside: just before start
	in.Now = time.Date(2026, 7, 27, 21, 59, 0, 0, time.UTC)
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("21:59 outside overnight window: FinalAction = %q, want allow", d.FinalAction)
	}
}

func TestDisabledRulesSkipped(t *testing.T) {
	rules := []Rule{
		{
			ID:       ruleID(1),
			Name:     "disabled-block",
			Enabled:  false,
			Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:      ActionBlock,
					BlockReason: "should not apply",
				},
			},
		},
		{
			ID:       ruleID(2),
			Name:     "enabled-allow",
			Enabled:  true,
			Priority: 20,
			Sections: RuleSections{
				General: GeneralSection{
					Action:       ActionAllow,
					TLSIntercept: true,
				},
			},
		},
	}
	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)

	d := eng.Evaluate(baseInput(t))
	if d.FinalAction != ActionAllow {
		t.Fatalf("FinalAction = %q, want allow", d.FinalAction)
	}
	if !d.TLSIntercept {
		t.Fatal("expected enabled allow rule to apply")
	}
	for _, id := range d.EvaluatedRuleIDs {
		if id == ruleID(1) {
			t.Fatal("disabled rule must not appear in EvaluatedRuleIDs")
		}
	}
	for _, id := range d.MatchedRuleIDs {
		if id == ruleID(1) {
			t.Fatal("disabled rule must not appear in MatchedRuleIDs")
		}
	}
	if len(d.MatchedRuleIDs) != 1 || d.MatchedRuleIDs[0] != ruleID(2) {
		t.Fatalf("MatchedRuleIDs = %v", d.MatchedRuleIDs)
	}
}

func TestCompileOrdersByPriority(t *testing.T) {
	// Higher priority number defined first in slice; lower priority must evaluate first.
	rules := []Rule{
		{
			ID: ruleID(2), Name: "second", Enabled: true, Priority: 200,
			Sections: RuleSections{General: GeneralSection{Action: ActionAllow, TLSIntercept: true}},
		},
		{
			ID: ruleID(1), Name: "first", Enabled: true, Priority: 100,
			Sections: RuleSections{General: GeneralSection{
				Action: ActionBlock, BlockReason: "first",
			}},
		},
	}
	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)
	d := eng.Evaluate(baseInput(t))
	if d.FinalAction != ActionBlock {
		t.Fatalf("FinalAction = %q, want block from lower priority", d.FinalAction)
	}
	if len(d.EvaluatedRuleIDs) != 1 || d.EvaluatedRuleIDs[0] != ruleID(1) {
		t.Fatalf("EvaluatedRuleIDs = %v", d.EvaluatedRuleIDs)
	}
}

func TestEmptySourcesAndDestinationsMatchAll(t *testing.T) {
	rules := []Rule{
		{
			ID: ruleID(1), Name: "match-all", Enabled: true, Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action: ActionBlock, BlockReason: "all",
					Sources:      nil,
					Destinations: nil,
				},
			},
		},
	}
	snap, err := Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)
	d := eng.Evaluate(baseInput(t))
	if d.FinalAction != ActionBlock {
		t.Fatalf("empty conditions should match all: FinalAction = %q", d.FinalAction)
	}
}

func TestNilSnapshotAllows(t *testing.T) {
	var eng Engine
	d := eng.Evaluate(baseInput(t))
	if d.FinalAction != ActionAllow {
		t.Fatalf("nil snapshot FinalAction = %q, want allow", d.FinalAction)
	}
	if d.AuthMode != AuthDisable && d.AuthMode != "" {
		// empty or disable both acceptable as safe default; engine normalizes to disable
		t.Fatalf("AuthMode = %q", d.AuthMode)
	}
}

func TestObjectRefSourceIP(t *testing.T) {
	objID := ruleID(0xA1)
	objects := map[uuid.UUID]Object{
		objID: {
			ID:   objID,
			Name: "corp-net",
			Type: ObjectSourceIP,
			Definition: ObjectDefinition{
				CIDRs: []string{"10.0.0.0/8"},
			},
		},
	}
	rules := []Rule{
		{
			ID: ruleID(1), Name: "via-object", Enabled: true, Priority: 10,
			Sections: RuleSections{
				General: GeneralSection{
					Action:      ActionBlock,
					BlockReason: "object",
					Sources: []Condition{
						{Type: CondObjectRef, ObjectID: &objID},
					},
				},
			},
		},
	}
	snap, err := Compile(rules, objects)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng Engine
	eng.Swap(snap)

	in := baseInput(t)
	in.ClientIP = net.ParseIP("10.0.0.5")
	d := eng.Evaluate(in)
	if d.FinalAction != ActionBlock {
		t.Fatalf("object CIDR match: FinalAction = %q", d.FinalAction)
	}
	in.ClientIP = net.ParseIP("11.0.0.5")
	d = eng.Evaluate(in)
	if d.FinalAction != ActionAllow {
		t.Fatalf("outside object CIDR: FinalAction = %q", d.FinalAction)
	}
}
