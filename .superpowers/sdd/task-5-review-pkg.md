BASE 330642df79edb206978f9599a19b2001255790c3 HEAD 0c091d7887b4c2a324674a76a7e525844fc68685

 .superpowers/sdd/progress.md      |   4 +  .superpowers/sdd/task-5-report.md | 182 ++++++++++++  internal/policy/compile.go        | 379 +++++++++++++++++++++++++  internal/policy/engine.go         | 102 +++++++  internal/policy/engine_test.go    | 571 ++++++++++++++++++++++++++++++++++++++  internal/policy/match.go          | 359 ++++++++++++++++++++++++  internal/policy/simulate.go       |  20 ++  internal/policy/simulate_test.go  | 175 ++++++++++++  internal/policy/types.go          | 237 ++++++++++++++++  9 files changed, 2029 insertions(+)
diff --git a/internal/policy/compile.go b/internal/policy/compile.go
new file mode 100644
index 0000000..558772a
--- /dev/null
+++ b/internal/policy/compile.go
@@ -0,0 +1,379 @@
+package policy
+
+import (
+	"fmt"
+	"net"
+	"regexp"
+	"sort"
+	"strings"
+
+	"github.com/google/uuid"
+)
+
+// Snapshot is an immutable compiled policy set for hot-path evaluation.
+// Safe for concurrent readers after publication via Engine.Swap.
+type Snapshot struct {
+	rules []compiledRule
+}
+
+// compiledRule is a single enabled rule ready for pure matching.
+type compiledRule struct {
+	id       uuid.UUID
+	priority int
+	name     string
+
+	sources      []compiledCond
+	destinations []compiledCond
+	// web_filtering additional constraints (AND)
+	webSources      []compiledCond
+	webDestinations []compiledCond
+	timeWindows     []compiledTimeWindow
+	methods         []string
+	protocols       []string
+
+	action       Action
+	blockPageID  *uuid.UUID
+	blockReason  string
+	tlsIntercept bool
+	authMode     string
+
+	rbiIsolated      bool
+	rbiBlockCopyFrom bool
+	rbiBlockCopyTo   bool
+
+	casb        []CASBRestriction
+	malwareScan bool
+	headerMods  []HeaderMod
+}
+
+// Compile builds an immutable Snapshot from rules and reusable objects.
+// Rules are ordered by ascending priority (lower first). Disabled rules are omitted.
+// Compile itself performs no I/O; objects must already be loaded by the caller.
+func Compile(rules []Rule, objects map[uuid.UUID]Object) (*Snapshot, error) {
+	if objects == nil {
+		objects = map[uuid.UUID]Object{}
+	}
+
+	// Stable order: priority ASC, then name, then id for determinism.
+	sorted := make([]Rule, len(rules))
+	copy(sorted, rules)
+	sort.SliceStable(sorted, func(i, j int) bool {
+		if sorted[i].Priority != sorted[j].Priority {
+			return sorted[i].Priority < sorted[j].Priority
+		}
+		if sorted[i].Name != sorted[j].Name {
+			return sorted[i].Name < sorted[j].Name
+		}
+		return sorted[i].ID.String() < sorted[j].ID.String()
+	})
+
+	out := make([]compiledRule, 0, len(sorted))
+	for _, r := range sorted {
+		if !r.Enabled {
+			continue
+		}
+		cr, err := compileRule(r, objects)
+		if err != nil {
+			return nil, fmt.Errorf("rule %s (%s): %w", r.ID, r.Name, err)
+		}
+		out = append(out, cr)
+	}
+	return &Snapshot{rules: out}, nil
+}
+
+func compileRule(r Rule, objects map[uuid.UUID]Object) (compiledRule, error) {
+	g := r.Sections.General
+	w := r.Sections.WebFiltering
+	cr := compiledRule{
+		id:               r.ID,
+		priority:         r.Priority,
+		name:             r.Name,
+		action:           normalizeAction(g.Action),
+		blockPageID:      cloneUUID(g.BlockPageID),
+		blockReason:      g.BlockReason,
+		tlsIntercept:     g.TLSIntercept,
+		authMode:         normalizeAuthMode(g.AuthMode),
+		rbiIsolated:      r.Sections.RBI.Mode == RBIIsolated,
+		rbiBlockCopyFrom: r.Sections.RBI.BlockCopyFromSite,
+		rbiBlockCopyTo:   r.Sections.RBI.BlockCopyToSite,
+		malwareScan:      r.Sections.Antimalware.Enabled,
+		methods:          append([]string(nil), w.Methods...),
+		protocols:        append([]string(nil), w.Protocols...),
+	}
+
+	var err error
+	if cr.sources, err = compileConditions(g.Sources, objects); err != nil {
+		return cr, fmt.Errorf("sources: %w", err)
+	}
+	if cr.destinations, err = compileConditions(g.Destinations, objects); err != nil {
+		return cr, fmt.Errorf("destinations: %w", err)
+	}
+	if cr.webSources, err = compileConditions(w.Sources, objects); err != nil {
+		return cr, fmt.Errorf("web sources: %w", err)
+	}
+	if cr.webDestinations, err = compileConditions(w.Destinations, objects); err != nil {
+		return cr, fmt.Errorf("web destinations: %w", err)
+	}
+
+	for _, tw := range w.TimeWindows {
+		cw, err := compileTimeWindow(tw)
+		if err != nil {
+			return cr, fmt.Errorf("time window: %w", err)
+		}
+		cr.timeWindows = append(cr.timeWindows, cw)
+	}
+
+	if len(r.Sections.CASB.Restrictions) > 0 {
+		cr.casb = append([]CASBRestriction(nil), r.Sections.CASB.Restrictions...)
+	}
+	if len(w.HeaderMods) > 0 {
+		cr.headerMods = append([]HeaderMod(nil), w.HeaderMods...)
+	}
+	return cr, nil
+}
+
+func normalizeAction(a Action) Action {
+	switch Action(strings.ToLower(string(a))) {
+	case ActionBlock:
+		return ActionBlock
+	default:
+		return ActionAllow
+	}
+}
+
+func normalizeAuthMode(m string) string {
+	switch strings.ToLower(strings.TrimSpace(m)) {
+	case AuthIPCached:
+		return AuthIPCached
+	case AuthPerRequest:
+		return AuthPerRequest
+	case AuthDisable, "":
+		return AuthDisable
+	default:
+		return m
+	}
+}
+
+func cloneUUID(id *uuid.UUID) *uuid.UUID {
+	if id == nil {
+		return nil
+	}
+	v := *id
+	return &v
+}
+
+func compileConditions(conds []Condition, objects map[uuid.UUID]Object) ([]compiledCond, error) {
+	if len(conds) == 0 {
+		return nil, nil
+	}
+	out := make([]compiledCond, 0, len(conds))
+	for i, c := range conds {
+		cc, err := compileOneCondition(c, objects)
+		if err != nil {
+			return nil, fmt.Errorf("condition[%d]: %w", i, err)
+		}
+		if cc != nil {
+			out = append(out, cc)
+		}
+	}
+	return out, nil
+}
+
+func compileOneCondition(c Condition, objects map[uuid.UUID]Object) (compiledCond, error) {
+	typ := c.Type
+	if typ == CondObjectRef || c.ObjectID != nil {
+		if c.ObjectID == nil {
+			return nil, fmt.Errorf("object_ref missing object_id")
+		}
+		obj, ok := objects[*c.ObjectID]
+		if !ok {
+			return nil, fmt.Errorf("unknown object %s", c.ObjectID)
+		}
+		return compileObject(obj)
+	}
+
+	switch typ {
+	case CondSourceIP:
+		n, err := parseCIDROrIP(c.Value)
+		if err != nil {
+			return nil, err
+		}
+		return condAnyIP{nets: []*net.IPNet{n}}, nil
+
+	case CondSourceUser:
+		u := strings.ToLower(strings.TrimSpace(c.Value))
+		return condAnyUser{users: map[string]struct{}{u: {}}}, nil
+
+	case CondUserAgent:
+		ua := strings.ToLower(c.Value)
+		return condAnyUA{agents: map[string]struct{}{ua: {}}}, nil
+
+	case CondDestinationDomain:
+		d := strings.TrimSpace(c.Value)
+		if d == "" {
+			return nil, fmt.Errorf("empty domain")
+		}
+		return condAnyDomain{domains: []string{d}}, nil
+
+	case CondDestinationURL:
+		if c.Value == "" {
+			return nil, fmt.Errorf("empty url")
+		}
+		return condAnyURLPrefix{prefixes: []string{c.Value}}, nil
+
+	case CondDestinationRegex:
+		pat := c.Regex
+		if pat == "" {
+			pat = c.Value
+		}
+		re, err := regexp.Compile(pat)
+		if err != nil {
+			return nil, err
+		}
+		return condAnyRegex{res: []*regexp.Regexp{re}}, nil
+
+	case CondTimeWindow:
+		tw := TimeWindow{}
+		if c.TimeWindow != nil {
+			tw = *c.TimeWindow
+		}
+		cw, err := compileTimeWindow(tw)
+		if err != nil {
+			return nil, err
+		}
+		return condTime{windows: []compiledTimeWindow{cw}}, nil
+
+	case "":
+		return nil, fmt.Errorf("missing condition type")
+
+	default:
+		return nil, fmt.Errorf("unsupported condition type %q", typ)
+	}
+}
+
+func compileObject(obj Object) (compiledCond, error) {
+	def := obj.Definition
+	switch obj.Type {
+	case ObjectSourceIP:
+		var nets []*net.IPNet
+		cidrs := append([]string(nil), def.CIDRs...)
+		if def.CIDR != "" {
+			cidrs = append(cidrs, def.CIDR)
+		}
+		if len(cidrs) == 0 {
+			return nil, fmt.Errorf("object %s: no cidrs", obj.ID)
+		}
+		for _, s := range cidrs {
+			n, err := parseCIDROrIP(s)
+			if err != nil {
+				return nil, fmt.Errorf("object %s: %w", obj.ID, err)
+			}
+			nets = append(nets, n)
+		}
+		return condAnyIP{nets: nets}, nil
+
+	case ObjectSourceUser:
+		users := map[string]struct{}{}
+		for _, u := range def.Usernames {
+			users[strings.ToLower(u)] = struct{}{}
+		}
+		if def.Username != "" {
+			users[strings.ToLower(def.Username)] = struct{}{}
+		}
+		if len(users) == 0 {
+			return nil, fmt.Errorf("object %s: no usernames", obj.ID)
+		}
+		return condAnyUser{users: users}, nil
+
+	case ObjectUserAgent:
+		agents := map[string]struct{}{}
+		for _, a := range def.UserAgents {
+			agents[strings.ToLower(a)] = struct{}{}
+		}
+		if def.UserAgent != "" {
+			agents[strings.ToLower(def.UserAgent)] = struct{}{}
+		}
+		if len(agents) == 0 {
+			return nil, fmt.Errorf("object %s: no user agents", obj.ID)
+		}
+		return condAnyUA{agents: agents}, nil
+
+	case ObjectDestinationDomain:
+		var domains []string
+		domains = append(domains, def.Domains...)
+		if def.Domain != "" {
+			domains = append(domains, def.Domain)
+		}
+		if len(domains) == 0 {
+			return nil, fmt.Errorf("object %s: no domains", obj.ID)
+		}
+		return condAnyDomain{domains: domains}, nil
+
+	case ObjectDestinationURL:
+		var prefixes []string
+		prefixes = append(prefixes, def.URLs...)
+		if def.URL != "" {
+			prefixes = append(prefixes, def.URL)
+		}
+		if len(prefixes) == 0 {
+			return nil, fmt.Errorf("object %s: no urls", obj.ID)
+		}
+		return condAnyURLPrefix{prefixes: prefixes}, nil
+
+	case ObjectDestinationRegex:
+		if def.Regex == "" {
+			return nil, fmt.Errorf("object %s: empty regex", obj.ID)
+		}
+		re, err := regexp.Compile(def.Regex)
+		if err != nil {
+			return nil, err
+		}
+		return condAnyRegex{res: []*regexp.Regexp{re}}, nil
+
+	case ObjectTimeWindow:
+		if def.TimeWindow == nil {
+			return nil, fmt.Errorf("object %s: missing time_window", obj.ID)
+		}
+		cw, err := compileTimeWindow(*def.TimeWindow)
+		if err != nil {
+			return nil, err
+		}
+		return condTime{windows: []compiledTimeWindow{cw}}, nil
+
+	case ObjectCASBAppRef:
+		// CASB app refs as destination conditions: match hosts with domain suffix rules.
+		if len(def.Hosts) == 0 {
+			return nil, fmt.Errorf("object %s: casb_app_ref has no hosts", obj.ID)
+		}
+		return condAnyDomain{domains: append([]string(nil), def.Hosts...)}, nil
+
+	default:
+		return nil, fmt.Errorf("object %s: unsupported type %q", obj.ID, obj.Type)
+	}
+}
+
+// matches reports whether the compiled rule matches the request input.
+func (r *compiledRule) matches(in RequestInput) bool {
+	if !matchAnyCondition(r.sources, in) {
+		return false
+	}
+	if !matchAnyCondition(r.destinations, in) {
+		return false
+	}
+	if !matchAnyCondition(r.webSources, in) {
+		return false
+	}
+	if !matchAnyCondition(r.webDestinations, in) {
+		return false
+	}
+	if !matchAllTimeWindows(r.timeWindows, in.Now) {
+		return false
+	}
+	if !matchMethod(r.methods, in.Method) {
+		return false
+	}
+	if !matchProtocol(r.protocols, in.URL) {
+		return false
+	}
+	return true
+}
diff --git a/internal/policy/engine.go b/internal/policy/engine.go
new file mode 100644
index 0000000..7b42e86
--- /dev/null
+++ b/internal/policy/engine.go
@@ -0,0 +1,102 @@
+package policy
+
+import (
+	"sync/atomic"
+
+	"github.com/google/uuid"
+)
+
+// Engine holds an atomically swappable compiled policy snapshot.
+// Evaluate is pure with respect to external I/O: it only reads the snapshot
+// and the RequestInput.
+type Engine struct {
+	snap atomic.Pointer[Snapshot]
+}
+
+// Swap publishes a new compiled snapshot for subsequent Evaluate calls.
+// Passing nil clears the snapshot (Evaluate returns the safe default allow).
+func (e *Engine) Swap(s *Snapshot) {
+	e.snap.Store(s)
+}
+
+// Load returns the current snapshot (may be nil).
+func (e *Engine) Load() *Snapshot {
+	return e.snap.Load()
+}
+
+// Evaluate applies ordered policy to in and returns an accumulated Decision.
+// No I/O is performed. Nil or empty snapshots yield default allow.
+func (e *Engine) Evaluate(in RequestInput) Decision {
+	s := e.snap.Load()
+	if s == nil {
+		return defaultDecision()
+	}
+	return evaluateRules(s.rules, in)
+}
+
+// evaluateRules is the pure core used by Engine.Evaluate and Simulate.
+func evaluateRules(rules []compiledRule, in RequestInput) Decision {
+	d := defaultDecision()
+	if len(rules) == 0 {
+		return d
+	}
+
+	// Pre-size lightly; append grows as needed.
+	d.EvaluatedRuleIDs = make([]uuid.UUID, 0, len(rules))
+	d.MatchedRuleIDs = make([]uuid.UUID, 0, 4)
+
+	for i := range rules {
+		r := &rules[i]
+		d.EvaluatedRuleIDs = append(d.EvaluatedRuleIDs, r.id)
+
+		if !r.matches(in) {
+			continue
+		}
+
+		d.MatchedRuleIDs = append(d.MatchedRuleIDs, r.id)
+		accumulateAllowActions(&d, r)
+
+		if r.action == ActionBlock {
+			d.FinalAction = ActionBlock
+			d.BlockReason = r.blockReason
+			d.BlockPageID = cloneUUID(r.blockPageID)
+			// Stop on first matching Block (firewall-style).
+			return d
+		}
+		// Allow: keep FinalAction allow and continue.
+		d.FinalAction = ActionAllow
+	}
+	return d
+}
+
+// accumulateAllowActions merges additive actions from a matched rule.
+// TLSIntercept / RBI / malware use OR semantics; AuthMode last non-disable wins
+// when later rules set a stronger mode; CASB and header mods append.
+func accumulateAllowActions(d *Decision, r *compiledRule) {
+	if r.tlsIntercept {
+		d.TLSIntercept = true
+	}
+	if r.authMode != "" && r.authMode != AuthDisable {
+		d.AuthMode = r.authMode
+	} else if r.authMode == AuthDisable && d.AuthMode == "" {
+		d.AuthMode = AuthDisable
+	}
+	if r.rbiIsolated {
+		d.RBIIsolated = true
+	}
+	if r.rbiBlockCopyFrom {
+		d.RBIBlockCopyFrom = true
+	}
+	if r.rbiBlockCopyTo {
+		d.RBIBlockCopyTo = true
+	}
+	if r.malwareScan {
+		d.MalwareScan = true
+	}
+	if len(r.casb) > 0 {
+		d.CASB = append(d.CASB, r.casb...)
+	}
+	if len(r.headerMods) > 0 {
+		d.HeaderMods = append(d.HeaderMods, r.headerMods...)
+	}
+}
diff --git a/internal/policy/engine_test.go b/internal/policy/engine_test.go
new file mode 100644
index 0000000..405bdb7
--- /dev/null
+++ b/internal/policy/engine_test.go
@@ -0,0 +1,571 @@
+package policy
+
+import (
+	"net"
+	"net/url"
+	"testing"
+	"time"
+
+	"github.com/google/uuid"
+)
+
+func mustURL(t *testing.T, raw string) *url.URL {
+	t.Helper()
+	u, err := url.Parse(raw)
+	if err != nil {
+		t.Fatalf("parse url %q: %v", raw, err)
+	}
+	return u
+}
+
+func ruleID(n byte) uuid.UUID {
+	return uuid.UUID{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, n}
+}
+
+func baseInput(t *testing.T) RequestInput {
+	t.Helper()
+	return RequestInput{
+		ClientIP:  net.ParseIP("10.1.2.3"),
+		Username:  "alice",
+		UserAgent: "TestAgent/1.0",
+		Method:    "GET",
+		URL:       mustURL(t, "https://www.example.com/path"),
+		Now:       time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
+	}
+}
+
+func TestOrderedBlockStops(t *testing.T) {
+	blockPage := ruleID(0xB1)
+	rules := []Rule{
+		{
+			ID:       ruleID(1),
+			Name:     "block-first",
+			Enabled:  true,
+			Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:      ActionBlock,
+					BlockPageID: &blockPage,
+					BlockReason: "blocked by rule 1",
+					Destinations: []Condition{
+						{Type: CondDestinationDomain, Value: "example.com"},
+					},
+				},
+			},
+		},
+		{
+			ID:       ruleID(2),
+			Name:     "allow-malware",
+			Enabled:  true,
+			Priority: 20,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:       ActionAllow,
+					TLSIntercept: true,
+				},
+				Antimalware: AntimalwareSection{Enabled: true},
+			},
+		},
+	}
+
+	snap, err := Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+
+	d := eng.Evaluate(baseInput(t))
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("FinalAction = %q, want block", d.FinalAction)
+	}
+	if d.BlockReason != "blocked by rule 1" {
+		t.Fatalf("BlockReason = %q", d.BlockReason)
+	}
+	if d.BlockPageID == nil || *d.BlockPageID != blockPage {
+		t.Fatalf("BlockPageID = %v, want %v", d.BlockPageID, blockPage)
+	}
+	// Block stops: second rule must not be evaluated or matched.
+	if len(d.MatchedRuleIDs) != 1 || d.MatchedRuleIDs[0] != ruleID(1) {
+		t.Fatalf("MatchedRuleIDs = %v", d.MatchedRuleIDs)
+	}
+	if len(d.EvaluatedRuleIDs) != 1 || d.EvaluatedRuleIDs[0] != ruleID(1) {
+		t.Fatalf("EvaluatedRuleIDs = %v, want only first rule", d.EvaluatedRuleIDs)
+	}
+	if d.MalwareScan {
+		t.Fatal("MalwareScan should not accumulate after block stop")
+	}
+}
+
+func TestAllowContinuesAndAccumulates(t *testing.T) {
+	rules := []Rule{
+		{
+			ID:       ruleID(1),
+			Name:     "allow-mitm-rbi",
+			Enabled:  true,
+			Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:       ActionAllow,
+					TLSIntercept: true,
+					AuthMode:     AuthIPCached,
+					Destinations: []Condition{
+						{Type: CondDestinationDomain, Value: "example.com"},
+					},
+				},
+				RBI: RBISection{
+					Mode:              RBIIsolated,
+					BlockCopyFromSite: true,
+				},
+				Antimalware: AntimalwareSection{Enabled: true},
+			},
+		},
+		{
+			ID:       ruleID(2),
+			Name:     "allow-casb-headers",
+			Enabled:  true,
+			Priority: 20,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:       ActionAllow,
+					TLSIntercept: false, // should not clear prior true
+					AuthMode:     AuthPerRequest,
+				},
+				RBI: RBISection{
+					Mode:            RBINotIsolated,
+					BlockCopyToSite: true,
+				},
+				CASB: CASBSection{
+					Restrictions: []CASBRestriction{
+						{App: "chatgpt", Actions: []string{"block_upload"}},
+					},
+				},
+				WebFiltering: WebFilteringSection{
+					HeaderMods: []HeaderMod{
+						{Op: HeaderSet, Target: HeaderRequest, Name: "X-WSP", Value: "1"},
+					},
+				},
+			},
+		},
+		{
+			ID:       ruleID(3),
+			Name:     "no-match-later",
+			Enabled:  true,
+			Priority: 30,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action: ActionAllow,
+					Destinations: []Condition{
+						{Type: CondDestinationDomain, Value: "other.example"},
+					},
+				},
+				Antimalware: AntimalwareSection{Enabled: true},
+			},
+		},
+	}
+
+	snap, err := Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+
+	d := eng.Evaluate(baseInput(t))
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("FinalAction = %q, want allow", d.FinalAction)
+	}
+	if !d.TLSIntercept {
+		t.Fatal("TLSIntercept should stay true after accumulation")
+	}
+	if d.AuthMode != AuthPerRequest {
+		t.Fatalf("AuthMode = %q, want last matching allow's mode", d.AuthMode)
+	}
+	if !d.RBIIsolated {
+		t.Fatal("RBIIsolated should remain true once set")
+	}
+	if !d.RBIBlockCopyFrom {
+		t.Fatal("RBIBlockCopyFrom should accumulate")
+	}
+	if !d.RBIBlockCopyTo {
+		t.Fatal("RBIBlockCopyTo should accumulate from later allow")
+	}
+	if !d.MalwareScan {
+		t.Fatal("MalwareScan should accumulate from first allow")
+	}
+	if len(d.CASB) != 1 || d.CASB[0].App != "chatgpt" {
+		t.Fatalf("CASB = %+v", d.CASB)
+	}
+	if len(d.HeaderMods) != 1 || d.HeaderMods[0].Name != "X-WSP" {
+		t.Fatalf("HeaderMods = %+v", d.HeaderMods)
+	}
+	// Rules 1 and 2 match; rule 3 evaluated but not matched.
+	if len(d.MatchedRuleIDs) != 2 {
+		t.Fatalf("MatchedRuleIDs = %v", d.MatchedRuleIDs)
+	}
+	if len(d.EvaluatedRuleIDs) != 3 {
+		t.Fatalf("EvaluatedRuleIDs = %v, want all three", d.EvaluatedRuleIDs)
+	}
+}
+
+func TestDomainSuffixMatch(t *testing.T) {
+	rules := []Rule{
+		{
+			ID:       ruleID(1),
+			Name:     "suffix",
+			Enabled:  true,
+			Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:      ActionBlock,
+					BlockReason: "domain match",
+					Destinations: []Condition{
+						{Type: CondDestinationDomain, Value: "example.com"},
+					},
+				},
+			},
+		},
+	}
+	snap, err := Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+
+	// Suffix: www.example.com matches example.com
+	in := baseInput(t)
+	in.URL = mustURL(t, "https://www.example.com/")
+	d := eng.Evaluate(in)
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("www.example.com: FinalAction = %q, want block", d.FinalAction)
+	}
+
+	// Exact apex
+	in.URL = mustURL(t, "https://example.com/")
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("example.com: FinalAction = %q, want block", d.FinalAction)
+	}
+
+	// Non-suffix sibling must not match
+	in.URL = mustURL(t, "https://notexample.com/")
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("notexample.com: FinalAction = %q, want allow (no match)", d.FinalAction)
+	}
+
+	// Different TLD
+	in.URL = mustURL(t, "https://example.org/")
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("example.org: FinalAction = %q, want allow", d.FinalAction)
+	}
+}
+
+func TestCIDRMatch(t *testing.T) {
+	rules := []Rule{
+		{
+			ID:       ruleID(1),
+			Name:     "src-cidr",
+			Enabled:  true,
+			Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:      ActionBlock,
+					BlockReason: "src cidr",
+					Sources: []Condition{
+						{Type: CondSourceIP, Value: "10.0.0.0/8"},
+					},
+				},
+			},
+		},
+	}
+	snap, err := Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+
+	in := baseInput(t)
+	in.ClientIP = net.ParseIP("10.9.9.9")
+	d := eng.Evaluate(in)
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("10.9.9.9 in 10/8: FinalAction = %q, want block", d.FinalAction)
+	}
+
+	in.ClientIP = net.ParseIP("192.168.1.1")
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("192.168.1.1 outside 10/8: FinalAction = %q, want allow", d.FinalAction)
+	}
+
+	// Single host as CIDR /32
+	rules[0].Sections.General.Sources = []Condition{
+		{Type: CondSourceIP, Value: "203.0.113.50"},
+	}
+	snap, err = Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile single IP: %v", err)
+	}
+	eng.Swap(snap)
+
+	in.ClientIP = net.ParseIP("203.0.113.50")
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("exact IP: FinalAction = %q, want block", d.FinalAction)
+	}
+	in.ClientIP = net.ParseIP("203.0.113.51")
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("other IP: FinalAction = %q, want allow", d.FinalAction)
+	}
+}
+
+func TestTimeWindow(t *testing.T) {
+	// Monday 12:00 UTC ΓÇö inside weekday window MonΓÇôFri 09:00ΓÇô17:00
+	rules := []Rule{
+		{
+			ID:       ruleID(1),
+			Name:     "business-hours-block",
+			Enabled:  true,
+			Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:      ActionBlock,
+					BlockReason: "after hours only allow",
+				},
+				WebFiltering: WebFilteringSection{
+					TimeWindows: []TimeWindow{
+						{
+							DaysOfWeek: []int{1, 2, 3, 4, 5}, // Mon-Fri
+							StartTime:  "09:00",
+							EndTime:    "17:00",
+							Timezone:   "UTC",
+						},
+					},
+				},
+			},
+		},
+	}
+	snap, err := Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+
+	// 2026-07-27 is a Monday
+	in := baseInput(t)
+	in.Now = time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC)
+	d := eng.Evaluate(in)
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("Mon 12:00 in window: FinalAction = %q, want block", d.FinalAction)
+	}
+
+	// Outside hours same day
+	in.Now = time.Date(2026, 7, 27, 20, 0, 0, 0, time.UTC)
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("Mon 20:00 outside window: FinalAction = %q, want allow", d.FinalAction)
+	}
+
+	// Weekend inside clock window
+	in.Now = time.Date(2026, 7, 25, 12, 0, 0, 0, time.UTC) // Saturday
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("Sat 12:00 not in days: FinalAction = %q, want allow", d.FinalAction)
+	}
+
+	// Absolute range
+	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
+	end := time.Date(2026, 6, 30, 23, 59, 59, 0, time.UTC)
+	rules[0].Sections.WebFiltering.TimeWindows = []TimeWindow{
+		{Start: &start, End: &end},
+	}
+	snap, err = Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile absolute: %v", err)
+	}
+	eng.Swap(snap)
+
+	in.Now = time.Date(2026, 3, 15, 10, 0, 0, 0, time.UTC)
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("inside absolute range: FinalAction = %q, want block", d.FinalAction)
+	}
+	in.Now = time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC)
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("outside absolute range: FinalAction = %q, want allow", d.FinalAction)
+	}
+}
+
+func TestDisabledRulesSkipped(t *testing.T) {
+	rules := []Rule{
+		{
+			ID:       ruleID(1),
+			Name:     "disabled-block",
+			Enabled:  false,
+			Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:      ActionBlock,
+					BlockReason: "should not apply",
+				},
+			},
+		},
+		{
+			ID:       ruleID(2),
+			Name:     "enabled-allow",
+			Enabled:  true,
+			Priority: 20,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:       ActionAllow,
+					TLSIntercept: true,
+				},
+			},
+		},
+	}
+	snap, err := Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+
+	d := eng.Evaluate(baseInput(t))
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("FinalAction = %q, want allow", d.FinalAction)
+	}
+	if !d.TLSIntercept {
+		t.Fatal("expected enabled allow rule to apply")
+	}
+	for _, id := range d.EvaluatedRuleIDs {
+		if id == ruleID(1) {
+			t.Fatal("disabled rule must not appear in EvaluatedRuleIDs")
+		}
+	}
+	for _, id := range d.MatchedRuleIDs {
+		if id == ruleID(1) {
+			t.Fatal("disabled rule must not appear in MatchedRuleIDs")
+		}
+	}
+	if len(d.MatchedRuleIDs) != 1 || d.MatchedRuleIDs[0] != ruleID(2) {
+		t.Fatalf("MatchedRuleIDs = %v", d.MatchedRuleIDs)
+	}
+}
+
+func TestCompileOrdersByPriority(t *testing.T) {
+	// Higher priority number defined first in slice; lower priority must evaluate first.
+	rules := []Rule{
+		{
+			ID: ruleID(2), Name: "second", Enabled: true, Priority: 200,
+			Sections: RuleSections{General: GeneralSection{Action: ActionAllow, TLSIntercept: true}},
+		},
+		{
+			ID: ruleID(1), Name: "first", Enabled: true, Priority: 100,
+			Sections: RuleSections{General: GeneralSection{
+				Action: ActionBlock, BlockReason: "first",
+			}},
+		},
+	}
+	snap, err := Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+	d := eng.Evaluate(baseInput(t))
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("FinalAction = %q, want block from lower priority", d.FinalAction)
+	}
+	if len(d.EvaluatedRuleIDs) != 1 || d.EvaluatedRuleIDs[0] != ruleID(1) {
+		t.Fatalf("EvaluatedRuleIDs = %v", d.EvaluatedRuleIDs)
+	}
+}
+
+func TestEmptySourcesAndDestinationsMatchAll(t *testing.T) {
+	rules := []Rule{
+		{
+			ID: ruleID(1), Name: "match-all", Enabled: true, Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action: ActionBlock, BlockReason: "all",
+					Sources:      nil,
+					Destinations: nil,
+				},
+			},
+		},
+	}
+	snap, err := Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+	d := eng.Evaluate(baseInput(t))
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("empty conditions should match all: FinalAction = %q", d.FinalAction)
+	}
+}
+
+func TestNilSnapshotAllows(t *testing.T) {
+	var eng Engine
+	d := eng.Evaluate(baseInput(t))
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("nil snapshot FinalAction = %q, want allow", d.FinalAction)
+	}
+	if d.AuthMode != AuthDisable && d.AuthMode != "" {
+		// empty or disable both acceptable as safe default; engine normalizes to disable
+		t.Fatalf("AuthMode = %q", d.AuthMode)
+	}
+}
+
+func TestObjectRefSourceIP(t *testing.T) {
+	objID := ruleID(0xA1)
+	objects := map[uuid.UUID]Object{
+		objID: {
+			ID:   objID,
+			Name: "corp-net",
+			Type: ObjectSourceIP,
+			Definition: ObjectDefinition{
+				CIDRs: []string{"10.0.0.0/8"},
+			},
+		},
+	}
+	rules := []Rule{
+		{
+			ID: ruleID(1), Name: "via-object", Enabled: true, Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:      ActionBlock,
+					BlockReason: "object",
+					Sources: []Condition{
+						{Type: CondObjectRef, ObjectID: &objID},
+					},
+				},
+			},
+		},
+	}
+	snap, err := Compile(rules, objects)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+
+	in := baseInput(t)
+	in.ClientIP = net.ParseIP("10.0.0.5")
+	d := eng.Evaluate(in)
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("object CIDR match: FinalAction = %q", d.FinalAction)
+	}
+	in.ClientIP = net.ParseIP("11.0.0.5")
+	d = eng.Evaluate(in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("outside object CIDR: FinalAction = %q", d.FinalAction)
+	}
+}
diff --git a/internal/policy/match.go b/internal/policy/match.go
new file mode 100644
index 0000000..ff02610
--- /dev/null
+++ b/internal/policy/match.go
@@ -0,0 +1,359 @@
+package policy
+
+import (
+	"net"
+	"net/url"
+	"regexp"
+	"strconv"
+	"strings"
+	"time"
+)
+
+// matchAnyCondition returns true if conditions is empty (match-all) or any
+// condition matches (OR within sources / destinations lists).
+func matchAnyCondition(conds []compiledCond, in RequestInput) bool {
+	if len(conds) == 0 {
+		return true
+	}
+	for _, c := range conds {
+		if c.match(in) {
+			return true
+		}
+	}
+	return false
+}
+
+// matchAllTimeWindows returns true if windows is empty or the request time
+// falls in at least one window (OR across listed windows).
+func matchAllTimeWindows(windows []compiledTimeWindow, now time.Time) bool {
+	if len(windows) == 0 {
+		return true
+	}
+	for _, w := range windows {
+		if w.contains(now) {
+			return true
+		}
+	}
+	return false
+}
+
+func matchMethod(methods []string, method string) bool {
+	if len(methods) == 0 {
+		return true
+	}
+	m := strings.ToUpper(method)
+	for _, allowed := range methods {
+		if strings.ToUpper(allowed) == m {
+			return true
+		}
+	}
+	return false
+}
+
+func matchProtocol(protocols []string, u *url.URL) bool {
+	if len(protocols) == 0 {
+		return true
+	}
+	scheme := ""
+	if u != nil {
+		scheme = strings.ToLower(u.Scheme)
+	}
+	for _, p := range protocols {
+		if strings.ToLower(p) == scheme {
+			return true
+		}
+	}
+	return false
+}
+
+// domainSuffixMatch reports whether host equals domain or is a subdomain of it.
+// Host and domain are compared case-insensitively; ports are stripped from host.
+// Prevents false positives like "notexample.com" matching "example.com".
+func domainSuffixMatch(host, domain string) bool {
+	host = strings.ToLower(strings.TrimSpace(host))
+	domain = strings.ToLower(strings.TrimSpace(domain))
+	if host == "" || domain == "" {
+		return false
+	}
+	// Strip port if present (IPv6 [addr]:port handled poorly; host from URL.Hostname is preferred).
+	if h, _, err := net.SplitHostPort(host); err == nil {
+		host = h
+	}
+	host = strings.TrimSuffix(host, ".")
+	domain = strings.TrimPrefix(domain, "*.")
+	domain = strings.TrimSuffix(domain, ".")
+
+	if host == domain {
+		return true
+	}
+	return strings.HasSuffix(host, "."+domain)
+}
+
+// parseCIDROrIP accepts "10.0.0.0/8", "2001:db8::/32", or a bare IP (as /32 or /128).
+func parseCIDROrIP(s string) (*net.IPNet, error) {
+	s = strings.TrimSpace(s)
+	if s == "" {
+		return nil, errInvalidCIDR
+	}
+	if strings.Contains(s, "/") {
+		_, n, err := net.ParseCIDR(s)
+		return n, err
+	}
+	ip := net.ParseIP(s)
+	if ip == nil {
+		return nil, errInvalidCIDR
+	}
+	if v4 := ip.To4(); v4 != nil {
+		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
+	}
+	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
+}
+
+type errString string
+
+func (e errString) Error() string { return string(e) }
+
+const errInvalidCIDR = errString("invalid CIDR or IP")
+
+// hostname extracts the host from the request URL without port.
+func hostname(u *url.URL) string {
+	if u == nil {
+		return ""
+	}
+	return strings.ToLower(u.Hostname())
+}
+
+func fullURLString(u *url.URL) string {
+	if u == nil {
+		return ""
+	}
+	return u.String()
+}
+
+// --- compiled matchers (immutable; built by Compile) ---
+
+type compiledCond interface {
+	match(in RequestInput) bool
+}
+
+type condAnyIP struct {
+	nets []*net.IPNet
+}
+
+func (c condAnyIP) match(in RequestInput) bool {
+	if in.ClientIP == nil {
+		return false
+	}
+	ip := in.ClientIP
+	for _, n := range c.nets {
+		if n.Contains(ip) {
+			return true
+		}
+	}
+	return false
+}
+
+type condAnyUser struct {
+	users map[string]struct{}
+}
+
+func (c condAnyUser) match(in RequestInput) bool {
+	_, ok := c.users[strings.ToLower(in.Username)]
+	return ok
+}
+
+type condAnyUA struct {
+	// Exact match for v1; values lowercased.
+	agents map[string]struct{}
+}
+
+func (c condAnyUA) match(in RequestInput) bool {
+	_, ok := c.agents[strings.ToLower(in.UserAgent)]
+	return ok
+}
+
+type condAnyDomain struct {
+	domains []string
+}
+
+func (c condAnyDomain) match(in RequestInput) bool {
+	host := hostname(in.URL)
+	for _, d := range c.domains {
+		if domainSuffixMatch(host, d) {
+			return true
+		}
+	}
+	return false
+}
+
+type condAnyURLPrefix struct {
+	prefixes []string
+}
+
+func (c condAnyURLPrefix) match(in RequestInput) bool {
+	raw := fullURLString(in.URL)
+	for _, p := range c.prefixes {
+		if strings.HasPrefix(raw, p) || (in.URL != nil && strings.HasPrefix(in.URL.String(), p)) {
+			return true
+		}
+		// Also allow matching host+path without forcing scheme.
+		if in.URL != nil {
+			hp := in.URL.Host + in.URL.Path
+			if strings.HasPrefix(hp, p) || strings.HasPrefix(raw, p) {
+				return true
+			}
+		}
+	}
+	return false
+}
+
+type condAnyRegex struct {
+	res []*regexp.Regexp
+}
+
+func (c condAnyRegex) match(in RequestInput) bool {
+	raw := fullURLString(in.URL)
+	for _, re := range c.res {
+		if re.MatchString(raw) {
+			return true
+		}
+	}
+	return false
+}
+
+type condTime struct {
+	windows []compiledTimeWindow
+}
+
+func (c condTime) match(in RequestInput) bool {
+	return matchAllTimeWindows(c.windows, in.Now)
+}
+
+type compiledTimeWindow struct {
+	start    *time.Time
+	end      *time.Time
+	days     map[time.Weekday]struct{} // empty map means all days when useDays is false
+	useDays  bool
+	startMin int // minutes from midnight; -1 if unset
+	endMin   int // minutes from midnight; -1 if unset
+	loc      *time.Location
+	hasClock bool
+	hasAbs   bool
+}
+
+func compileTimeWindow(tw TimeWindow) (compiledTimeWindow, error) {
+	cw := compiledTimeWindow{startMin: -1, endMin: -1, loc: time.UTC}
+	if tw.Timezone != "" {
+		loc, err := time.LoadLocation(tw.Timezone)
+		if err != nil {
+			return cw, err
+		}
+		cw.loc = loc
+	}
+	if tw.Start != nil {
+		s := tw.Start.UTC()
+		cw.start = &s
+		cw.hasAbs = true
+	}
+	if tw.End != nil {
+		e := tw.End.UTC()
+		cw.end = &e
+		cw.hasAbs = true
+	}
+	if len(tw.DaysOfWeek) > 0 {
+		cw.useDays = true
+		cw.days = make(map[time.Weekday]struct{}, len(tw.DaysOfWeek))
+		for _, d := range tw.DaysOfWeek {
+			cw.days[time.Weekday(d)] = struct{}{}
+		}
+	}
+	if tw.StartTime != "" {
+		m, err := parseHHMM(tw.StartTime)
+		if err != nil {
+			return cw, err
+		}
+		cw.startMin = m
+		cw.hasClock = true
+	}
+	if tw.EndTime != "" {
+		m, err := parseHHMM(tw.EndTime)
+		if err != nil {
+			return cw, err
+		}
+		cw.endMin = m
+		cw.hasClock = true
+	}
+	return cw, nil
+}
+
+func parseHHMM(s string) (int, error) {
+	parts := strings.Split(s, ":")
+	if len(parts) != 2 {
+		return 0, errString("invalid time " + s)
+	}
+	h, err := strconv.Atoi(parts[0])
+	if err != nil || h < 0 || h > 23 {
+		return 0, errString("invalid hour in " + s)
+	}
+	m, err := strconv.Atoi(parts[1])
+	if err != nil || m < 0 || m > 59 {
+		return 0, errString("invalid minute in " + s)
+	}
+	return h*60 + m, nil
+}
+
+func (w compiledTimeWindow) contains(now time.Time) bool {
+	if now.IsZero() {
+		return false
+	}
+	// Absolute range (compared in UTC).
+	if w.hasAbs {
+		t := now.UTC()
+		if w.start != nil && t.Before(*w.start) {
+			return false
+		}
+		if w.end != nil && t.After(*w.end) {
+			return false
+		}
+		// If only absolute bounds (no recurring fields), absolute alone decides.
+		if !w.useDays && !w.hasClock {
+			return true
+		}
+	}
+
+	local := now.In(w.loc)
+
+	if w.useDays {
+		if _, ok := w.days[local.Weekday()]; !ok {
+			return false
+		}
+	}
+
+	if w.hasClock {
+		mins := local.Hour()*60 + local.Minute()
+		if w.startMin >= 0 && mins < w.startMin {
+			return false
+		}
+		if w.endMin >= 0 && mins >= w.endMin {
+			// End is exclusive at exact end minute boundary: 17:00 means until 17:00 not including.
+			// Design: "09:00ΓÇô17:00" business hours ΓåÆ 16:59 in, 17:00 out.
+			return false
+		}
+		// Handle overnight windows (e.g. 22:00ΓÇô06:00) when both set and start > end.
+		if w.startMin >= 0 && w.endMin >= 0 && w.startMin > w.endMin {
+			// mins is inside if >= start OR < end (already checked mins >= end as fail for normal).
+			// For overnight: fail if end <= mins < start.
+			if mins >= w.endMin && mins < w.startMin {
+				return false
+			}
+			return true
+		}
+	}
+
+	// Recurring with only days (no clock) after optional absolute ΓÇö already checked days.
+	if w.useDays || w.hasClock || w.hasAbs {
+		return true
+	}
+	// Empty window definition matches nothing meaningful; treat as no constraint.
+	return true
+}
diff --git a/internal/policy/simulate.go b/internal/policy/simulate.go
new file mode 100644
index 0000000..b68a8bc
--- /dev/null
+++ b/internal/policy/simulate.go
@@ -0,0 +1,20 @@
+package policy
+
+import "github.com/google/uuid"
+
+// Simulate compiles rules (skipping disabled) and evaluates in with full trace
+// fields (MatchedRuleIDs / EvaluatedRuleIDs). Same semantics as
+// Compile + Engine.Evaluate; intended for the admin simulation tool.
+// Pure: no I/O. Compile errors yield a default allow decision with empty trace
+// (callers that need compile errors should call Compile directly).
+func Simulate(rules []Rule, objects map[uuid.UUID]Object, in RequestInput) Decision {
+	snap, err := Compile(rules, objects)
+	if err != nil {
+		// Simulation of invalid policy: fail soft to allow for UI debugging
+		// of matchers; production loads should use Compile and surface errors.
+		d := defaultDecision()
+		d.BlockReason = "compile error: " + err.Error()
+		return d
+	}
+	return evaluateRules(snap.rules, in)
+}
diff --git a/internal/policy/simulate_test.go b/internal/policy/simulate_test.go
new file mode 100644
index 0000000..1c5bfb6
--- /dev/null
+++ b/internal/policy/simulate_test.go
@@ -0,0 +1,175 @@
+package policy
+
+import (
+	"net"
+	"testing"
+	"time"
+)
+
+func TestSimulateMatchesEvaluateTrace(t *testing.T) {
+	blockPage := ruleID(0xB2)
+	rules := []Rule{
+		{
+			ID:       ruleID(1),
+			Name:     "allow-scan",
+			Enabled:  true,
+			Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:       ActionAllow,
+					TLSIntercept: true,
+					Destinations: []Condition{
+						{Type: CondDestinationDomain, Value: "example.com"},
+					},
+				},
+				Antimalware: AntimalwareSection{Enabled: true},
+			},
+		},
+		{
+			ID:       ruleID(2),
+			Name:     "block-host",
+			Enabled:  true,
+			Priority: 20,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:      ActionBlock,
+					BlockPageID: &blockPage,
+					BlockReason: "blocked",
+					Destinations: []Condition{
+						{Type: CondDestinationDomain, Value: "example.com"},
+					},
+				},
+			},
+		},
+		{
+			ID:       ruleID(3),
+			Name:     "never-reached",
+			Enabled:  true,
+			Priority: 30,
+			Sections: RuleSections{
+				General: GeneralSection{Action: ActionAllow},
+			},
+		},
+	}
+
+	in := baseInput(t)
+	sim := Simulate(rules, nil, in)
+
+	if sim.FinalAction != ActionBlock {
+		t.Fatalf("Simulate FinalAction = %q, want block", sim.FinalAction)
+	}
+	if sim.BlockReason != "blocked" {
+		t.Fatalf("BlockReason = %q", sim.BlockReason)
+	}
+	// Full trace: allow matched, then block matched and stopped.
+	if len(sim.MatchedRuleIDs) != 2 {
+		t.Fatalf("MatchedRuleIDs = %v, want allow+block", sim.MatchedRuleIDs)
+	}
+	if sim.MatchedRuleIDs[0] != ruleID(1) || sim.MatchedRuleIDs[1] != ruleID(2) {
+		t.Fatalf("MatchedRuleIDs order = %v", sim.MatchedRuleIDs)
+	}
+	if len(sim.EvaluatedRuleIDs) != 2 {
+		t.Fatalf("EvaluatedRuleIDs = %v, rule 3 must not run after block", sim.EvaluatedRuleIDs)
+	}
+	if !sim.TLSIntercept || !sim.MalwareScan {
+		t.Fatal("accumulated allow actions should remain visible on final block decision")
+	}
+
+	// Engine with compiled snapshot must agree on final decision fields.
+	snap, err := Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng Engine
+	eng.Swap(snap)
+	ev := eng.Evaluate(in)
+
+	if ev.FinalAction != sim.FinalAction ||
+		ev.BlockReason != sim.BlockReason ||
+		ev.TLSIntercept != sim.TLSIntercept ||
+		ev.MalwareScan != sim.MalwareScan {
+		t.Fatalf("Evaluate vs Simulate mismatch:\n  eval=%+v\n  sim=%+v", ev, sim)
+	}
+	if len(ev.MatchedRuleIDs) != len(sim.MatchedRuleIDs) {
+		t.Fatalf("MatchedRuleIDs eval=%v sim=%v", ev.MatchedRuleIDs, sim.MatchedRuleIDs)
+	}
+	if len(ev.EvaluatedRuleIDs) != len(sim.EvaluatedRuleIDs) {
+		t.Fatalf("EvaluatedRuleIDs eval=%v sim=%v", ev.EvaluatedRuleIDs, sim.EvaluatedRuleIDs)
+	}
+}
+
+func TestSimulateDisabledSkipped(t *testing.T) {
+	rules := []Rule{
+		{
+			ID: ruleID(1), Name: "off", Enabled: false, Priority: 1,
+			Sections: RuleSections{General: GeneralSection{Action: ActionBlock, BlockReason: "off"}},
+		},
+		{
+			ID: ruleID(2), Name: "on", Enabled: true, Priority: 2,
+			Sections: RuleSections{General: GeneralSection{Action: ActionAllow, AuthMode: AuthIPCached}},
+		},
+	}
+	d := Simulate(rules, nil, baseInput(t))
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("FinalAction = %q", d.FinalAction)
+	}
+	if d.AuthMode != AuthIPCached {
+		t.Fatalf("AuthMode = %q", d.AuthMode)
+	}
+	if len(d.EvaluatedRuleIDs) != 1 || d.EvaluatedRuleIDs[0] != ruleID(2) {
+		t.Fatalf("EvaluatedRuleIDs = %v", d.EvaluatedRuleIDs)
+	}
+}
+
+func TestSimulateCIDRAndDomainAndTime(t *testing.T) {
+	start := time.Date(2026, 7, 1, 0, 0, 0, 0, time.UTC)
+	end := time.Date(2026, 7, 31, 23, 59, 59, 0, time.UTC)
+	rules := []Rule{
+		{
+			ID: ruleID(1), Name: "combo", Enabled: true, Priority: 10,
+			Sections: RuleSections{
+				General: GeneralSection{
+					Action:      ActionBlock,
+					BlockReason: "combo",
+					Sources: []Condition{
+						{Type: CondSourceIP, Value: "192.168.0.0/16"},
+					},
+					Destinations: []Condition{
+						{Type: CondDestinationDomain, Value: "blocked.example"},
+					},
+				},
+				WebFiltering: WebFilteringSection{
+					TimeWindows: []TimeWindow{{Start: &start, End: &end}},
+					Methods:     []string{"POST", "PUT"},
+				},
+			},
+		},
+	}
+
+	// All conditions match
+	in := RequestInput{
+		ClientIP: net.ParseIP("192.168.10.5"),
+		Method:   "POST",
+		URL:      mustURL(t, "https://api.blocked.example/upload"),
+		Now:      time.Date(2026, 7, 15, 8, 0, 0, 0, time.UTC),
+	}
+	d := Simulate(rules, nil, in)
+	if d.FinalAction != ActionBlock {
+		t.Fatalf("all match: FinalAction = %q, want block", d.FinalAction)
+	}
+
+	// Wrong method
+	in.Method = "GET"
+	d = Simulate(rules, nil, in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("method miss: FinalAction = %q, want allow", d.FinalAction)
+	}
+
+	// Wrong domain
+	in.Method = "POST"
+	in.URL = mustURL(t, "https://other.example/")
+	d = Simulate(rules, nil, in)
+	if d.FinalAction != ActionAllow {
+		t.Fatalf("domain miss: FinalAction = %q, want allow", d.FinalAction)
+	}
+}
diff --git a/internal/policy/types.go b/internal/policy/types.go
new file mode 100644
index 0000000..3cfb3b8
--- /dev/null
+++ b/internal/policy/types.go
@@ -0,0 +1,237 @@
+// Package policy implements a pure ordered policy evaluation engine.
+// Evaluate and Simulate perform no I/O and never touch a database.
+package policy
+
+import (
+	"net"
+	"net/url"
+	"time"
+
+	"github.com/google/uuid"
+)
+
+// Action is the primary allow/block outcome of a rule or decision.
+type Action string
+
+const (
+	ActionAllow Action = "allow"
+	ActionBlock Action = "block"
+)
+
+// Auth modes for proxy authentication (design ┬º5.3).
+const (
+	AuthDisable    = "disable"
+	AuthIPCached   = "ip_cached"
+	AuthPerRequest = "per_request"
+)
+
+// RBI modes.
+const (
+	RBIIsolated    = "isolated"
+	RBINotIsolated = "not_isolated"
+)
+
+// Condition type identifiers (inline or via object type).
+const (
+	CondSourceIP          = "source_ip"
+	CondSourceUser        = "source_user"
+	CondUserAgent         = "user_agent"
+	CondDestinationDomain = "destination_domain"
+	CondDestinationURL    = "destination_url"
+	CondDestinationRegex  = "destination_regex"
+	CondTimeWindow        = "time_window"
+	CondObjectRef         = "object_ref"
+)
+
+// Object type identifiers stored on reusable_objects.type.
+const (
+	ObjectSourceIP          = "source_ip"
+	ObjectSourceUser        = "source_user"
+	ObjectUserAgent         = "user_agent"
+	ObjectDestinationDomain = "destination_domain"
+	ObjectDestinationURL    = "destination_url"
+	ObjectDestinationRegex  = "destination_regex"
+	ObjectTimeWindow        = "time_window"
+	ObjectHeaderMod         = "header_mod"
+	ObjectCASBAppRef        = "casb_app_ref"
+)
+
+// Header modification ops / targets.
+const (
+	HeaderSet    = "set"
+	HeaderAppend = "append"
+	HeaderRemove = "remove"
+
+	HeaderRequest  = "request"
+	HeaderResponse = "response"
+)
+
+// Decision is the pure result of evaluating a request against policy.
+type Decision struct {
+	FinalAction      Action
+	BlockPageID      *uuid.UUID
+	BlockReason      string
+	TLSIntercept     bool
+	AuthMode         string // disable | ip_cached | per_request
+	RBIIsolated      bool
+	RBIBlockCopyFrom bool
+	RBIBlockCopyTo   bool
+	CASB             []CASBRestriction
+	MalwareScan      bool
+	HeaderMods       []HeaderMod
+	MatchedRuleIDs   []uuid.UUID
+	EvaluatedRuleIDs []uuid.UUID
+}
+
+// RequestInput is the pure input for Evaluate / Simulate.
+type RequestInput struct {
+	ClientIP  net.IP
+	Username  string
+	UserAgent string
+	Method    string
+	URL       *url.URL
+	Now       time.Time
+}
+
+// CASBRestriction is an accumulated CASB control from matched rules.
+type CASBRestriction struct {
+	App     string   `json:"app"`
+	Actions []string `json:"actions"`
+	// Optional type filters (MIME / extensions); empty = all.
+	MIMETypes  []string `json:"mime_types,omitempty"`
+	Extensions []string `json:"extensions,omitempty"`
+}
+
+// HeaderMod is an HTTP header mutation applied on allow paths.
+type HeaderMod struct {
+	Op     string `json:"op"`     // set | append | remove
+	Target string `json:"target"` // request | response
+	Name   string `json:"name"`
+	Value  string `json:"value,omitempty"`
+}
+
+// Condition is an inline match condition or reference to a reusable object.
+type Condition struct {
+	Type     string     `json:"type"`
+	Value    string     `json:"value,omitempty"`
+	ObjectID *uuid.UUID `json:"object_id,omitempty"`
+	// Optional structured fields (used when Type is time_window or object embeds them).
+	TimeWindow *TimeWindow `json:"time_window,omitempty"`
+	Regex      string      `json:"regex,omitempty"`
+}
+
+// TimeWindow is either an absolute range and/or a recurring weekly window.
+// DaysOfWeek uses time.Weekday values (0=Sunday ΓÇª 6=Saturday). Empty = all days.
+// StartTime/EndTime are "HH:MM" in the given Timezone (default UTC).
+type TimeWindow struct {
+	Start      *time.Time `json:"start,omitempty"`
+	End        *time.Time `json:"end,omitempty"`
+	DaysOfWeek []int      `json:"days_of_week,omitempty"`
+	StartTime  string     `json:"start_time,omitempty"`
+	EndTime    string     `json:"end_time,omitempty"`
+	Timezone   string     `json:"timezone,omitempty"`
+}
+
+// Rule is one ordered policy entry (maps to policies table row + sections JSON).
+type Rule struct {
+	ID          uuid.UUID    `json:"id"`
+	Name        string       `json:"name"`
+	Description string       `json:"description,omitempty"`
+	Enabled     bool         `json:"enabled"`
+	Priority    int          `json:"priority"` // lower = evaluated first
+	Sections    RuleSections `json:"sections"`
+}
+
+// RuleSections mirrors policies.sections JSONB.
+type RuleSections struct {
+	General      GeneralSection      `json:"general"`
+	WebFiltering WebFilteringSection `json:"web_filtering"`
+	RBI          RBISection          `json:"rbi"`
+	CASB         CASBSection         `json:"casb"`
+	Antimalware  AntimalwareSection  `json:"antimalware"`
+}
+
+// GeneralSection is the primary match + action configuration.
+type GeneralSection struct {
+	Sources      []Condition `json:"sources"`
+	Destinations []Condition `json:"destinations"`
+	Action       Action      `json:"action"`
+	BlockPageID  *uuid.UUID  `json:"block_page_id,omitempty"`
+	BlockReason  string      `json:"block_reason,omitempty"`
+	TLSIntercept bool        `json:"tls_intercept"`
+	AuthMode     string      `json:"auth_mode,omitempty"`
+}
+
+// WebFilteringSection adds time/method/protocol filters and header mods.
+type WebFilteringSection struct {
+	// Optional overrides; when non-empty they further restrict the match
+	// (AND with general). Empty means inherit general only.
+	Sources      []Condition  `json:"sources,omitempty"`
+	Destinations []Condition  `json:"destinations,omitempty"`
+	TimeWindows  []TimeWindow `json:"time_windows,omitempty"`
+	Methods      []string     `json:"methods,omitempty"`   // empty = any
+	Protocols    []string     `json:"protocols,omitempty"` // http, https; empty = any
+	HeaderMods   []HeaderMod  `json:"header_mods,omitempty"`
+}
+
+// RBISection configures isolation for matching traffic.
+type RBISection struct {
+	Mode              string `json:"mode"` // isolated | not_isolated
+	BlockCopyFromSite bool   `json:"block_copy_from_site"`
+	BlockCopyToSite   bool   `json:"block_copy_to_site"`
+}
+
+// CASBSection lists app restrictions for matching traffic.
+type CASBSection struct {
+	Restrictions []CASBRestriction `json:"restrictions,omitempty"`
+}
+
+// AntimalwareSection enables body scanning for matching traffic.
+type AntimalwareSection struct {
+	Enabled      bool   `json:"enabled"`
+	FailMode     string `json:"fail_mode,omitempty"` // fail_open | fail_closed
+	MaxScanBytes int64  `json:"max_scan_bytes,omitempty"`
+}
+
+// Object is a reusable named condition/action definition.
+type Object struct {
+	ID         uuid.UUID        `json:"id"`
+	Name       string           `json:"name"`
+	Type       string           `json:"type"`
+	Definition ObjectDefinition `json:"definition"`
+	IsSystem   bool             `json:"is_system,omitempty"`
+}
+
+// ObjectDefinition holds type-specific fields for reusable objects.
+type ObjectDefinition struct {
+	// Network / host
+	CIDRs   []string `json:"cidrs,omitempty"`
+	CIDR    string   `json:"cidr,omitempty"`
+	Domains []string `json:"domains,omitempty"`
+	Domain  string   `json:"domain,omitempty"`
+	// Users / UA
+	Usernames  []string `json:"usernames,omitempty"`
+	Username   string   `json:"username,omitempty"`
+	UserAgents []string `json:"user_agents,omitempty"`
+	UserAgent  string   `json:"user_agent,omitempty"`
+	// URL / regex
+	URLs  []string `json:"urls,omitempty"`
+	URL   string   `json:"url,omitempty"`
+	Regex string   `json:"regex,omitempty"`
+	// Time
+	TimeWindow *TimeWindow `json:"time_window,omitempty"`
+	// Header mod
+	HeaderMod *HeaderMod `json:"header_mod,omitempty"`
+	// CASB app ref
+	App     string   `json:"app,omitempty"`
+	Hosts   []string `json:"hosts,omitempty"`
+	Actions []string `json:"actions,omitempty"`
+}
+
+// defaultDecision is the safe outcome when no rules match or snapshot is empty.
+func defaultDecision() Decision {
+	return Decision{
+		FinalAction: ActionAllow,
+		AuthMode:    AuthDisable,
+	}
+}
