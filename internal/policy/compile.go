package policy

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// Snapshot is an immutable compiled policy set for hot-path evaluation.
// Safe for concurrent readers after publication via Engine.Swap.
type Snapshot struct {
	rules []compiledRule
}

// compiledRule is a single enabled rule ready for pure matching.
type compiledRule struct {
	id       uuid.UUID
	priority int
	name     string

	sources      []compiledCond
	destinations []compiledCond
	// web_filtering additional constraints (AND)
	webSources      []compiledCond
	webDestinations []compiledCond
	timeWindows     []compiledTimeWindow
	methods         []string
	protocols       []string

	action       Action
	blockPageID  *uuid.UUID
	blockReason  string
	tlsIntercept bool
	authMode     string

	rbiIsolated      bool
	rbiExplicit      bool // true if rbi.mode was isolated or not_isolated (not empty)
	rbiBlockCopyFrom bool
	rbiBlockCopyTo   bool

	casb              []CASBRestriction
	malwareScan       bool
	malwareFailClosed bool
	malwareMaxBytes   int64
	headerMods        []HeaderMod
}

// Compile builds an immutable Snapshot from rules and reusable objects.
// Rules are ordered by ascending priority (lower first). Disabled rules are omitted.
// Compile itself performs no I/O; objects must already be loaded by the caller.
func Compile(rules []Rule, objects map[uuid.UUID]Object) (*Snapshot, error) {
	if objects == nil {
		objects = map[uuid.UUID]Object{}
	}

	// Stable order: priority ASC, then name, then id for determinism.
	sorted := make([]Rule, len(rules))
	copy(sorted, rules)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Priority != sorted[j].Priority {
			return sorted[i].Priority < sorted[j].Priority
		}
		if sorted[i].Name != sorted[j].Name {
			return sorted[i].Name < sorted[j].Name
		}
		return sorted[i].ID.String() < sorted[j].ID.String()
	})

	out := make([]compiledRule, 0, len(sorted))
	for _, r := range sorted {
		if !r.Enabled {
			continue
		}
		cr, err := compileRule(r, objects)
		if err != nil {
			return nil, fmt.Errorf("rule %s (%s): %w", r.ID, r.Name, err)
		}
		out = append(out, cr)
	}
	return &Snapshot{rules: out}, nil
}

func compileRule(r Rule, objects map[uuid.UUID]Object) (compiledRule, error) {
	g := r.Sections.General
	w := r.Sections.WebFiltering
	cr := compiledRule{
		id:               r.ID,
		priority:         r.Priority,
		name:             r.Name,
		action:           normalizeAction(g.Action),
		blockPageID:      cloneUUID(g.BlockPageID),
		blockReason:      g.BlockReason,
		tlsIntercept:     g.TLSIntercept,
		authMode:         normalizeAuthMode(g.AuthMode),
		rbiIsolated:      strings.EqualFold(strings.TrimSpace(r.Sections.RBI.Mode), RBIIsolated),
		rbiExplicit:      isExplicitRBIMode(r.Sections.RBI.Mode),
		rbiBlockCopyFrom: r.Sections.RBI.BlockCopyFromSite,
		rbiBlockCopyTo:   r.Sections.RBI.BlockCopyToSite,
		malwareScan:      r.Sections.Antimalware.Enabled,
		malwareFailClosed: strings.EqualFold(strings.TrimSpace(r.Sections.Antimalware.FailMode), "fail_closed"),
		malwareMaxBytes:   r.Sections.Antimalware.MaxScanBytes,
		methods:           append([]string(nil), w.Methods...),
		protocols:         append([]string(nil), w.Protocols...),
	}

	var err error
	if cr.sources, err = compileConditions(g.Sources, objects); err != nil {
		return cr, fmt.Errorf("sources: %w", err)
	}
	if cr.destinations, err = compileConditions(g.Destinations, objects); err != nil {
		return cr, fmt.Errorf("destinations: %w", err)
	}
	if cr.webSources, err = compileConditions(w.Sources, objects); err != nil {
		return cr, fmt.Errorf("web sources: %w", err)
	}
	if cr.webDestinations, err = compileConditions(w.Destinations, objects); err != nil {
		return cr, fmt.Errorf("web destinations: %w", err)
	}

	for _, tw := range w.TimeWindows {
		cw, err := compileTimeWindow(tw)
		if err != nil {
			return cr, fmt.Errorf("time window: %w", err)
		}
		cr.timeWindows = append(cr.timeWindows, cw)
	}

	if len(r.Sections.CASB.Restrictions) > 0 {
		cr.casb = append([]CASBRestriction(nil), r.Sections.CASB.Restrictions...)
	}
	if len(w.HeaderMods) > 0 {
		cr.headerMods = append([]HeaderMod(nil), w.HeaderMods...)
	}
	return cr, nil
}

func normalizeAction(a Action) Action {
	switch Action(strings.ToLower(string(a))) {
	case ActionBlock:
		return ActionBlock
	default:
		return ActionAllow
	}
}

func normalizeAuthMode(m string) string {
	switch strings.ToLower(strings.TrimSpace(m)) {
	case AuthIPCached:
		return AuthIPCached
	case AuthPerRequest:
		return AuthPerRequest
	case AuthDisable, "":
		return AuthDisable
	default:
		return m
	}
}

func cloneUUID(id *uuid.UUID) *uuid.UUID {
	if id == nil {
		return nil
	}
	v := *id
	return &v
}

func compileConditions(conds []Condition, objects map[uuid.UUID]Object) ([]compiledCond, error) {
	if len(conds) == 0 {
		return nil, nil
	}
	out := make([]compiledCond, 0, len(conds))
	for i, c := range conds {
		cc, err := compileOneCondition(c, objects)
		if err != nil {
			return nil, fmt.Errorf("condition[%d]: %w", i, err)
		}
		if cc != nil {
			out = append(out, cc)
		}
	}
	return out, nil
}

// normalizeConditionType maps short aliases used in UI/API to canonical types.
func normalizeConditionType(typ string) string {
	switch strings.ToLower(strings.TrimSpace(typ)) {
	case "domain", "host", "hostname", CondDestinationDomain:
		return CondDestinationDomain
	case "url", CondDestinationURL:
		return CondDestinationURL
	case "regex", CondDestinationRegex:
		return CondDestinationRegex
	case "ip", "cidr", "src_ip", CondSourceIP:
		return CondSourceIP
	case "user", "username", CondSourceUser:
		return CondSourceUser
	case "ua", CondUserAgent:
		return CondUserAgent
	case "time", CondTimeWindow:
		return CondTimeWindow
	case "category", "url-category", CondURLCategory:
		return CondURLCategory
	case "object", "ref", CondObjectRef:
		return CondObjectRef
	default:
		return strings.TrimSpace(typ)
	}
}

func isExplicitRBIMode(mode string) bool {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case RBIIsolated, RBINotIsolated:
		return true
	default:
		return false
	}
}

func compileOneCondition(c Condition, objects map[uuid.UUID]Object) (compiledCond, error) {
	typ := normalizeConditionType(c.Type)
	if typ == CondObjectRef || c.ObjectID != nil {
		if c.ObjectID == nil {
			return nil, fmt.Errorf("object_ref missing object_id")
		}
		obj, ok := objects[*c.ObjectID]
		if !ok {
			return nil, fmt.Errorf("unknown object %s", c.ObjectID)
		}
		return compileObject(obj)
	}

	switch typ {
	case CondSourceIP:
		n, err := parseCIDROrIP(c.Value)
		if err != nil {
			return nil, err
		}
		return condAnyIP{nets: []*net.IPNet{n}}, nil

	case CondSourceUser:
		u := strings.ToLower(strings.TrimSpace(c.Value))
		return condAnyUser{users: map[string]struct{}{u: {}}}, nil

	case CondUserAgent:
		ua := strings.ToLower(c.Value)
		return condAnyUA{agents: map[string]struct{}{ua: {}}}, nil

	case CondDestinationDomain:
		d := strings.TrimSpace(c.Value)
		if d == "" {
			return nil, fmt.Errorf("empty domain")
		}
		return condAnyDomain{domains: []string{d}}, nil

	case CondDestinationURL:
		if c.Value == "" {
			return nil, fmt.Errorf("empty url")
		}
		return condAnyURLPrefix{prefixes: []string{c.Value}}, nil

	case CondDestinationRegex:
		pat := c.Regex
		if pat == "" {
			pat = c.Value
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
		return condAnyRegex{res: []*regexp.Regexp{re}}, nil

	case CondURLCategory:
		id := strings.ToLower(strings.TrimSpace(c.Value))
		if id == "" {
			return nil, fmt.Errorf("empty url_category")
		}
		if _, ok := CategoryByID(id); !ok {
			return nil, fmt.Errorf("unknown url_category %q", id)
		}
		return condURLCategory{id: id}, nil

	case CondTimeWindow:
		tw := TimeWindow{}
		if c.TimeWindow != nil {
			tw = *c.TimeWindow
		}
		cw, err := compileTimeWindow(tw)
		if err != nil {
			return nil, err
		}
		return condTime{windows: []compiledTimeWindow{cw}}, nil

	case "":
		return nil, fmt.Errorf("missing condition type")

	default:
		return nil, fmt.Errorf("unsupported condition type %q", typ)
	}
}

func compileObject(obj Object) (compiledCond, error) {
	def := obj.Definition
	switch obj.Type {
	case ObjectSourceIP:
		var nets []*net.IPNet
		cidrs := append([]string(nil), def.CIDRs...)
		if def.CIDR != "" {
			cidrs = append(cidrs, def.CIDR)
		}
		if len(cidrs) == 0 {
			return nil, fmt.Errorf("object %s: no cidrs", obj.ID)
		}
		for _, s := range cidrs {
			n, err := parseCIDROrIP(s)
			if err != nil {
				return nil, fmt.Errorf("object %s: %w", obj.ID, err)
			}
			nets = append(nets, n)
		}
		return condAnyIP{nets: nets}, nil

	case ObjectSourceUser:
		users := map[string]struct{}{}
		for _, u := range def.Usernames {
			users[strings.ToLower(u)] = struct{}{}
		}
		if def.Username != "" {
			users[strings.ToLower(def.Username)] = struct{}{}
		}
		if len(users) == 0 {
			return nil, fmt.Errorf("object %s: no usernames", obj.ID)
		}
		return condAnyUser{users: users}, nil

	case ObjectUserAgent:
		agents := map[string]struct{}{}
		for _, a := range def.UserAgents {
			agents[strings.ToLower(a)] = struct{}{}
		}
		if def.UserAgent != "" {
			agents[strings.ToLower(def.UserAgent)] = struct{}{}
		}
		if len(agents) == 0 {
			return nil, fmt.Errorf("object %s: no user agents", obj.ID)
		}
		return condAnyUA{agents: agents}, nil

	case ObjectDestinationDomain:
		var domains []string
		domains = append(domains, def.Domains...)
		if def.Domain != "" {
			domains = append(domains, def.Domain)
		}
		if len(domains) == 0 {
			return nil, fmt.Errorf("object %s: no domains", obj.ID)
		}
		return condAnyDomain{domains: domains}, nil

	case ObjectDestinationURL:
		var prefixes []string
		prefixes = append(prefixes, def.URLs...)
		if def.URL != "" {
			prefixes = append(prefixes, def.URL)
		}
		if len(prefixes) == 0 {
			return nil, fmt.Errorf("object %s: no urls", obj.ID)
		}
		return condAnyURLPrefix{prefixes: prefixes}, nil

	case ObjectDestinationRegex:
		if def.Regex == "" {
			return nil, fmt.Errorf("object %s: empty regex", obj.ID)
		}
		re, err := regexp.Compile(def.Regex)
		if err != nil {
			return nil, err
		}
		return condAnyRegex{res: []*regexp.Regexp{re}}, nil

	case ObjectTimeWindow:
		if def.TimeWindow == nil {
			return nil, fmt.Errorf("object %s: missing time_window", obj.ID)
		}
		cw, err := compileTimeWindow(*def.TimeWindow)
		if err != nil {
			return nil, err
		}
		return condTime{windows: []compiledTimeWindow{cw}}, nil

	case ObjectCASBAppRef:
		// CASB app refs as destination conditions: match hosts with domain suffix rules.
		if len(def.Hosts) == 0 {
			return nil, fmt.Errorf("object %s: casb_app_ref has no hosts", obj.ID)
		}
		return condAnyDomain{domains: append([]string(nil), def.Hosts...)}, nil

	default:
		return nil, fmt.Errorf("object %s: unsupported type %q", obj.ID, obj.Type)
	}
}

// matches reports whether the compiled rule matches the request input.
func (r *compiledRule) matches(in RequestInput) bool {
	if !matchAnyCondition(r.sources, in) {
		return false
	}
	if !matchAnyCondition(r.destinations, in) {
		return false
	}
	if !matchAnyCondition(r.webSources, in) {
		return false
	}
	if !matchAnyCondition(r.webDestinations, in) {
		return false
	}
	if !matchAllTimeWindows(r.timeWindows, in.Now) {
		return false
	}
	if !matchMethod(r.methods, in.Method) {
		return false
	}
	if !matchProtocol(r.protocols, in.URL) {
		return false
	}
	return true
}
