// Package policy implements a pure ordered policy evaluation engine.
// Evaluate and Simulate perform no I/O and never touch a database.
package policy

import (
	"net"
	"net/url"
	"time"

	"github.com/google/uuid"
)

// Action is the primary allow/block outcome of a rule or decision.
type Action string

const (
	ActionAllow Action = "allow"
	ActionBlock Action = "block"
)

// Auth modes for proxy authentication (design §5.3).
const (
	AuthDisable    = "disable"
	AuthIPCached   = "ip_cached"
	AuthPerRequest = "per_request"
)

// RBI modes.
const (
	RBIIsolated    = "isolated"
	RBINotIsolated = "not_isolated"
)

// Condition type identifiers (inline or via object type).
const (
	CondSourceIP          = "source_ip"
	CondSourceUser        = "source_user"
	CondUserAgent         = "user_agent"
	CondDestinationDomain = "destination_domain"
	CondDestinationURL    = "destination_url"
	CondDestinationRegex  = "destination_regex"
	CondTimeWindow        = "time_window"
	CondObjectRef         = "object_ref"
)

// Object type identifiers stored on reusable_objects.type.
const (
	ObjectSourceIP          = "source_ip"
	ObjectSourceUser        = "source_user"
	ObjectUserAgent         = "user_agent"
	ObjectDestinationDomain = "destination_domain"
	ObjectDestinationURL    = "destination_url"
	ObjectDestinationRegex  = "destination_regex"
	ObjectTimeWindow        = "time_window"
	ObjectHeaderMod         = "header_mod"
	ObjectCASBAppRef        = "casb_app_ref"
)

// Header modification ops / targets.
const (
	HeaderSet    = "set"
	HeaderAppend = "append"
	HeaderRemove = "remove"

	HeaderRequest  = "request"
	HeaderResponse = "response"
)

// Decision is the pure result of evaluating a request against policy.
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

// RequestInput is the pure input for Evaluate / Simulate.
type RequestInput struct {
	ClientIP  net.IP
	Username  string
	UserAgent string
	Method    string
	URL       *url.URL
	Now       time.Time
}

// CASBRestriction is an accumulated CASB control from matched rules.
type CASBRestriction struct {
	App     string   `json:"app"`
	Actions []string `json:"actions"`
	// Optional type filters (MIME / extensions); empty = all.
	MIMETypes  []string `json:"mime_types,omitempty"`
	Extensions []string `json:"extensions,omitempty"`
}

// HeaderMod is an HTTP header mutation applied on allow paths.
type HeaderMod struct {
	Op     string `json:"op"`     // set | append | remove
	Target string `json:"target"` // request | response
	Name   string `json:"name"`
	Value  string `json:"value,omitempty"`
}

// Condition is an inline match condition or reference to a reusable object.
type Condition struct {
	Type     string     `json:"type"`
	Value    string     `json:"value,omitempty"`
	ObjectID *uuid.UUID `json:"object_id,omitempty"`
	// Optional structured fields (used when Type is time_window or object embeds them).
	TimeWindow *TimeWindow `json:"time_window,omitempty"`
	Regex      string      `json:"regex,omitempty"`
}

// TimeWindow is either an absolute range and/or a recurring weekly window.
// DaysOfWeek uses time.Weekday values (0=Sunday … 6=Saturday). Empty = all days.
// StartTime/EndTime are "HH:MM" in the given Timezone (default UTC).
type TimeWindow struct {
	Start      *time.Time `json:"start,omitempty"`
	End        *time.Time `json:"end,omitempty"`
	DaysOfWeek []int      `json:"days_of_week,omitempty"`
	StartTime  string     `json:"start_time,omitempty"`
	EndTime    string     `json:"end_time,omitempty"`
	Timezone   string     `json:"timezone,omitempty"`
}

// Rule is one ordered policy entry (maps to policies table row + sections JSON).
type Rule struct {
	ID          uuid.UUID    `json:"id"`
	Name        string       `json:"name"`
	Description string       `json:"description,omitempty"`
	Enabled     bool         `json:"enabled"`
	Priority    int          `json:"priority"` // lower = evaluated first
	Sections    RuleSections `json:"sections"`
}

// RuleSections mirrors policies.sections JSONB.
type RuleSections struct {
	General      GeneralSection      `json:"general"`
	WebFiltering WebFilteringSection `json:"web_filtering"`
	RBI          RBISection          `json:"rbi"`
	CASB         CASBSection         `json:"casb"`
	Antimalware  AntimalwareSection  `json:"antimalware"`
}

// GeneralSection is the primary match + action configuration.
type GeneralSection struct {
	Sources      []Condition `json:"sources"`
	Destinations []Condition `json:"destinations"`
	Action       Action      `json:"action"`
	BlockPageID  *uuid.UUID  `json:"block_page_id,omitempty"`
	BlockReason  string      `json:"block_reason,omitempty"`
	TLSIntercept bool        `json:"tls_intercept"`
	AuthMode     string      `json:"auth_mode,omitempty"`
}

// WebFilteringSection adds time/method/protocol filters and header mods.
type WebFilteringSection struct {
	// Optional overrides; when non-empty they further restrict the match
	// (AND with general). Empty means inherit general only.
	Sources      []Condition  `json:"sources,omitempty"`
	Destinations []Condition  `json:"destinations,omitempty"`
	TimeWindows  []TimeWindow `json:"time_windows,omitempty"`
	Methods      []string     `json:"methods,omitempty"`   // empty = any
	Protocols    []string     `json:"protocols,omitempty"` // http, https; empty = any
	HeaderMods   []HeaderMod  `json:"header_mods,omitempty"`
}

// RBISection configures isolation for matching traffic.
type RBISection struct {
	Mode              string `json:"mode"` // isolated | not_isolated
	BlockCopyFromSite bool   `json:"block_copy_from_site"`
	BlockCopyToSite   bool   `json:"block_copy_to_site"`
}

// CASBSection lists app restrictions for matching traffic.
type CASBSection struct {
	Restrictions []CASBRestriction `json:"restrictions,omitempty"`
}

// AntimalwareSection enables body scanning for matching traffic.
type AntimalwareSection struct {
	Enabled      bool   `json:"enabled"`
	FailMode     string `json:"fail_mode,omitempty"` // fail_open | fail_closed
	MaxScanBytes int64  `json:"max_scan_bytes,omitempty"`
}

// Object is a reusable named condition/action definition.
type Object struct {
	ID         uuid.UUID        `json:"id"`
	Name       string           `json:"name"`
	Type       string           `json:"type"`
	Definition ObjectDefinition `json:"definition"`
	IsSystem   bool             `json:"is_system,omitempty"`
}

// ObjectDefinition holds type-specific fields for reusable objects.
type ObjectDefinition struct {
	// Network / host
	CIDRs   []string `json:"cidrs,omitempty"`
	CIDR    string   `json:"cidr,omitempty"`
	Domains []string `json:"domains,omitempty"`
	Domain  string   `json:"domain,omitempty"`
	// Users / UA
	Usernames  []string `json:"usernames,omitempty"`
	Username   string   `json:"username,omitempty"`
	UserAgents []string `json:"user_agents,omitempty"`
	UserAgent  string   `json:"user_agent,omitempty"`
	// URL / regex
	URLs  []string `json:"urls,omitempty"`
	URL   string   `json:"url,omitempty"`
	Regex string   `json:"regex,omitempty"`
	// Time
	TimeWindow *TimeWindow `json:"time_window,omitempty"`
	// Header mod
	HeaderMod *HeaderMod `json:"header_mod,omitempty"`
	// CASB app ref
	App     string   `json:"app,omitempty"`
	Hosts   []string `json:"hosts,omitempty"`
	Actions []string `json:"actions,omitempty"`
}

// defaultDecision is the safe outcome when no rules match or snapshot is empty.
func defaultDecision() Decision {
	return Decision{
		FinalAction: ActionAllow,
		AuthMode:    AuthDisable,
	}
}
