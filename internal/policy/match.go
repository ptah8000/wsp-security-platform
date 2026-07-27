package policy

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// matchAnyCondition returns true if conditions is empty (match-all) or any
// condition matches (OR within sources / destinations lists).
func matchAnyCondition(conds []compiledCond, in RequestInput) bool {
	if len(conds) == 0 {
		return true
	}
	for _, c := range conds {
		if c.match(in) {
			return true
		}
	}
	return false
}

// matchAllTimeWindows returns true if windows is empty or the request time
// falls in at least one window (OR across listed windows).
func matchAllTimeWindows(windows []compiledTimeWindow, now time.Time) bool {
	if len(windows) == 0 {
		return true
	}
	for _, w := range windows {
		if w.contains(now) {
			return true
		}
	}
	return false
}

func matchMethod(methods []string, method string) bool {
	if len(methods) == 0 {
		return true
	}
	m := strings.ToUpper(method)
	for _, allowed := range methods {
		if strings.ToUpper(allowed) == m {
			return true
		}
	}
	return false
}

func matchProtocol(protocols []string, u *url.URL) bool {
	if len(protocols) == 0 {
		return true
	}
	scheme := ""
	if u != nil {
		scheme = strings.ToLower(u.Scheme)
	}
	for _, p := range protocols {
		if strings.ToLower(p) == scheme {
			return true
		}
	}
	return false
}

// domainSuffixMatch reports whether host equals domain or is a subdomain of it.
// Host and domain are compared case-insensitively; ports are stripped from host.
// Prevents false positives like "notexample.com" matching "example.com".
func domainSuffixMatch(host, domain string) bool {
	host = strings.ToLower(strings.TrimSpace(host))
	domain = strings.ToLower(strings.TrimSpace(domain))
	if host == "" || domain == "" {
		return false
	}
	// Strip port if present (IPv6 [addr]:port handled poorly; host from URL.Hostname is preferred).
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")

	if host == domain {
		return true
	}
	return strings.HasSuffix(host, "."+domain)
}

// parseCIDROrIP accepts "10.0.0.0/8", "2001:db8::/32", or a bare IP (as /32 or /128).
func parseCIDROrIP(s string) (*net.IPNet, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil, errInvalidCIDR
	}
	if strings.Contains(s, "/") {
		_, n, err := net.ParseCIDR(s)
		return n, err
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, errInvalidCIDR
	}
	if v4 := ip.To4(); v4 != nil {
		return &net.IPNet{IP: v4, Mask: net.CIDRMask(32, 32)}, nil
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(128, 128)}, nil
}

type errString string

func (e errString) Error() string { return string(e) }

const errInvalidCIDR = errString("invalid CIDR or IP")

// hostname extracts the host from the request URL without port.
func hostname(u *url.URL) string {
	if u == nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func fullURLString(u *url.URL) string {
	if u == nil {
		return ""
	}
	return u.String()
}

// --- compiled matchers (immutable; built by Compile) ---

type compiledCond interface {
	match(in RequestInput) bool
}

type condAnyIP struct {
	nets []*net.IPNet
}

func (c condAnyIP) match(in RequestInput) bool {
	if in.ClientIP == nil {
		return false
	}
	ip := in.ClientIP
	for _, n := range c.nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type condAnyUser struct {
	users map[string]struct{}
}

func (c condAnyUser) match(in RequestInput) bool {
	_, ok := c.users[strings.ToLower(in.Username)]
	return ok
}

type condAnyUA struct {
	// Exact match for v1; values lowercased.
	agents map[string]struct{}
}

func (c condAnyUA) match(in RequestInput) bool {
	_, ok := c.agents[strings.ToLower(in.UserAgent)]
	return ok
}

type condAnyDomain struct {
	domains []string
}

func (c condAnyDomain) match(in RequestInput) bool {
	host := hostname(in.URL)
	for _, d := range c.domains {
		if domainSuffixMatch(host, d) {
			return true
		}
	}
	return false
}

type condAnyURLPrefix struct {
	prefixes []string
}

func (c condAnyURLPrefix) match(in RequestInput) bool {
	raw := fullURLString(in.URL)
	for _, p := range c.prefixes {
		if strings.HasPrefix(raw, p) || (in.URL != nil && strings.HasPrefix(in.URL.String(), p)) {
			return true
		}
		// Also allow matching host+path without forcing scheme.
		if in.URL != nil {
			hp := in.URL.Host + in.URL.Path
			if strings.HasPrefix(hp, p) || strings.HasPrefix(raw, p) {
				return true
			}
		}
	}
	return false
}

type condAnyRegex struct {
	res []*regexp.Regexp
}

func (c condAnyRegex) match(in RequestInput) bool {
	raw := fullURLString(in.URL)
	for _, re := range c.res {
		if re.MatchString(raw) {
			return true
		}
	}
	return false
}

type condTime struct {
	windows []compiledTimeWindow
}

func (c condTime) match(in RequestInput) bool {
	return matchAllTimeWindows(c.windows, in.Now)
}

type compiledTimeWindow struct {
	start    *time.Time
	end      *time.Time
	days     map[time.Weekday]struct{} // empty map means all days when useDays is false
	useDays  bool
	startMin int // minutes from midnight; -1 if unset
	endMin   int // minutes from midnight; -1 if unset
	loc      *time.Location
	hasClock bool
	hasAbs   bool
}

func compileTimeWindow(tw TimeWindow) (compiledTimeWindow, error) {
	cw := compiledTimeWindow{startMin: -1, endMin: -1, loc: time.UTC}
	if tw.Timezone != "" {
		loc, err := time.LoadLocation(tw.Timezone)
		if err != nil {
			return cw, err
		}
		cw.loc = loc
	}
	if tw.Start != nil {
		s := tw.Start.UTC()
		cw.start = &s
		cw.hasAbs = true
	}
	if tw.End != nil {
		e := tw.End.UTC()
		cw.end = &e
		cw.hasAbs = true
	}
	if len(tw.DaysOfWeek) > 0 {
		cw.useDays = true
		cw.days = make(map[time.Weekday]struct{}, len(tw.DaysOfWeek))
		for _, d := range tw.DaysOfWeek {
			cw.days[time.Weekday(d)] = struct{}{}
		}
	}
	if tw.StartTime != "" {
		m, err := parseHHMM(tw.StartTime)
		if err != nil {
			return cw, err
		}
		cw.startMin = m
		cw.hasClock = true
	}
	if tw.EndTime != "" {
		m, err := parseHHMM(tw.EndTime)
		if err != nil {
			return cw, err
		}
		cw.endMin = m
		cw.hasClock = true
	}
	return cw, nil
}

func parseHHMM(s string) (int, error) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return 0, errString("invalid time " + s)
	}
	h, err := strconv.Atoi(parts[0])
	if err != nil || h < 0 || h > 23 {
		return 0, errString("invalid hour in " + s)
	}
	m, err := strconv.Atoi(parts[1])
	if err != nil || m < 0 || m > 59 {
		return 0, errString("invalid minute in " + s)
	}
	return h*60 + m, nil
}

func (w compiledTimeWindow) contains(now time.Time) bool {
	if now.IsZero() {
		return false
	}
	// Absolute range (compared in UTC).
	if w.hasAbs {
		t := now.UTC()
		if w.start != nil && t.Before(*w.start) {
			return false
		}
		if w.end != nil && t.After(*w.end) {
			return false
		}
		// If only absolute bounds (no recurring fields), absolute alone decides.
		if !w.useDays && !w.hasClock {
			return true
		}
	}

	local := now.In(w.loc)

	if w.useDays {
		if _, ok := w.days[local.Weekday()]; !ok {
			return false
		}
	}

	if w.hasClock {
		mins := local.Hour()*60 + local.Minute()
		// Overnight windows (e.g. 22:00–06:00): startMin > endMin wraps past midnight.
		// Match with mins >= startMin || mins < endMin (end exclusive, same as same-day windows).
		if w.startMin >= 0 && w.endMin >= 0 && w.startMin > w.endMin {
			if !(mins >= w.startMin || mins < w.endMin) {
				return false
			}
		} else {
			if w.startMin >= 0 && mins < w.startMin {
				return false
			}
			if w.endMin >= 0 && mins >= w.endMin {
				// End is exclusive at exact end minute boundary: 17:00 means until 17:00 not including.
				// Design: "09:00–17:00" business hours → 16:59 in, 17:00 out.
				return false
			}
		}
	}

	// Recurring with only days (no clock) after optional absolute — already checked days.
	if w.useDays || w.hasClock || w.hasAbs {
		return true
	}
	// Empty window definition matches nothing meaningful; treat as no constraint.
	return true
}
