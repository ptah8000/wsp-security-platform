package casb

import (
	"context"
	"net/http"
	"strings"

	"github.com/wsp-security/wsp/internal/policy"
)

// Inspector is the catalog of detectors used by the proxy pipeline.
// It routes restrictions to detectors by app id and host suffix.
type Inspector struct {
	detectors []Detector
	byApp     map[string]Detector
}

// NewInspector builds an Inspector from the given detectors (later apps override earlier on same id).
func NewInspector(detectors ...Detector) *Inspector {
	in := &Inspector{
		detectors: make([]Detector, 0, len(detectors)),
		byApp:     make(map[string]Detector, len(detectors)),
	}
	for _, d := range detectors {
		if d == nil {
			continue
		}
		app := strings.ToLower(strings.TrimSpace(d.App()))
		if app == "" {
			continue
		}
		in.detectors = append(in.detectors, d)
		in.byApp[app] = d
	}
	return in
}

// Default returns the v1 catalog: ChatGPT + Google Drive (full) and Slack/M365/WhatsApp (partial).
func Default() *Inspector {
	return NewInspector(
		ChatGPT{},
		GoogleDrive{},
		Slack{},
		M365{},
		WhatsApp{},
	)
}

// Detectors returns registered detectors (for diagnostics / coverage matrix).
func (in *Inspector) Detectors() []Detector {
	if in == nil {
		return nil
	}
	out := make([]Detector, len(in.detectors))
	copy(out, in.detectors)
	return out
}

// InspectRequest evaluates request-side CASB controls.
// Returns the first Hit among matching restrictions, or nil.
func (in *Inspector) InspectRequest(ctx context.Context, req *http.Request, restrictions []policy.CASBRestriction) *Hit {
	if in == nil || req == nil || len(restrictions) == 0 {
		return nil
	}
	host := requestHost(req)
	for _, r := range restrictions {
		d := in.detectorFor(r, host)
		if d == nil {
			continue
		}
		if hit := d.InspectRequest(ctx, req, r); hit != nil {
			return hit
		}
	}
	return nil
}

// InspectResponse evaluates response-side CASB controls.
// Returns the first Hit among matching restrictions, or nil.
func (in *Inspector) InspectResponse(ctx context.Context, req *http.Request, resp *http.Response, restrictions []policy.CASBRestriction) *Hit {
	if in == nil || req == nil || resp == nil || len(restrictions) == 0 {
		return nil
	}
	host := requestHost(req)
	for _, r := range restrictions {
		d := in.detectorFor(r, host)
		if d == nil {
			continue
		}
		if hit := d.InspectResponse(ctx, req, resp, r); hit != nil {
			return hit
		}
	}
	return nil
}

// detectorFor resolves a restriction to a detector that also claims the request host.
// If App is set, only that detector is considered (still must match host).
// If App is empty, any detector whose host suffixes match may be used (first registered).
func (in *Inspector) detectorFor(r policy.CASBRestriction, host string) Detector {
	app := strings.ToLower(strings.TrimSpace(r.App))
	if app != "" {
		d, ok := in.byApp[app]
		if !ok {
			return nil
		}
		if !hostMatches(host, d.HostSuffixes()) {
			return nil
		}
		return d
	}
	// Unscoped restriction: match first detector for this host.
	for _, d := range in.detectors {
		if hostMatches(host, d.HostSuffixes()) {
			return d
		}
	}
	return nil
}

// ProxyAdapter implements the proxy CASBInspector seam (Decision → reason string).
// When Decision.CASB is empty, inspection is a no-op.
type ProxyAdapter struct {
	Inner *Inspector
}

// NewProxyAdapter returns a ProxyAdapter with the default detector catalog.
func NewProxyAdapter() *ProxyAdapter {
	return &ProxyAdapter{Inner: Default()}
}

// InspectRequest implements proxy.CASBInspector.
func (a *ProxyAdapter) InspectRequest(ctx context.Context, req *http.Request, d policy.Decision) (blockReason string, err error) {
	if a == nil || a.Inner == nil || len(d.CASB) == 0 {
		return "", nil
	}
	hit := a.Inner.InspectRequest(ctx, req, d.CASB)
	if hit == nil {
		return "", nil
	}
	if hit.Message != "" {
		return hit.Message, nil
	}
	return FormatMessage(hit.App, hit.Action, ""), nil
}

// InspectResponse implements proxy.CASBInspector.
func (a *ProxyAdapter) InspectResponse(ctx context.Context, req *http.Request, resp *http.Response, d policy.Decision) (blockReason string, err error) {
	if a == nil || a.Inner == nil || len(d.CASB) == 0 {
		return "", nil
	}
	hit := a.Inner.InspectResponse(ctx, req, resp, d.CASB)
	if hit == nil {
		return "", nil
	}
	if hit.Message != "" {
		return hit.Message, nil
	}
	return FormatMessage(hit.App, hit.Action, ""), nil
}
