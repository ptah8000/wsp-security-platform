package proxy

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/auth"
	"github.com/wsp-security/wsp/internal/blockpage"
	"github.com/wsp-security/wsp/internal/casb"
	"github.com/wsp-security/wsp/internal/logging"
	"github.com/wsp-security/wsp/internal/malware"
	"github.com/wsp-security/wsp/internal/policy"
)

// Pipeline hook interfaces.

// CASBInspector inspects request/response for cloud app controls.
// Implementations live in package casb (e.g. casb.ProxyAdapter). Returns a
// targeted block reason string when a restriction hits; empty means allow.
type CASBInspector interface {
	// InspectRequest returns a block reason when the request should be denied.
	InspectRequest(ctx context.Context, req *http.Request, d policy.Decision) (blockReason string, err error)
	InspectResponse(ctx context.Context, req *http.Request, resp *http.Response, d policy.Decision) (blockReason string, err error)
}

// RBIOrchestrator hands off isolated browsing.
type RBIOrchestrator interface {
	// ShouldIsolate reports whether this request should use RBI.
	ShouldIsolate(d policy.Decision) bool
	// HandleIsolation serves the isolation viewer instead of origin bytes.
	// Returns true if the request was fully handled (viewer HTML written).
	// Returns false when isolation cannot start (Docker down, max sessions, …)
	// so the proxy fails closed with a block page.
	HandleIsolation(w http.ResponseWriter, req *http.Request, d policy.Decision) bool
}

// rbiPathServer is an optional extension for /rbi/* viewer and WebSocket routes.
// Implemented by *rbi.Orchestrator; stubs omit it.
type rbiPathServer interface {
	ServeRBIPath(w http.ResponseWriter, req *http.Request) bool
}

// noopCASB is a silent no-op used only when explicitly desired in tests.
// Production defaults to casb.NewProxyAdapter() via ensureHooks / main.
type noopCASB struct{}

func (noopCASB) InspectRequest(context.Context, *http.Request, policy.Decision) (string, error) {
	return "", nil
}
func (noopCASB) InspectResponse(context.Context, *http.Request, *http.Response, policy.Decision) (string, error) {
	return "", nil
}

// noopRBI is the default RBI stub (never isolates).
type noopRBI struct{}

func (noopRBI) ShouldIsolate(policy.Decision) bool { return false }
func (noopRBI) HandleIsolation(http.ResponseWriter, *http.Request, policy.Decision) bool {
	return false
}

// pipelineResult holds evaluation outcome for one request/connect.
type pipelineResult struct {
	Input     policy.RequestInput
	Decision  policy.Decision
	Username  string
	RequestID uuid.UUID
	SessionID uuid.UUID
	Start     time.Time
}

// buildInput constructs policy.RequestInput from an HTTP request.
func buildInput(req *http.Request, clientIP net.IP, username string, target *url.URL, method string) policy.RequestInput {
	ua := ""
	if req != nil {
		ua = req.UserAgent()
		if method == "" {
			method = req.Method
		}
	}
	if method == "" {
		method = http.MethodGet
	}
	return policy.RequestInput{
		ClientIP:  clientIP,
		Username:  username,
		UserAgent: ua,
		Method:    method,
		URL:       target,
		Now:       time.Now().UTC(),
	}
}

// evaluate runs policy.Engine (nil-safe → default allow).
func (s *Server) evaluate(in policy.RequestInput) policy.Decision {
	if s != nil && s.evaluateHook != nil {
		return s.evaluateHook(in)
	}
	if s == nil || s.Engine == nil {
		return policy.Decision{FinalAction: policy.ActionAllow, AuthMode: policy.AuthDisable}
	}
	return s.Engine.Evaluate(in)
}

// resolveAuth enforces proxy auth based on decision.AuthMode.
// Returns username, whether auth failed (caller should 407), and optional www-auth.
// When AuthMode is disable/empty, Proxy-Authorization is ignored (never treated as identity).
func (s *Server) resolveAuth(ctx context.Context, req *http.Request, clientIP string, mode string) (username string, need407 bool) {
	if mode == "" || mode == policy.AuthDisable {
		return "", false
	}

	ip := clientIP

	if mode == policy.AuthIPCached && s.AuthCache != nil {
		if u, _, ok := s.AuthCache.Get(ctx, ip); ok {
			return u, false
		}
	}

	user, pass, ok := proxyBasicAuth(req)
	if !ok {
		return "", true
	}

	if s.Store == nil {
		// Without store we cannot verify; treat as unauthenticated.
		return "", true
	}

	dbUser, err := s.Store.GetUserByUsername(ctx, user)
	if err != nil || !dbUser.Enabled || !auth.CheckPassword(dbUser.PasswordHash, pass) {
		return "", true
	}

	if mode == policy.AuthIPCached && s.AuthCache != nil {
		if err := s.AuthCache.Put(ctx, ip, dbUser.ID, dbUser.Username); err != nil {
			slog.Warn("proxy auth cache put failed", "err", err)
		}
	}
	return dbUser.Username, false
}

func proxyBasicAuth(req *http.Request) (username, password string, ok bool) {
	if req == nil {
		return "", "", false
	}
	h := req.Header.Get("Proxy-Authorization")
	if h == "" {
		return "", "", false
	}
	const prefix = "Basic "
	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
		return "", "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
	if err != nil {
		return "", "", false
	}
	user, pass, found := strings.Cut(string(raw), ":")
	if !found {
		return "", "", false
	}
	return user, pass, true
}

func writeProxyAuthRequired(w http.ResponseWriter) {
	w.Header().Set("Proxy-Authenticate", `Basic realm="WSP"`)
	http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
}

// loadBlockHTML returns custom or default block page HTML.
func (s *Server) loadBlockHTML(ctx context.Context, pageID *uuid.UUID) string {
	if s != nil && s.Store != nil {
		if pageID != nil && *pageID != uuid.Nil {
			if p, err := s.Store.GetBlockPage(ctx, *pageID); err == nil && p.HTML != "" {
				return p.HTML
			}
		}
		if p, err := s.Store.GetSystemDefaultBlockPage(ctx); err == nil && p.HTML != "" {
			return p.HTML
		}
	}
	return blockpage.DefaultHTML()
}

func (s *Server) writeBlockPage(w http.ResponseWriter, req *http.Request, d policy.Decision, clientIP, username string, target *url.URL) int {
	ctx := req.Context()
	html := s.loadBlockHTML(ctx, d.BlockPageID)
	ruleID := ""
	if len(d.MatchedRuleIDs) > 0 {
		ruleID = d.MatchedRuleIDs[0].String()
	}
	urlStr := ""
	if target != nil {
		urlStr = target.String()
	}
	body := blockpage.Render(html, blockpage.Context{
		URL:       urlStr,
		Reason:    d.BlockReason,
		Username:  username,
		ClientIP:  clientIP,
		RuleID:    ruleID,
		Timestamp: time.Now().UTC(),
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusForbidden)
	_, _ = w.Write(body)
	return len(body)
}

// applyRequestHeaderMods mutates req headers per policy.
func applyRequestHeaderMods(req *http.Request, mods []policy.HeaderMod) {
	for _, m := range mods {
		if m.Target != "" && m.Target != policy.HeaderRequest {
			continue
		}
		switch m.Op {
		case policy.HeaderSet:
			req.Header.Set(m.Name, m.Value)
		case policy.HeaderAppend:
			req.Header.Add(m.Name, m.Value)
		case policy.HeaderRemove:
			req.Header.Del(m.Name)
		}
	}
}

// applyResponseHeaderMods mutates resp headers per policy.
func applyResponseHeaderMods(resp *http.Response, mods []policy.HeaderMod) {
	if resp == nil {
		return
	}
	for _, m := range mods {
		if m.Target != policy.HeaderResponse {
			continue
		}
		switch m.Op {
		case policy.HeaderSet:
			resp.Header.Set(m.Name, m.Value)
		case policy.HeaderAppend:
			resp.Header.Add(m.Name, m.Value)
		case policy.HeaderRemove:
			resp.Header.Del(m.Name)
		}
	}
}

// recordOutcome writes a request log via Recorder.
func (s *Server) recordOutcome(ctx context.Context, pr *pipelineResult, req *http.Request, target *url.URL, decision string, reqSize, respSize int64, errMsg string) {
	if s == nil || s.Recorder == nil || pr == nil {
		return
	}
	scheme, host, path, query, urlStr := "", "", "", "", ""
	if target != nil {
		scheme = target.Scheme
		host = target.Host
		path = target.Path
		query = target.RawQuery
		urlStr = target.String()
	}
	method := ""
	ua := ""
	proto := ""
	if req != nil {
		method = req.Method
		ua = req.UserAgent()
		proto = req.Proto
	}
	actions := map[string]any{
		"tls_intercept": pr.Decision.TLSIntercept,
		"rbi_isolated":  pr.Decision.RBIIsolated,
		"malware_scan":  pr.Decision.MalwareScan,
		"auth_mode":     pr.Decision.AuthMode,
	}
	if len(pr.Decision.CASB) > 0 {
		actions["casb"] = pr.Decision.CASB
	}
	timings := map[string]any{
		"total_ms": time.Since(pr.Start).Milliseconds(),
	}
	var sessionID *uuid.UUID
	if pr.SessionID != uuid.Nil {
		id := pr.SessionID
		sessionID = &id
	}
	s.Recorder.Record(ctx, logging.RequestRecord{
		SessionID:        sessionID,
		RequestID:        pr.RequestID,
		TS:               time.Now().UTC(),
		ClientIP:         ipString(pr.Input.ClientIP),
		Username:         pr.Username,
		UserAgent:        ua,
		Method:           method,
		Scheme:           scheme,
		Host:             host,
		Path:             path,
		Query:            query,
		URL:              urlStr,
		Protocol:         proto,
		RequestSize:      reqSize,
		ResponseSize:     respSize,
		Decision:         decision,
		MatchedRuleIDs:   pr.Decision.MatchedRuleIDs,
		EvaluatedRuleIDs: pr.Decision.EvaluatedRuleIDs,
		Actions:          actions,
		Timings:          timings,
		BlockReason:      pr.Decision.BlockReason,
		BlockPageID:      pr.Decision.BlockPageID,
		Error:            errMsg,
	})
}

func ipString(ip net.IP) string {
	if ip == nil {
		return ""
	}
	return ip.String()
}

// clientIPFromRequest extracts the remote IP (no X-Forwarded-For trust in v1).
func clientIPFromRequest(req *http.Request) net.IP {
	if req == nil || req.RemoteAddr == "" {
		return nil
	}
	host, _, err := net.SplitHostPort(req.RemoteAddr)
	if err != nil {
		return net.ParseIP(req.RemoteAddr)
	}
	return net.ParseIP(host)
}

// ensureHooks fills default stubs when interfaces are nil.
// Safe for concurrent callers: initialization runs at most once (sync.Once).
// Prefer calling from Start; request paths also call for tests that skip Start.
func (s *Server) ensureHooks() {
	if s == nil {
		return
	}
	s.hooksOnce.Do(func() {
		if s.CASB == nil {
			// Default: full CASB catalog (no-op only when Decision.CASB is empty).
			s.CASB = casb.NewProxyAdapter()
		}
		if s.Malware == nil {
			s.Malware = malware.Nop{}
		}
		if s.RBI == nil {
			s.RBI = noopRBI{}
		}
		if s.Sessions == nil {
			s.Sessions = NewSessionTracker(s.Store, DefaultSessionIdle)
		}
		if s.Dialer == nil {
			s.Dialer = &net.Dialer{Timeout: 30 * time.Second}
		}
		if s.Transport == nil {
			s.Transport = &http.Transport{
				Proxy:                 nil, // never chain
				DialContext:           s.Dialer.DialContext,
				ForceAttemptHTTP2:     true,
				MaxIdleConns:          100,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				// Origin TLS: system roots (MITM is client-side only).
			}
		}
	})
}

// needsIsolation reports whether this request must be handled by RBI (fail-closed).
// Checks Decision.RBIIsolated explicitly, and RBIOrchestrator.ShouldIsolate.
func needsIsolation(d policy.Decision, rbi RBIOrchestrator) bool {
	if d.RBIIsolated {
		return true
	}
	if rbi != nil && rbi.ShouldIsolate(d) {
		return true
	}
	return false
}

// rbiUnavailableReason is served when isolation is required but HandleIsolation fails.
const rbiUnavailableReason = "Remote browser isolation required but unavailable"

// decisionLabel maps FinalAction to log decision string, with overrides.
func decisionLabel(d policy.Decision, override string) string {
	if override != "" {
		return override
	}
	if d.FinalAction == policy.ActionBlock {
		return string(policy.ActionBlock)
	}
	return string(policy.ActionAllow)
}

// malwareScanOutcome is the result of buffering + scanning a body.
type malwareScanOutcome struct {
	// Body is a replacement ReadCloser with the buffered content (and any unread tail).
	Body io.ReadCloser
	// Size is the number of bytes buffered for scanning (not including un-scanned tail).
	Size int64
	// BlockReason is non-empty when the request/response must be blocked.
	BlockReason string
	// ErrMsg is recorded in request logs (scan error detail or empty).
	ErrMsg string
}

// scanHTTPBody buffers up to maxBytes, scans via Malware, and returns a
// replacement body for forwarding. When Content-Length exceeds the cap the
// body is not scanned (fail-open on size). Scan transport errors honor
// MalwareFailClosed.
func (s *Server) scanHTTPBody(ctx context.Context, body io.ReadCloser, contentLength int64) malwareScanOutcome {
	maxBytes := s.malwareMaxBytes()
	if body == nil {
		return malwareScanOutcome{Body: http.NoBody}
	}

	// Oversized known length: skip scan, pass body through unchanged.
	if contentLength > 0 && contentLength > maxBytes {
		slog.Debug("malware scan skipped: content-length exceeds max",
			"content_length", contentLength, "max_bytes", maxBytes)
		return malwareScanOutcome{Body: body, ErrMsg: "malware_skipped_oversize"}
	}

	// Read up to maxBytes+1 to detect unknown-length overflow.
	limited := io.LimitReader(body, maxBytes+1)
	buf, err := io.ReadAll(limited)
	if err != nil {
		_ = body.Close()
		reason := ""
		errMsg := "malware_buffer: " + err.Error()
		if s != nil && s.MalwareFailClosed {
			reason = "Malware scan failed (unable to read body)"
		} else {
			slog.Error("malware body buffer failed (fail-open)", "err", err)
		}
		return malwareScanOutcome{Body: io.NopCloser(bytes.NewReader(nil)), ErrMsg: errMsg, BlockReason: reason}
	}

	var tail io.Reader
	oversize := int64(len(buf)) > maxBytes
	if oversize {
		// Keep first maxBytes for potential pass-through; rest stays on body.
		head := buf[:maxBytes]
		restFirst := buf[maxBytes:] // 1 peek byte
		tail = io.MultiReader(bytes.NewReader(restFirst), body)
		buf = head
		slog.Debug("malware scan skipped: body exceeds max bytes", "max_bytes", maxBytes)
		newBody := &multiReadCloser{
			r:     io.MultiReader(bytes.NewReader(buf), tail),
			close: body.Close,
		}
		return malwareScanOutcome{Body: newBody, Size: int64(len(buf)), ErrMsg: "malware_skipped_oversize"}
	}
	// Fully buffered — close original.
	_ = body.Close()

	if len(buf) == 0 {
		return malwareScanOutcome{Body: http.NoBody, Size: 0}
	}

	scanner := s.Malware
	if scanner == nil {
		scanner = malware.Nop{}
	}
	res, scanErr := scanner.Scan(ctx, bytes.NewReader(buf), maxBytes)
	if scanErr == nil && res.Error != nil {
		scanErr = res.Error
	}

	replacement := io.NopCloser(bytes.NewReader(buf))
	out := malwareScanOutcome{Body: replacement, Size: int64(len(buf))}

	if scanErr != nil {
		out.ErrMsg = "malware_scan: " + scanErr.Error()
		if s != nil && s.MalwareFailClosed {
			out.BlockReason = "Malware scan unavailable"
			slog.Error("malware scan failed (fail-closed)", "err", scanErr)
		} else {
			slog.Error("malware scan failed (fail-open)", "err", scanErr)
		}
		return out
	}
	if res.Infected {
		sig := res.Signature
		if sig == "" {
			sig = "unknown"
		}
		out.BlockReason = fmt.Sprintf("Malware detected: %s", sig)
		out.ErrMsg = "malware_detected"
		return out
	}
	return out
}

func (s *Server) malwareMaxBytes() int64 {
	if s != nil && s.MalwareMaxBytes > 0 {
		return s.MalwareMaxBytes
	}
	return malware.DefaultMaxScanBytes
}

// multiReadCloser chains a reader with a closer (original body).
type multiReadCloser struct {
	r     io.Reader
	close func() error
}

func (m *multiReadCloser) Read(p []byte) (int, error) { return m.r.Read(p) }
func (m *multiReadCloser) Close() error {
	if m.close != nil {
		return m.close()
	}
	return nil
}
