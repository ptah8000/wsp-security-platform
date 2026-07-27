package rbi

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/wsp-security/wsp/internal/policy"
)

// ErrMaxSessions is returned when ActiveCount would exceed MaxSessions.
var ErrMaxSessions = errors.New("maximum RBI sessions reached")

// ErrDockerUnavailable is returned when the runtime cannot be reached.
var ErrDockerUnavailable = errors.New("docker unavailable for RBI")

// Orchestrator manages ephemeral Chromium RBI sessions.
type Orchestrator struct {
	Runtime     ContainerRuntime
	Image       string
	MaxSessions int
	// Network optional Docker network for RBI containers.
	Network string
	// ViewerBaseURL is only used when preferRedirect is true (debug).
	ViewerBaseURL string
	// preferRedirect forces admin-plane redirect (not seamless). Default false.
	preferRedirect bool
	// IdleTimeout for viewer inactivity / stop after WS close (default 15m).
	IdleTimeout time.Duration
	// SessionStartTimeout bounds container create + CDP connect (default 60s).
	SessionStartTimeout time.Duration
	// CDPConnect if set overrides liveSession.connectCDP (tests).
	CDPConnect func(ctx context.Context, s *liveSession) error

	mu       sync.RWMutex
	sessions map[string]*liveSession
}

// Config for NewOrchestrator.
type Config struct {
	Runtime        ContainerRuntime
	Image          string
	MaxSessions    int
	Network        string
	ViewerBaseURL  string
	PreferRedirect bool // debug only; seamless in-place is the product default
	IdleTimeout    time.Duration
}

// NewOrchestrator returns an Orchestrator. Runtime may be nil only for tests that inject later.
func NewOrchestrator(cfg Config) *Orchestrator {
	max := cfg.MaxSessions
	if max <= 0 {
		max = 10
	}
	idle := cfg.IdleTimeout
	if idle <= 0 {
		idle = 15 * time.Minute
	}
	img := cfg.Image
	if img == "" {
		img = "browserless/chrome:latest"
	}
	return &Orchestrator{
		Runtime:             cfg.Runtime,
		Image:               img,
		MaxSessions:         max,
		Network:             cfg.Network,
		ViewerBaseURL:       strings.TrimRight(cfg.ViewerBaseURL, "/"),
		preferRedirect:      cfg.PreferRedirect,
		IdleTimeout:         idle,
		SessionStartTimeout: 60 * time.Second,
		sessions:            make(map[string]*liveSession),
	}
}

// Start creates a container, connects CDP, navigates to targetURL.
func (o *Orchestrator) Start(ctx context.Context, targetURL string, opts SessionOpts) (Session, error) {
	if o == nil {
		return nil, errors.New("orchestrator is nil")
	}
	if targetURL == "" {
		return nil, errors.New("target URL is empty")
	}
	if o.Runtime == nil {
		return nil, ErrDockerUnavailable
	}

	o.mu.Lock()
	if len(o.sessions) >= o.MaxSessions {
		o.mu.Unlock()
		return nil, ErrMaxSessions
	}
	// Reserve a slot with a placeholder to avoid races past MaxSessions.
	id := newSessionID()
	placeholder := &liveSession{id: id, targetURL: targetURL, opts: opts, orch: o}
	o.sessions[id] = placeholder
	o.mu.Unlock()

	startCtx := ctx
	var cancel context.CancelFunc
	if o.SessionStartTimeout > 0 {
		startCtx, cancel = context.WithTimeout(ctx, o.SessionStartTimeout)
		defer cancel()
	}

	// Fail closed: clean placeholder if anything below fails.
	fail := func(err error) (Session, error) {
		o.mu.Lock()
		delete(o.sessions, id)
		o.mu.Unlock()
		return nil, err
	}

	if err := o.Runtime.Ping(startCtx); err != nil {
		return fail(fmt.Errorf("%w: %v", ErrDockerUnavailable, err))
	}

	info, err := o.Runtime.CreateAndStart(startCtx, CreateOpts{
		Image:   o.Image,
		Network: o.Network,
		Name:    "wsp-rbi-" + id[:8],
		Labels: map[string]string{
			"wsp.rbi.session": id,
		},
	})
	if err != nil {
		return fail(err)
	}

	sess := &liveSession{
		id:          id,
		targetURL:   targetURL,
		containerID: info.ID,
		cdpAddr:     info.CDPAddr,
		opts:        opts,
		orch:        o,
	}

	connect := o.CDPConnect
	if connect == nil {
		connect = func(ctx context.Context, s *liveSession) error {
			return s.connectCDP(ctx)
		}
	}
	if err := connect(startCtx, sess); err != nil {
		_ = o.Runtime.Remove(context.Background(), info.ID, true)
		return fail(fmt.Errorf("CDP connect: %w", err))
	}

	o.mu.Lock()
	o.sessions[id] = sess
	o.mu.Unlock()

	// Auto-stop if no viewer attaches (e.g. user abandons redirect) to free slots.
	go o.reapIfUnattached(id, 2*time.Minute)

	slog.Info("rbi session started",
		"session", id,
		"container_id", shortID(info.ID),
		"target", targetURL,
		"active", o.ActiveCount(),
	)
	return sess, nil
}

func (o *Orchestrator) reapIfUnattached(id string, wait time.Duration) {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	<-timer.C
	o.mu.RLock()
	s, ok := o.sessions[id]
	o.mu.RUnlock()
	if !ok || s == nil || s.stopped.Load() {
		return
	}
	if s.attached.Load() {
		return
	}
	slog.Info("rbi reaping unattached session", "session", id)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_ = o.Stop(ctx, id)
}

// Get returns a live session by id.
func (o *Orchestrator) Get(id string) (Session, bool) {
	if o == nil {
		return nil, false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	s, ok := o.sessions[id]
	if !ok || s == nil || s.stopped.Load() {
		return nil, false
	}
	return s, true
}

// Stop ends a session and removes its container.
func (o *Orchestrator) Stop(ctx context.Context, id string) error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	s, ok := o.sessions[id]
	if ok {
		delete(o.sessions, id)
	}
	o.mu.Unlock()
	if !ok || s == nil {
		return nil
	}
	return s.Stop(ctx)
}

// ActiveCount returns the number of tracked sessions.
func (o *Orchestrator) ActiveCount() int {
	if o == nil {
		return 0
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	return len(o.sessions)
}

// StopAll tears down every session (graceful shutdown).
func (o *Orchestrator) StopAll(ctx context.Context) {
	if o == nil {
		return
	}
	o.mu.Lock()
	ids := make([]string, 0, len(o.sessions))
	for id := range o.sessions {
		ids = append(ids, id)
	}
	o.mu.Unlock()
	for _, id := range ids {
		_ = o.Stop(ctx, id)
	}
}

func (o *Orchestrator) forget(id string) {
	if o == nil {
		return
	}
	o.mu.Lock()
	delete(o.sessions, id)
	o.mu.Unlock()
}

func (o *Orchestrator) idleTimeout() time.Duration {
	if o != nil && o.IdleTimeout > 0 {
		return o.IdleTimeout
	}
	return 15 * time.Minute
}

// --- proxy.RBIOrchestrator adapter ---

// ShouldIsolate reports whether the policy decision requires RBI.
func (o *Orchestrator) ShouldIsolate(d policy.Decision) bool {
	return d.RBIIsolated
}

// HandleIsolation starts an RBI session and serves a seamless same-origin viewer.
// The user stays on the requested host/path in the address bar; only a pixel
// stream is shown (no origin HTML/JS). Optional ViewerBaseURL still supports
// admin-plane handoff for debugging when WSP_RBI_REDIRECT=1 is used via config.
// Returns true when the client was given a viewer (session started).
// Returns false when Docker/session start fails so the proxy can fail-closed.
func (o *Orchestrator) HandleIsolation(w http.ResponseWriter, req *http.Request, d policy.Decision) bool {
	if o == nil || w == nil || req == nil {
		return false
	}
	// Control paths should not create nested sessions.
	if req.URL != nil && IsControlPath(req.URL.Path) {
		return o.ServeRBIPath(w, req)
	}

	// Only top-level document navigations start isolation. Subresources must never
	// receive origin bytes under an isolation policy (handled by the proxy).
	if !IsDocumentNavigation(req) {
		slog.Debug("rbi skip non-document under isolation policy", "path", req.URL.Path)
		return false
	}

	target := isolationTargetURL(req)
	if target == "" {
		slog.Warn("rbi HandleIsolation: empty target URL")
		return false
	}

	opts := SessionOpts{
		BlockCopyFrom: d.RBIBlockCopyFrom,
		BlockCopyTo:   d.RBIBlockCopyTo,
	}
	if req.RemoteAddr != "" {
		opts.ClientIP = req.RemoteAddr
	}

	ctx := req.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	sess, err := o.Start(ctx, target, opts)
	if err != nil {
		slog.Warn("rbi start failed", "target", target, "err", err)
		return false
	}

	// Seamless default: serve viewer under the MITM site origin (same URL bar).
	// Redirect only if ViewerBaseURL is explicitly set AND Redirect preferred
	// (we leave ViewerBaseURL empty in product config for seamless UX).
	if base := strings.TrimRight(o.ViewerBaseURL, "/"); base != "" && o.preferRedirect {
		loc := base + SessionPathPrefix + sess.ID()
		WriteIsolationRedirect(w, loc, target)
		slog.Info("rbi isolation redirect", "session", sess.ID(), "viewer", loc, "target", target)
		return true
	}

	WriteIsolationHTML(w, sess.ID(), target, viewerFlags{
		BlockCopyFrom: opts.BlockCopyFrom,
		BlockCopyTo:   opts.BlockCopyTo,
		TargetURL:     target,
	})
	slog.Info("rbi isolation viewer served in-place", "session", sess.ID(), "target", target)
	return true
}

// IsDocumentNavigation reports top-level navigations that should start RBI.
// Accept: */* alone is NOT a document (avoids spawning RBI for XHR/images).
func IsDocumentNavigation(req *http.Request) bool {
	if req == nil {
		return false
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return false
	}
	dest := strings.ToLower(strings.TrimSpace(req.Header.Get("Sec-Fetch-Dest")))
	switch dest {
	case "document", "iframe", "frame":
		return true
	case "empty":
		return acceptPrefersHTML(req.Header.Get("Accept"))
	case "":
		accept := req.Header.Get("Accept")
		if accept == "" {
			return true // curl lab probes
		}
		return acceptPrefersHTML(accept)
	default:
		return false
	}
}

func acceptPrefersHTML(accept string) bool {
	accept = strings.ToLower(accept)
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "application/xhtml")
}

// isolationTargetURL builds a clean navigation URL (no default :443) for Chromium.
func isolationTargetURL(req *http.Request) string {
	if req == nil || req.URL == nil {
		return ""
	}
	u := *req.URL
	if u.Scheme == "" {
		u.Scheme = "https"
	}
	host := u.Hostname()
	if host == "" {
		host = req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
	}
	if host == "" {
		return ""
	}
	u.Host = host
	if u.Path == "" {
		u.Path = "/"
	}
	// Drop userinfo / fragment noise.
	u.User = nil
	u.Fragment = ""
	return u.String()
}
