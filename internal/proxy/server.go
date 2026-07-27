// Package proxy implements the explicit HTTP/HTTPS MITM data-plane gateway.
package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/auth"
	"github.com/wsp-security/wsp/internal/certs"
	"github.com/wsp-security/wsp/internal/logging"
	"github.com/wsp-security/wsp/internal/policy"
	"github.com/wsp-security/wsp/internal/store"
)

// Server is the explicit forward proxy with optional TLS interception.
type Server struct {
	Addr     string
	Engine   *policy.Engine
	Certs    *certs.Provider
	Store    *store.Store
	Recorder *logging.Recorder

	// AuthCache is optional; used when policy AuthMode is ip_cached.
	AuthCache *auth.ProxyAuthCache
	// Sessions maps client identity → browsing session (created if nil).
	Sessions *SessionTracker

	// Optional pipeline hooks (default to no-op stubs).
	CASB    CASBInspector
	Malware MalwareScanner
	RBI     RBIOrchestrator

	// Dialer / Transport for origin connections (tests may inject).
	Dialer    *net.Dialer
	Transport *http.Transport

	// IdleTimeout for MITM keep-alive reads (default 2m).
	IdleTimeout time.Duration

	httpServer *http.Server
	mu         sync.Mutex
	hooksOnce  sync.Once
}

// Start listens on Addr and serves until ctx is cancelled or Shutdown.
// It blocks until the server stops; on ctx cancel it gracefully shuts down.
func (s *Server) Start(ctx context.Context) error {
	if s == nil {
		return errors.New("proxy server is nil")
	}
	if s.Addr == "" {
		return errors.New("proxy addr is empty")
	}
	s.ensureHooks()

	s.mu.Lock()
	s.httpServer = &http.Server{
		Addr:              s.Addr,
		Handler:           s,
		ReadHeaderTimeout: 15 * time.Second,
		// Disable base ReadTimeout so long-lived CONNECT tunnels work.
		// Per-request deadlines set inside MITM loop.
		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
	}
	srv := s.httpServer
	s.mu.Unlock()

	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("proxy listen %s: %w", s.Addr, err)
	}
	// Reflect actual bound address (useful when Addr is :0).
	s.mu.Lock()
	s.Addr = ln.Addr().String()
	s.mu.Unlock()

	errc := make(chan error, 1)
	go func() {
		slog.Info("proxy listening", "addr", ln.Addr().String())
		err := srv.Serve(ln)
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return <-errc
	case err := <-errc:
		return err
	}
}

// BoundAddr returns the actual listen address after Start binds (e.g. when Addr was :0).
func (s *Server) BoundAddr() string {
	if s == nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.Addr
}

// Shutdown gracefully stops the HTTP server.
func (s *Server) Shutdown(ctx context.Context) error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	srv := s.httpServer
	s.mu.Unlock()
	if srv == nil {
		return nil
	}
	return srv.Shutdown(ctx)
}

// ServeHTTP implements http.Handler for the explicit proxy.
func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	s.ensureHooks()

	if req.Method == http.MethodConnect {
		s.handleCONNECT(w, req)
		return
	}

	// Absolute-form URI required for forward proxy HTTP requests.
	if req.URL == nil || !req.URL.IsAbs() {
		// Some clients send origin-form with Host header — accept and absolutize.
		if req.Host != "" && req.URL != nil {
			scheme := "http"
			u := &url.URL{
				Scheme:   scheme,
				Host:     req.Host,
				Path:     req.URL.Path,
				RawQuery: req.URL.RawQuery,
			}
			req.URL = u
		} else {
			http.Error(w, "absolute-form request URI required", http.StatusBadRequest)
			return
		}
	}

	s.handleHTTP(w, req)
}

// handleHTTP processes plain HTTP absolute-form proxy requests.
func (s *Server) handleHTTP(w http.ResponseWriter, req *http.Request) {
	start := time.Now().UTC()
	s.ensureHooks()

	clientIP := clientIPFromRequest(req)
	clientIPStr := ipString(clientIP)
	target := cloneURL(req.URL)
	if target.Scheme == "" {
		target.Scheme = "http"
	}

	in := buildInput(req, clientIP, "", target, req.Method)
	d := s.evaluate(in)

	username, need407 := s.resolveAuth(req.Context(), req, clientIPStr, d.AuthMode)
	if need407 {
		writeProxyAuthRequired(w)
		pr := &pipelineResult{
			Input:     in,
			Decision:  d,
			RequestID: uuid.New(),
			Start:     start,
		}
		s.recordOutcome(req.Context(), pr, req, target, "auth_required", req.ContentLength, 0, "proxy authentication required")
		return
	}
	if username != "" {
		in.Username = username
		d = s.evaluate(in)
	}

	requestID := uuid.New()
	sessionID := s.Sessions.Acquire(req.Context(), clientIPStr, username, req.UserAgent())
	pr := &pipelineResult{
		Input:     in,
		Decision:  d,
		Username:  username,
		RequestID: requestID,
		SessionID: sessionID,
		Start:     start,
	}

	if d.FinalAction == policy.ActionBlock {
		n := s.writeBlockPage(w, req, d, clientIPStr, username, target)
		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(n), "")
		return
	}

	// RBI fail-closed: never forward origin when isolation is required.
	if needsIsolation(d, s.RBI) {
		if s.RBI.HandleIsolation(w, req, d) {
			s.recordOutcome(req.Context(), pr, req, target, "allow", req.ContentLength, 0, "rbi")
			return
		}
		d.FinalAction = policy.ActionBlock
		if d.BlockReason == "" {
			d.BlockReason = rbiUnavailableReason
		}
		pr.Decision = d
		n := s.writeBlockPage(w, req, d, clientIPStr, username, target)
		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(n), "rbi_unavailable")
		return
	}

	if reason, err := s.CASB.InspectRequest(req.Context(), req, d); err != nil {
		slog.Warn("CASB inspect request error", "err", err)
	} else if reason != "" {
		d.FinalAction = policy.ActionBlock
		d.BlockReason = reason
		pr.Decision = d
		n := s.writeBlockPage(w, req, d, clientIPStr, username, target)
		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(n), "")
		return
	}

	applyRequestHeaderMods(req, d.HeaderMods)
	stripHopByHop(req.Header)
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	// Ensure Host header matches target.
	if outReq.Host == "" {
		outReq.Host = target.Host
	}

	resp, err := s.Transport.RoundTrip(outReq)
	if err != nil {
		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
		s.recordOutcome(req.Context(), pr, req, target, "error", req.ContentLength, 0, err.Error())
		return
	}
	defer resp.Body.Close()

	if reason, err := s.CASB.InspectResponse(req.Context(), req, resp, d); err != nil {
		slog.Warn("CASB inspect response error", "err", err)
	} else if reason != "" {
		d.FinalAction = policy.ActionBlock
		d.BlockReason = reason
		pr.Decision = d
		n := s.writeBlockPage(w, req, d, clientIPStr, username, target)
		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(n), "")
		return
	}

	if d.MalwareScan {
		_, _ = s.Malware.Scan(req.Context(), strings.NewReader(""), 0)
	}

	applyResponseHeaderMods(resp, d.HeaderMods)
	stripHopByHop(resp.Header)

	for k, vv := range resp.Header {
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	n, copyErr := io.Copy(w, resp.Body)
	errMsg := ""
	if copyErr != nil {
		errMsg = copyErr.Error()
	}
	s.recordOutcome(req.Context(), pr, req, target, "allow", req.ContentLength, n, errMsg)
}
