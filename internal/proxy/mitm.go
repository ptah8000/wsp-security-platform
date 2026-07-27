package proxy

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/blockpage"
	"github.com/wsp-security/wsp/internal/policy"
)

// handleCONNECT processes HTTP CONNECT: tunnel or MITM.
func (s *Server) handleCONNECT(w http.ResponseWriter, req *http.Request) {
	start := time.Now().UTC()
	s.ensureHooks()

	clientIP := clientIPFromRequest(req)
	clientIPStr := ipString(clientIP)
	rawTarget := req.Host
	if rawTarget == "" {
		rawTarget = req.URL.Host
	}
	if rawTarget == "" {
		http.Error(w, "CONNECT host required", http.StatusBadRequest)
		return
	}
	hostOnly, _, targetHost, err := parseCONNECTTarget(rawTarget)
	if err != nil {
		http.Error(w, "invalid CONNECT host", http.StatusBadRequest)
		return
	}

	targetURL := &url.URL{Scheme: "https", Host: hostOnly, Path: "/"}
	in := buildInput(req, clientIP, "", targetURL, http.MethodConnect)
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
		s.recordOutcome(req.Context(), pr, req, targetURL, "auth_required", 0, 0, "proxy authentication required")
		return
	}
	if username != "" {
		in.Username = username
		// Re-evaluate with username so user-scoped rules apply.
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

	// Block without MITM: 403 short body (cannot show HTML page inside CONNECT).
	if d.FinalAction == policy.ActionBlock && !d.TLSIntercept {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusForbidden)
		body := blockpage.ShortBody(d.BlockReason)
		_, _ = w.Write(body)
		s.recordOutcome(req.Context(), pr, req, targetURL, "block", 0, int64(len(body)), "")
		return
	}

	// Hijack client connection for tunnel or MITM.
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		s.recordOutcome(req.Context(), pr, req, targetURL, decisionLabel(d, "error"), 0, 0, "hijack unsupported")
		return
	}

	clientConn, clientBuf, err := hj.Hijack()
	if err != nil {
		slog.Warn("CONNECT hijack failed", "err", err)
		s.recordOutcome(req.Context(), pr, req, targetURL, decisionLabel(d, "error"), 0, 0, err.Error())
		return
	}

	// MITM path (also used for block-with-intercept so we can serve a block page).
	if d.TLSIntercept {
		s.serveMITM(clientConn, clientBuf, req, pr, hostOnly, targetHost)
		return
	}

	// Transparent tunnel (no interception).
	s.serveTunnel(clientConn, clientBuf, req, pr, targetHost, targetURL)
}

// serveTunnel dials origin and bidirectionally copies bytes after 200.
func (s *Server) serveTunnel(clientConn net.Conn, clientBuf *bufio.ReadWriter, req *http.Request, pr *pipelineResult, targetHost string, targetURL *url.URL) {
	defer clientConn.Close()

	ctx := req.Context()
	originConn, err := s.Dialer.DialContext(ctx, "tcp", targetHost)
	if err != nil {
		_, _ = clientBuf.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nconnect failed\r\n")
		_ = clientBuf.Flush()
		s.recordOutcome(ctx, pr, req, targetURL, "error", 0, 0, err.Error())
		return
	}
	defer originConn.Close()

	_, _ = clientBuf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := clientBuf.Flush(); err != nil {
		s.recordOutcome(ctx, pr, req, targetURL, "error", 0, 0, err.Error())
		return
	}

	// Log CONNECT allow (tunnel) once; individual HTTP messages are opaque.
	s.recordOutcome(ctx, pr, req, targetURL, "allow", 0, 0, "")

	// Any buffered client bytes after CONNECT request line/headers.
	var clientReader io.Reader = clientConn
	if clientBuf.Reader != nil && clientBuf.Reader.Buffered() > 0 {
		clientReader = io.MultiReader(clientBuf.Reader, clientConn)
	}

	errc := make(chan error, 2)
	go func() {
		_, err := io.Copy(originConn, clientReader)
		errc <- err
	}()
	go func() {
		_, err := io.Copy(clientConn, originConn)
		errc <- err
	}()
	<-errc
}

// serveMITM terminates TLS toward the client with a leaf signed by the active CA,
// then runs the HTTP pipeline for each decrypted request.
func (s *Server) serveMITM(clientConn net.Conn, clientBuf *bufio.ReadWriter, connectReq *http.Request, pr *pipelineResult, hostOnly, dialAddr string) {
	defer clientConn.Close()

	ctx := connectReq.Context()
	if s.Certs == nil {
		_, _ = clientBuf.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nno CA configured for MITM\r\n")
		_ = clientBuf.Flush()
		s.recordOutcome(ctx, pr, connectReq, pr.Input.URL, "error", 0, 0, "no CA")
		return
	}

	leaf, err := s.Certs.SignHost(hostOnly)
	if err != nil {
		_, _ = clientBuf.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nMITM cert failed\r\n")
		_ = clientBuf.Flush()
		s.recordOutcome(ctx, pr, connectReq, pr.Input.URL, "error", 0, 0, err.Error())
		return
	}

	_, _ = clientBuf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
	if err := clientBuf.Flush(); err != nil {
		s.recordOutcome(ctx, pr, connectReq, pr.Input.URL, "error", 0, 0, err.Error())
		return
	}

	// Log the CONNECT itself as allow/block intent; per-request logs follow.
	connectDecision := decisionLabel(pr.Decision, "")
	if pr.Decision.FinalAction == policy.ActionBlock {
		connectDecision = "block"
	}
	s.recordOutcome(ctx, pr, connectReq, pr.Input.URL, connectDecision, 0, 0, "")

	var rawClient io.Reader = clientConn
	if clientBuf.Reader != nil && clientBuf.Reader.Buffered() > 0 {
		rawClient = io.MultiReader(clientBuf.Reader, clientConn)
	}
	// tls.Server needs a net.Conn; wrap buffered reader.
	tlsConn := tls.Server(&bufConn{Conn: clientConn, r: rawClient}, &tls.Config{
		Certificates: []tls.Certificate{*leaf},
		MinVersion:   tls.VersionTLS12,
	})
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		slog.Debug("MITM handshake failed", "host", hostOnly, "err", err)
		return
	}
	defer tlsConn.Close()

	// If CONNECT-stage policy already blocked, show block page once and close.
	if pr.Decision.FinalAction == policy.ActionBlock {
		s.serveBlockedOnTLS(tlsConn, connectReq, pr)
		return
	}

	// Origin authority including port (required so RoundTrip does not default to :443).
	originAuthority := dialAddr
	if _, _, err := net.SplitHostPort(dialAddr); err != nil {
		originAuthority = net.JoinHostPort(hostOnly, "443")
	}

	br := bufio.NewReader(tlsConn)
	for {
		_ = tlsConn.SetDeadline(time.Now().Add(s.idleTimeout()))
		req, err := http.ReadRequest(br)
		if err != nil {
			if err != io.EOF {
				slog.Debug("MITM read request", "host", hostOnly, "err", err)
			}
			return
		}

		// Rewrite to absolute origin URL for pipeline/forward.
		req.URL.Scheme = "https"
		req.URL.Host = originAuthority
		req.Host = originAuthority
		req.RequestURI = ""
		// Preserve client identity from CONNECT.
		req.RemoteAddr = connectReq.RemoteAddr

		// RBI viewer/WS under the isolated origin (same TLS session).
		if req.URL != nil && strings.HasPrefix(req.URL.Path, "/rbi/") {
			rw := &mitmResponseWriter{w: tlsConn, conn: tlsConn, br: br, header: make(http.Header)}
			if s.tryServeRBIPath(rw, req) {
				if rw.hijacked {
					// WebSocket took the connection; end MITM loop.
					return
				}
				continue
			}
		}

		if s.handleMITMRequest(tlsConn, br, req, pr, originAuthority) {
			// Connection hijacked (e.g. RBI WS via HandleIsolation edge cases).
			return
		}
	}
}

// serveBlockedOnTLS writes an HTTP block page over the established TLS channel.
func (s *Server) serveBlockedOnTLS(conn net.Conn, connectReq *http.Request, pr *pipelineResult) {
	// Wait for first client request if possible so we respond properly.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		// No request; write a synthetic response anyway.
		req = &http.Request{Method: http.MethodGet, URL: pr.Input.URL, Header: make(http.Header)}
	} else {
		if req.URL.Scheme == "" {
			req.URL.Scheme = "https"
		}
		if req.URL.Host == "" && pr.Input.URL != nil {
			req.URL.Host = pr.Input.URL.Host
		}
	}

	html := s.loadBlockHTML(context.Background(), pr.Decision.BlockPageID)
	ruleID := ""
	if len(pr.Decision.MatchedRuleIDs) > 0 {
		ruleID = pr.Decision.MatchedRuleIDs[0].String()
	}
	urlStr := ""
	if pr.Input.URL != nil {
		urlStr = pr.Input.URL.String()
	}
	body := blockpage.Render(html, blockpage.Context{
		URL:       urlStr,
		Reason:    pr.Decision.BlockReason,
		Username:  pr.Username,
		ClientIP:  ipString(pr.Input.ClientIP),
		RuleID:    ruleID,
		Timestamp: time.Now().UTC(),
	})

	resp := &http.Response{
		StatusCode:    http.StatusForbidden,
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Connection", "close")
	resp.Header.Set("Cache-Control", "no-store")
	_ = resp.Write(conn)

	// Per-request log for the blocked page.
	pr2 := *pr
	pr2.RequestID = uuid.New()
	pr2.Start = time.Now().UTC()
	s.recordOutcome(context.Background(), &pr2, req, pr.Input.URL, "block", 0, int64(len(body)), "")
}

// handleMITMRequest evaluates policy again for the full URL and forwards to origin.
// Returns true when the underlying connection was hijacked (caller must stop the MITM loop).
func (s *Server) handleMITMRequest(clientWriter io.Writer, br *bufio.Reader, req *http.Request, connectPR *pipelineResult, dialAddr string) (hijacked bool) {
	start := time.Now().UTC()
	s.ensureHooks()

	clientIP := connectPR.Input.ClientIP
	clientIPStr := ipString(clientIP)
	username := connectPR.Username

	target := cloneURL(req.URL)
	if target.Scheme == "" {
		target.Scheme = "https"
	}
	in := buildInput(req, clientIP, username, target, req.Method)
	d := s.evaluate(in)

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
		html := s.loadBlockHTML(req.Context(), d.BlockPageID)
		ruleID := ""
		if len(d.MatchedRuleIDs) > 0 {
			ruleID = d.MatchedRuleIDs[0].String()
		}
		body := blockpage.Render(html, blockpage.Context{
			URL:       target.String(),
			Reason:    d.BlockReason,
			Username:  username,
			ClientIP:  clientIPStr,
			RuleID:    ruleID,
			Timestamp: time.Now().UTC(),
		})
		resp := &http.Response{
			StatusCode:    http.StatusForbidden,
			ProtoMajor:    1,
			ProtoMinor:    1,
			Header:        make(http.Header),
			Body:          io.NopCloser(strings.NewReader(string(body))),
			ContentLength: int64(len(body)),
			Close:         true,
		}
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		resp.Header.Set("Cache-Control", "no-store")
		_ = resp.Write(clientWriter)
		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(len(body)), "")
		_ = req.Body.Close()
		return false
	}

	// RBI fail-closed: never forward origin when isolation is required.
	if needsIsolation(d, s.RBI) {
		conn, _ := clientWriter.(net.Conn)
		rw := &mitmResponseWriter{w: clientWriter, conn: conn, br: br, header: make(http.Header)}
		if s.RBI.HandleIsolation(rw, req, d) {
			s.recordOutcome(req.Context(), pr, req, target, "allow", req.ContentLength, rw.n, "rbi")
			_ = req.Body.Close()
			return rw.hijacked
		}
		d.FinalAction = policy.ActionBlock
		if d.BlockReason == "" {
			d.BlockReason = rbiUnavailableReason
		}
		pr.Decision = d
		body := blockpage.Render(s.loadBlockHTML(req.Context(), d.BlockPageID), blockpage.Context{
			URL: target.String(), Reason: d.BlockReason, Username: username,
			ClientIP: clientIPStr, Timestamp: time.Now().UTC(),
		})
		resp := &http.Response{
			StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))),
			ContentLength: int64(len(body)), Close: true,
		}
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		resp.Header.Set("Cache-Control", "no-store")
		_ = resp.Write(clientWriter)
		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(len(body)), "rbi_unavailable")
		_ = req.Body.Close()
		return false
	}

	// CASB request-side enforcement (targeted block page on Hit).
	if reason, err := s.CASB.InspectRequest(req.Context(), req, d); err != nil {
		slog.Warn("CASB inspect request error", "err", err)
	} else if reason != "" {
		d.FinalAction = policy.ActionBlock
		d.BlockReason = reason
		pr.Decision = d
		n := writeMITMBlock(clientWriter, s.loadBlockHTML(req.Context(), nil), target, reason, username, clientIPStr)
		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(n), "casb")
		_ = req.Body.Close()
		return false
	}

	// Request-body malware scan when policy enables it.
	reqSize := req.ContentLength
	if d.MalwareScan && req.Body != nil && req.Body != http.NoBody {
		out := s.scanHTTPBody(req.Context(), req.Body, req.ContentLength)
		req.Body = out.Body
		if out.ErrMsg != "malware_skipped_oversize" && out.Size >= 0 && req.Body != http.NoBody {
			req.ContentLength = out.Size
			req.Header.Set("Content-Length", fmt.Sprintf("%d", out.Size))
			req.Header.Del("Transfer-Encoding")
			reqSize = out.Size
		}
		if out.BlockReason != "" {
			d.FinalAction = policy.ActionBlock
			d.BlockReason = out.BlockReason
			pr.Decision = d
			n := writeMITMBlock(clientWriter, s.loadBlockHTML(req.Context(), d.BlockPageID), target, d.BlockReason, username, clientIPStr)
			s.recordOutcome(req.Context(), pr, req, target, "block", reqSize, int64(n), out.ErrMsg)
			return false
		}
	}

	applyRequestHeaderMods(req, d.HeaderMods)
	stripHopByHop(req.Header)
	req.Header.Del("Proxy-Authorization")
	req.Header.Del("Proxy-Connection")

	// Dial origin with real TLS (verify system roots / default).
	// dialAddr is host:port from CONNECT so non-443 origins work (e.g. httptest).
	originURL := cloneURL(target)
	if dialAddr != "" {
		originURL.Host = dialAddr
	}
	outReq := req.Clone(req.Context())
	outReq.RequestURI = ""
	outReq.URL = originURL
	outReq.Host = originURL.Host

	resp, err := s.Transport.RoundTrip(outReq)
	if err != nil {
		errBody := fmt.Sprintf("Bad Gateway: %v", err)
		r := &http.Response{
			StatusCode: http.StatusBadGateway, ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader(errBody)),
			ContentLength: int64(len(errBody)), Close: true,
		}
		r.Header.Set("Content-Type", "text/plain; charset=utf-8")
		_ = r.Write(clientWriter)
		s.recordOutcome(req.Context(), pr, req, target, "error", reqSize, int64(len(errBody)), err.Error())
		return false
	}
	defer resp.Body.Close()

	// CASB response-side enforcement (targeted block page on Hit).
	if reason, err := s.CASB.InspectResponse(req.Context(), req, resp, d); err != nil {
		slog.Warn("CASB inspect response error", "err", err)
	} else if reason != "" {
		_ = resp.Body.Close()
		d.FinalAction = policy.ActionBlock
		d.BlockReason = reason
		pr.Decision = d
		n := writeMITMBlock(clientWriter, s.loadBlockHTML(req.Context(), nil), target, reason, username, clientIPStr)
		s.recordOutcome(req.Context(), pr, req, target, "block", reqSize, int64(n), "casb")
		return false
	}

	// Response-body malware scan when policy enables it.
	if d.MalwareScan {
		out := s.scanHTTPBody(req.Context(), resp.Body, resp.ContentLength)
		resp.Body = out.Body
		if out.Size > 0 && out.ErrMsg != "malware_skipped_oversize" {
			resp.ContentLength = out.Size
			resp.Header.Set("Content-Length", fmt.Sprintf("%d", out.Size))
			resp.Header.Del("Transfer-Encoding")
		}
		if out.BlockReason != "" {
			d.FinalAction = policy.ActionBlock
			d.BlockReason = out.BlockReason
			pr.Decision = d
			n := writeMITMBlock(clientWriter, s.loadBlockHTML(req.Context(), d.BlockPageID), target, d.BlockReason, username, clientIPStr)
			s.recordOutcome(req.Context(), pr, req, target, "block", reqSize, int64(n), out.ErrMsg)
			return false
		}
	}

	applyResponseHeaderMods(resp, d.HeaderMods)
	stripHopByHop(resp.Header)

	// Measure response size while streaming to client.
	cw := &countingWriter{w: clientWriter}
	if err := resp.Write(cw); err != nil {
		s.recordOutcome(req.Context(), pr, req, target, "error", reqSize, cw.n, err.Error())
		return false
	}
	s.recordOutcome(req.Context(), pr, req, target, "allow", reqSize, cw.n, "")
	return false
}

// writeMITMBlock writes an HTML block page as an HTTP/1.1 response on the MITM TLS connection.
func writeMITMBlock(w io.Writer, htmlTpl string, target *url.URL, reason, username, clientIP string) int {
	urlStr := ""
	if target != nil {
		urlStr = target.String()
	}
	body := blockpage.Render(htmlTpl, blockpage.Context{
		URL: urlStr, Reason: reason, Username: username, ClientIP: clientIP, Timestamp: time.Now().UTC(),
	})
	resp := &http.Response{
		StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1,
		Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))),
		ContentLength: int64(len(body)), Close: true,
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Cache-Control", "no-store")
	_ = resp.Write(w)
	return len(body)
}

// bufConn presents a net.Conn that reads from r first (buffered CONNECT leftovers).
type bufConn struct {
	net.Conn
	r io.Reader
}

func (c *bufConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

func cloneURL(u *url.URL) *url.URL {
	if u == nil {
		return &url.URL{}
	}
	c := *u
	return &c
}

func stripHopByHop(h http.Header) {
	// RFC 7230: Connection token list names additional hop-by-hop headers.
	// Read Connection BEFORE deleting it, otherwise tokens are never stripped.
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
	for _, k := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(k)
	}
}

// parseCONNECTTarget splits a CONNECT authority into host, port, and dial address.
// Supports hostname, IPv4, IPv6 (bare or bracketed), with optional port (default 443).
func parseCONNECTTarget(raw string) (host, port, dialAddr string, err error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", "", "", fmt.Errorf("empty CONNECT host")
	}
	// host:port or [ipv6]:port
	if h, p, e := net.SplitHostPort(raw); e == nil {
		if p == "" {
			p = "443"
		}
		return h, p, net.JoinHostPort(h, p), nil
	}
	// Bare host / IP without port.
	h := raw
	if strings.HasPrefix(h, "[") && strings.HasSuffix(h, "]") {
		h = strings.TrimSuffix(strings.TrimPrefix(h, "["), "]")
	}
	// Accept bare IPv6, IPv4, or hostname without ':'.
	if net.ParseIP(h) != nil || !strings.Contains(raw, ":") {
		return h, "443", net.JoinHostPort(h, "443"), nil
	}
	return "", "", "", fmt.Errorf("invalid CONNECT host %q", raw)
}

// mitmResponseWriter adapts an MITM TLS/conn writer to http.ResponseWriter
// so RBIOrchestrator.HandleIsolation can serve viewer HTML on the MITM path.
// It also implements http.Hijacker for RBI WebSocket upgrades.
type mitmResponseWriter struct {
	w           io.Writer
	conn        net.Conn
	br          *bufio.Reader
	header      http.Header
	status      int
	wroteHeader bool
	wrote       bool
	hijacked    bool
	n           int64
}

func (m *mitmResponseWriter) Header() http.Header {
	if m.header == nil {
		m.header = make(http.Header)
	}
	return m.header
}

func (m *mitmResponseWriter) WriteHeader(statusCode int) {
	if m.wroteHeader || m.hijacked {
		return
	}
	m.status = statusCode
	m.wroteHeader = true
	if statusCode == 0 {
		statusCode = http.StatusOK
	}
	// Minimal HTTP/1.1 response line + headers; body follows via Write.
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP/1.1 %d %s\r\n", statusCode, http.StatusText(statusCode))
	if m.header.Get("Content-Type") == "" {
		m.header.Set("Content-Type", "text/html; charset=utf-8")
	}
	for k, vv := range m.header {
		for _, v := range vv {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	n, _ := io.WriteString(m.w, b.String())
	m.n += int64(n)
	m.wrote = true
}

func (m *mitmResponseWriter) Write(p []byte) (int, error) {
	if m.hijacked {
		return 0, http.ErrHijacked
	}
	if !m.wroteHeader {
		m.WriteHeader(http.StatusOK)
	}
	n, err := m.w.Write(p)
	m.n += int64(n)
	m.wrote = true
	return n, err
}

// Hijack implements http.Hijacker for WebSocket upgrades on the MITM TLS conn.
func (m *mitmResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if m.hijacked {
		return nil, nil, fmt.Errorf("connection already hijacked")
	}
	if m.wroteHeader {
		return nil, nil, fmt.Errorf("http: connection has been written to")
	}
	if m.conn == nil {
		return nil, nil, fmt.Errorf("hijack not supported")
	}
	m.hijacked = true
	m.wroteHeader = true
	m.wrote = true
	br := m.br
	if br == nil {
		br = bufio.NewReader(m.conn)
	}
	bc := &bufConn{Conn: m.conn, r: br}
	bw := bufio.NewWriter(m.conn)
	return bc, bufio.NewReadWriter(br, bw), nil
}

func (s *Server) idleTimeout() time.Duration {
	if s != nil && s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return 2 * time.Minute
}
