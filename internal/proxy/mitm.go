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
	targetHost := req.Host
	if targetHost == "" {
		targetHost = req.URL.Host
	}
	if targetHost == "" {
		http.Error(w, "CONNECT host required", http.StatusBadRequest)
		return
	}
	// Ensure host:port form; default 443.
	if !strings.Contains(targetHost, ":") {
		targetHost = net.JoinHostPort(targetHost, "443")
	}
	hostOnly, port, err := net.SplitHostPort(targetHost)
	if err != nil {
		http.Error(w, "invalid CONNECT host", http.StatusBadRequest)
		return
	}
	if port == "" {
		port = "443"
		targetHost = net.JoinHostPort(hostOnly, port)
	}

	targetURL := &url.URL{Scheme: "https", Host: hostOnly, Path: "/"}
	in := buildInput(req, clientIP, "", targetURL, http.MethodConnect)
	d := s.evaluate(in)

	username, need407 := s.resolveAuth(req.Context(), req, clientIPStr, d.AuthMode)
	if need407 {
		writeProxyAuthRequired(w)
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

		s.handleMITMRequest(tlsConn, req, pr, originAuthority)
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
		StatusCode: http.StatusForbidden,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(string(body))),
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
func (s *Server) handleMITMRequest(clientWriter io.Writer, req *http.Request, connectPR *pipelineResult, dialAddr string) {
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
		return
	}

	// RBI stub: if policy says isolate and orchestrator handles it, stop.
	if s.RBI.ShouldIsolate(d) {
		// RBI needs ResponseWriter; for MITM path, stub never handles.
		// When real RBI lands it will write viewer HTML here.
	}

	// CASB request-side stub.
	if reason, err := s.CASB.InspectRequest(req.Context(), req, d); err != nil {
		slog.Warn("CASB inspect request error", "err", err)
	} else if reason != "" {
		d.FinalAction = policy.ActionBlock
		d.BlockReason = reason
		pr.Decision = d
		body := blockpage.Render(s.loadBlockHTML(req.Context(), nil), blockpage.Context{
			URL: target.String(), Reason: reason, Username: username, ClientIP: clientIPStr, Timestamp: time.Now().UTC(),
		})
		resp := &http.Response{
			StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))),
			ContentLength: int64(len(body)), Close: true,
		}
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		_ = resp.Write(clientWriter)
		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(len(body)), "")
		_ = req.Body.Close()
		return
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
		s.recordOutcome(req.Context(), pr, req, target, "error", req.ContentLength, int64(len(errBody)), err.Error())
		return
	}
	defer resp.Body.Close()

	// CASB response-side stub.
	if reason, err := s.CASB.InspectResponse(req.Context(), req, resp, d); err != nil {
		slog.Warn("CASB inspect response error", "err", err)
	} else if reason != "" {
		_ = resp.Body.Close()
		body := blockpage.Render(s.loadBlockHTML(req.Context(), nil), blockpage.Context{
			URL: target.String(), Reason: reason, Username: username, ClientIP: clientIPStr, Timestamp: time.Now().UTC(),
		})
		br := &http.Response{
			StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1,
			Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))),
			ContentLength: int64(len(body)), Close: true,
		}
		br.Header.Set("Content-Type", "text/html; charset=utf-8")
		_ = br.Write(clientWriter)
		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(len(body)), "")
		return
	}

	// Malware scan stub: only invoked when policy enables; no-op returns clean.
	// Real body scanning is wired in a later task (avoids buffering here).
	if d.MalwareScan {
		if _, err := s.Malware.Scan(req.Context(), strings.NewReader(""), 0); err != nil {
			slog.Debug("malware scan stub", "err", err)
		}
	}

	applyResponseHeaderMods(resp, d.HeaderMods)
	stripHopByHop(resp.Header)

	// Measure response size while streaming to client.
	cw := &countingWriter{w: clientWriter}
	if err := resp.Write(cw); err != nil {
		s.recordOutcome(req.Context(), pr, req, target, "error", req.ContentLength, cw.n, err.Error())
		return
	}
	s.recordOutcome(req.Context(), pr, req, target, "allow", req.ContentLength, cw.n, "")
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
	// RFC 7230 hop-by-hop headers.
	for _, k := range []string{
		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
	} {
		h.Del(k)
	}
	if c := h.Get("Connection"); c != "" {
		for _, f := range strings.Split(c, ",") {
			if f = strings.TrimSpace(f); f != "" {
				h.Del(f)
			}
		}
	}
}

func (s *Server) idleTimeout() time.Duration {
	if s != nil && s.IdleTimeout > 0 {
		return s.IdleTimeout
	}
	return 2 * time.Minute
}
