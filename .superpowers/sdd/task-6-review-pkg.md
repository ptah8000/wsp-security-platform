BASE db473758c1d5dbe0a8ee5909d0b78423ed01e86a HEAD 92c9b5d1526488ceca44ff5b89aad4d2accc1c1e

 .superpowers/sdd/task-6-report.md        | 139 +++++++++  cmd/wsp/main.go                          | 110 ++++++-  internal/blockpage/render.go             |  92 ++++++  internal/blockpage/render_test.go        |  42 +++  internal/logging/recorder.go             | 185 ++++++++++++  internal/logging/recorder_test.go        |  28 ++  internal/proxy/mitm.go                   | 500 +++++++++++++++++++++++++++++++  internal/proxy/pipeline.go               | 381 +++++++++++++++++++++++  internal/proxy/policyload.go             |  71 +++++  internal/proxy/proxy_integration_test.go | 355 ++++++++++++++++++++++  internal/proxy/server.go                 | 271 +++++++++++++++++  internal/proxy/session.go                | 115 +++++++  internal/store/policies.go               | 162 ++++++++++  internal/store/request_logs.go           | 351 ++++++++++++++++++++++  internal/store/sessions.go               | 147 +++++++++  15 files changed, 2933 insertions(+), 16 deletions(-)
diff --git a/cmd/wsp/main.go b/cmd/wsp/main.go
index b4d64b9..b2c8975 100644
--- a/cmd/wsp/main.go
+++ b/cmd/wsp/main.go
@@ -6,10 +6,16 @@ import (
 	"fmt"
 	"log/slog"
 	"os"
+	"os/signal"
 	"strings"
+	"syscall"
 	"time"
 
+	"github.com/wsp-security/wsp/internal/auth"
+	"github.com/wsp-security/wsp/internal/certs"
 	"github.com/wsp-security/wsp/internal/config"
+	"github.com/wsp-security/wsp/internal/logging"
+	"github.com/wsp-security/wsp/internal/proxy"
 	"github.com/wsp-security/wsp/internal/store"
 	_ "github.com/wsp-security/wsp/web" // embed admin UI assets (placeholder in v1 scaffold)
 )
@@ -41,14 +47,13 @@ func main() {
 		"admin_addr", cfg.AdminAddr,
 	)
 
-	if err := runMigrations(cfg); err != nil {
-		slog.Error("migrations failed", "err", err)
+	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
+	defer stop()
+
+	if err := run(ctx, cfg); err != nil {
+		slog.Error("wsp exited with error", "err", err)
 		os.Exit(1)
 	}
-
-	slog.Info("scaffold complete; listeners not started yet",
-		"hint", "subsequent tasks wire proxy and management API",
-	)
 }
 
 func setupLogger(level string) {
@@ -66,25 +71,98 @@ func setupLogger(level string) {
 	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv})))
 }
 
-// runMigrations opens the store, applies pending SQL migrations, and closes the pool.
-// Later tasks will keep a long-lived Store for listeners.
-func runMigrations(cfg config.Config) error {
-	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
+func run(ctx context.Context, cfg config.Config) error {
+	dbCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
 	defer cancel()
 
-	s, err := store.New(ctx, cfg.DatabaseURL)
+	st, err := store.New(dbCtx, cfg.DatabaseURL)
 	if err != nil {
 		return fmt.Errorf("store: %w", err)
 	}
-	defer s.Close()
+	defer st.Close()
 
-	if err := s.Migrate(ctx); err != nil {
-		return err
+	if err := st.Migrate(dbCtx); err != nil {
+		return fmt.Errorf("migrate: %w", err)
 	}
-	complete, err := s.IsSetupComplete(ctx)
+	complete, err := st.IsSetupComplete(dbCtx)
 	if err != nil {
 		return fmt.Errorf("setup status: %w", err)
 	}
 	slog.Info("migrations applied", "setup_complete", complete)
-	return nil
+
+	startProxy := cfg.Mode == "all" || cfg.Mode == "gateway"
+	// Management plane is wired in a later task.
+	if cfg.Mode == "management" {
+		slog.Info("management mode: proxy not started; admin API not yet wired")
+		<-ctx.Done()
+		return nil
+	}
+
+	if !startProxy {
+		slog.Info("no listeners for mode", "mode", cfg.Mode)
+		<-ctx.Done()
+		return nil
+	}
+
+	engine, err := proxy.LoadEngineFromStore(dbCtx, st)
+	if err != nil {
+		slog.Warn("policy load failed; using empty engine (default allow)", "err", err)
+		engine = nil
+	} else {
+		slog.Info("policy engine loaded from store")
+	}
+
+	var certProvider *certs.Provider
+	if cfg.DataKey != "" {
+		cp, err := certs.NewProvider(st, cfg.DataKey)
+		if err != nil {
+			slog.Warn("certs provider init failed; MITM unavailable", "err", err)
+		} else {
+			certProvider = cp
+			// Warm active CA into memory if present.
+			if _, ok, err := certProvider.ActiveCA(dbCtx); err != nil {
+				slog.Warn("load active CA", "err", err)
+			} else if ok {
+				slog.Info("active CA loaded for MITM")
+			} else {
+				slog.Info("no active CA; MITM requires GenerateSelfSignedCA (wizard)")
+			}
+		}
+	} else {
+		slog.Warn("WSP_DATA_KEY not set; MITM cert provider disabled")
+	}
+
+	rec := logging.NewRecorder(st)
+	authCache := auth.NewProxyAuthCache(st, 8*time.Hour)
+
+	srv := &proxy.Server{
+		Addr:      cfg.ProxyAddr,
+		Engine:    engine,
+		Certs:     certProvider,
+		Store:     st,
+		Recorder:  rec,
+		AuthCache: authCache,
+		Sessions:  proxy.NewSessionTracker(st, proxy.DefaultSessionIdle),
+	}
+
+	errc := make(chan error, 1)
+	go func() {
+		errc <- srv.Start(ctx)
+	}()
+
+	slog.Info("gateway ready", "proxy_addr", cfg.ProxyAddr, "mode", cfg.Mode)
+
+	select {
+	case <-ctx.Done():
+		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
+		defer cancel()
+		_ = srv.Shutdown(shutdownCtx)
+		if err := <-errc; err != nil {
+			return err
+		}
+		slog.Info("wsp stopped")
+		return nil
+	case err := <-errc:
+		return err
+	}
 }
diff --git a/internal/blockpage/render.go b/internal/blockpage/render.go
new file mode 100644
index 0000000..7539a55
--- /dev/null
+++ b/internal/blockpage/render.go
@@ -0,0 +1,92 @@
+// Package blockpage renders policy block HTML for denied proxy requests.
+package blockpage
+
+import (
+	"html"
+	"strings"
+	"time"
+)
+
+// DefaultSystemBlockPageID is the UUID of the seed system block page in migrations.
+const DefaultSystemBlockPageID = "00000000-0000-4000-8000-000000000001"
+
+// Context holds values substituted into block page templates.
+type Context struct {
+	URL       string
+	Reason    string
+	Username  string
+	ClientIP  string
+	RuleID    string
+	Timestamp time.Time
+}
+
+// DefaultHTML is the built-in block page used when no custom HTML is available.
+func DefaultHTML() string {
+	return `<!DOCTYPE html>
+<html lang="en">
+<head>
+  <meta charset="utf-8"/>
+  <meta name="viewport" content="width=device-width, initial-scale=1"/>
+  <title>Access Blocked</title>
+  <style>
+    body { font-family: system-ui, sans-serif; background: #0f172a; color: #e2e8f0;
+           display: grid; place-items: center; min-height: 100vh; margin: 0; }
+    main { max-width: 32rem; padding: 2rem; border: 1px solid #334155; border-radius: 0.75rem;
+           background: #1e293b; text-align: center; }
+    h1 { margin: 0 0 0.75rem; font-size: 1.5rem; }
+    p { margin: 0; color: #94a3b8; line-height: 1.5; }
+    .meta { margin-top: 1rem; font-size: 0.875rem; word-break: break-all; }
+  </style>
+</head>
+<body>
+  <main>
+    <h1>Access blocked</h1>
+    <p>This request was blocked by your organization&rsquo;s web security policy.</p>
+    <p class="meta">{{REASON}}</p>
+    <p class="meta">{{URL}}</p>
+    <p class="meta">{{TIMESTAMP}}</p>
+  </main>
+</body>
+</html>`
+}
+
+// Render substitutes known placeholders in htmlTemplate.
+// Unknown placeholders are left as-is. Values are HTML-escaped.
+//
+// Placeholders: {{URL}} {{REASON}} {{USERNAME}} {{CLIENT_IP}} {{RULE_ID}} {{TIMESTAMP}}
+func Render(htmlTemplate string, ctx Context) []byte {
+	if htmlTemplate == "" {
+		htmlTemplate = DefaultHTML()
+	}
+	ts := ctx.Timestamp
+	if ts.IsZero() {
+		ts = time.Now().UTC()
+	}
+	reason := ctx.Reason
+	if reason == "" {
+		reason = "Blocked by policy"
+	}
+
+	repl := map[string]string{
+		"{{URL}}":       html.EscapeString(ctx.URL),
+		"{{REASON}}":    html.EscapeString(reason),
+		"{{USERNAME}}":  html.EscapeString(ctx.Username),
+		"{{CLIENT_IP}}": html.EscapeString(ctx.ClientIP),
+		"{{RULE_ID}}":   html.EscapeString(ctx.RuleID),
+		"{{TIMESTAMP}}": html.EscapeString(ts.UTC().Format(time.RFC3339)),
+	}
+
+	out := htmlTemplate
+	for k, v := range repl {
+		out = strings.ReplaceAll(out, k, v)
+	}
+	return []byte(out)
+}
+
+// ShortBody is a plain-text body for CONNECT 403 responses when MITM is off.
+func ShortBody(reason string) []byte {
+	if reason == "" {
+		reason = "Blocked by policy"
+	}
+	return []byte(reason + "\n")
+}
diff --git a/internal/blockpage/render_test.go b/internal/blockpage/render_test.go
new file mode 100644
index 0000000..d07b886
--- /dev/null
+++ b/internal/blockpage/render_test.go
@@ -0,0 +1,42 @@
+package blockpage
+
+import (
+	"strings"
+	"testing"
+	"time"
+)
+
+func TestRenderEscapesAndSubstitutes(t *testing.T) {
+	html := `<p>{{REASON}}</p><a>{{URL}}</a><span>{{USERNAME}}</span>`
+	out := string(Render(html, Context{
+		URL:      `https://x.test/<script>`,
+		Reason:   `blocked & denied`,
+		Username: `al<ice>`,
+		Timestamp: time.Date(2026, 7, 27, 12, 0, 0, 0, time.UTC),
+	}))
+	if strings.Contains(out, "<script>") {
+		t.Fatalf("URL not escaped: %s", out)
+	}
+	if !strings.Contains(out, "blocked &amp; denied") {
+		t.Fatalf("reason not escaped: %s", out)
+	}
+	if !strings.Contains(out, "al&lt;ice&gt;") {
+		t.Fatalf("username not escaped: %s", out)
+	}
+}
+
+func TestRenderDefaultTemplate(t *testing.T) {
+	out := string(Render("", Context{Reason: "nope", URL: "https://example.com"}))
+	if !strings.Contains(out, "Access blocked") {
+		t.Fatalf("missing title: %s", out)
+	}
+	if !strings.Contains(out, "nope") {
+		t.Fatalf("missing reason: %s", out)
+	}
+}
+
+func TestShortBody(t *testing.T) {
+	if string(ShortBody("")) != "Blocked by policy\n" {
+		t.Fatalf("default short body unexpected")
+	}
+}
diff --git a/internal/logging/recorder.go b/internal/logging/recorder.go
new file mode 100644
index 0000000..f7a1ef3
--- /dev/null
+++ b/internal/logging/recorder.go
@@ -0,0 +1,185 @@
+// Package logging records data-plane sessions and request observations.
+package logging
+
+import (
+	"context"
+	"encoding/json"
+	"log/slog"
+	"sync"
+	"time"
+
+	"github.com/google/uuid"
+
+	"github.com/wsp-security/wsp/internal/store"
+)
+
+// DefaultMemCap is the max in-memory records retained when Store is nil or for tests.
+const DefaultMemCap = 256
+
+// RequestRecord is one proxy pipeline observation (maps to request_logs).
+type RequestRecord struct {
+	SessionID        *uuid.UUID
+	RequestID        uuid.UUID
+	TS               time.Time
+	ClientIP         string
+	Username         string
+	UserAgent        string
+	Method           string
+	Scheme           string
+	Host             string
+	Path             string
+	Query            string
+	URL              string
+	Protocol         string
+	RequestSize      int64
+	ResponseSize     int64
+	Decision         string
+	MatchedRuleIDs   []uuid.UUID
+	EvaluatedRuleIDs []uuid.UUID
+	Actions          map[string]any
+	Timings          map[string]any
+	BlockReason      string
+	BlockPageID      *uuid.UUID
+	Error            string
+}
+
+// Recorder writes request logs to PostgreSQL when a Store is configured, and
+// always retains a bounded in-memory ring for tests and local debugging.
+type Recorder struct {
+	store  *store.Store
+	memCap int
+
+	mu  sync.Mutex
+	mem []RequestRecord
+}
+
+// NewRecorder builds a Recorder. store may be nil (memory-only).
+func NewRecorder(s *store.Store) *Recorder {
+	return &Recorder{
+		store:  s,
+		memCap: DefaultMemCap,
+		mem:    make([]RequestRecord, 0, 32),
+	}
+}
+
+// Record persists rec (async-safe). Missing RequestID/TS are filled in.
+// Failures against the database are logged but do not return to the caller so
+// the data plane is not blocked by log sink issues; in-memory always succeeds.
+func (r *Recorder) Record(ctx context.Context, rec RequestRecord) {
+	if r == nil {
+		return
+	}
+	if rec.RequestID == uuid.Nil {
+		rec.RequestID = uuid.New()
+	}
+	if rec.TS.IsZero() {
+		rec.TS = time.Now().UTC()
+	}
+	if rec.MatchedRuleIDs == nil {
+		rec.MatchedRuleIDs = []uuid.UUID{}
+	}
+	if rec.EvaluatedRuleIDs == nil {
+		rec.EvaluatedRuleIDs = []uuid.UUID{}
+	}
+
+	r.pushMem(rec)
+
+	if r.store == nil {
+		return
+	}
+
+	row := store.RequestLog{
+		SessionID:        rec.SessionID,
+		RequestID:        rec.RequestID,
+		TS:               rec.TS,
+		ClientIP:         rec.ClientIP,
+		Username:         rec.Username,
+		UserAgent:        rec.UserAgent,
+		Method:           rec.Method,
+		Scheme:           rec.Scheme,
+		Host:             rec.Host,
+		Path:             rec.Path,
+		Query:            rec.Query,
+		URL:              rec.URL,
+		Protocol:         rec.Protocol,
+		Decision:         rec.Decision,
+		MatchedRuleIDs:   rec.MatchedRuleIDs,
+		EvaluatedRuleIDs: rec.EvaluatedRuleIDs,
+		BlockReason:      rec.BlockReason,
+		BlockPageID:      rec.BlockPageID,
+		Error:            rec.Error,
+	}
+	if rec.RequestSize != 0 {
+		v := rec.RequestSize
+		row.RequestSize = &v
+	}
+	if rec.ResponseSize != 0 {
+		v := rec.ResponseSize
+		row.ResponseSize = &v
+	}
+	if rec.Actions != nil {
+		if b, err := json.Marshal(rec.Actions); err == nil {
+			row.Actions = b
+		}
+	}
+	if rec.Timings != nil {
+		if b, err := json.Marshal(rec.Timings); err == nil {
+			row.Timings = b
+		}
+	}
+
+	if _, err := r.store.InsertRequestLog(ctx, row); err != nil {
+		slog.Warn("request log insert failed", "err", err, "request_id", rec.RequestID)
+	}
+}
+
+// Recent returns a copy of the in-memory ring (oldest first).
+func (r *Recorder) Recent() []RequestRecord {
+	if r == nil {
+		return nil
+	}
+	r.mu.Lock()
+	defer r.mu.Unlock()
+	out := make([]RequestRecord, len(r.mem))
+	copy(out, r.mem)
+	return out
+}
+
+// Last returns the most recent in-memory record, if any.
+func (r *Recorder) Last() (RequestRecord, bool) {
+	if r == nil {
+		return RequestRecord{}, false
+	}
+	r.mu.Lock()
+	defer r.mu.Unlock()
+	if len(r.mem) == 0 {
+		return RequestRecord{}, false
+	}
+	return r.mem[len(r.mem)-1], true
+}
+
+// ClearMem drops in-memory records (tests).
+func (r *Recorder) ClearMem() {
+	if r == nil {
+		return
+	}
+	r.mu.Lock()
+	defer r.mu.Unlock()
+	r.mem = r.mem[:0]
+}
+
+func (r *Recorder) pushMem(rec RequestRecord) {
+	r.mu.Lock()
+	defer r.mu.Unlock()
+	capN := r.memCap
+	if capN <= 0 {
+		capN = DefaultMemCap
+	}
+	if len(r.mem) >= capN {
+		// Drop oldest.
+		copy(r.mem, r.mem[1:])
+		r.mem[len(r.mem)-1] = rec
+		return
+	}
+	r.mem = append(r.mem, rec)
+}
diff --git a/internal/logging/recorder_test.go b/internal/logging/recorder_test.go
new file mode 100644
index 0000000..7a39ece
--- /dev/null
+++ b/internal/logging/recorder_test.go
@@ -0,0 +1,28 @@
+package logging
+
+import (
+	"context"
+	"testing"
+
+	"github.com/google/uuid"
+)
+
+func TestRecorderMemoryRing(t *testing.T) {
+	r := NewRecorder(nil)
+	r.memCap = 3
+	for i := 0; i < 5; i++ {
+		r.Record(context.Background(), RequestRecord{
+			RequestID: uuid.New(),
+			Decision:  "allow",
+			Host:      "h",
+		})
+	}
+	recent := r.Recent()
+	if len(recent) != 3 {
+		t.Fatalf("len=%d want 3", len(recent))
+	}
+	last, ok := r.Last()
+	if !ok || last.Decision != "allow" {
+		t.Fatalf("last ok=%v decision=%q", ok, last.Decision)
+	}
+}
diff --git a/internal/proxy/mitm.go b/internal/proxy/mitm.go
new file mode 100644
index 0000000..f0534db
--- /dev/null
+++ b/internal/proxy/mitm.go
@@ -0,0 +1,500 @@
+package proxy
+
+import (
+	"bufio"
+	"context"
+	"crypto/tls"
+	"fmt"
+	"io"
+	"log/slog"
+	"net"
+	"net/http"
+	"net/url"
+	"strings"
+	"time"
+
+	"github.com/google/uuid"
+
+	"github.com/wsp-security/wsp/internal/blockpage"
+	"github.com/wsp-security/wsp/internal/policy"
+)
+
+// handleCONNECT processes HTTP CONNECT: tunnel or MITM.
+func (s *Server) handleCONNECT(w http.ResponseWriter, req *http.Request) {
+	start := time.Now().UTC()
+	s.ensureHooks()
+
+	clientIP := clientIPFromRequest(req)
+	clientIPStr := ipString(clientIP)
+	targetHost := req.Host
+	if targetHost == "" {
+		targetHost = req.URL.Host
+	}
+	if targetHost == "" {
+		http.Error(w, "CONNECT host required", http.StatusBadRequest)
+		return
+	}
+	// Ensure host:port form; default 443.
+	if !strings.Contains(targetHost, ":") {
+		targetHost = net.JoinHostPort(targetHost, "443")
+	}
+	hostOnly, port, err := net.SplitHostPort(targetHost)
+	if err != nil {
+		http.Error(w, "invalid CONNECT host", http.StatusBadRequest)
+		return
+	}
+	if port == "" {
+		port = "443"
+		targetHost = net.JoinHostPort(hostOnly, port)
+	}
+
+	targetURL := &url.URL{Scheme: "https", Host: hostOnly, Path: "/"}
+	in := buildInput(req, clientIP, "", targetURL, http.MethodConnect)
+	d := s.evaluate(in)
+
+	username, need407 := s.resolveAuth(req.Context(), req, clientIPStr, d.AuthMode)
+	if need407 {
+		writeProxyAuthRequired(w)
+		return
+	}
+	if username != "" {
+		in.Username = username
+		// Re-evaluate with username so user-scoped rules apply.
+		d = s.evaluate(in)
+	}
+
+	requestID := uuid.New()
+	sessionID := s.Sessions.Acquire(req.Context(), clientIPStr, username, req.UserAgent())
+	pr := &pipelineResult{
+		Input:     in,
+		Decision:  d,
+		Username:  username,
+		RequestID: requestID,
+		SessionID: sessionID,
+		Start:     start,
+	}
+
+	// Block without MITM: 403 short body (cannot show HTML page inside CONNECT).
+	if d.FinalAction == policy.ActionBlock && !d.TLSIntercept {
+		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
+		w.WriteHeader(http.StatusForbidden)
+		body := blockpage.ShortBody(d.BlockReason)
+		_, _ = w.Write(body)
+		s.recordOutcome(req.Context(), pr, req, targetURL, "block", 0, int64(len(body)), "")
+		return
+	}
+
+	// Hijack client connection for tunnel or MITM.
+	hj, ok := w.(http.Hijacker)
+	if !ok {
+		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
+		s.recordOutcome(req.Context(), pr, req, targetURL, decisionLabel(d, "error"), 0, 0, "hijack unsupported")
+		return
+	}
+
+	clientConn, clientBuf, err := hj.Hijack()
+	if err != nil {
+		slog.Warn("CONNECT hijack failed", "err", err)
+		s.recordOutcome(req.Context(), pr, req, targetURL, decisionLabel(d, "error"), 0, 0, err.Error())
+		return
+	}
+
+	// MITM path (also used for block-with-intercept so we can serve a block page).
+	if d.TLSIntercept {
+		s.serveMITM(clientConn, clientBuf, req, pr, hostOnly, targetHost)
+		return
+	}
+
+	// Transparent tunnel (no interception).
+	s.serveTunnel(clientConn, clientBuf, req, pr, targetHost, targetURL)
+}
+
+// serveTunnel dials origin and bidirectionally copies bytes after 200.
+func (s *Server) serveTunnel(clientConn net.Conn, clientBuf *bufio.ReadWriter, req *http.Request, pr *pipelineResult, targetHost string, targetURL *url.URL) {
+	defer clientConn.Close()
+
+	ctx := req.Context()
+	originConn, err := s.Dialer.DialContext(ctx, "tcp", targetHost)
+	if err != nil {
+		_, _ = clientBuf.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nconnect failed\r\n")
+		_ = clientBuf.Flush()
+		s.recordOutcome(ctx, pr, req, targetURL, "error", 0, 0, err.Error())
+		return
+	}
+	defer originConn.Close()
+
+	_, _ = clientBuf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
+	if err := clientBuf.Flush(); err != nil {
+		s.recordOutcome(ctx, pr, req, targetURL, "error", 0, 0, err.Error())
+		return
+	}
+
+	// Log CONNECT allow (tunnel) once; individual HTTP messages are opaque.
+	s.recordOutcome(ctx, pr, req, targetURL, "allow", 0, 0, "")
+
+	// Any buffered client bytes after CONNECT request line/headers.
+	var clientReader io.Reader = clientConn
+	if clientBuf.Reader != nil && clientBuf.Reader.Buffered() > 0 {
+		clientReader = io.MultiReader(clientBuf.Reader, clientConn)
+	}
+
+	errc := make(chan error, 2)
+	go func() {
+		_, err := io.Copy(originConn, clientReader)
+		errc <- err
+	}()
+	go func() {
+		_, err := io.Copy(clientConn, originConn)
+		errc <- err
+	}()
+	<-errc
+}
+
+// serveMITM terminates TLS toward the client with a leaf signed by the active CA,
+// then runs the HTTP pipeline for each decrypted request.
+func (s *Server) serveMITM(clientConn net.Conn, clientBuf *bufio.ReadWriter, connectReq *http.Request, pr *pipelineResult, hostOnly, dialAddr string) {
+	defer clientConn.Close()
+
+	ctx := connectReq.Context()
+	if s.Certs == nil {
+		_, _ = clientBuf.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nno CA configured for MITM\r\n")
+		_ = clientBuf.Flush()
+		s.recordOutcome(ctx, pr, connectReq, pr.Input.URL, "error", 0, 0, "no CA")
+		return
+	}
+
+	leaf, err := s.Certs.SignHost(hostOnly)
+	if err != nil {
+		_, _ = clientBuf.WriteString("HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nMITM cert failed\r\n")
+		_ = clientBuf.Flush()
+		s.recordOutcome(ctx, pr, connectReq, pr.Input.URL, "error", 0, 0, err.Error())
+		return
+	}
+
+	_, _ = clientBuf.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
+	if err := clientBuf.Flush(); err != nil {
+		s.recordOutcome(ctx, pr, connectReq, pr.Input.URL, "error", 0, 0, err.Error())
+		return
+	}
+
+	// Log the CONNECT itself as allow/block intent; per-request logs follow.
+	connectDecision := decisionLabel(pr.Decision, "")
+	if pr.Decision.FinalAction == policy.ActionBlock {
+		connectDecision = "block"
+	}
+	s.recordOutcome(ctx, pr, connectReq, pr.Input.URL, connectDecision, 0, 0, "")
+
+	var rawClient io.Reader = clientConn
+	if clientBuf.Reader != nil && clientBuf.Reader.Buffered() > 0 {
+		rawClient = io.MultiReader(clientBuf.Reader, clientConn)
+	}
+	// tls.Server needs a net.Conn; wrap buffered reader.
+	tlsConn := tls.Server(&bufConn{Conn: clientConn, r: rawClient}, &tls.Config{
+		Certificates: []tls.Certificate{*leaf},
+		MinVersion:   tls.VersionTLS12,
+	})
+	if err := tlsConn.HandshakeContext(ctx); err != nil {
+		slog.Debug("MITM handshake failed", "host", hostOnly, "err", err)
+		return
+	}
+	defer tlsConn.Close()
+
+	// If CONNECT-stage policy already blocked, show block page once and close.
+	if pr.Decision.FinalAction == policy.ActionBlock {
+		s.serveBlockedOnTLS(tlsConn, connectReq, pr)
+		return
+	}
+
+	// Origin authority including port (required so RoundTrip does not default to :443).
+	originAuthority := dialAddr
+	if _, _, err := net.SplitHostPort(dialAddr); err != nil {
+		originAuthority = net.JoinHostPort(hostOnly, "443")
+	}
+
+	br := bufio.NewReader(tlsConn)
+	for {
+		_ = tlsConn.SetDeadline(time.Now().Add(s.idleTimeout()))
+		req, err := http.ReadRequest(br)
+		if err != nil {
+			if err != io.EOF {
+				slog.Debug("MITM read request", "host", hostOnly, "err", err)
+			}
+			return
+		}
+
+		// Rewrite to absolute origin URL for pipeline/forward.
+		req.URL.Scheme = "https"
+		req.URL.Host = originAuthority
+		req.Host = originAuthority
+		req.RequestURI = ""
+		// Preserve client identity from CONNECT.
+		req.RemoteAddr = connectReq.RemoteAddr
+
+		s.handleMITMRequest(tlsConn, req, pr, originAuthority)
+	}
+}
+
+// serveBlockedOnTLS writes an HTTP block page over the established TLS channel.
+func (s *Server) serveBlockedOnTLS(conn net.Conn, connectReq *http.Request, pr *pipelineResult) {
+	// Wait for first client request if possible so we respond properly.
+	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
+	br := bufio.NewReader(conn)
+	req, err := http.ReadRequest(br)
+	if err != nil {
+		// No request; write a synthetic response anyway.
+		req = &http.Request{Method: http.MethodGet, URL: pr.Input.URL, Header: make(http.Header)}
+	} else {
+		if req.URL.Scheme == "" {
+			req.URL.Scheme = "https"
+		}
+		if req.URL.Host == "" && pr.Input.URL != nil {
+			req.URL.Host = pr.Input.URL.Host
+		}
+	}
+
+	html := s.loadBlockHTML(context.Background(), pr.Decision.BlockPageID)
+	ruleID := ""
+	if len(pr.Decision.MatchedRuleIDs) > 0 {
+		ruleID = pr.Decision.MatchedRuleIDs[0].String()
+	}
+	urlStr := ""
+	if pr.Input.URL != nil {
+		urlStr = pr.Input.URL.String()
+	}
+	body := blockpage.Render(html, blockpage.Context{
+		URL:       urlStr,
+		Reason:    pr.Decision.BlockReason,
+		Username:  pr.Username,
+		ClientIP:  ipString(pr.Input.ClientIP),
+		RuleID:    ruleID,
+		Timestamp: time.Now().UTC(),
+	})
+
+	resp := &http.Response{
+		StatusCode: http.StatusForbidden,
+		ProtoMajor: 1,
+		ProtoMinor: 1,
+		Header:     make(http.Header),
+		Body:       io.NopCloser(strings.NewReader(string(body))),
+		ContentLength: int64(len(body)),
+	}
+	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
+	resp.Header.Set("Connection", "close")
+	resp.Header.Set("Cache-Control", "no-store")
+	_ = resp.Write(conn)
+
+	// Per-request log for the blocked page.
+	pr2 := *pr
+	pr2.RequestID = uuid.New()
+	pr2.Start = time.Now().UTC()
+	s.recordOutcome(context.Background(), &pr2, req, pr.Input.URL, "block", 0, int64(len(body)), "")
+}
+
+// handleMITMRequest evaluates policy again for the full URL and forwards to origin.
+func (s *Server) handleMITMRequest(clientWriter io.Writer, req *http.Request, connectPR *pipelineResult, dialAddr string) {
+	start := time.Now().UTC()
+	s.ensureHooks()
+
+	clientIP := connectPR.Input.ClientIP
+	clientIPStr := ipString(clientIP)
+	username := connectPR.Username
+
+	target := cloneURL(req.URL)
+	if target.Scheme == "" {
+		target.Scheme = "https"
+	}
+	in := buildInput(req, clientIP, username, target, req.Method)
+	d := s.evaluate(in)
+
+	requestID := uuid.New()
+	sessionID := s.Sessions.Acquire(req.Context(), clientIPStr, username, req.UserAgent())
+	pr := &pipelineResult{
+		Input:     in,
+		Decision:  d,
+		Username:  username,
+		RequestID: requestID,
+		SessionID: sessionID,
+		Start:     start,
+	}
+
+	if d.FinalAction == policy.ActionBlock {
+		html := s.loadBlockHTML(req.Context(), d.BlockPageID)
+		ruleID := ""
+		if len(d.MatchedRuleIDs) > 0 {
+			ruleID = d.MatchedRuleIDs[0].String()
+		}
+		body := blockpage.Render(html, blockpage.Context{
+			URL:       target.String(),
+			Reason:    d.BlockReason,
+			Username:  username,
+			ClientIP:  clientIPStr,
+			RuleID:    ruleID,
+			Timestamp: time.Now().UTC(),
+		})
+		resp := &http.Response{
+			StatusCode:    http.StatusForbidden,
+			ProtoMajor:    1,
+			ProtoMinor:    1,
+			Header:        make(http.Header),
+			Body:          io.NopCloser(strings.NewReader(string(body))),
+			ContentLength: int64(len(body)),
+			Close:         true,
+		}
+		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
+		resp.Header.Set("Cache-Control", "no-store")
+		_ = resp.Write(clientWriter)
+		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(len(body)), "")
+		_ = req.Body.Close()
+		return
+	}
+
+	// RBI stub: if policy says isolate and orchestrator handles it, stop.
+	if s.RBI.ShouldIsolate(d) {
+		// RBI needs ResponseWriter; for MITM path, stub never handles.
+		// When real RBI lands it will write viewer HTML here.
+	}
+
+	// CASB request-side stub.
+	if reason, err := s.CASB.InspectRequest(req.Context(), req, d); err != nil {
+		slog.Warn("CASB inspect request error", "err", err)
+	} else if reason != "" {
+		d.FinalAction = policy.ActionBlock
+		d.BlockReason = reason
+		pr.Decision = d
+		body := blockpage.Render(s.loadBlockHTML(req.Context(), nil), blockpage.Context{
+			URL: target.String(), Reason: reason, Username: username, ClientIP: clientIPStr, Timestamp: time.Now().UTC(),
+		})
+		resp := &http.Response{
+			StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1,
+			Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))),
+			ContentLength: int64(len(body)), Close: true,
+		}
+		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
+		_ = resp.Write(clientWriter)
+		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(len(body)), "")
+		_ = req.Body.Close()
+		return
+	}
+
+	applyRequestHeaderMods(req, d.HeaderMods)
+	stripHopByHop(req.Header)
+	req.Header.Del("Proxy-Authorization")
+	req.Header.Del("Proxy-Connection")
+
+	// Dial origin with real TLS (verify system roots / default).
+	// dialAddr is host:port from CONNECT so non-443 origins work (e.g. httptest).
+	originURL := cloneURL(target)
+	if dialAddr != "" {
+		originURL.Host = dialAddr
+	}
+	outReq := req.Clone(req.Context())
+	outReq.RequestURI = ""
+	outReq.URL = originURL
+	outReq.Host = originURL.Host
+
+	resp, err := s.Transport.RoundTrip(outReq)
+	if err != nil {
+		errBody := fmt.Sprintf("Bad Gateway: %v", err)
+		r := &http.Response{
+			StatusCode: http.StatusBadGateway, ProtoMajor: 1, ProtoMinor: 1,
+			Header: make(http.Header), Body: io.NopCloser(strings.NewReader(errBody)),
+			ContentLength: int64(len(errBody)), Close: true,
+		}
+		r.Header.Set("Content-Type", "text/plain; charset=utf-8")
+		_ = r.Write(clientWriter)
+		s.recordOutcome(req.Context(), pr, req, target, "error", req.ContentLength, int64(len(errBody)), err.Error())
+		return
+	}
+	defer resp.Body.Close()
+
+	// CASB response-side stub.
+	if reason, err := s.CASB.InspectResponse(req.Context(), req, resp, d); err != nil {
+		slog.Warn("CASB inspect response error", "err", err)
+	} else if reason != "" {
+		_ = resp.Body.Close()
+		body := blockpage.Render(s.loadBlockHTML(req.Context(), nil), blockpage.Context{
+			URL: target.String(), Reason: reason, Username: username, ClientIP: clientIPStr, Timestamp: time.Now().UTC(),
+		})
+		br := &http.Response{
+			StatusCode: http.StatusForbidden, ProtoMajor: 1, ProtoMinor: 1,
+			Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(body))),
+			ContentLength: int64(len(body)), Close: true,
+		}
+		br.Header.Set("Content-Type", "text/html; charset=utf-8")
+		_ = br.Write(clientWriter)
+		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(len(body)), "")
+		return
+	}
+
+	// Malware scan stub: only invoked when policy enables; no-op returns clean.
+	// Real body scanning is wired in a later task (avoids buffering here).
+	if d.MalwareScan {
+		if _, err := s.Malware.Scan(req.Context(), strings.NewReader(""), 0); err != nil {
+			slog.Debug("malware scan stub", "err", err)
+		}
+	}
+
+	applyResponseHeaderMods(resp, d.HeaderMods)
+	stripHopByHop(resp.Header)
+
+	// Measure response size while streaming to client.
+	cw := &countingWriter{w: clientWriter}
+	if err := resp.Write(cw); err != nil {
+		s.recordOutcome(req.Context(), pr, req, target, "error", req.ContentLength, cw.n, err.Error())
+		return
+	}
+	s.recordOutcome(req.Context(), pr, req, target, "allow", req.ContentLength, cw.n, "")
+}
+
+// bufConn presents a net.Conn that reads from r first (buffered CONNECT leftovers).
+type bufConn struct {
+	net.Conn
+	r io.Reader
+}
+
+func (c *bufConn) Read(p []byte) (int, error) {
+	return c.r.Read(p)
+}
+
+type countingWriter struct {
+	w io.Writer
+	n int64
+}
+
+func (c *countingWriter) Write(p []byte) (int, error) {
+	n, err := c.w.Write(p)
+	c.n += int64(n)
+	return n, err
+}
+
+func cloneURL(u *url.URL) *url.URL {
+	if u == nil {
+		return &url.URL{}
+	}
+	c := *u
+	return &c
+}
+
+func stripHopByHop(h http.Header) {
+	// RFC 7230 hop-by-hop headers.
+	for _, k := range []string{
+		"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
+		"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
+	} {
+		h.Del(k)
+	}
+	if c := h.Get("Connection"); c != "" {
+		for _, f := range strings.Split(c, ",") {
+			if f = strings.TrimSpace(f); f != "" {
+				h.Del(f)
+			}
+		}
+	}
+}
+
+func (s *Server) idleTimeout() time.Duration {
+	if s != nil && s.IdleTimeout > 0 {
+		return s.IdleTimeout
+	}
+	return 2 * time.Minute
+}
diff --git a/internal/proxy/pipeline.go b/internal/proxy/pipeline.go
new file mode 100644
index 0000000..7b47604
--- /dev/null
+++ b/internal/proxy/pipeline.go
@@ -0,0 +1,381 @@
+package proxy
+
+import (
+	"context"
+	"encoding/base64"
+	"io"
+	"log/slog"
+	"net"
+	"net/http"
+	"net/url"
+	"strings"
+	"time"
+
+	"github.com/google/uuid"
+
+	"github.com/wsp-security/wsp/internal/auth"
+	"github.com/wsp-security/wsp/internal/blockpage"
+	"github.com/wsp-security/wsp/internal/logging"
+	"github.com/wsp-security/wsp/internal/policy"
+)
+
+// Pipeline hook interfaces (stubs until later tasks).
+
+// CASBInspector inspects request/response for cloud app controls.
+type CASBInspector interface {
+	// InspectRequest returns a block reason when the request should be denied.
+	InspectRequest(ctx context.Context, req *http.Request, d policy.Decision) (blockReason string, err error)
+	InspectResponse(ctx context.Context, req *http.Request, resp *http.Response, d policy.Decision) (blockReason string, err error)
+}
+
+// MalwareScanner scans bodies when policy enables malware scanning.
+type MalwareScanner interface {
+	// Scan returns threat name when malicious; empty string means clean/skipped.
+	Scan(ctx context.Context, r io.Reader, maxBytes int64) (threat string, err error)
+}
+
+// RBIOrchestrator hands off isolated browsing (stub no-op in v1 skeleton).
+type RBIOrchestrator interface {
+	// ShouldIsolate reports whether this request should use RBI.
+	ShouldIsolate(d policy.Decision) bool
+	// HandleIsolation serves the isolation viewer instead of origin bytes.
+	// Returns true if the request was fully handled.
+	HandleIsolation(w http.ResponseWriter, req *http.Request, d policy.Decision) bool
+}
+
+// noopCASB is the default CASB stub.
+type noopCASB struct{}
+
+func (noopCASB) InspectRequest(context.Context, *http.Request, policy.Decision) (string, error) {
+	return "", nil
+}
+func (noopCASB) InspectResponse(context.Context, *http.Request, *http.Response, policy.Decision) (string, error) {
+	return "", nil
+}
+
+// noopMalware is the default malware stub.
+type noopMalware struct{}
+
+func (noopMalware) Scan(context.Context, io.Reader, int64) (string, error) { return "", nil }
+
+// noopRBI is the default RBI stub (never isolates).
+type noopRBI struct{}
+
+func (noopRBI) ShouldIsolate(policy.Decision) bool { return false }
+func (noopRBI) HandleIsolation(http.ResponseWriter, *http.Request, policy.Decision) bool {
+	return false
+}
+
+// pipelineResult holds evaluation outcome for one request/connect.
+type pipelineResult struct {
+	Input     policy.RequestInput
+	Decision  policy.Decision
+	Username  string
+	RequestID uuid.UUID
+	SessionID uuid.UUID
+	Start     time.Time
+}
+
+// buildInput constructs policy.RequestInput from an HTTP request.
+func buildInput(req *http.Request, clientIP net.IP, username string, target *url.URL, method string) policy.RequestInput {
+	ua := ""
+	if req != nil {
+		ua = req.UserAgent()
+		if method == "" {
+			method = req.Method
+		}
+	}
+	if method == "" {
+		method = http.MethodGet
+	}
+	return policy.RequestInput{
+		ClientIP:  clientIP,
+		Username:  username,
+		UserAgent: ua,
+		Method:    method,
+		URL:       target,
+		Now:       time.Now().UTC(),
+	}
+}
+
+// evaluate runs policy.Engine (nil-safe ΓåÆ default allow).
+func (s *Server) evaluate(in policy.RequestInput) policy.Decision {
+	if s == nil || s.Engine == nil {
+		return policy.Decision{FinalAction: policy.ActionAllow, AuthMode: policy.AuthDisable}
+	}
+	return s.Engine.Evaluate(in)
+}
+
+// resolveAuth enforces proxy auth based on decision.AuthMode.
+// Returns username, whether auth failed (caller should 407), and optional www-auth.
+func (s *Server) resolveAuth(ctx context.Context, req *http.Request, clientIP string, mode string) (username string, need407 bool) {
+	if mode == "" || mode == policy.AuthDisable {
+		// Still surface any provided credentials for logging.
+		if u, _, ok := proxyBasicAuth(req); ok {
+			return u, false
+		}
+		return "", false
+	}
+
+	ip := clientIP
+
+	if mode == policy.AuthIPCached && s.AuthCache != nil {
+		if u, _, ok := s.AuthCache.Get(ctx, ip); ok {
+			return u, false
+		}
+	}
+
+	user, pass, ok := proxyBasicAuth(req)
+	if !ok {
+		return "", true
+	}
+
+	if s.Store == nil {
+		// Without store we cannot verify; treat as unauthenticated.
+		return "", true
+	}
+
+	dbUser, err := s.Store.GetUserByUsername(ctx, user)
+	if err != nil || !dbUser.Enabled || !auth.CheckPassword(dbUser.PasswordHash, pass) {
+		return "", true
+	}
+
+	if mode == policy.AuthIPCached && s.AuthCache != nil {
+		if err := s.AuthCache.Put(ctx, ip, dbUser.ID, dbUser.Username); err != nil {
+			slog.Warn("proxy auth cache put failed", "err", err)
+		}
+	}
+	return dbUser.Username, false
+}
+
+func proxyBasicAuth(req *http.Request) (username, password string, ok bool) {
+	if req == nil {
+		return "", "", false
+	}
+	h := req.Header.Get("Proxy-Authorization")
+	if h == "" {
+		return "", "", false
+	}
+	const prefix = "Basic "
+	if len(h) < len(prefix) || !strings.EqualFold(h[:len(prefix)], prefix) {
+		return "", "", false
+	}
+	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(h[len(prefix):]))
+	if err != nil {
+		return "", "", false
+	}
+	user, pass, found := strings.Cut(string(raw), ":")
+	if !found {
+		return "", "", false
+	}
+	return user, pass, true
+}
+
+func writeProxyAuthRequired(w http.ResponseWriter) {
+	w.Header().Set("Proxy-Authenticate", `Basic realm="WSP"`)
+	http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
+}
+
+// loadBlockHTML returns custom or default block page HTML.
+func (s *Server) loadBlockHTML(ctx context.Context, pageID *uuid.UUID) string {
+	if s != nil && s.Store != nil {
+		if pageID != nil && *pageID != uuid.Nil {
+			if p, err := s.Store.GetBlockPage(ctx, *pageID); err == nil && p.HTML != "" {
+				return p.HTML
+			}
+		}
+		if p, err := s.Store.GetSystemDefaultBlockPage(ctx); err == nil && p.HTML != "" {
+			return p.HTML
+		}
+	}
+	return blockpage.DefaultHTML()
+}
+
+func (s *Server) writeBlockPage(w http.ResponseWriter, req *http.Request, d policy.Decision, clientIP, username string, target *url.URL) int {
+	ctx := req.Context()
+	html := s.loadBlockHTML(ctx, d.BlockPageID)
+	ruleID := ""
+	if len(d.MatchedRuleIDs) > 0 {
+		ruleID = d.MatchedRuleIDs[0].String()
+	}
+	urlStr := ""
+	if target != nil {
+		urlStr = target.String()
+	}
+	body := blockpage.Render(html, blockpage.Context{
+		URL:       urlStr,
+		Reason:    d.BlockReason,
+		Username:  username,
+		ClientIP:  clientIP,
+		RuleID:    ruleID,
+		Timestamp: time.Now().UTC(),
+	})
+	w.Header().Set("Content-Type", "text/html; charset=utf-8")
+	w.Header().Set("Cache-Control", "no-store")
+	w.WriteHeader(http.StatusForbidden)
+	_, _ = w.Write(body)
+	return len(body)
+}
+
+// applyRequestHeaderMods mutates req headers per policy.
+func applyRequestHeaderMods(req *http.Request, mods []policy.HeaderMod) {
+	for _, m := range mods {
+		if m.Target != "" && m.Target != policy.HeaderRequest {
+			continue
+		}
+		switch m.Op {
+		case policy.HeaderSet:
+			req.Header.Set(m.Name, m.Value)
+		case policy.HeaderAppend:
+			req.Header.Add(m.Name, m.Value)
+		case policy.HeaderRemove:
+			req.Header.Del(m.Name)
+		}
+	}
+}
+
+// applyResponseHeaderMods mutates resp headers per policy.
+func applyResponseHeaderMods(resp *http.Response, mods []policy.HeaderMod) {
+	if resp == nil {
+		return
+	}
+	for _, m := range mods {
+		if m.Target != policy.HeaderResponse {
+			continue
+		}
+		switch m.Op {
+		case policy.HeaderSet:
+			resp.Header.Set(m.Name, m.Value)
+		case policy.HeaderAppend:
+			resp.Header.Add(m.Name, m.Value)
+		case policy.HeaderRemove:
+			resp.Header.Del(m.Name)
+		}
+	}
+}
+
+// recordOutcome writes a request log via Recorder.
+func (s *Server) recordOutcome(ctx context.Context, pr *pipelineResult, req *http.Request, target *url.URL, decision string, reqSize, respSize int64, errMsg string) {
+	if s == nil || s.Recorder == nil || pr == nil {
+		return
+	}
+	scheme, host, path, query, urlStr := "", "", "", "", ""
+	if target != nil {
+		scheme = target.Scheme
+		host = target.Host
+		path = target.Path
+		query = target.RawQuery
+		urlStr = target.String()
+	}
+	method := ""
+	ua := ""
+	proto := ""
+	if req != nil {
+		method = req.Method
+		ua = req.UserAgent()
+		proto = req.Proto
+	}
+	actions := map[string]any{
+		"tls_intercept": pr.Decision.TLSIntercept,
+		"rbi_isolated":  pr.Decision.RBIIsolated,
+		"malware_scan":  pr.Decision.MalwareScan,
+		"auth_mode":     pr.Decision.AuthMode,
+	}
+	if len(pr.Decision.CASB) > 0 {
+		actions["casb"] = pr.Decision.CASB
+	}
+	timings := map[string]any{
+		"total_ms": time.Since(pr.Start).Milliseconds(),
+	}
+	var sessionID *uuid.UUID
+	if pr.SessionID != uuid.Nil {
+		id := pr.SessionID
+		sessionID = &id
+	}
+	s.Recorder.Record(ctx, logging.RequestRecord{
+		SessionID:        sessionID,
+		RequestID:        pr.RequestID,
+		TS:               time.Now().UTC(),
+		ClientIP:         ipString(pr.Input.ClientIP),
+		Username:         pr.Username,
+		UserAgent:        ua,
+		Method:           method,
+		Scheme:           scheme,
+		Host:             host,
+		Path:             path,
+		Query:            query,
+		URL:              urlStr,
+		Protocol:         proto,
+		RequestSize:      reqSize,
+		ResponseSize:     respSize,
+		Decision:         decision,
+		MatchedRuleIDs:   pr.Decision.MatchedRuleIDs,
+		EvaluatedRuleIDs: pr.Decision.EvaluatedRuleIDs,
+		Actions:          actions,
+		Timings:          timings,
+		BlockReason:      pr.Decision.BlockReason,
+		BlockPageID:      pr.Decision.BlockPageID,
+		Error:            errMsg,
+	})
+}
+
+func ipString(ip net.IP) string {
+	if ip == nil {
+		return ""
+	}
+	return ip.String()
+}
+
+// clientIPFromRequest extracts the remote IP (no X-Forwarded-For trust in v1).
+func clientIPFromRequest(req *http.Request) net.IP {
+	if req == nil || req.RemoteAddr == "" {
+		return nil
+	}
+	host, _, err := net.SplitHostPort(req.RemoteAddr)
+	if err != nil {
+		return net.ParseIP(req.RemoteAddr)
+	}
+	return net.ParseIP(host)
+}
+
+// ensureHooks fills default stubs when interfaces are nil.
+func (s *Server) ensureHooks() {
+	if s.CASB == nil {
+		s.CASB = noopCASB{}
+	}
+	if s.Malware == nil {
+		s.Malware = noopMalware{}
+	}
+	if s.RBI == nil {
+		s.RBI = noopRBI{}
+	}
+	if s.Sessions == nil {
+		s.Sessions = NewSessionTracker(s.Store, DefaultSessionIdle)
+	}
+	if s.Dialer == nil {
+		s.Dialer = &net.Dialer{Timeout: 30 * time.Second}
+	}
+	if s.Transport == nil {
+		s.Transport = &http.Transport{
+			Proxy:                 nil, // never chain
+			DialContext:           s.Dialer.DialContext,
+			ForceAttemptHTTP2:     true,
+			MaxIdleConns:          100,
+			IdleConnTimeout:       90 * time.Second,
+			TLSHandshakeTimeout:   10 * time.Second,
+			ExpectContinueTimeout: 1 * time.Second,
+			// Origin TLS: system roots (MITM is client-side only).
+		}
+	}
+}
+
+// decisionLabel maps FinalAction to log decision string, with overrides.
+func decisionLabel(d policy.Decision, override string) string {
+	if override != "" {
+		return override
+	}
+	if d.FinalAction == policy.ActionBlock {
+		return string(policy.ActionBlock)
+	}
+	return string(policy.ActionAllow)
+}
diff --git a/internal/proxy/policyload.go b/internal/proxy/policyload.go
new file mode 100644
index 0000000..f92ef63
--- /dev/null
+++ b/internal/proxy/policyload.go
@@ -0,0 +1,71 @@
+package proxy
+
+import (
+	"context"
+	"encoding/json"
+	"fmt"
+
+	"github.com/google/uuid"
+
+	"github.com/wsp-security/wsp/internal/policy"
+	"github.com/wsp-security/wsp/internal/store"
+)
+
+// LoadEngineFromStore lists policies/objects from the database, compiles them,
+// and returns a ready Engine. Empty policy set yields an engine with default allow.
+func LoadEngineFromStore(ctx context.Context, s *store.Store) (*policy.Engine, error) {
+	if s == nil {
+		return nil, fmt.Errorf("store is nil")
+	}
+	rows, err := s.ListPolicies(ctx)
+	if err != nil {
+		return nil, err
+	}
+	objs, err := s.ListReusableObjects(ctx)
+	if err != nil {
+		return nil, err
+	}
+
+	rules := make([]policy.Rule, 0, len(rows))
+	for _, row := range rows {
+		var sections policy.RuleSections
+		if len(row.Sections) > 0 {
+			if err := json.Unmarshal(row.Sections, &sections); err != nil {
+				return nil, fmt.Errorf("policy %s sections: %w", row.ID, err)
+			}
+		}
+		rules = append(rules, policy.Rule{
+			ID:          row.ID,
+			Name:        row.Name,
+			Description: row.Description,
+			Enabled:     row.Enabled,
+			Priority:    row.Priority,
+			Sections:    sections,
+		})
+	}
+
+	objectMap := make(map[uuid.UUID]policy.Object, len(objs))
+	for _, o := range objs {
+		var def policy.ObjectDefinition
+		if len(o.Definition) > 0 {
+			if err := json.Unmarshal(o.Definition, &def); err != nil {
+				return nil, fmt.Errorf("object %s definition: %w", o.ID, err)
+			}
+		}
+		objectMap[o.ID] = policy.Object{
+			ID:         o.ID,
+			Name:       o.Name,
+			Type:       o.Type,
+			Definition: def,
+			IsSystem:   o.IsSystem,
+		}
+	}
+
+	snap, err := policy.Compile(rules, objectMap)
+	if err != nil {
+		return nil, fmt.Errorf("compile policy: %w", err)
+	}
+	eng := &policy.Engine{}
+	eng.Swap(snap)
+	return eng, nil
+}
diff --git a/internal/proxy/proxy_integration_test.go b/internal/proxy/proxy_integration_test.go
new file mode 100644
index 0000000..92a2689
--- /dev/null
+++ b/internal/proxy/proxy_integration_test.go
@@ -0,0 +1,355 @@
+package proxy_test
+
+import (
+	"context"
+	"crypto/tls"
+	"crypto/x509"
+	"fmt"
+	"io"
+	"net"
+	"net/http"
+	"net/http/httptest"
+	"net/url"
+	"strings"
+	"testing"
+	"time"
+
+	"github.com/google/uuid"
+
+	"github.com/wsp-security/wsp/internal/certs"
+	"github.com/wsp-security/wsp/internal/logging"
+	"github.com/wsp-security/wsp/internal/policy"
+	"github.com/wsp-security/wsp/internal/proxy"
+)
+
+const testDataKey = "test-data-key-16b"
+
+func allowMITMEngine(t *testing.T) *policy.Engine {
+	t.Helper()
+	rules := []policy.Rule{{
+		ID:       uuid.MustParse("00000000-0000-4000-8000-000000000099"),
+		Name:     "test-allow-mitm",
+		Enabled:  true,
+		Priority: 100,
+		Sections: policy.RuleSections{
+			General: policy.GeneralSection{
+				Action:       policy.ActionAllow,
+				TLSIntercept: true,
+				AuthMode:     policy.AuthDisable,
+			},
+		},
+	}}
+	snap, err := policy.Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng policy.Engine
+	eng.Swap(snap)
+	return &eng
+}
+
+func blockEngine(t *testing.T, domain string) *policy.Engine {
+	t.Helper()
+	rules := []policy.Rule{{
+		ID:       uuid.MustParse("00000000-0000-4000-8000-000000000098"),
+		Name:     "test-block",
+		Enabled:  true,
+		Priority: 10,
+		Sections: policy.RuleSections{
+			General: policy.GeneralSection{
+				Action:      policy.ActionBlock,
+				BlockReason: "blocked for test",
+				Destinations: []policy.Condition{
+					{Type: policy.CondDestinationDomain, Value: domain},
+				},
+			},
+		},
+	}}
+	snap, err := policy.Compile(rules, nil)
+	if err != nil {
+		t.Fatalf("Compile: %v", err)
+	}
+	var eng policy.Engine
+	eng.Swap(snap)
+	return &eng
+}
+
+func startProxy(t *testing.T, srv *proxy.Server) (proxyURL *url.URL, cancel context.CancelFunc) {
+	t.Helper()
+	srv.Addr = "127.0.0.1:0"
+	ctx, cancel := context.WithCancel(context.Background())
+	errc := make(chan error, 1)
+	go func() {
+		errc <- srv.Start(ctx)
+	}()
+
+	// Wait until Addr is updated from :0 bind.
+	var addr string
+	deadline := time.Now().Add(3 * time.Second)
+	for time.Now().Before(deadline) {
+		addr = srv.BoundAddr()
+		if addr != "" && !strings.HasSuffix(addr, ":0") && strings.Contains(addr, ":") {
+			conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
+			if err == nil {
+				_ = conn.Close()
+				break
+			}
+		}
+		time.Sleep(10 * time.Millisecond)
+	}
+	addr = srv.BoundAddr()
+	if addr == "" || strings.HasSuffix(addr, ":0") {
+		cancel()
+		t.Fatal("proxy did not bind")
+	}
+
+	u, err := url.Parse("http://" + addr)
+	if err != nil {
+		cancel()
+		t.Fatalf("proxy url: %v", err)
+	}
+	t.Cleanup(func() {
+		cancel()
+		select {
+		case <-errc:
+		case <-time.After(5 * time.Second):
+		}
+	})
+	return u, cancel
+}
+
+func TestIntegration_HTTPAbsoluteFormAllow(t *testing.T) {
+	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
+		if r.URL.Path != "/hello" {
+			http.NotFound(w, r)
+			return
+		}
+		_, _ = io.WriteString(w, "plain-ok")
+	}))
+	t.Cleanup(origin.Close)
+
+	rec := logging.NewRecorder(nil)
+	srv := &proxy.Server{
+		Engine:   allowMITMEngine(t),
+		Recorder: rec,
+	}
+	proxyURL, _ := startProxy(t, srv)
+
+	client := &http.Client{
+		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
+		Timeout:   5 * time.Second,
+	}
+	resp, err := client.Get(origin.URL + "/hello")
+	if err != nil {
+		t.Fatalf("GET via proxy: %v", err)
+	}
+	defer resp.Body.Close()
+	body, _ := io.ReadAll(resp.Body)
+	if resp.StatusCode != http.StatusOK || string(body) != "plain-ok" {
+		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
+	}
+
+	// Wait briefly for async-style record (sync actually).
+	last, ok := rec.Last()
+	if !ok {
+		t.Fatal("expected request log")
+	}
+	if last.Decision != "allow" {
+		t.Fatalf("decision=%q want allow", last.Decision)
+	}
+	if last.Host == "" {
+		t.Fatal("expected host in log")
+	}
+	if last.RequestID == uuid.Nil {
+		t.Fatal("expected request_id")
+	}
+	if last.SessionID == nil || *last.SessionID == uuid.Nil {
+		t.Fatal("expected session_id")
+	}
+}
+
+func TestIntegration_HTTPS_MITM_AndLog(t *testing.T) {
+	// Origin TLS with its own cert (proxy verifies via system roots ΓÇö for loopback
+	// we use httptest.NewTLSServer which uses a test cert; Transport must skip verify
+	// toward origin only in this test).
+	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
+		if r.URL.Path != "/secure" {
+			http.NotFound(w, r)
+			return
+		}
+		_, _ = io.WriteString(w, "mitm-ok")
+	}))
+	t.Cleanup(origin.Close)
+
+	// httptest TLS uses a cert for example.com style; extract host:port.
+	originURL, err := url.Parse(origin.URL)
+	if err != nil {
+		t.Fatal(err)
+	}
+
+	ca, err := certs.NewProvider(nil, testDataKey)
+	if err != nil {
+		t.Fatalf("NewProvider: %v", err)
+	}
+	if _, err := ca.GenerateSelfSignedCA(context.Background(), "WSP MITM Test CA"); err != nil {
+		t.Fatalf("GenerateSelfSignedCA: %v", err)
+	}
+	caPEM, ok, err := ca.ActiveCA(context.Background())
+	if err != nil || !ok {
+		t.Fatalf("ActiveCA: ok=%v err=%v", ok, err)
+	}
+	pool := x509.NewCertPool()
+	if !pool.AppendCertsFromPEM(caPEM) {
+		t.Fatal("append CA PEM")
+	}
+
+	rec := logging.NewRecorder(nil)
+	// Origin transport: trust httptest cert (InsecureSkipVerify for origin dial only).
+	originTransport := &http.Transport{
+		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test origin cert
+	}
+	srv := &proxy.Server{
+		Engine:    allowMITMEngine(t),
+		Certs:     ca,
+		Recorder:  rec,
+		Transport: originTransport,
+	}
+	proxyURL, _ := startProxy(t, srv)
+
+	client := &http.Client{
+		Timeout: 10 * time.Second,
+		Transport: &http.Transport{
+			Proxy: http.ProxyURL(proxyURL),
+			TLSClientConfig: &tls.Config{
+				RootCAs:    pool,
+				MinVersion: tls.VersionTLS12,
+				// ServerName: host from origin URL (IP) ΓÇö leaf is signed for that host.
+				ServerName: originURL.Hostname(),
+			},
+		},
+	}
+
+	resp, err := client.Get(origin.URL + "/secure")
+	if err != nil {
+		t.Fatalf("HTTPS GET via MITM proxy: %v", err)
+	}
+	defer resp.Body.Close()
+	body, _ := io.ReadAll(resp.Body)
+	if resp.StatusCode != http.StatusOK {
+		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
+	}
+	if string(body) != "mitm-ok" {
+		t.Fatalf("body=%q want mitm-ok", body)
+	}
+
+	// Expect at least CONNECT log + inner request log.
+	deadline := time.Now().Add(2 * time.Second)
+	var foundAllow bool
+	var foundHost bool
+	for time.Now().Before(deadline) {
+		for _, r := range rec.Recent() {
+			if r.Decision == "allow" && r.Method != http.MethodConnect && strings.Contains(r.Path, "/secure") {
+				foundAllow = true
+			}
+			if r.Host != "" {
+				foundHost = true
+			}
+			if r.Decision == "allow" && r.Method == http.MethodConnect {
+				// CONNECT recorded
+			}
+		}
+		if foundAllow {
+			break
+		}
+		time.Sleep(20 * time.Millisecond)
+	}
+	if !foundAllow {
+		var dump []string
+		for _, r := range rec.Recent() {
+			dump = append(dump, fmt.Sprintf("%s %s %s %s", r.Decision, r.Method, r.Host, r.Path))
+		}
+		t.Fatalf("expected allow log for /secure; logs=%v", dump)
+	}
+	if !foundHost {
+		t.Fatal("expected host field in logs")
+	}
+}
+
+func TestIntegration_HTTPBlockPage(t *testing.T) {
+	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
+		_, _ = io.WriteString(w, "should-not-reach")
+	}))
+	t.Cleanup(origin.Close)
+
+	ou, _ := url.Parse(origin.URL)
+	// Domain match on IP string (destination_domain uses suffix/host match).
+	eng := blockEngine(t, ou.Hostname())
+
+	rec := logging.NewRecorder(nil)
+	srv := &proxy.Server{Engine: eng, Recorder: rec}
+	proxyURL, _ := startProxy(t, srv)
+
+	client := &http.Client{
+		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
+		Timeout:   5 * time.Second,
+	}
+	resp, err := client.Get(origin.URL + "/nope")
+	if err != nil {
+		t.Fatalf("GET: %v", err)
+	}
+	defer resp.Body.Close()
+	body, _ := io.ReadAll(resp.Body)
+	if resp.StatusCode != http.StatusForbidden {
+		t.Fatalf("status=%d want 403", resp.StatusCode)
+	}
+	if !strings.Contains(string(body), "blocked") && !strings.Contains(string(body), "Blocked") {
+		t.Fatalf("block page body unexpected: %q", body)
+	}
+	last, ok := rec.Last()
+	if !ok || last.Decision != "block" {
+		t.Fatalf("log decision=%v ok=%v", last.Decision, ok)
+	}
+}
+
+func TestIntegration_SessionIdleReuse(t *testing.T) {
+	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
+		_, _ = io.WriteString(w, "ok")
+	}))
+	t.Cleanup(origin.Close)
+
+	rec := logging.NewRecorder(nil)
+	tracker := proxy.NewSessionTracker(nil, 30*time.Minute)
+	srv := &proxy.Server{
+		Engine:   allowMITMEngine(t),
+		Recorder: rec,
+		Sessions: tracker,
+	}
+	proxyURL, _ := startProxy(t, srv)
+
+	client := &http.Client{
+		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
+		Timeout:   5 * time.Second,
+	}
+	for i := 0; i < 2; i++ {
+		resp, err := client.Get(origin.URL + "/")
+		if err != nil {
+			t.Fatalf("GET %d: %v", i, err)
+		}
+		_, _ = io.Copy(io.Discard, resp.Body)
+		_ = resp.Body.Close()
+	}
+
+	logs := rec.Recent()
+	if len(logs) < 2 {
+		t.Fatalf("expected >=2 logs, got %d", len(logs))
+	}
+	if logs[0].SessionID == nil || logs[1].SessionID == nil {
+		t.Fatal("missing session ids")
+	}
+	if *logs[0].SessionID != *logs[1].SessionID {
+		t.Fatalf("session ids differ: %s vs %s", logs[0].SessionID, logs[1].SessionID)
+	}
+	if tracker.Len() != 1 {
+		t.Fatalf("tracker len=%d want 1", tracker.Len())
+	}
+}
diff --git a/internal/proxy/server.go b/internal/proxy/server.go
new file mode 100644
index 0000000..8294d5f
--- /dev/null
+++ b/internal/proxy/server.go
@@ -0,0 +1,271 @@
+// Package proxy implements the explicit HTTP/HTTPS MITM data-plane gateway.
+package proxy
+
+import (
+	"context"
+	"errors"
+	"fmt"
+	"io"
+	"log/slog"
+	"net"
+	"net/http"
+	"net/url"
+	"strings"
+	"sync"
+	"time"
+
+	"github.com/google/uuid"
+
+	"github.com/wsp-security/wsp/internal/auth"
+	"github.com/wsp-security/wsp/internal/certs"
+	"github.com/wsp-security/wsp/internal/logging"
+	"github.com/wsp-security/wsp/internal/policy"
+	"github.com/wsp-security/wsp/internal/store"
+)
+
+// Server is the explicit forward proxy with optional TLS interception.
+type Server struct {
+	Addr     string
+	Engine   *policy.Engine
+	Certs    *certs.Provider
+	Store    *store.Store
+	Recorder *logging.Recorder
+
+	// AuthCache is optional; used when policy AuthMode is ip_cached.
+	AuthCache *auth.ProxyAuthCache
+	// Sessions maps client identity ΓåÆ browsing session (created if nil).
+	Sessions *SessionTracker
+
+	// Optional pipeline hooks (default to no-op stubs).
+	CASB    CASBInspector
+	Malware MalwareScanner
+	RBI     RBIOrchestrator
+
+	// Dialer / Transport for origin connections (tests may inject).
+	Dialer    *net.Dialer
+	Transport *http.Transport
+
+	// IdleTimeout for MITM keep-alive reads (default 2m).
+	IdleTimeout time.Duration
+
+	httpServer *http.Server
+	mu         sync.Mutex
+}
+
+// Start listens on Addr and serves until ctx is cancelled or Shutdown.
+// It blocks until the server stops; on ctx cancel it gracefully shuts down.
+func (s *Server) Start(ctx context.Context) error {
+	if s == nil {
+		return errors.New("proxy server is nil")
+	}
+	if s.Addr == "" {
+		return errors.New("proxy addr is empty")
+	}
+	s.ensureHooks()
+
+	s.mu.Lock()
+	s.httpServer = &http.Server{
+		Addr:              s.Addr,
+		Handler:           s,
+		ReadHeaderTimeout: 15 * time.Second,
+		// Disable base ReadTimeout so long-lived CONNECT tunnels work.
+		// Per-request deadlines set inside MITM loop.
+		ErrorLog: slog.NewLogLogger(slog.Default().Handler(), slog.LevelDebug),
+	}
+	srv := s.httpServer
+	s.mu.Unlock()
+
+	ln, err := net.Listen("tcp", s.Addr)
+	if err != nil {
+		return fmt.Errorf("proxy listen %s: %w", s.Addr, err)
+	}
+	// Reflect actual bound address (useful when Addr is :0).
+	s.mu.Lock()
+	s.Addr = ln.Addr().String()
+	s.mu.Unlock()
+
+	errc := make(chan error, 1)
+	go func() {
+		slog.Info("proxy listening", "addr", ln.Addr().String())
+		err := srv.Serve(ln)
+		if err != nil && !errors.Is(err, http.ErrServerClosed) {
+			errc <- err
+			return
+		}
+		errc <- nil
+	}()
+
+	select {
+	case <-ctx.Done():
+		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
+		defer cancel()
+		_ = srv.Shutdown(shutdownCtx)
+		return <-errc
+	case err := <-errc:
+		return err
+	}
+}
+
+// BoundAddr returns the actual listen address after Start binds (e.g. when Addr was :0).
+func (s *Server) BoundAddr() string {
+	if s == nil {
+		return ""
+	}
+	s.mu.Lock()
+	defer s.mu.Unlock()
+	return s.Addr
+}
+
+// Shutdown gracefully stops the HTTP server.
+func (s *Server) Shutdown(ctx context.Context) error {
+	if s == nil {
+		return nil
+	}
+	s.mu.Lock()
+	srv := s.httpServer
+	s.mu.Unlock()
+	if srv == nil {
+		return nil
+	}
+	return srv.Shutdown(ctx)
+}
+
+// ServeHTTP implements http.Handler for the explicit proxy.
+func (s *Server) ServeHTTP(w http.ResponseWriter, req *http.Request) {
+	s.ensureHooks()
+
+	if req.Method == http.MethodConnect {
+		s.handleCONNECT(w, req)
+		return
+	}
+
+	// Absolute-form URI required for forward proxy HTTP requests.
+	if req.URL == nil || !req.URL.IsAbs() {
+		// Some clients send origin-form with Host header ΓÇö accept and absolutize.
+		if req.Host != "" && req.URL != nil {
+			scheme := "http"
+			u := &url.URL{
+				Scheme:   scheme,
+				Host:     req.Host,
+				Path:     req.URL.Path,
+				RawQuery: req.URL.RawQuery,
+			}
+			req.URL = u
+		} else {
+			http.Error(w, "absolute-form request URI required", http.StatusBadRequest)
+			return
+		}
+	}
+
+	s.handleHTTP(w, req)
+}
+
+// handleHTTP processes plain HTTP absolute-form proxy requests.
+func (s *Server) handleHTTP(w http.ResponseWriter, req *http.Request) {
+	start := time.Now().UTC()
+	s.ensureHooks()
+
+	clientIP := clientIPFromRequest(req)
+	clientIPStr := ipString(clientIP)
+	target := cloneURL(req.URL)
+	if target.Scheme == "" {
+		target.Scheme = "http"
+	}
+
+	in := buildInput(req, clientIP, "", target, req.Method)
+	d := s.evaluate(in)
+
+	username, need407 := s.resolveAuth(req.Context(), req, clientIPStr, d.AuthMode)
+	if need407 {
+		writeProxyAuthRequired(w)
+		return
+	}
+	if username != "" {
+		in.Username = username
+		d = s.evaluate(in)
+	}
+
+	requestID := uuid.New()
+	sessionID := s.Sessions.Acquire(req.Context(), clientIPStr, username, req.UserAgent())
+	pr := &pipelineResult{
+		Input:     in,
+		Decision:  d,
+		Username:  username,
+		RequestID: requestID,
+		SessionID: sessionID,
+		Start:     start,
+	}
+
+	if d.FinalAction == policy.ActionBlock {
+		n := s.writeBlockPage(w, req, d, clientIPStr, username, target)
+		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(n), "")
+		return
+	}
+
+	if s.RBI.ShouldIsolate(d) && s.RBI.HandleIsolation(w, req, d) {
+		s.recordOutcome(req.Context(), pr, req, target, "allow", req.ContentLength, 0, "rbi")
+		return
+	}
+
+	if reason, err := s.CASB.InspectRequest(req.Context(), req, d); err != nil {
+		slog.Warn("CASB inspect request error", "err", err)
+	} else if reason != "" {
+		d.FinalAction = policy.ActionBlock
+		d.BlockReason = reason
+		pr.Decision = d
+		n := s.writeBlockPage(w, req, d, clientIPStr, username, target)
+		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(n), "")
+		return
+	}
+
+	applyRequestHeaderMods(req, d.HeaderMods)
+	stripHopByHop(req.Header)
+	req.Header.Del("Proxy-Authorization")
+	req.Header.Del("Proxy-Connection")
+
+	outReq := req.Clone(req.Context())
+	outReq.RequestURI = ""
+	// Ensure Host header matches target.
+	if outReq.Host == "" {
+		outReq.Host = target.Host
+	}
+
+	resp, err := s.Transport.RoundTrip(outReq)
+	if err != nil {
+		http.Error(w, "Bad Gateway: "+err.Error(), http.StatusBadGateway)
+		s.recordOutcome(req.Context(), pr, req, target, "error", req.ContentLength, 0, err.Error())
+		return
+	}
+	defer resp.Body.Close()
+
+	if reason, err := s.CASB.InspectResponse(req.Context(), req, resp, d); err != nil {
+		slog.Warn("CASB inspect response error", "err", err)
+	} else if reason != "" {
+		d.FinalAction = policy.ActionBlock
+		d.BlockReason = reason
+		pr.Decision = d
+		n := s.writeBlockPage(w, req, d, clientIPStr, username, target)
+		s.recordOutcome(req.Context(), pr, req, target, "block", req.ContentLength, int64(n), "")
+		return
+	}
+
+	if d.MalwareScan {
+		_, _ = s.Malware.Scan(req.Context(), strings.NewReader(""), 0)
+	}
+
+	applyResponseHeaderMods(resp, d.HeaderMods)
+	stripHopByHop(resp.Header)
+
+	for k, vv := range resp.Header {
+		for _, v := range vv {
+			w.Header().Add(k, v)
+		}
+	}
+	w.WriteHeader(resp.StatusCode)
+	n, copyErr := io.Copy(w, resp.Body)
+	errMsg := ""
+	if copyErr != nil {
+		errMsg = copyErr.Error()
+	}
+	s.recordOutcome(req.Context(), pr, req, target, "allow", req.ContentLength, n, errMsg)
+}
diff --git a/internal/proxy/session.go b/internal/proxy/session.go
new file mode 100644
index 0000000..b972029
--- /dev/null
+++ b/internal/proxy/session.go
@@ -0,0 +1,115 @@
+package proxy
+
+import (
+	"context"
+	"log/slog"
+	"sync"
+	"time"
+
+	"github.com/google/uuid"
+
+	"github.com/wsp-security/wsp/internal/store"
+)
+
+// DefaultSessionIdle is how long a browsing session stays open without requests.
+const DefaultSessionIdle = 30 * time.Minute
+
+// SessionTracker maps client IP + username ΓåÆ browsing session with idle timeout.
+// When a Store is configured, new sessions are persisted; idle expiry is in-memory.
+type SessionTracker struct {
+	store *store.Store
+	idle  time.Duration
+
+	mu   sync.Mutex
+	byKey map[string]*trackedSession
+}
+
+type trackedSession struct {
+	id         uuid.UUID
+	lastActive time.Time
+	clientIP   string
+	username   string
+	userAgent  string
+}
+
+// NewSessionTracker builds a tracker. store may be nil (memory-only session IDs).
+// Non-positive idle uses DefaultSessionIdle.
+func NewSessionTracker(s *store.Store, idle time.Duration) *SessionTracker {
+	if idle <= 0 {
+		idle = DefaultSessionIdle
+	}
+	return &SessionTracker{
+		store: s,
+		idle:  idle,
+		byKey: make(map[string]*trackedSession),
+	}
+}
+
+// Acquire returns the session ID for clientIP+username, creating or refreshing as needed.
+func (t *SessionTracker) Acquire(ctx context.Context, clientIP, username, userAgent string) uuid.UUID {
+	if t == nil {
+		return uuid.New()
+	}
+	key := sessionKey(clientIP, username)
+	now := time.Now().UTC()
+
+	t.mu.Lock()
+	defer t.mu.Unlock()
+
+	if ts, ok := t.byKey[key]; ok {
+		if now.Sub(ts.lastActive) < t.idle {
+			ts.lastActive = now
+			if userAgent != "" {
+				ts.userAgent = userAgent
+			}
+			return ts.id
+		}
+		// Idle expired ΓÇö mark ended in DB if possible, then create fresh.
+		oldID := ts.id
+		delete(t.byKey, key)
+		if t.store != nil {
+			go func(id uuid.UUID) {
+				c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
+				defer cancel()
+				_ = t.store.EndBrowsingSession(c, id)
+			}(oldID)
+		}
+	}
+
+	id := uuid.New()
+	if t.store != nil {
+		row, err := t.store.CreateBrowsingSession(ctx, store.BrowsingSession{
+			ClientIP:  clientIP,
+			Username:  username,
+			UserAgent: userAgent,
+		})
+		if err != nil {
+			slog.Warn("create browsing session failed; using ephemeral id", "err", err)
+		} else {
+			id = row.ID
+		}
+	}
+
+	t.byKey[key] = &trackedSession{
+		id:         id,
+		lastActive: now,
+		clientIP:   clientIP,
+		username:   username,
+		userAgent:  userAgent,
+	}
+	return id
+}
+
+// Len returns the number of active in-memory sessions (tests/metrics).
+func (t *SessionTracker) Len() int {
+	if t == nil {
+		return 0
+	}
+	t.mu.Lock()
+	defer t.mu.Unlock()
+	return len(t.byKey)
+}
+
+func sessionKey(clientIP, username string) string {
+	return clientIP + "\x00" + username
+}
