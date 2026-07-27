package proxy_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/certs"
	"github.com/wsp-security/wsp/internal/logging"
	"github.com/wsp-security/wsp/internal/policy"
	"github.com/wsp-security/wsp/internal/proxy"
)

const testDataKey = "test-data-key-16b"

func allowMITMEngine(t *testing.T) *policy.Engine {
	t.Helper()
	rules := []policy.Rule{{
		ID:       uuid.MustParse("00000000-0000-4000-8000-000000000099"),
		Name:     "test-allow-mitm",
		Enabled:  true,
		Priority: 100,
		Sections: policy.RuleSections{
			General: policy.GeneralSection{
				Action:       policy.ActionAllow,
				TLSIntercept: true,
				AuthMode:     policy.AuthDisable,
			},
		},
	}}
	snap, err := policy.Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng policy.Engine
	eng.Swap(snap)
	return &eng
}

func blockEngine(t *testing.T, domain string) *policy.Engine {
	t.Helper()
	rules := []policy.Rule{{
		ID:       uuid.MustParse("00000000-0000-4000-8000-000000000098"),
		Name:     "test-block",
		Enabled:  true,
		Priority: 10,
		Sections: policy.RuleSections{
			General: policy.GeneralSection{
				Action:      policy.ActionBlock,
				BlockReason: "blocked for test",
				Destinations: []policy.Condition{
					{Type: policy.CondDestinationDomain, Value: domain},
				},
			},
		},
	}}
	snap, err := policy.Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng policy.Engine
	eng.Swap(snap)
	return &eng
}

func startProxy(t *testing.T, srv *proxy.Server) (proxyURL *url.URL, cancel context.CancelFunc) {
	t.Helper()
	srv.Addr = "127.0.0.1:0"
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() {
		errc <- srv.Start(ctx)
	}()

	// Wait until Addr is updated from :0 bind.
	var addr string
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		addr = srv.BoundAddr()
		if addr != "" && !strings.HasSuffix(addr, ":0") && strings.Contains(addr, ":") {
			conn, err := net.DialTimeout("tcp", addr, 50*time.Millisecond)
			if err == nil {
				_ = conn.Close()
				break
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	addr = srv.BoundAddr()
	if addr == "" || strings.HasSuffix(addr, ":0") {
		cancel()
		t.Fatal("proxy did not bind")
	}

	u, err := url.Parse("http://" + addr)
	if err != nil {
		cancel()
		t.Fatalf("proxy url: %v", err)
	}
	t.Cleanup(func() {
		cancel()
		select {
		case <-errc:
		case <-time.After(5 * time.Second):
		}
	})
	return u, cancel
}

func TestIntegration_HTTPAbsoluteFormAllow(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/hello" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "plain-ok")
	}))
	t.Cleanup(origin.Close)

	rec := logging.NewRecorder(nil)
	srv := &proxy.Server{
		Engine:   allowMITMEngine(t),
		Recorder: rec,
	}
	proxyURL, _ := startProxy(t, srv)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(origin.URL + "/hello")
	if err != nil {
		t.Fatalf("GET via proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "plain-ok" {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}

	// Wait briefly for async-style record (sync actually).
	last, ok := rec.Last()
	if !ok {
		t.Fatal("expected request log")
	}
	if last.Decision != "allow" {
		t.Fatalf("decision=%q want allow", last.Decision)
	}
	if last.Host == "" {
		t.Fatal("expected host in log")
	}
	if last.RequestID == uuid.Nil {
		t.Fatal("expected request_id")
	}
	if last.SessionID == nil || *last.SessionID == uuid.Nil {
		t.Fatal("expected session_id")
	}
}

func TestIntegration_HTTPS_MITM_AndLog(t *testing.T) {
	// Origin TLS with its own cert (proxy verifies via system roots — for loopback
	// we use httptest.NewTLSServer which uses a test cert; Transport must skip verify
	// toward origin only in this test).
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/secure" {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "mitm-ok")
	}))
	t.Cleanup(origin.Close)

	// httptest TLS uses a cert for example.com style; extract host:port.
	originURL, err := url.Parse(origin.URL)
	if err != nil {
		t.Fatal(err)
	}

	ca, err := certs.NewProvider(nil, testDataKey)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if _, err := ca.GenerateSelfSignedCA(context.Background(), "WSP MITM Test CA"); err != nil {
		t.Fatalf("GenerateSelfSignedCA: %v", err)
	}
	caPEM, ok, err := ca.ActiveCA(context.Background())
	if err != nil || !ok {
		t.Fatalf("ActiveCA: ok=%v err=%v", ok, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("append CA PEM")
	}

	rec := logging.NewRecorder(nil)
	// Origin transport: trust httptest cert (InsecureSkipVerify for origin dial only).
	originTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test origin cert
	}
	srv := &proxy.Server{
		Engine:    allowMITMEngine(t),
		Certs:     ca,
		Recorder:  rec,
		Transport: originTransport,
	}
	proxyURL, _ := startProxy(t, srv)

	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
			TLSClientConfig: &tls.Config{
				RootCAs:    pool,
				MinVersion: tls.VersionTLS12,
				// ServerName: host from origin URL (IP) — leaf is signed for that host.
				ServerName: originURL.Hostname(),
			},
		},
	}

	resp, err := client.Get(origin.URL + "/secure")
	if err != nil {
		t.Fatalf("HTTPS GET via MITM proxy: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status=%d body=%q", resp.StatusCode, body)
	}
	if string(body) != "mitm-ok" {
		t.Fatalf("body=%q want mitm-ok", body)
	}

	// Expect at least CONNECT log + inner request log.
	deadline := time.Now().Add(2 * time.Second)
	var foundAllow bool
	var foundHost bool
	for time.Now().Before(deadline) {
		for _, r := range rec.Recent() {
			if r.Decision == "allow" && r.Method != http.MethodConnect && strings.Contains(r.Path, "/secure") {
				foundAllow = true
			}
			if r.Host != "" {
				foundHost = true
			}
			if r.Decision == "allow" && r.Method == http.MethodConnect {
				// CONNECT recorded
			}
		}
		if foundAllow {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !foundAllow {
		var dump []string
		for _, r := range rec.Recent() {
			dump = append(dump, fmt.Sprintf("%s %s %s %s", r.Decision, r.Method, r.Host, r.Path))
		}
		t.Fatalf("expected allow log for /secure; logs=%v", dump)
	}
	if !foundHost {
		t.Fatal("expected host field in logs")
	}
}

func TestIntegration_HTTPBlockPage(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "should-not-reach")
	}))
	t.Cleanup(origin.Close)

	ou, _ := url.Parse(origin.URL)
	// Domain match on IP string (destination_domain uses suffix/host match).
	eng := blockEngine(t, ou.Hostname())

	rec := logging.NewRecorder(nil)
	srv := &proxy.Server{Engine: eng, Recorder: rec}
	proxyURL, _ := startProxy(t, srv)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	resp, err := client.Get(origin.URL + "/nope")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want 403", resp.StatusCode)
	}
	if !strings.Contains(string(body), "blocked") && !strings.Contains(string(body), "Blocked") {
		t.Fatalf("block page body unexpected: %q", body)
	}
	last, ok := rec.Last()
	if !ok || last.Decision != "block" {
		t.Fatalf("log decision=%v ok=%v", last.Decision, ok)
	}
}

func TestIntegration_SessionIdleReuse(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(origin.Close)

	rec := logging.NewRecorder(nil)
	tracker := proxy.NewSessionTracker(nil, 30*time.Minute)
	srv := &proxy.Server{
		Engine:   allowMITMEngine(t),
		Recorder: rec,
		Sessions: tracker,
	}
	proxyURL, _ := startProxy(t, srv)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL)},
		Timeout:   5 * time.Second,
	}
	for i := 0; i < 2; i++ {
		resp, err := client.Get(origin.URL + "/")
		if err != nil {
			t.Fatalf("GET %d: %v", i, err)
		}
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}

	logs := rec.Recent()
	if len(logs) < 2 {
		t.Fatalf("expected >=2 logs, got %d", len(logs))
	}
	if logs[0].SessionID == nil || logs[1].SessionID == nil {
		t.Fatal("missing session ids")
	}
	if *logs[0].SessionID != *logs[1].SessionID {
		t.Fatalf("session ids differ: %s vs %s", logs[0].SessionID, logs[1].SessionID)
	}
	if tracker.Len() != 1 {
		t.Fatalf("tracker len=%d want 1", tracker.Len())
	}
}
