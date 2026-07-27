package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/logging"
	"github.com/wsp-security/wsp/internal/malware"
	"github.com/wsp-security/wsp/internal/policy"
)

// stubScanner is a malware.Scanner for pipeline tests.
type stubScanner struct {
	threat  string
	err     error
	skipped bool
	calls   int
}

func (s *stubScanner) Ping(context.Context) error { return nil }

func (s *stubScanner) Scan(_ context.Context, r io.Reader, maxBytes int64) (malware.Result, error) {
	s.calls++
	if s.err != nil {
		return malware.Result{Error: s.err}, s.err
	}
	if s.skipped {
		return malware.Result{Skipped: true}, nil
	}
	if s.threat != "" {
		// Drain reader like a real scanner.
		_, _ = io.Copy(io.Discard, io.LimitReader(r, maxBytes))
		return malware.Result{Infected: true, Signature: s.threat}, nil
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(r, maxBytes))
	return malware.Result{}, nil
}

func TestMalwareScan_BlocksInfectedResponse(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write([]byte("X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR"))
	}))
	t.Cleanup(origin.Close)

	rules := []policy.Rule{{
		ID:       uuid.MustParse("00000000-0000-4000-8000-0000000000b1"),
		Name:     "malware-on",
		Enabled:  true,
		Priority: 1,
		Sections: policy.RuleSections{
			General:     policy.GeneralSection{Action: policy.ActionAllow, AuthMode: policy.AuthDisable},
			Antimalware: policy.AntimalwareSection{Enabled: true},
		},
	}}
	snap, err := policy.Compile(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	var eng policy.Engine
	eng.Swap(snap)

	scan := &stubScanner{threat: "Eicar-Test-Signature"}
	rec := logging.NewRecorder(nil)
	srv := &Server{
		Engine:   &eng,
		Recorder: rec,
		Malware:  scan,
	}

	target, _ := url.Parse(origin.URL + "/eicar")
	req := httptest.NewRequest(http.MethodGet, target.String(), nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.RequestURI = target.String()

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Malware detected") || !strings.Contains(rr.Body.String(), "Eicar-Test-Signature") {
		t.Fatalf("body=%q", rr.Body.String())
	}
	if scan.calls < 1 {
		t.Fatal("expected scanner to be called")
	}
	last, ok := rec.Last()
	if !ok || last.Decision != "block" {
		t.Fatalf("log=%+v ok=%v", last, ok)
	}
	if last.Error != "malware_detected" {
		t.Fatalf("error field=%q", last.Error)
	}
}

func TestMalwareScan_FailOpenOnError(t *testing.T) {
	originHit := false
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHit = true
		_, _ = w.Write([]byte("clean-body"))
	}))
	t.Cleanup(origin.Close)

	rules := []policy.Rule{{
		ID:       uuid.MustParse("00000000-0000-4000-8000-0000000000b2"),
		Name:     "malware-on",
		Enabled:  true,
		Priority: 1,
		Sections: policy.RuleSections{
			General:     policy.GeneralSection{Action: policy.ActionAllow, AuthMode: policy.AuthDisable},
			Antimalware: policy.AntimalwareSection{Enabled: true},
		},
	}}
	snap, err := policy.Compile(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	var eng policy.Engine
	eng.Swap(snap)

	scan := &stubScanner{err: errors.New("clamd down")}
	rec := logging.NewRecorder(nil)
	srv := &Server{
		Engine:            &eng,
		Recorder:          rec,
		Malware:           scan,
		MalwareFailClosed: false,
	}

	target, _ := url.Parse(origin.URL + "/ok")
	req := httptest.NewRequest(http.MethodGet, target.String(), nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.RequestURI = target.String()

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if !originHit {
		t.Fatal("origin should be contacted (fail-open after response)")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200 (fail-open)", rr.Code)
	}
	if rr.Body.String() != "clean-body" {
		t.Fatalf("body=%q", rr.Body.String())
	}
}

func TestMalwareScan_FailClosedOnError(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("clean-body"))
	}))
	t.Cleanup(origin.Close)

	rules := []policy.Rule{{
		ID:       uuid.MustParse("00000000-0000-4000-8000-0000000000b3"),
		Name:     "malware-on",
		Enabled:  true,
		Priority: 1,
		Sections: policy.RuleSections{
			General:     policy.GeneralSection{Action: policy.ActionAllow, AuthMode: policy.AuthDisable},
			Antimalware: policy.AntimalwareSection{Enabled: true},
		},
	}}
	snap, err := policy.Compile(rules, nil)
	if err != nil {
		t.Fatal(err)
	}
	var eng policy.Engine
	eng.Swap(snap)

	scan := &stubScanner{err: errors.New("clamd down")}
	rec := logging.NewRecorder(nil)
	srv := &Server{
		Engine:            &eng,
		Recorder:          rec,
		Malware:           scan,
		MalwareFailClosed: true,
	}

	target, _ := url.Parse(origin.URL + "/ok")
	req := httptest.NewRequest(http.MethodGet, target.String(), nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.RequestURI = target.String()

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403 (fail-closed)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Malware scan unavailable") {
		t.Fatalf("body=%q", rr.Body.String())
	}
	last, ok := rec.Last()
	if !ok || last.Decision != "block" {
		t.Fatalf("log=%+v", last)
	}
}

func TestMalwareScan_NotCalledWhenPolicyDisabled(t *testing.T) {
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(origin.Close)

	scan := &stubScanner{threat: "should-not-matter"}
	srv := &Server{Malware: scan}

	target, _ := url.Parse(origin.URL + "/")
	req := httptest.NewRequest(http.MethodGet, target.String(), nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.RequestURI = target.String()
	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if scan.calls != 0 {
		t.Fatalf("scanner called %d times; policy MalwareScan is false", scan.calls)
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
}

func TestStripHopByHop_ConnectionTokens(t *testing.T) {
	h := make(http.Header)
	h.Set("Connection", "close, X-Custom-Hop")
	h.Set("X-Custom-Hop", "should-strip")
	h.Set("X-Keep", "keep-me")
	h.Set("Keep-Alive", "timeout=5")
	stripHopByHop(h)
	if h.Get("Connection") != "" {
		t.Fatal("Connection should be removed")
	}
	if h.Get("X-Custom-Hop") != "" {
		t.Fatal("Connection-listed hop header should be removed")
	}
	if h.Get("Keep-Alive") != "" {
		t.Fatal("Keep-Alive should be removed")
	}
	if h.Get("X-Keep") != "keep-me" {
		t.Fatalf("end-to-end header stripped: %q", h.Get("X-Keep"))
	}
}

func TestParseCONNECTTarget_IPv6AndHost(t *testing.T) {
	cases := []struct {
		raw, host, port, dial string
		wantErr               bool
	}{
		{"example.com", "example.com", "443", "example.com:443", false},
		{"example.com:8443", "example.com", "8443", "example.com:8443", false},
		{"127.0.0.1", "127.0.0.1", "443", "127.0.0.1:443", false},
		{"127.0.0.1:9443", "127.0.0.1", "9443", "127.0.0.1:9443", false},
		{"[::1]:443", "::1", "443", "[::1]:443", false},
		{"[2001:db8::1]:8443", "2001:db8::1", "8443", "[2001:db8::1]:8443", false},
		{"::1", "::1", "443", "[::1]:443", false},
		{"2001:db8::1", "2001:db8::1", "443", "[2001:db8::1]:443", false},
		{"[::1]", "::1", "443", "[::1]:443", false},
		{"", "", "", "", true},
		{"not a host::bad", "", "", "", true},
	}
	for _, tc := range cases {
		host, port, dial, err := parseCONNECTTarget(tc.raw)
		if tc.wantErr {
			if err == nil {
				t.Errorf("parseCONNECTTarget(%q) expected error", tc.raw)
			}
			continue
		}
		if err != nil {
			t.Errorf("parseCONNECTTarget(%q): %v", tc.raw, err)
			continue
		}
		if host != tc.host || port != tc.port || dial != tc.dial {
			t.Errorf("parseCONNECTTarget(%q)=(%q,%q,%q) want (%q,%q,%q)",
				tc.raw, host, port, dial, tc.host, tc.port, tc.dial)
		}
	}
}

func TestResolveAuth_DisableIgnoresProxyAuthorization(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	// Arbitrary unverified credentials must not become identity when auth is disabled.
	cred := base64.StdEncoding.EncodeToString([]byte("spoofed:x"))
	req.Header.Set("Proxy-Authorization", "Basic "+cred)
	u, need407 := s.resolveAuth(req.Context(), req, "1.2.3.4", policy.AuthDisable)
	if need407 {
		t.Fatal("auth disable must not require 407")
	}
	if u != "" {
		t.Fatalf("username=%q want empty when auth disabled", u)
	}
	u, need407 = s.resolveAuth(req.Context(), req, "1.2.3.4", "")
	if need407 || u != "" {
		t.Fatalf("empty mode: user=%q need407=%v", u, need407)
	}
}

func TestNeedsIsolation(t *testing.T) {
	if needsIsolation(policy.Decision{}, noopRBI{}) {
		t.Fatal("empty decision should not isolate")
	}
	if !needsIsolation(policy.Decision{RBIIsolated: true}, noopRBI{}) {
		t.Fatal("RBIIsolated must force isolation even when orchestrator ShouldIsolate is false")
	}
	force := forceIsolateRBI{}
	if !needsIsolation(policy.Decision{}, force) {
		t.Fatal("ShouldIsolate true must isolate")
	}
}

type forceIsolateRBI struct{}

func (forceIsolateRBI) ShouldIsolate(policy.Decision) bool { return true }
func (forceIsolateRBI) HandleIsolation(http.ResponseWriter, *http.Request, policy.Decision) bool {
	return false
}

// successRBI starts a fake isolation viewer (HandleIsolation true).
type successRBI struct {
	calls int
}

func (s *successRBI) ShouldIsolate(d policy.Decision) bool { return d.RBIIsolated }
func (s *successRBI) HandleIsolation(w http.ResponseWriter, req *http.Request, d policy.Decision) bool {
	s.calls++
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("<html>RBI viewer mock</html>"))
	return true
}

func TestRBIHandleIsolation_SuccessDoesNotForward(t *testing.T) {
	originHit := false
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHit = true
		_, _ = w.Write([]byte("origin-should-not-see"))
	}))
	t.Cleanup(origin.Close)

	rules := []policy.Rule{{
		ID:       uuid.MustParse("00000000-0000-4000-8000-0000000000a2"),
		Name:     "rbi-ok",
		Enabled:  true,
		Priority: 1,
		Sections: policy.RuleSections{
			General: policy.GeneralSection{Action: policy.ActionAllow, AuthMode: policy.AuthDisable},
			RBI:     policy.RBISection{Mode: policy.RBIIsolated},
		},
	}}
	snap, err := policy.Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng policy.Engine
	eng.Swap(snap)

	rbiHook := &successRBI{}
	rec := logging.NewRecorder(nil)
	srv := &Server{
		Engine:   &eng,
		Recorder: rec,
		RBI:      rbiHook,
	}

	target, err := url.Parse(origin.URL + "/secret")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, target.String(), nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.RequestURI = target.String()

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if originHit {
		t.Fatal("origin must not be contacted when RBI isolation handles the request")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want 200", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "RBI viewer") {
		t.Fatalf("body=%q", rr.Body.String())
	}
	if rbiHook.calls != 1 {
		t.Fatalf("HandleIsolation calls=%d", rbiHook.calls)
	}
	last, ok := rec.Last()
	if !ok || last.Decision != "allow" {
		t.Fatalf("log decision=%v ok=%v", last.Decision, ok)
	}
	if last.Error != "rbi" {
		t.Fatalf("error field=%q want rbi", last.Error)
	}
}

func TestRBIFailClosed_HTTPDoesNotForward(t *testing.T) {
	originHit := false
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		originHit = true
		_, _ = w.Write([]byte("origin-should-not-see"))
	}))
	t.Cleanup(origin.Close)

	// Engine that allows but sets RBIIsolated via a compiled rule.
	rules := []policy.Rule{{
		ID:       uuid.MustParse("00000000-0000-4000-8000-0000000000a1"),
		Name:     "rbi",
		Enabled:  true,
		Priority: 1,
		Sections: policy.RuleSections{
			General: policy.GeneralSection{Action: policy.ActionAllow, AuthMode: policy.AuthDisable},
			RBI:     policy.RBISection{Mode: policy.RBIIsolated},
		},
	}}
	snap, err := policy.Compile(rules, nil)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	var eng policy.Engine
	eng.Swap(snap)

	rec := logging.NewRecorder(nil)
	srv := &Server{
		Engine:   &eng,
		Recorder: rec,
		RBI:      noopRBI{}, // HandleIsolation always false → fail-closed
	}

	target, err := url.Parse(origin.URL + "/secret")
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, target.String(), nil)
	req.RemoteAddr = "127.0.0.1:12345"
	req.RequestURI = target.String()

	rr := httptest.NewRecorder()
	srv.ServeHTTP(rr, req)

	if originHit {
		t.Fatal("origin must not be contacted when RBI isolation required and unavailable")
	}
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "isolation") && !strings.Contains(rr.Body.String(), "Blocked") {
		t.Fatalf("body=%q", rr.Body.String())
	}
	last, ok := rec.Last()
	if !ok || last.Decision != "block" {
		t.Fatalf("log decision=%v ok=%v", last.Decision, ok)
	}
	if last.Error != "rbi_unavailable" {
		t.Fatalf("error field=%q want rbi_unavailable", last.Error)
	}
}
