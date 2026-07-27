package proxy

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/wsp-security/wsp/internal/logging"
	"github.com/wsp-security/wsp/internal/policy"
)

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
