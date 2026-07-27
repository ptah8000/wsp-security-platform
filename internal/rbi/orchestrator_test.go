package rbi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/wsp-security/wsp/internal/policy"
)

// mockRuntime implements ContainerRuntime for orchestrator tests.
type mockRuntime struct {
	mu        sync.Mutex
	pingErr   error
	createErr error
	removeErr error
	created   int
	removed   []string
	seq       int
}

func (m *mockRuntime) Ping(ctx context.Context) error { return m.pingErr }

func (m *mockRuntime) CreateAndStart(ctx context.Context, opts CreateOpts) (ContainerInfo, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return ContainerInfo{}, m.createErr
	}
	m.created++
	m.seq++
	id := "cid-" + strings.Repeat("b", 8) + string(rune('0'+m.seq))
	id = "cid00000000" + string(rune('0'+m.seq))
	return ContainerInfo{
		ID:            id,
		CDPAddr:       "127.0.0.1:39999",
		ContainerPort: 3000,
		HostPort:      "39999",
	}, nil
}

func (m *mockRuntime) Remove(ctx context.Context, id string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.removed = append(m.removed, id)
	return m.removeErr
}

func TestOrchestrator_StartStop_MaxSessions(t *testing.T) {
	rt := &mockRuntime{}
	var connectCalls atomic.Int32
	o := NewOrchestrator(Config{
		Runtime:     rt,
		Image:       "test/chrome:1",
		MaxSessions: 2,
	})
	o.CDPConnect = func(ctx context.Context, s *liveSession) error {
		connectCalls.Add(1)
		return nil // skip real go-rod
	}

	ctx := context.Background()
	s1, err := o.Start(ctx, "https://example.com/", SessionOpts{})
	if err != nil {
		t.Fatalf("Start1: %v", err)
	}
	s2, err := o.Start(ctx, "https://example.org/", SessionOpts{BlockCopyFrom: true})
	if err != nil {
		t.Fatalf("Start2: %v", err)
	}
	if o.ActiveCount() != 2 {
		t.Fatalf("active=%d", o.ActiveCount())
	}

	_, err = o.Start(ctx, "https://third.example/", SessionOpts{})
	if !errors.Is(err, ErrMaxSessions) {
		t.Fatalf("want ErrMaxSessions, got %v", err)
	}

	if _, ok := o.Get(s1.ID()); !ok {
		t.Fatal("Get s1")
	}

	if err := o.Stop(ctx, s1.ID()); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if o.ActiveCount() != 1 {
		t.Fatalf("active after stop=%d", o.ActiveCount())
	}
	if len(rt.removed) != 1 {
		t.Fatalf("removed=%v", rt.removed)
	}

	// Slot free again.
	s3, err := o.Start(ctx, "https://again.example/", SessionOpts{})
	if err != nil {
		t.Fatalf("Start3: %v", err)
	}
	_ = s2
	_ = o.Stop(ctx, s2.ID())
	_ = o.Stop(ctx, s3.ID())
	if o.ActiveCount() != 0 {
		t.Fatalf("active=%d want 0", o.ActiveCount())
	}
	if connectCalls.Load() != 3 {
		t.Fatalf("connectCalls=%d", connectCalls.Load())
	}
}

func TestOrchestrator_DockerUnavailable(t *testing.T) {
	rt := &mockRuntime{pingErr: errors.New("daemon down")}
	o := NewOrchestrator(Config{Runtime: rt, MaxSessions: 5})
	o.CDPConnect = func(ctx context.Context, s *liveSession) error { return nil }

	_, err := o.Start(context.Background(), "https://x.test/", SessionOpts{})
	if !errors.Is(err, ErrDockerUnavailable) {
		t.Fatalf("err=%v", err)
	}
	if o.ActiveCount() != 0 {
		t.Fatalf("leaked sessions: %d", o.ActiveCount())
	}
}

func TestOrchestrator_CreateError_CleansPlaceholder(t *testing.T) {
	rt := &mockRuntime{createErr: errors.New("create fail")}
	o := NewOrchestrator(Config{Runtime: rt})
	o.CDPConnect = func(ctx context.Context, s *liveSession) error { return nil }

	_, err := o.Start(context.Background(), "https://x.test/", SessionOpts{})
	if err == nil {
		t.Fatal("expected error")
	}
	if o.ActiveCount() != 0 {
		t.Fatalf("leaked: %d", o.ActiveCount())
	}
}

func TestOrchestrator_HandleIsolation_Success(t *testing.T) {
	rt := &mockRuntime{}
	o := NewOrchestrator(Config{Runtime: rt, MaxSessions: 5})
	o.CDPConnect = func(ctx context.Context, s *liveSession) error { return nil }

	req := httptest.NewRequest(http.MethodGet, "https://isolated.example/app", nil)
	rr := httptest.NewRecorder()
	d := policy.Decision{
		RBIIsolated:      true,
		RBIBlockCopyFrom: true,
		RBIBlockCopyTo:   true,
	}
	if !o.HandleIsolation(rr, req, d) {
		t.Fatal("HandleIsolation should return true when session starts")
	}
	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d", rr.Code)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "RBI") || !strings.Contains(body, "/rbi/ws/") {
		t.Fatalf("viewer HTML missing markers: %s", body[:min(200, len(body))])
	}
	if o.ActiveCount() != 1 {
		t.Fatalf("active=%d", o.ActiveCount())
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("ct=%q", rr.Header().Get("Content-Type"))
	}
}

func TestOrchestrator_HandleIsolation_FailClosed(t *testing.T) {
	rt := &mockRuntime{pingErr: errors.New("no docker")}
	o := NewOrchestrator(Config{Runtime: rt})
	o.CDPConnect = func(ctx context.Context, s *liveSession) error { return nil }

	req := httptest.NewRequest(http.MethodGet, "https://isolated.example/", nil)
	rr := httptest.NewRecorder()
	if o.HandleIsolation(rr, req, policy.Decision{RBIIsolated: true}) {
		t.Fatal("HandleIsolation must return false when Docker unavailable")
	}
	if o.ActiveCount() != 0 {
		t.Fatal("no sessions on failure")
	}
}

func TestOrchestrator_ShouldIsolate(t *testing.T) {
	o := NewOrchestrator(Config{})
	if o.ShouldIsolate(policy.Decision{}) {
		t.Fatal("empty")
	}
	if !o.ShouldIsolate(policy.Decision{RBIIsolated: true}) {
		t.Fatal("want isolate")
	}
}

func TestServeRBIPath_NotFound(t *testing.T) {
	o := NewOrchestrator(Config{Runtime: &mockRuntime{}})
	req := httptest.NewRequest(http.MethodGet, "http://proxy/rbi/session/nope", nil)
	rr := httptest.NewRecorder()
	if !o.ServeRBIPath(rr, req) {
		t.Fatal("should handle path")
	}
	if rr.Code != http.StatusNotFound {
		t.Fatalf("code=%d", rr.Code)
	}
}

func TestIsControlPath(t *testing.T) {
	if !IsControlPath("/rbi/session/x") || !IsControlPath("/rbi/ws/x") {
		t.Fatal("expected control paths")
	}
	if IsControlPath("/other") || IsControlPath("") {
		t.Fatal("non-control")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
