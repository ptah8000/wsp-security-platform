package rbi

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// mockAPI is a DockerAPI test double that records create/remove.
type mockAPI struct {
	mu sync.Mutex

	pingErr    error
	createErr  error
	startErr   error
	inspectErr error
	removeErr  error
	pullErr    error
	imageOK    bool

	created []createCall
	started []string
	removed []removeCall

	hostPort  string
	ipAddress string
	nextID    int
}

type createCall struct {
	Image  string
	Memory int64
	Name   string
}

type removeCall struct {
	ID    string
	Force bool
}

func (m *mockAPI) Ping(ctx context.Context) error { return m.pingErr }

func (m *mockAPI) ImageExists(ctx context.Context, ref string) (bool, error) {
	return m.imageOK, nil
}

func (m *mockAPI) ImagePull(ctx context.Context, ref string) error {
	if m.pullErr != nil {
		return m.pullErr
	}
	m.imageOK = true
	return nil
}

func (m *mockAPI) ContainerCreate(ctx context.Context, body createContainerBody, name string) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.createErr != nil {
		return "", m.createErr
	}
	m.nextID++
	id := "containerid000" + itoa(m.nextID)
	m.created = append(m.created, createCall{
		Image:  body.Image,
		Memory: body.HostConfig.Memory,
		Name:   name,
	})
	return id, nil
}

func (m *mockAPI) ContainerStart(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.startErr != nil {
		return m.startErr
	}
	m.started = append(m.started, id)
	return nil
}

func (m *mockAPI) ContainerInspect(ctx context.Context, id string) (inspectResult, error) {
	if m.inspectErr != nil {
		return inspectResult{}, m.inspectErr
	}
	hp := m.hostPort
	if hp == "" {
		hp = "39999"
	}
	ip := m.ipAddress
	return inspectResult{
		ID:         id,
		IPAddress:  ip,
		HostPort:   hp,
		Running:    true,
		NetworkIPs: map[string]string{},
	}, nil
}

func (m *mockAPI) ContainerRemove(ctx context.Context, id string, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.removeErr != nil {
		return m.removeErr
	}
	m.removed = append(m.removed, removeCall{ID: id, Force: force})
	return nil
}

func itoa(n int) string {
	if n <= 0 {
		return "0"
	}
	var b [16]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	return string(b[i:])
}

func TestDockerRuntime_CreateAndStart_Remove(t *testing.T) {
	cdp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"Browser":"Chrome","webSocketDebuggerUrl":"ws://127.0.0.1:9/devtools"}`))
	}))
	t.Cleanup(cdp.Close)

	hostPort := strings.TrimPrefix(cdp.URL, "http://")
	parts := strings.Split(hostPort, ":")
	if len(parts) < 2 {
		t.Fatalf("bad test URL %s", cdp.URL)
	}

	api := &mockAPI{imageOK: true, hostPort: parts[len(parts)-1], ipAddress: ""}
	rt := &DockerRuntime{
		API:         api,
		CDPHost:     "127.0.0.1",
		PullMissing: false,
		HTTPClient:  cdp.Client(),
	}

	ctx := context.Background()
	info, err := rt.CreateAndStart(ctx, CreateOpts{
		Image: "browserless/chrome:test",
	})
	if err != nil {
		t.Fatalf("CreateAndStart: %v", err)
	}
	if info.ID == "" {
		t.Fatal("empty container id")
	}
	if !strings.Contains(info.CDPAddr, parts[len(parts)-1]) {
		t.Fatalf("CDPAddr=%q want host port %s", info.CDPAddr, parts[len(parts)-1])
	}
	if len(api.created) != 1 {
		t.Fatalf("created=%d", len(api.created))
	}
	if api.created[0].Image != "browserless/chrome:test" {
		t.Fatalf("image=%q", api.created[0].Image)
	}
	if api.created[0].Memory != DefaultMemoryBytes {
		t.Fatalf("memory=%d want %d", api.created[0].Memory, DefaultMemoryBytes)
	}
	if len(api.started) != 1 || api.started[0] != info.ID {
		t.Fatalf("started=%v", api.started)
	}

	if err := rt.Remove(ctx, info.ID, true); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if len(api.removed) != 1 || !api.removed[0].Force || api.removed[0].ID != info.ID {
		t.Fatalf("removed=%v", api.removed)
	}
}

func TestDockerRuntime_CreateFails_NoLeak(t *testing.T) {
	api := &mockAPI{imageOK: true, startErr: errors.New("start boom")}
	rt := &DockerRuntime{API: api, PullMissing: false}
	_, err := rt.CreateAndStart(context.Background(), CreateOpts{Image: "x"})
	if err == nil {
		t.Fatal("expected error")
	}
	if len(api.removed) != 1 || !api.removed[0].Force {
		t.Fatalf("expected force-remove after start failure, got %v", api.removed)
	}
}

func TestDockerRuntime_PingError(t *testing.T) {
	api := &mockAPI{pingErr: errors.New("no daemon")}
	rt := &DockerRuntime{API: api}
	if err := rt.Ping(context.Background()); err == nil {
		t.Fatal("expected ping error")
	}
}

func TestDockerRuntime_PreferContainerIP(t *testing.T) {
	rt := &DockerRuntime{}
	addr := rt.resolveCDPAddr(ContainerInfo{IPAddress: "10.0.0.5", ContainerPort: 3000, HostPort: "12345"})
	if addr != "10.0.0.5:3000" {
		t.Fatalf("addr=%q", addr)
	}
	// Container IP still preferred when CDPHost is set (shared-network CDP).
	rt.CDPHost = "127.0.0.1"
	addr = rt.resolveCDPAddr(ContainerInfo{IPAddress: "10.0.0.5", ContainerPort: 3000, HostPort: "12345"})
	if addr != "10.0.0.5:3000" {
		t.Fatalf("addr with CDPHost should still prefer IP, got %q", addr)
	}
	// HostPort + CDPHost only when no container IP (sibling network missing).
	addr = rt.resolveCDPAddr(ContainerInfo{HostPort: "12345"})
	if addr != "127.0.0.1:12345" {
		t.Fatalf("hostport fallback=%q", addr)
	}
	rt.CDPHost = "host.docker.internal"
	addr = rt.resolveCDPAddr(ContainerInfo{HostPort: "12345"})
	if addr != "host.docker.internal:12345" {
		t.Fatalf("cdp host fallback=%q", addr)
	}
}
