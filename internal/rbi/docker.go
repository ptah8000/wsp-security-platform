package rbi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// DefaultContainerPort is the CDP/HTTP port inside browserless/chrome images.
	DefaultContainerPort = 3000
	// DefaultMemoryBytes is the per-container memory limit (1 GiB).
	DefaultMemoryBytes int64 = 1 << 30
	defaultCDPWaitTimeout    = 45 * time.Second
	defaultCDPPollInterval   = 400 * time.Millisecond
	dockerAPIVersion         = "v1.44"
)

// CreateOpts configures an ephemeral Chromium container.
type CreateOpts struct {
	Image         string
	ContainerPort int
	MemoryBytes   int64
	Name          string
	Labels        map[string]string
	Network       string
}

// ContainerInfo is the result of CreateAndStart.
type ContainerInfo struct {
	ID            string
	CDPAddr       string
	ContainerPort int
	HostPort      string
	IPAddress     string
}

// ContainerRuntime creates and destroys RBI browser containers.
// Tests inject a mock; production uses DockerRuntime.
type ContainerRuntime interface {
	Ping(ctx context.Context) error
	CreateAndStart(ctx context.Context, opts CreateOpts) (ContainerInfo, error)
	Remove(ctx context.Context, id string, force bool) error
}

// DockerAPI is the subset of Docker operations used by DockerRuntime.
// Narrow interface enables unit tests without a real daemon.
type DockerAPI interface {
	Ping(ctx context.Context) error
	ImageExists(ctx context.Context, ref string) (bool, error)
	ImagePull(ctx context.Context, ref string) error
	ContainerCreate(ctx context.Context, body createContainerBody, name string) (string, error)
	ContainerStart(ctx context.Context, id string) error
	ContainerInspect(ctx context.Context, id string) (inspectResult, error)
	ContainerRemove(ctx context.Context, id string, force bool) error
}

type inspectResult struct {
	ID         string
	IPAddress  string
	HostPort   string
	Running    bool
	NetworkIPs map[string]string
}

// createContainerBody is a minimal Docker create payload.
type createContainerBody struct {
	Image        string              `json:"Image"`
	Env          []string            `json:"Env,omitempty"`
	Labels       map[string]string   `json:"Labels,omitempty"`
	ExposedPorts map[string]struct{} `json:"ExposedPorts,omitempty"`
	HostConfig   hostConfigBody      `json:"HostConfig"`
}

type hostConfigBody struct {
	Memory       int64                        `json:"Memory"`
	NanoCPUs     int64                        `json:"NanoCpus,omitempty"`
	PidsLimit    int64                        `json:"PidsLimit,omitempty"`
	AutoRemove   bool                         `json:"AutoRemove"`
	CapDrop      []string                     `json:"CapDrop,omitempty"`
	SecurityOpt  []string                     `json:"SecurityOpt,omitempty"`
	PortBindings map[string][]portBindingBody `json:"PortBindings,omitempty"`
	NetworkMode  string                       `json:"NetworkMode,omitempty"`
}

type portBindingBody struct {
	HostIP   string `json:"HostIp,omitempty"`
	HostPort string `json:"HostPort,omitempty"`
}

// DockerRuntime implements ContainerRuntime via the Docker Engine HTTP API.
type DockerRuntime struct {
	API DockerAPI
	// CDPHost, when set, forces CDP via published ports on this host.
	CDPHost string
	// HTTPClient probes CDP readiness (optional).
	HTTPClient *http.Client
	// PullMissing pulls the image when not present locally (default true).
	PullMissing bool
}

// NewDockerRuntime connects to dockerHost (e.g. unix:///var/run/docker.sock or
// tcp://127.0.0.1:2375). Empty host uses DOCKER_HOST / default unix socket.
func NewDockerRuntime(dockerHost string) (*DockerRuntime, error) {
	api, err := newEngineHTTP(dockerHost)
	if err != nil {
		return nil, err
	}
	return &DockerRuntime{
		API:         api,
		PullMissing: true,
		HTTPClient:  &http.Client{Timeout: 3 * time.Second},
	}, nil
}

// Ping checks Docker daemon reachability.
func (d *DockerRuntime) Ping(ctx context.Context) error {
	if d == nil || d.API == nil {
		return fmt.Errorf("docker runtime not configured")
	}
	return d.API.Ping(ctx)
}

// CreateAndStart pulls (if needed), creates, starts, and waits for CDP readiness.
func (d *DockerRuntime) CreateAndStart(ctx context.Context, opts CreateOpts) (ContainerInfo, error) {
	if d == nil || d.API == nil {
		return ContainerInfo{}, fmt.Errorf("docker runtime not configured")
	}
	if opts.Image == "" {
		return ContainerInfo{}, fmt.Errorf("RBI image is empty")
	}
	port := opts.ContainerPort
	if port <= 0 {
		port = DefaultContainerPort
	}
	mem := opts.MemoryBytes
	if mem <= 0 {
		mem = DefaultMemoryBytes
	}

	if err := d.ensureImage(ctx, opts.Image); err != nil {
		return ContainerInfo{}, err
	}

	portKey := strconv.Itoa(port) + "/tcp"
	labels := map[string]string{"wsp.rbi": "1"}
	for k, v := range opts.Labels {
		labels[k] = v
	}

	// Attach to the gateway Compose network when set so CDP is reachable via
	// container IP (published 127.0.0.1 ports are NOT visible from sibling containers).
	hc := hostConfigBody{
		Memory:     mem,
		NanoCPUs:   1_000_000_000, // 1 CPU
		PidsLimit:  512,
		AutoRemove: false,
		// Do not CapDrop ALL — breaks Chromium networking/TLS in many images.
		SecurityOpt: []string{"no-new-privileges:true"},
		PortBindings: map[string][]portBindingBody{
			portKey: {{
				HostIP:   "0.0.0.0",
				HostPort: "0",
			}},
		},
	}
	if opts.Network != "" {
		hc.NetworkMode = opts.Network
	}

	body := createContainerBody{
		Image: opts.Image,
		// browserless: keep session alive; disable ad-block surprises.
		Env: []string{
			"CONNECTION_TIMEOUT=600000",
			"DEFAULT_BLOCK_ADS=false",
			// Help Chromium accept public HTTPS when image CA store is incomplete.
			`DEFAULT_LAUNCH_ARGS=["--ignore-certificate-errors","--no-sandbox","--disable-dev-shm-usage"]`,
		},
		Labels: labels,
		ExposedPorts: map[string]struct{}{
			portKey: {},
		},
		HostConfig: hc,
	}

	id, err := d.API.ContainerCreate(ctx, body, opts.Name)
	if err != nil {
		return ContainerInfo{}, fmt.Errorf("container create: %w", err)
	}

	if err := d.API.ContainerStart(ctx, id); err != nil {
		_ = d.API.ContainerRemove(context.Background(), id, true)
		return ContainerInfo{}, fmt.Errorf("container start: %w", err)
	}

	insp, err := d.API.ContainerInspect(ctx, id)
	if err != nil {
		_ = d.API.ContainerRemove(context.Background(), id, true)
		return ContainerInfo{}, fmt.Errorf("container inspect: %w", err)
	}

	info := ContainerInfo{
		ID:            id,
		ContainerPort: port,
		HostPort:      insp.HostPort,
		IPAddress:     insp.IPAddress,
	}
	if info.IPAddress == "" && len(insp.NetworkIPs) > 0 {
		for _, ip := range insp.NetworkIPs {
			if ip != "" {
				info.IPAddress = ip
				break
			}
		}
	}
	info.CDPAddr = d.resolveCDPAddr(info)
	if info.CDPAddr == "" {
		_ = d.API.ContainerRemove(context.Background(), id, true)
		return ContainerInfo{}, fmt.Errorf("could not resolve CDP address for container %s", id)
	}

	if err := d.waitCDP(ctx, info.CDPAddr); err != nil {
		_ = d.API.ContainerRemove(context.Background(), id, true)
		return ContainerInfo{}, fmt.Errorf("CDP not ready on %s: %w", info.CDPAddr, err)
	}

	slog.Info("rbi container ready",
		"container_id", shortID(id),
		"cdp", info.CDPAddr,
		"image", opts.Image,
	)
	return info, nil
}

// Remove force-removes the container.
func (d *DockerRuntime) Remove(ctx context.Context, id string, force bool) error {
	if d == nil || d.API == nil {
		return fmt.Errorf("docker runtime not configured")
	}
	if id == "" {
		return nil
	}
	return d.API.ContainerRemove(ctx, id, force)
}

func (d *DockerRuntime) ensureImage(ctx context.Context, ref string) error {
	ok, err := d.API.ImageExists(ctx, ref)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if !d.PullMissing {
		return fmt.Errorf("image %q not present locally", ref)
	}
	slog.Info("pulling RBI image", "image", ref)
	if err := d.API.ImagePull(ctx, ref); err != nil {
		return fmt.Errorf("image pull %s: %w", ref, err)
	}
	return nil
}

func (d *DockerRuntime) resolveCDPAddr(info ContainerInfo) string {
	// Prefer container IP on a shared Docker network (works from the gateway container).
	if info.IPAddress != "" {
		return net.JoinHostPort(info.IPAddress, strconv.Itoa(info.ContainerPort))
	}
	// Explicit CDP host (e.g. host.docker.internal) + published host port.
	if d != nil && d.CDPHost != "" && info.HostPort != "" {
		return net.JoinHostPort(d.CDPHost, info.HostPort)
	}
	// Last resort: published port on loopback (only when gateway runs on the host).
	if info.HostPort != "" {
		return net.JoinHostPort("127.0.0.1", info.HostPort)
	}
	return ""
}

func (d *DockerRuntime) waitCDP(ctx context.Context, addr string) error {
	client := d.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	}
	deadline := time.Now().Add(defaultCDPWaitTimeout)
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	urls := []string{
		"http://" + addr + "/json/version",
		"http://" + addr + "/",
	}
	var last error
	for time.Now().Before(deadline) {
		if err := ctx.Err(); err != nil {
			return err
		}
		for _, u := range urls {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
			if err != nil {
				last = err
				continue
			}
			resp, err := client.Do(req)
			if err != nil {
				last = err
				continue
			}
			_ = resp.Body.Close()
			if resp.StatusCode > 0 && resp.StatusCode < 500 {
				return nil
			}
			last = fmt.Errorf("status %d", resp.StatusCode)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(defaultCDPPollInterval):
		}
	}
	if last == nil {
		last = fmt.Errorf("timeout")
	}
	return last
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}

// defaultDockerHost is overridden per-OS (unix socket vs named pipe).
func defaultDockerHost() string {
	return defaultDockerHostOS()
}

// --- Engine HTTP client ---

type engineHTTP struct {
	base   string // e.g. http://docker
	client *http.Client
}

func newEngineHTTP(dockerHost string) (*engineHTTP, error) {
	host := strings.TrimSpace(dockerHost)
	if host == "" {
		host = defaultDockerHost()
	}
	u, err := url.Parse(host)
	if err != nil {
		return nil, fmt.Errorf("parse DOCKER_HOST: %w", err)
	}

	var (
		base   string
		dialer func(ctx context.Context, network, addr string) (net.Conn, error)
	)
	switch u.Scheme {
	case "unix":
		sock := u.Path
		if sock == "" {
			sock = "/var/run/docker.sock"
		}
		base = "http://docker"
		dialer = func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "unix", sock)
		}
	case "npipe":
		// Windows named pipe: npipe:////./pipe/docker_engine
		path := u.Path
		if path == "" {
			path = u.Opaque
		}
		if path == "" || !strings.Contains(path, "pipe") {
			path = "//./pipe/docker_engine"
		}
		base = "http://docker"
		pipePath := path
		dialer = func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialDockerNpipe(ctx, pipePath)
		}
	case "tcp", "http":
		base = "http://" + u.Host
		if u.Host == "" {
			return nil, fmt.Errorf("DOCKER_HOST tcp missing host")
		}
	case "https":
		base = "https://" + u.Host
	default:
		// Bare path or host:port
		if strings.HasPrefix(host, "/") {
			base = "http://docker"
			sock := host
			dialer = func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "unix", sock)
			}
		} else {
			return nil, fmt.Errorf("unsupported DOCKER_HOST scheme %q", u.Scheme)
		}
	}

	tr := &http.Transport{}
	if dialer != nil {
		tr.DialContext = dialer
	}
	return &engineHTTP{
		base: base + "/" + dockerAPIVersion,
		client: &http.Client{
			Transport: tr,
			Timeout:   0, // per-request via context
		},
	}, nil
}

func (e *engineHTTP) do(ctx context.Context, method, path string, body io.Reader, contentType string) (*http.Response, error) {
	u := e.base + path
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	return e.client.Do(req)
}

func (e *engineHTTP) Ping(ctx context.Context) error {
	resp, err := e.do(ctx, http.MethodGet, "/_ping", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("docker ping: status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}

func (e *engineHTTP) ImageExists(ctx context.Context, ref string) (bool, error) {
	path := "/images/" + url.PathEscape(ref) + "/json"
	// PathEscape encodes "/" which breaks image refs like repo/name:tag.
	// Docker expects the ref literally in the path (with :tag).
	path = "/images/" + encodeImageRef(ref) + "/json"
	resp, err := e.do(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return false, fmt.Errorf("image inspect: status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
}

func encodeImageRef(ref string) string {
	// Keep slashes; escape only what would break the path.
	return strings.ReplaceAll(url.PathEscape(ref), "%2F", "/")
}

func (e *engineHTTP) ImagePull(ctx context.Context, ref string) error {
	q := url.Values{"fromImage": {ref}}
	// Split tag if present for fromImage/tag query form.
	image, tag := ref, "latest"
	if i := strings.LastIndex(ref, ":"); i > 0 && !strings.Contains(ref[i:], "/") {
		image, tag = ref[:i], ref[i+1:]
	}
	q = url.Values{"fromImage": {image}, "tag": {tag}}
	resp, err := e.do(ctx, http.MethodPost, "/images/create?"+q.Encode(), nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	// Pull streams JSON progress lines; drain fully.
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("image pull status %d", resp.StatusCode)
	}
	return nil
}

func (e *engineHTTP) ContainerCreate(ctx context.Context, body createContainerBody, name string) (string, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return "", err
	}
	path := "/containers/create"
	if name != "" {
		path += "?name=" + url.QueryEscape(name)
	}
	resp, err := e.do(ctx, http.MethodPost, path, bytes.NewReader(raw), "application/json")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("create status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	var out struct {
		ID string `json:"Id"`
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return "", fmt.Errorf("create decode: %w", err)
	}
	if out.ID == "" {
		return "", fmt.Errorf("create: empty id")
	}
	return out.ID, nil
}

func (e *engineHTTP) ContainerStart(ctx context.Context, id string) error {
	resp, err := e.do(ctx, http.MethodPost, "/containers/"+id+"/start", nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent && resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("start status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	return nil
}

func (e *engineHTTP) ContainerInspect(ctx context.Context, id string) (inspectResult, error) {
	resp, err := e.do(ctx, http.MethodGet, "/containers/"+id+"/json", nil, "")
	if err != nil {
		return inspectResult{}, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return inspectResult{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return inspectResult{}, fmt.Errorf("inspect status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
	}
	var raw struct {
		ID      string `json:"Id"`
		State   *struct {
			Running bool `json:"Running"`
		} `json:"State"`
		NetworkSettings *struct {
			IPAddress string `json:"IPAddress"`
			Ports     map[string][]struct {
				HostIP   string `json:"HostIp"`
				HostPort string `json:"HostPort"`
			} `json:"Ports"`
			Networks map[string]*struct {
				IPAddress string `json:"IPAddress"`
			} `json:"Networks"`
		} `json:"NetworkSettings"`
	}
	if err := json.Unmarshal(b, &raw); err != nil {
		return inspectResult{}, err
	}
	out := inspectResult{
		ID:         raw.ID,
		NetworkIPs: map[string]string{},
	}
	if raw.State != nil {
		out.Running = raw.State.Running
	}
	if raw.NetworkSettings != nil {
		out.IPAddress = raw.NetworkSettings.IPAddress
		for name, ep := range raw.NetworkSettings.Networks {
			if ep != nil && ep.IPAddress != "" {
				out.NetworkIPs[name] = ep.IPAddress
				if out.IPAddress == "" {
					out.IPAddress = ep.IPAddress
				}
			}
		}
		for p, bindings := range raw.NetworkSettings.Ports {
			if !strings.HasSuffix(p, "/tcp") {
				continue
			}
			if len(bindings) > 0 && bindings[0].HostPort != "" {
				out.HostPort = bindings[0].HostPort
				break
			}
		}
	}
	return out, nil
}

func (e *engineHTTP) ContainerRemove(ctx context.Context, id string, force bool) error {
	q := url.Values{"v": {"1"}}
	if force {
		q.Set("force", "1")
	}
	resp, err := e.do(ctx, http.MethodDelete, "/containers/"+id+"?"+q.Encode(), nil, "")
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent || resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusNotFound {
		return nil
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return fmt.Errorf("remove status %d: %s", resp.StatusCode, bytes.TrimSpace(b))
}
