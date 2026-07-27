package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestCheckHealthy(t *testing.T) {
	c := &Checker{
		Version:   "0.1.0-test",
		StartedAt: time.Now().UTC().Add(-2 * time.Second),
		PingDB:    func(ctx context.Context) error { return nil },
		PingClam:  func(ctx context.Context) error { return nil },
		PingDocker: func(ctx context.Context) error { return nil },
		RBIActiveCount: func() int { return 2 },
		GatewayListening: func() bool { return true },
	}
	rep := c.Check(context.Background())
	if rep.Status != StatusHealthy {
		t.Fatalf("status=%s want healthy", rep.Status)
	}
	if rep.Version != "0.1.0-test" {
		t.Fatalf("version=%q", rep.Version)
	}
	if rep.UptimeSec < 1 {
		t.Fatalf("uptime_sec=%d", rep.UptimeSec)
	}
	if rep.NumGoroutine < 1 {
		t.Fatalf("num_goroutine=%d", rep.NumGoroutine)
	}
	names := map[string]bool{}
	for _, comp := range rep.Components {
		names[comp.Name] = true
		if comp.Status != StatusHealthy {
			t.Errorf("component %s status=%s", comp.Name, comp.Status)
		}
	}
	for _, want := range []string{"database", "gateway", "clamav", "rbi_docker", "process"} {
		if !names[want] {
			t.Errorf("missing component %s", want)
		}
	}
}

func TestCheckCriticalDB(t *testing.T) {
	c := &Checker{
		Version: "x",
		PingDB:  func(ctx context.Context) error { return errors.New("db down") },
		PingClam: func(ctx context.Context) error { return errors.New("clam down") },
	}
	rep := c.Check(context.Background())
	if rep.Status != StatusCritical {
		t.Fatalf("status=%s want critical", rep.Status)
	}
}

func TestCheckDegradedClam(t *testing.T) {
	c := &Checker{
		Version:  "x",
		PingDB:   func(ctx context.Context) error { return nil },
		PingClam: func(ctx context.Context) error { return errors.New("clam down") },
	}
	rep := c.Check(context.Background())
	if rep.Status != StatusDegraded {
		t.Fatalf("status=%s want degraded", rep.Status)
	}
}

func TestProcessComponentAlwaysPresent(t *testing.T) {
	c := &Checker{Version: "x"}
	rep := c.Check(context.Background())
	var found bool
	for _, comp := range rep.Components {
		if comp.Name == "process" {
			found = true
			detail, ok := comp.Detail.(map[string]any)
			if !ok {
				t.Fatalf("process detail type %T", comp.Detail)
			}
			if _, ok := detail["alloc_bytes"]; !ok {
				t.Fatal("missing alloc_bytes")
			}
			if _, ok := detail["num_cpu"]; !ok {
				t.Fatal("missing num_cpu")
			}
		}
	}
	if !found {
		t.Fatal("process component missing")
	}
}
