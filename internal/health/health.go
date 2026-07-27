// Package health aggregates component readiness for the management health API.
package health

import (
	"context"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Status is the overall health level.
type Status string

const (
	StatusHealthy  Status = "healthy"
	StatusDegraded Status = "degraded"
	StatusCritical Status = "critical"
)

// Component is one checked subsystem.
type Component struct {
	Name    string `json:"name"`
	Status  Status `json:"status"`
	Message string `json:"message,omitempty"`
	Detail  any    `json:"detail,omitempty"`
}

// Report is the aggregate health response.
type Report struct {
	Status       Status      `json:"status"`
	Version      string      `json:"version"`
	UptimeSec    int64       `json:"uptime_sec"`
	GoVersion    string      `json:"go_version"`
	NumGoroutine int         `json:"num_goroutine"`
	Components   []Component `json:"components"`
	CheckedAt    time.Time   `json:"checked_at"`
}

// Checker gathers optional subsystem probes.
type Checker struct {
	Version   string
	StartedAt time.Time

	// PingDB checks database connectivity.
	PingDB func(ctx context.Context) error
	// PingClam checks ClamAV (optional; nil = skip).
	PingClam func(ctx context.Context) error
	// PingDocker checks Docker for RBI (optional; nil = skip).
	PingDocker func(ctx context.Context) error
	// RBIActiveCount returns active isolation sessions (optional).
	RBIActiveCount func() int
	// GatewayListening reports whether the proxy listener is up (optional).
	GatewayListening func() bool
}

// Check runs all configured probes and returns an aggregate Report.
func (c *Checker) Check(ctx context.Context) Report {
	now := time.Now().UTC()
	started := c.StartedAt
	if started.IsZero() {
		started = now
	}

	rep := Report{
		Status:       StatusHealthy,
		Version:      c.Version,
		UptimeSec:    int64(now.Sub(started).Seconds()),
		GoVersion:    runtime.Version(),
		NumGoroutine: runtime.NumGoroutine(),
		CheckedAt:    now,
		Components:   make([]Component, 0, 6),
	}

	// Database is critical.
	if c.PingDB != nil {
		if err := c.PingDB(ctx); err != nil {
			rep.Components = append(rep.Components, Component{
				Name: "database", Status: StatusCritical, Message: err.Error(),
			})
			rep.Status = StatusCritical
		} else {
			rep.Components = append(rep.Components, Component{
				Name: "database", Status: StatusHealthy, Message: "ok",
			})
		}
	}

	// Gateway listening is informational when mode is management-only.
	if c.GatewayListening != nil {
		if c.GatewayListening() {
			rep.Components = append(rep.Components, Component{
				Name: "gateway", Status: StatusHealthy, Message: "listening",
			})
		} else {
			rep.Components = append(rep.Components, Component{
				Name: "gateway", Status: StatusDegraded, Message: "not listening",
			})
			if rep.Status == StatusHealthy {
				rep.Status = StatusDegraded
			}
		}
	}

	// ClamAV: degraded when unreachable (fail-open default).
	if c.PingClam != nil {
		if err := c.PingClam(ctx); err != nil {
			rep.Components = append(rep.Components, Component{
				Name: "clamav", Status: StatusDegraded, Message: err.Error(),
			})
			if rep.Status == StatusHealthy {
				rep.Status = StatusDegraded
			}
		} else {
			rep.Components = append(rep.Components, Component{
				Name: "clamav", Status: StatusHealthy, Message: "pong",
			})
		}
	}

	// RBI / Docker.
	if c.PingDocker != nil {
		detail := map[string]any{}
		if c.RBIActiveCount != nil {
			detail["active_sessions"] = c.RBIActiveCount()
		}
		if err := c.PingDocker(ctx); err != nil {
			rep.Components = append(rep.Components, Component{
				Name: "rbi_docker", Status: StatusDegraded, Message: err.Error(), Detail: detail,
			})
			if rep.Status == StatusHealthy {
				rep.Status = StatusDegraded
			}
		} else {
			rep.Components = append(rep.Components, Component{
				Name: "rbi_docker", Status: StatusHealthy, Message: "ok", Detail: detail,
			})
		}
	} else if c.RBIActiveCount != nil {
		// Still report active RBI count when docker probe is not wired.
		rep.Components = append(rep.Components, Component{
			Name:   "rbi",
			Status: StatusHealthy,
			Detail: map[string]any{"active_sessions": c.RBIActiveCount()},
		})
	}

	// Best-effort process + host stats (always healthy; metrics are informational).
	rep.Components = append(rep.Components, processComponent())

	return rep
}

func processComponent() Component {
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)

	detail := map[string]any{
		"alloc_bytes":       ms.Alloc,
		"total_alloc_bytes": ms.TotalAlloc,
		"sys_bytes":         ms.Sys,
		"heap_inuse_bytes":  ms.HeapInuse,
		"heap_sys_bytes":    ms.HeapSys,
		"num_gc":            ms.NumGC,
		"num_cpu":           runtime.NumCPU(),
		"gomaxprocs":        runtime.GOMAXPROCS(0),
		"num_goroutine":     runtime.NumGoroutine(),
	}
	if load, ok := readLoadAverage(); ok {
		detail["load_avg_1"] = load[0]
		detail["load_avg_5"] = load[1]
		detail["load_avg_15"] = load[2]
	}
	if rss, ok := readRSSBytes(); ok {
		detail["rss_bytes"] = rss
	}

	return Component{
		Name:    "process",
		Status:  StatusHealthy,
		Message: "ok",
		Detail:  detail,
	}
}

// readLoadAverage is best-effort (Linux /proc/loadavg). Returns 1/5/15 min averages.
func readLoadAverage() ([3]float64, bool) {
	b, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return [3]float64{}, false
	}
	fields := strings.Fields(string(b))
	if len(fields) < 3 {
		return [3]float64{}, false
	}
	var out [3]float64
	for i := 0; i < 3; i++ {
		v, err := strconv.ParseFloat(fields[i], 64)
		if err != nil {
			return [3]float64{}, false
		}
		out[i] = v
	}
	return out, true
}

// readRSSBytes is best-effort RSS from Linux /proc/self/status (VmRSS, kB).
func readRSSBytes() (uint64, bool) {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0, false
	}
	for _, line := range strings.Split(string(b), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0, false
		}
		kb, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0, false
		}
		return kb * 1024, true
	}
	return 0, false
}
