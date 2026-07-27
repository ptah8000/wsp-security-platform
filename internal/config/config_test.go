package config

import (
	"testing"
	"time"
)

func TestLoadDefaults(t *testing.T) {
	clearWSPEnv(t)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.Mode != "all" {
		t.Errorf("Mode = %q, want all", cfg.Mode)
	}
	if cfg.ProxyAddr != ":8080" {
		t.Errorf("ProxyAddr = %q, want :8080", cfg.ProxyAddr)
	}
	if cfg.AdminAddr != ":3000" {
		t.Errorf("AdminAddr = %q, want :3000", cfg.AdminAddr)
	}
	if cfg.DatabaseURL != "postgres://wsp:wsp@localhost:5432/wsp?sslmode=disable" {
		t.Errorf("DatabaseURL = %q, unexpected default", cfg.DatabaseURL)
	}
	if cfg.DataKey != "" {
		t.Errorf("DataKey = %q, want empty when unset", cfg.DataKey)
	}
	if cfg.ClamdAddr != "clamav:3310" {
		t.Errorf("ClamdAddr = %q, want clamav:3310", cfg.ClamdAddr)
	}
	if cfg.DockerHost != "unix:///var/run/docker.sock" {
		t.Errorf("DockerHost = %q, want unix:///var/run/docker.sock", cfg.DockerHost)
	}
	if cfg.RBIImage != "browserless/chrome:latest" {
		t.Errorf("RBIImage = %q, want browserless/chrome:latest", cfg.RBIImage)
	}
	if cfg.MaxRBISessions != 10 {
		t.Errorf("MaxRBISessions = %d, want 10", cfg.MaxRBISessions)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("LogLevel = %q, want info", cfg.LogLevel)
	}
	if cfg.ShutdownTimeout != 15*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 15s", cfg.ShutdownTimeout)
	}
}

func TestLoadInvalidMode(t *testing.T) {
	clearWSPEnv(t)
	t.Setenv("WSP_MODE", "invalid")

	_, err := Load()
	if err == nil {
		t.Fatal("Load() expected error for invalid WSP_MODE, got nil")
	}
}

func TestLoadValidModes(t *testing.T) {
	for _, mode := range []string{"all", "gateway", "management"} {
		t.Run(mode, func(t *testing.T) {
			clearWSPEnv(t)
			t.Setenv("WSP_MODE", mode)

			cfg, err := Load()
			if err != nil {
				t.Fatalf("Load() unexpected error for mode %q: %v", mode, err)
			}
			if cfg.Mode != mode {
				t.Errorf("Mode = %q, want %q", cfg.Mode, mode)
			}
		})
	}
}

func TestLoadOverrides(t *testing.T) {
	clearWSPEnv(t)
	t.Setenv("WSP_PROXY_ADDR", ":9090")
	t.Setenv("WSP_ADMIN_ADDR", ":4000")
	t.Setenv("WSP_DATABASE_URL", "postgres://u:p@db:5432/wsp?sslmode=disable")
	t.Setenv("WSP_DATA_KEY", "test-key")
	t.Setenv("WSP_CLAMD_ADDR", "127.0.0.1:3310")
	t.Setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
	t.Setenv("WSP_RBI_IMAGE", "custom/chrome:1")
	t.Setenv("WSP_MAX_RBI_SESSIONS", "25")
	t.Setenv("WSP_LOG_LEVEL", "debug")
	t.Setenv("WSP_SHUTDOWN_TIMEOUT_SEC", "30")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.ProxyAddr != ":9090" {
		t.Errorf("ProxyAddr = %q, want :9090", cfg.ProxyAddr)
	}
	if cfg.AdminAddr != ":4000" {
		t.Errorf("AdminAddr = %q, want :4000", cfg.AdminAddr)
	}
	if cfg.DatabaseURL != "postgres://u:p@db:5432/wsp?sslmode=disable" {
		t.Errorf("DatabaseURL = %q, unexpected", cfg.DatabaseURL)
	}
	if cfg.DataKey != "test-key" {
		t.Errorf("DataKey = %q, want test-key", cfg.DataKey)
	}
	if cfg.ClamdAddr != "127.0.0.1:3310" {
		t.Errorf("ClamdAddr = %q, want 127.0.0.1:3310", cfg.ClamdAddr)
	}
	if cfg.DockerHost != "tcp://127.0.0.1:2375" {
		t.Errorf("DockerHost = %q, want tcp://127.0.0.1:2375", cfg.DockerHost)
	}
	if cfg.RBIImage != "custom/chrome:1" {
		t.Errorf("RBIImage = %q, want custom/chrome:1", cfg.RBIImage)
	}
	if cfg.MaxRBISessions != 25 {
		t.Errorf("MaxRBISessions = %d, want 25", cfg.MaxRBISessions)
	}
	if cfg.LogLevel != "debug" {
		t.Errorf("LogLevel = %q, want debug", cfg.LogLevel)
	}
	if cfg.ShutdownTimeout != 30*time.Second {
		t.Errorf("ShutdownTimeout = %v, want 30s", cfg.ShutdownTimeout)
	}
}

func clearWSPEnv(t *testing.T) {
	t.Helper()
	keys := []string{
		"WSP_MODE",
		"WSP_PROXY_ADDR",
		"WSP_ADMIN_ADDR",
		"WSP_DATABASE_URL",
		"WSP_DATA_KEY",
		"WSP_CLAMD_ADDR",
		"DOCKER_HOST",
		"WSP_RBI_IMAGE",
		"WSP_MAX_RBI_SESSIONS",
		"WSP_LOG_LEVEL",
		"WSP_SHUTDOWN_TIMEOUT_SEC",
	}
	for _, k := range keys {
		t.Setenv(k, "")
	}
}
