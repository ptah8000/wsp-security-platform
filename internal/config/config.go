package config

import (
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config holds process bootstrap settings loaded from the environment.
type Config struct {
	Mode            string // all | gateway | management
	ProxyAddr       string
	AdminAddr       string
	DatabaseURL     string
	DataKey         string // 32-byte key, base64 or raw hex preferred
	ClamdAddr       string
	DockerHost      string
	RBIImage        string
	MaxRBISessions  int
	LogLevel        string
	ShutdownTimeout time.Duration
}

// Load reads configuration from environment variables, applying defaults.
func Load() (Config, error) {
	c := Config{
		Mode:            getenv("WSP_MODE", "all"),
		ProxyAddr:       getenv("WSP_PROXY_ADDR", ":8080"),
		AdminAddr:       getenv("WSP_ADMIN_ADDR", ":3000"),
		DatabaseURL:     getenv("WSP_DATABASE_URL", "postgres://wsp:wsp@localhost:5432/wsp?sslmode=disable"),
		DataKey:         os.Getenv("WSP_DATA_KEY"),
		ClamdAddr:       getenv("WSP_CLAMD_ADDR", "clamav:3310"),
		DockerHost:      getenv("DOCKER_HOST", "unix:///var/run/docker.sock"),
		RBIImage:        getenv("WSP_RBI_IMAGE", "browserless/chrome:latest"),
		MaxRBISessions:  getenvInt("WSP_MAX_RBI_SESSIONS", 10),
		LogLevel:        getenv("WSP_LOG_LEVEL", "info"),
		ShutdownTimeout: time.Duration(getenvInt("WSP_SHUTDOWN_TIMEOUT_SEC", 15)) * time.Second,
	}
	if c.Mode != "all" && c.Mode != "gateway" && c.Mode != "management" {
		return c, fmt.Errorf("invalid WSP_MODE %q", c.Mode)
	}
	return c, nil
}

func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func getenvInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def
	}
	return n
}
