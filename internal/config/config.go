package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds process bootstrap settings loaded from the environment.
type Config struct {
	Mode              string // all | gateway | management
	ProxyAddr         string
	AdminAddr         string
	DatabaseURL       string
	DataKey           string // 32-byte key, base64 or raw hex preferred
	ClamdAddr         string
	MalwareFailClosed bool // when true, scan errors block; default false (fail-open)
	DockerHost        string
	RBIImage          string
	RBINetwork        string // Docker network name for RBI containers (same as gateway)
	RBICDPHost        string // optional host for published CDP ports (e.g. host.docker.internal)
	MaxRBISessions    int
	// PublicProxyHost/Port are client-facing proxy coordinates for Client Setup / PAC.
	// When empty, Client Setup falls back to PROXY_HOST and the listen port.
	PublicProxyHost string
	PublicProxyPort string
	// SecureCookie sets HttpOnly session cookie Secure flag (admin behind TLS).
	SecureCookie bool
	LogLevel     string
	ShutdownTimeout time.Duration
}

// Load reads configuration from environment variables, applying defaults.
func Load() (Config, error) {
	c := Config{
		Mode:              getenv("WSP_MODE", "all"),
		ProxyAddr:         getenv("WSP_PROXY_ADDR", ":8080"),
		AdminAddr:         getenv("WSP_ADMIN_ADDR", ":3000"),
		DatabaseURL:       getenv("WSP_DATABASE_URL", "postgres://wsp:wsp@localhost:5432/wsp?sslmode=disable"),
		DataKey:           os.Getenv("WSP_DATA_KEY"),
		ClamdAddr:         getenv("WSP_CLAMD_ADDR", "clamav:3310"),
		MalwareFailClosed: getenvBool("WSP_MALWARE_FAIL_CLOSED", false),
		DockerHost:        getenv("DOCKER_HOST", "unix:///var/run/docker.sock"),
		RBIImage:          getenv("WSP_RBI_IMAGE", "browserless/chrome:latest"),
		RBINetwork:        getenv("WSP_RBI_NETWORK", ""),
		RBICDPHost:        getenv("WSP_RBI_CDP_HOST", ""),
		MaxRBISessions:    getenvInt("WSP_MAX_RBI_SESSIONS", 10),
		PublicProxyHost:   getenv("WSP_PUBLIC_PROXY_HOST", ""),
		PublicProxyPort:   getenv("WSP_PUBLIC_PROXY_PORT", ""),
		SecureCookie:      getenvBool("WSP_SECURE_COOKIE", false),
		LogLevel:          getenv("WSP_LOG_LEVEL", "info"),
		ShutdownTimeout:   time.Duration(getenvInt("WSP_SHUTDOWN_TIMEOUT_SEC", 15)) * time.Second,
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

// getenvBool parses common truthy/falsey env values; empty returns def.
// True: 1, true, yes, on (case-insensitive). False: 0, false, no, off.
func getenvBool(key string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(key))
	if v == "" {
		return def
	}
	switch strings.ToLower(v) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return def
	}
}
