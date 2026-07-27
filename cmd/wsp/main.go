package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/wsp-security/wsp/internal/config"
	_ "github.com/wsp-security/wsp/web" // embed admin UI assets (placeholder in v1 scaffold)
)

// Version is the binary version reported by --version.
const Version = "0.1.0"

func main() {
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Println(Version)
		os.Exit(0)
	}

	cfg, err := config.Load()
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		os.Exit(1)
	}

	setupLogger(cfg.LogLevel)

	slog.Info("wsp starting",
		"version", Version,
		"mode", cfg.Mode,
		"proxy_addr", cfg.ProxyAddr,
		"admin_addr", cfg.AdminAddr,
	)

	// migrate hook stub — store layer lands in a later task
	if err := runMigrationsStub(cfg); err != nil {
		slog.Error("migrations failed", "err", err)
		os.Exit(1)
	}

	slog.Info("scaffold complete; listeners not started yet",
		"hint", "subsequent tasks wire proxy and management API",
	)
}

func setupLogger(level string) {
	var lv slog.Level
	switch strings.ToLower(level) {
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		lv = slog.LevelInfo
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv})))
}

// runMigrationsStub is a placeholder until internal/store implements migrations.
func runMigrationsStub(cfg config.Config) error {
	slog.Info("migrate hook stub", "database_url_set", cfg.DatabaseURL != "")
	return nil
}
