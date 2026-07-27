package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/wsp-security/wsp/internal/config"
	"github.com/wsp-security/wsp/internal/store"
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

	if err := runMigrations(cfg); err != nil {
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

// runMigrations opens the store, applies pending SQL migrations, and closes the pool.
// Later tasks will keep a long-lived Store for listeners.
func runMigrations(cfg config.Config) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	s, err := store.New(ctx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer s.Close()

	if err := s.Migrate(ctx); err != nil {
		return err
	}
	complete, err := s.IsSetupComplete(ctx)
	if err != nil {
		return fmt.Errorf("setup status: %w", err)
	}
	slog.Info("migrations applied", "setup_complete", complete)
	return nil
}
