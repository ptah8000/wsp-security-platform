package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wsp-security/wsp/internal/auth"
	"github.com/wsp-security/wsp/internal/certs"
	"github.com/wsp-security/wsp/internal/config"
	"github.com/wsp-security/wsp/internal/logging"
	"github.com/wsp-security/wsp/internal/proxy"
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if err := run(ctx, cfg); err != nil {
		slog.Error("wsp exited with error", "err", err)
		os.Exit(1)
	}
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

func run(ctx context.Context, cfg config.Config) error {
	dbCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	st, err := store.New(dbCtx, cfg.DatabaseURL)
	if err != nil {
		return fmt.Errorf("store: %w", err)
	}
	defer st.Close()

	if err := st.Migrate(dbCtx); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	complete, err := st.IsSetupComplete(dbCtx)
	if err != nil {
		return fmt.Errorf("setup status: %w", err)
	}
	slog.Info("migrations applied", "setup_complete", complete)

	startProxy := cfg.Mode == "all" || cfg.Mode == "gateway"
	// Management plane is wired in a later task.
	if cfg.Mode == "management" {
		slog.Info("management mode: proxy not started; admin API not yet wired")
		<-ctx.Done()
		return nil
	}

	if !startProxy {
		slog.Info("no listeners for mode", "mode", cfg.Mode)
		<-ctx.Done()
		return nil
	}

	engine, err := proxy.LoadEngineFromStore(dbCtx, st)
	if err != nil {
		slog.Warn("policy load failed; using empty engine (default allow)", "err", err)
		engine = nil
	} else {
		slog.Info("policy engine loaded from store")
	}

	var certProvider *certs.Provider
	if cfg.DataKey != "" {
		cp, err := certs.NewProvider(st, cfg.DataKey)
		if err != nil {
			slog.Warn("certs provider init failed; MITM unavailable", "err", err)
		} else {
			certProvider = cp
			// Warm active CA into memory if present.
			if _, ok, err := certProvider.ActiveCA(dbCtx); err != nil {
				slog.Warn("load active CA", "err", err)
			} else if ok {
				slog.Info("active CA loaded for MITM")
			} else {
				slog.Info("no active CA; MITM requires GenerateSelfSignedCA (wizard)")
			}
		}
	} else {
		slog.Warn("WSP_DATA_KEY not set; MITM cert provider disabled")
	}

	rec := logging.NewRecorder(st)
	authCache := auth.NewProxyAuthCache(st, 8*time.Hour)

	srv := &proxy.Server{
		Addr:      cfg.ProxyAddr,
		Engine:    engine,
		Certs:     certProvider,
		Store:     st,
		Recorder:  rec,
		AuthCache: authCache,
		Sessions:  proxy.NewSessionTracker(st, proxy.DefaultSessionIdle),
	}

	errc := make(chan error, 1)
	go func() {
		errc <- srv.Start(ctx)
	}()

	slog.Info("gateway ready", "proxy_addr", cfg.ProxyAddr, "mode", cfg.Mode)

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		if err := <-errc; err != nil {
			return err
		}
		slog.Info("wsp stopped")
		return nil
	case err := <-errc:
		return err
	}
}
