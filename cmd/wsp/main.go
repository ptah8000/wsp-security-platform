package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/wsp-security/wsp/internal/audit"
	"github.com/wsp-security/wsp/internal/auth"
	"github.com/wsp-security/wsp/internal/casb"
	"github.com/wsp-security/wsp/internal/certs"
	"github.com/wsp-security/wsp/internal/config"
	"github.com/wsp-security/wsp/internal/health"
	"github.com/wsp-security/wsp/internal/logging"
	"github.com/wsp-security/wsp/internal/malware"
	"github.com/wsp-security/wsp/internal/mgmt"
	"github.com/wsp-security/wsp/internal/policy"
	"github.com/wsp-security/wsp/internal/proxy"
	"github.com/wsp-security/wsp/internal/rbi"
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
	startedAt := time.Now().UTC()

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
	startMgmt := cfg.Mode == "all" || cfg.Mode == "management"

	// Shared policy engine so management policy writes can hot-swap the gateway.
	var engine *policy.Engine
	if startProxy || startMgmt {
		eng, err := proxy.LoadEngineFromStore(dbCtx, st)
		if err != nil {
			slog.Warn("policy load failed; using empty engine (default allow)", "err", err)
			engine = &policy.Engine{}
		} else {
			engine = eng
			slog.Info("policy engine loaded from store")
		}
	}

	var certProvider *certs.Provider
	if cfg.DataKey != "" {
		cp, err := certs.NewProvider(st, cfg.DataKey)
		if err != nil {
			slog.Warn("certs provider init failed; MITM/CA unavailable", "err", err)
		} else {
			certProvider = cp
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

	clam := malware.NewClamd(cfg.ClamdAddr)
	// Best-effort ping at startup (clamd may still be loading signatures).
	pingCtx, pingCancel := context.WithTimeout(ctx, 5*time.Second)
	if err := clam.Ping(pingCtx); err != nil {
		slog.Warn("clamd not ready at startup; scans will retry per request",
			"addr", cfg.ClamdAddr, "err", err, "malware_fail_closed", cfg.MalwareFailClosed)
	} else {
		slog.Info("clamd ping ok", "addr", cfg.ClamdAddr)
	}
	pingCancel()

	rbiOrch := initRBI(cfg)

	// Hourly retention: drop request_logs / audit_logs older than settings, batches of 5000.
	retention := logging.NewRetentionJob(st)
	go retention.Start(ctx)
	slog.Info("retention job started",
		"interval", logging.DefaultRetentionInterval.String(),
		"batch_size", logging.DefaultRetentionBatchSize,
	)

	// DNS servers from settings (wizard / admin UI) drive the proxy dialer.
	dnsServers := loadDNSServers(dbCtx, st)

	errc := make(chan error, 2)
	var proxySrv *proxy.Server

	if startProxy {
		rec := logging.NewRecorder(st)
		authCache := auth.NewProxyAuthCache(st, 8*time.Hour)
		casbAdapter := casb.NewProxyAdapter()
		slog.Info("CASB catalog loaded", "detectors", len(casbAdapter.Inner.Detectors()))

		dialer := proxy.NewDNSDialer(dnsServers)
		proxySrv = &proxy.Server{
			Addr:              cfg.ProxyAddr,
			Engine:            engine,
			Certs:             certProvider,
			Store:             st,
			Recorder:          rec,
			AuthCache:         authCache,
			Sessions:          proxy.NewSessionTracker(st, proxy.DefaultSessionIdle),
			CASB:              casbAdapter,
			Malware:           clam,
			MalwareFailClosed: cfg.MalwareFailClosed,
			RBI:               rbiOrch,
			Dialer:            dialer,
		}
		go func() {
			errc <- proxySrv.Start(ctx)
		}()
		slog.Info("gateway ready", "proxy_addr", cfg.ProxyAddr, "mode", cfg.Mode,
			"rbi_image", cfg.RBIImage, "max_rbi_sessions", cfg.MaxRBISessions,
			"rbi_network", cfg.RBINetwork, "dns_servers", dialer.Servers())
	}

	if startMgmt {
		sessions := auth.NewSessionManager(st, auth.DefaultAdminSessionTTL)
		hc := &health.Checker{
			Version:   Version,
			StartedAt: startedAt,
			PingDB:    st.Ping,
			PingClam:  clam.Ping,
			PingDocker: func(ctx context.Context) error {
				if rbiOrch == nil || rbiOrch.Runtime == nil {
					return fmt.Errorf("rbi runtime not configured")
				}
				return rbiOrch.Runtime.Ping(ctx)
			},
			RBIActiveCount: rbiOrch.ActiveCount,
			GatewayListening: func() bool {
				return startProxy
			},
		}
		mgmtSrv := mgmt.New(mgmt.Deps{
			Store:           st,
			Sessions:        sessions,
			Certs:           certProvider,
			Engine:          engine,
			Audit:           audit.New(st),
			Health:          hc,
			AdminAddr:       cfg.AdminAddr,
			ProxyAddr:       cfg.ProxyAddr,
			PublicProxyHost: cfg.PublicProxyHost,
			PublicProxyPort: cfg.PublicProxyPort,
			SecureCookie:    cfg.SecureCookie,
			Version:         Version,
			RBI:             rbiOrch,
			OnDNSServersChanged: func(servers []string) {
				if proxySrv != nil {
					proxySrv.SetDNSServers(servers)
				}
			},
		})
		go func() {
			errc <- mgmtSrv.Start(ctx, cfg.AdminAddr)
		}()
		slog.Info("management API ready", "admin_addr", cfg.AdminAddr, "mode", cfg.Mode,
			"secure_cookie", cfg.SecureCookie)
	}

	if !startProxy && !startMgmt {
		slog.Info("no listeners for mode", "mode", cfg.Mode)
		<-ctx.Done()
		return nil
	}

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.ShutdownTimeout)
		defer cancel()
		if rbiOrch != nil {
			rbiOrch.StopAll(shutdownCtx)
		}
		if proxySrv != nil {
			_ = proxySrv.Shutdown(shutdownCtx)
		}
		// Drain started listeners.
		n := 0
		if startProxy {
			n++
		}
		if startMgmt {
			n++
		}
		var first error
		for i := 0; i < n; i++ {
			if err := <-errc; err != nil && first == nil {
				first = err
			}
		}
		slog.Info("wsp stopped")
		return first
	case err := <-errc:
		return err
	}
}

// initRBI builds the RBI orchestrator. When Docker is unreachable at startup,
// the orchestrator is still installed so policy isolation fails closed per request
// (HandleIsolation returns false → block page) rather than silently disabling RBI.
func initRBI(cfg config.Config) *rbi.Orchestrator {
	rt, err := rbi.NewDockerRuntime(cfg.DockerHost)
	if err != nil {
		slog.Warn("RBI docker client init failed; isolation will fail-closed until fixed",
			"err", err, "docker_host", cfg.DockerHost)
		return rbi.NewOrchestrator(rbi.Config{
			Runtime:       nil, // Start → ErrDockerUnavailable
			Image:         cfg.RBIImage,
			MaxSessions:   cfg.MaxRBISessions,
			Network:       cfg.RBINetwork,
			ViewerBaseURL: cfg.PublicAdminURL,
		})
	}
	if cfg.RBICDPHost != "" {
		rt.CDPHost = cfg.RBICDPHost
	}
	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rt.Ping(pingCtx); err != nil {
		slog.Warn("RBI docker ping failed; isolation will fail-closed until daemon is available",
			"err", err, "docker_host", cfg.DockerHost)
	} else {
		slog.Info("RBI docker ready",
			"image", cfg.RBIImage,
			"max_sessions", cfg.MaxRBISessions,
			"network", cfg.RBINetwork,
			"cdp_host", cfg.RBICDPHost,
		)
	}
	// Seamless product default: in-place MITM viewer (no URL-bar redirect).
	// PreferRedirect is left false; ViewerBaseURL unused unless we enable debug handoff later.
	return rbi.NewOrchestrator(rbi.Config{
		Runtime:        rt,
		Image:          cfg.RBIImage,
		MaxSessions:    cfg.MaxRBISessions,
		Network:        cfg.RBINetwork,
		ViewerBaseURL:  cfg.PublicAdminURL,
		PreferRedirect: false,
	})
}

// loadDNSServers reads dns_servers setting JSON array; empty on error/missing.
func loadDNSServers(ctx context.Context, st *store.Store) []string {
	if st == nil {
		return nil
	}
	raw, err := st.GetSetting(ctx, store.SettingDNSServers)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var servers []string
	if err := json.Unmarshal(raw, &servers); err != nil {
		slog.Warn("parse dns_servers setting", "err", err)
		return nil
	}
	return servers
}
