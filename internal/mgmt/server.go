// Package mgmt implements the Echo management REST API and embedded admin SPA.
package mgmt

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	"github.com/wsp-security/wsp/internal/audit"
	"github.com/wsp-security/wsp/internal/auth"
	"github.com/wsp-security/wsp/internal/certs"
	"github.com/wsp-security/wsp/internal/health"
	"github.com/wsp-security/wsp/internal/policy"
	"github.com/wsp-security/wsp/internal/store"
	"github.com/wsp-security/wsp/web"
)

// SessionCookieName is the HttpOnly admin session cookie.
const SessionCookieName = "wsp_session"

// context keys
const (
	ctxUserKey  = "wsp_user"
	ctxTokenKey = "wsp_token"
)

// Deps configures the management server.
type Deps struct {
	Store    *store.Store
	Sessions *auth.SessionManager
	Certs    *certs.Provider
	// Engine is shared with the proxy for hot policy reload (may be nil in management-only).
	Engine *policy.Engine
	Audit  *audit.Logger
	Health *health.Checker

	// AdminAddr is used for SPA/client-setup hints (e.g. ":3000").
	AdminAddr string
	// ProxyAddr is shown in client-setup (e.g. ":8080").
	ProxyAddr string
	// SecureCookie sets the Secure flag on session cookies (TLS terminations).
	SecureCookie bool
	// Version reported by health/export.
	Version string
}

// Server is the management HTTP API.
type Server struct {
	e        *echo.Echo
	store    *store.Store
	sessions *auth.SessionManager
	certs    *certs.Provider
	engine   *policy.Engine
	audit    *audit.Logger
	health   *health.Checker

	adminAddr    string
	proxyAddr    string
	secureCookie bool
	version      string

	// setupComplete overrides Store.IsSetupComplete when non-nil (tests).
	setupComplete func(ctx context.Context) (bool, error)
}

// New constructs the Echo app with all routes registered.
func New(d Deps) *Server {
	s := &Server{
		store:        d.Store,
		sessions:     d.Sessions,
		certs:        d.Certs,
		engine:       d.Engine,
		audit:        d.Audit,
		health:       d.Health,
		adminAddr:    d.AdminAddr,
		proxyAddr:    d.ProxyAddr,
		secureCookie: d.SecureCookie,
		version:      d.Version,
	}
	if s.version == "" {
		s.version = "0.1.0"
	}
	if s.audit == nil && d.Store != nil {
		s.audit = audit.New(d.Store)
	}

	e := echo.New()
	e.HideBanner = true
	e.HidePort = true
	e.HTTPErrorHandler = s.httpErrorHandler

	e.Use(middleware.Recover())
	e.Use(middleware.RequestID())
	e.Use(middleware.SecureWithConfig(middleware.SecureConfig{
		XSSProtection:         "1; mode=block",
		ContentTypeNosniff:    "nosniff",
		XFrameOptions:         "SAMEORIGIN",
		HSTSMaxAge:            0, // admin may be plain HTTP in lab
		ContentSecurityPolicy: "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; connect-src 'self'",
	}))
	e.Use(s.loadSession)

	// Unauthenticated liveness (process up).
	e.GET("/healthz", s.handleHealthz)

	api := e.Group("/api/v1")
	s.registerAPI(api)

	// Embedded SPA (placeholder until Task 11).
	s.mountSPA(e)

	s.e = e
	return s
}

// Echo exposes the underlying Echo instance (tests / custom mounts).
func (s *Server) Echo() *echo.Echo { return s.e }

// Handler returns the http.Handler for ListenAndServe.
func (s *Server) Handler() http.Handler { return s.e }

// Start listens on addr until ctx is cancelled.
func (s *Server) Start(ctx context.Context, addr string) error {
	if addr == "" {
		return errors.New("admin addr is empty")
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.e,
		ReadHeaderTimeout: 10 * time.Second,
	}
	errc := make(chan error, 1)
	go func() {
		slog.Info("management API listening", "addr", addr)
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errc <- err
			return
		}
		errc <- nil
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
		return <-errc
	case err := <-errc:
		return err
	}
}

func (s *Server) registerAPI(api *echo.Group) {
	// Setup status is always readable (SPA redirect). Mutations only when incomplete.
	api.GET("/setup/status", s.handleSetupStatus)
	setup := api.Group("/setup", s.requireSetupIncomplete)
	setup.POST("/admin", s.handleSetupAdmin)
	setup.POST("/ca", s.handleSetupCA)
	setup.POST("/network", s.handleSetupNetwork)
	setup.POST("/complete", s.handleSetupComplete)

	// Auth
	api.POST("/auth/login", s.handleLogin)
	api.POST("/auth/logout", s.handleLogout, s.requireAuth)
	api.GET("/auth/me", s.handleMe, s.requireAuth)

	// Authenticated admin routes
	authz := api.Group("", s.requireAuth, s.requireSetupComplete)

	authz.GET("/health", s.handleHealth)

	// Users
	authz.GET("/users", s.handleListUsers)
	authz.POST("/users", s.handleCreateUser)
	authz.GET("/users/:id", s.handleGetUser)
	authz.PUT("/users/:id", s.handleUpdateUser)
	authz.DELETE("/users/:id", s.handleDeleteUser)

	// Certificates (public metadata + PEM download only)
	authz.GET("/certificates", s.handleListCerts)
	authz.POST("/certificates/generate", s.handleGenerateCA)
	authz.GET("/certificates/:id", s.handleGetCertMeta)
	authz.GET("/certificates/:id/pem", s.handleDownloadCertPEM)

	// Settings
	authz.GET("/settings", s.handleListSettings)
	authz.GET("/settings/:key", s.handleGetSetting)
	authz.PUT("/settings/:key", s.handlePutSetting)

	// Block pages
	authz.GET("/block-pages", s.handleListBlockPages)
	authz.POST("/block-pages", s.handleCreateBlockPage)
	authz.GET("/block-pages/:id", s.handleGetBlockPage)
	authz.PUT("/block-pages/:id", s.handleUpdateBlockPage)
	authz.DELETE("/block-pages/:id", s.handleDeleteBlockPage)

	// Objects
	authz.GET("/objects", s.handleListObjects)
	authz.POST("/objects", s.handleCreateObject)
	authz.GET("/objects/:id", s.handleGetObject)
	authz.PUT("/objects/:id", s.handleUpdateObject)
	authz.DELETE("/objects/:id", s.handleDeleteObject)

	// Policies
	authz.GET("/policies", s.handleListPolicies)
	authz.POST("/policies", s.handleCreatePolicy)
	authz.POST("/policies/reorder", s.handleReorderPolicies)
	authz.POST("/policies/simulate", s.handleSimulate)
	authz.GET("/policies/:id", s.handleGetPolicy)
	authz.PUT("/policies/:id", s.handleUpdatePolicy)
	authz.DELETE("/policies/:id", s.handleDeletePolicy)

	// Logs + audit
	authz.GET("/logs/requests", s.handleSearchRequestLogs)
	authz.GET("/logs/sessions/:id", s.handleGetSessionDetail)
	authz.GET("/audit", s.handleListAudit)

	// Export + client setup
	authz.GET("/export/config", s.handleExportConfig)
	authz.GET("/client-setup", s.handleClientSetup)
}

func (s *Server) mountSPA(e *echo.Echo) {
	sub, err := fs.Sub(web.Dist, "dist")
	if err != nil {
		slog.Warn("web dist embed unavailable", "err", err)
		e.GET("/*", func(c echo.Context) error {
			return c.HTML(http.StatusOK, "<!doctype html><title>WSP</title><p>Admin UI not embedded</p>")
		})
		return
	}
	fileServer := http.FileServer(http.FS(sub))
	e.GET("/*", func(c echo.Context) error {
		path := c.Request().URL.Path
		// Never shadow API or healthz.
		if strings.HasPrefix(path, "/api/") || path == "/healthz" {
			return echo.ErrNotFound
		}
		// SPA fallback: serve index.html for unknown paths without extension.
		if path != "/" && !strings.Contains(strings.TrimPrefix(path, "/"), ".") {
			c.Request().URL.Path = "/"
		}
		fileServer.ServeHTTP(c.Response(), c.Request())
		return nil
	})
}

func (s *Server) httpErrorHandler(err error, c echo.Context) {
	if c.Response().Committed {
		return
	}
	code := http.StatusInternalServerError
	msg := "internal server error"
	var he *echo.HTTPError
	if errors.As(err, &he) {
		code = he.Code
		if m, ok := he.Message.(string); ok {
			msg = m
		} else {
			msg = fmt.Sprint(he.Message)
		}
	} else {
		slog.Error("mgmt handler error", "err", err, "path", c.Path())
	}
	_ = c.JSON(code, map[string]any{"error": msg})
}

func (s *Server) isSetupComplete(ctx context.Context) (bool, error) {
	if s.setupComplete != nil {
		return s.setupComplete(ctx)
	}
	if s.store == nil {
		return false, errors.New("store is nil")
	}
	return s.store.IsSetupComplete(ctx)
}

func (s *Server) currentUser(c echo.Context) *store.User {
	u, _ := c.Get(ctxUserKey).(*store.User)
	return u
}

func (s *Server) clientIP(c echo.Context) string {
	ip := c.RealIP()
	if ip == "" {
		ip = c.Request().RemoteAddr
	}
	return ip
}

func (s *Server) auditActor(c echo.Context) (userID *uuid.UUID, username, ip string) {
	ip = s.clientIP(c)
	u := s.currentUser(c)
	if u == nil {
		return nil, "", ip
	}
	id := u.ID
	return &id, u.Username, ip
}

func (s *Server) writeAudit(c echo.Context, action, targetType, targetID, summary string, detail any) {
	if s.audit == nil {
		return
	}
	uid, uname, ip := s.auditActor(c)
	s.audit.LogBestEffort(c.Request().Context(), audit.Event{
		ActorUserID:   uid,
		ActorUsername: uname,
		Action:        action,
		TargetType:    targetType,
		TargetID:      targetID,
		Summary:       summary,
		Detail:        detail,
		IP:            ip,
	})
}

func parseUUIDParam(c echo.Context, name string) (uuid.UUID, error) {
	raw := c.Param(name)
	id, err := uuid.Parse(raw)
	if err != nil {
		return uuid.Nil, echo.NewHTTPError(http.StatusBadRequest, "invalid "+name)
	}
	return id, nil
}

func storeNotFound(err error) bool {
	if err == nil {
		return false
	}
	// store wraps pgx.ErrNoRows; match by errors.Is when possible and by message.
	if errors.Is(err, errNoRows) {
		return true
	}
	return strings.Contains(err.Error(), "no rows")
}

// errNoRows mirrors pgx.ErrNoRows text for package-local matching without a hard pgx import in every handler.
var errNoRows = errors.New("no rows in result set")
