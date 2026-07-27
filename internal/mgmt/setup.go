package mgmt

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/auth"
	"github.com/wsp-security/wsp/internal/store"
)

// handleSetupStatus is always reachable (registered outside incomplete gate).
func (s *Server) handleSetupStatus(c echo.Context) error {
	complete, err := s.isSetupComplete(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "setup status unavailable")
	}

	var adminCount int
	var hasCA bool
	if s.store != nil {
		adminCount, _ = s.store.CountUsersByRole(c.Request().Context(), store.RoleAdmin)
		certs, err := s.store.ListCertificates(c.Request().Context())
		if err == nil {
			for _, cert := range certs {
				if cert.IsActive {
					hasCA = true
					break
				}
			}
		}
	}

	return c.JSON(http.StatusOK, map[string]any{
		"setup_completed": complete,
		"has_admin":       adminCount > 0,
		"has_ca":          hasCA,
		"steps": []string{
			"admin",
			"ca",
			"network",
			"complete",
		},
	})
}

type setupAdminRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
}

func (s *Server) handleSetupAdmin(c echo.Context) error {
	var req setupAdminRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "username and password are required")
	}
	if len(req.Password) < 8 {
		return echo.NewHTTPError(http.StatusBadRequest, "password must be at least 8 characters")
	}
	if s.store == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "store unavailable")
	}

	n, err := s.store.CountUsersByRole(c.Request().Context(), store.RoleAdmin)
	if err != nil {
		return err
	}
	if n > 0 {
		return echo.NewHTTPError(http.StatusConflict, "admin already exists")
	}

	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	user, err := s.store.CreateUser(c.Request().Context(), store.User{
		Username:     req.Username,
		PasswordHash: hash,
		DisplayName:  req.DisplayName,
		Role:         store.RoleAdmin,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return echo.NewHTTPError(http.StatusConflict, "username already taken")
		}
		return err
	}

	s.writeAudit(c, "setup.admin_create", "user", user.ID.String(), "Created first admin during setup", map[string]string{
		"username": user.Username,
	})

	return c.JSON(http.StatusCreated, map[string]any{
		"id":           user.ID,
		"username":     user.Username,
		"display_name": user.DisplayName,
		"role":         user.Role,
	})
}

type setupCARequest struct {
	Name string `json:"name"`
}

func (s *Server) handleSetupCA(c echo.Context) error {
	if s.certs == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "certificate provider unavailable (WSP_DATA_KEY?)")
	}
	var req setupCARequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "WSP Root CA"
	}

	meta, err := s.certs.GenerateSelfSignedCA(c.Request().Context(), name)
	if err != nil {
		return err
	}

	s.writeAudit(c, "setup.ca_generate", "certificate", meta.ID.String(), "Generated self-signed CA during setup", map[string]string{
		"name":        meta.Name,
		"fingerprint": meta.FingerprintSHA256,
	})

	return c.JSON(http.StatusCreated, meta)
}

type setupNetworkRequest struct {
	DNSServers []string `json:"dns_servers"`
}

func (s *Server) handleSetupNetwork(c echo.Context) error {
	var req setupNetworkRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	if len(req.DNSServers) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "dns_servers is required")
	}
	for _, d := range req.DNSServers {
		if strings.TrimSpace(d) == "" {
			return echo.NewHTTPError(http.StatusBadRequest, "dns_servers entries must be non-empty")
		}
	}
	if s.store == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "store unavailable")
	}

	raw, err := json.Marshal(req.DNSServers)
	if err != nil {
		return err
	}
	if err := s.store.SetSetting(c.Request().Context(), store.SettingDNSServers, raw); err != nil {
		return err
	}

	// Persist listen hints from process config for UI display.
	if s.proxyAddr != "" {
		raw, _ := json.Marshal(s.proxyAddr)
		_ = s.store.SetSetting(c.Request().Context(), store.SettingProxyListen, raw)
	}
	if s.adminAddr != "" {
		raw, _ := json.Marshal(s.adminAddr)
		_ = s.store.SetSetting(c.Request().Context(), store.SettingAdminListen, raw)
	}

	s.writeAudit(c, "setup.network", "settings", store.SettingDNSServers, "Saved DNS settings during setup", map[string]any{
		"dns_servers": req.DNSServers,
	})

	return c.JSON(http.StatusOK, map[string]any{
		"dns_servers":  req.DNSServers,
		"proxy_listen": s.proxyAddr,
		"admin_listen": s.adminAddr,
	})
}

func (s *Server) handleSetupComplete(c echo.Context) error {
	if s.store == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "store unavailable")
	}
	ctx := c.Request().Context()

	n, err := s.store.CountUsersByRole(ctx, store.RoleAdmin)
	if err != nil {
		return err
	}
	if n == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "create an admin account before completing setup")
	}

	certs, err := s.store.ListCertificates(ctx)
	if err != nil {
		return err
	}
	hasCA := false
	for _, cert := range certs {
		if cert.IsActive {
			hasCA = true
			break
		}
	}
	if !hasCA {
		return echo.NewHTTPError(http.StatusBadRequest, "generate a CA before completing setup")
	}

	if err := s.store.MarkSetupComplete(ctx); err != nil {
		return err
	}

	s.writeAudit(c, "setup.complete", "settings", store.SettingSetupCompleted, "First-run setup completed", nil)

	return c.JSON(http.StatusOK, map[string]any{
		"setup_completed": true,
		"message":         "Setup complete. Configure clients via /client-setup after login.",
	})
}
