package mgmt

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/store"
)

// Mutable settings keys (setup_completed is wizard-only).
var allowedSettingKeys = map[string]bool{
	store.SettingLogRetentionDays:   true,
	store.SettingAuditRetentionDays: true,
	store.SettingDNSServers:         true,
	store.SettingProxyListen:        true,
	store.SettingAdminListen:        true,
}

func (s *Server) handleListSettings(c echo.Context) error {
	list, err := s.store.ListSettings(c.Request().Context())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"settings": list})
}

func (s *Server) handleGetSetting(c echo.Context) error {
	key := c.Param("key")
	st, err := s.store.GetSettingRow(c.Request().Context(), key)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "setting not found")
		}
		return err
	}
	return c.JSON(http.StatusOK, st)
}

type putSettingBody struct {
	Value json.RawMessage `json:"value"`
}

func (s *Server) handlePutSetting(c echo.Context) error {
	key := strings.TrimSpace(c.Param("key"))
	if key == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "key is required")
	}
	if key == store.SettingSetupCompleted {
		return echo.NewHTTPError(http.StatusForbidden, "setup_completed cannot be changed via settings API")
	}
	if !allowedSettingKeys[key] {
		return echo.NewHTTPError(http.StatusBadRequest, "unknown or immutable setting key")
	}

	var req putSettingBody
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	if len(req.Value) == 0 || !json.Valid(req.Value) {
		return echo.NewHTTPError(http.StatusBadRequest, "value must be valid JSON")
	}

	// Light validation for retention days.
	if key == store.SettingLogRetentionDays || key == store.SettingAuditRetentionDays {
		var days int
		if err := json.Unmarshal(req.Value, &days); err != nil || days < 1 || days > 3650 {
			return echo.NewHTTPError(http.StatusBadRequest, "retention days must be an integer 1..3650")
		}
	}
	if key == store.SettingDNSServers {
		var servers []string
		if err := json.Unmarshal(req.Value, &servers); err != nil || len(servers) == 0 {
			return echo.NewHTTPError(http.StatusBadRequest, "dns_servers must be a non-empty JSON array of strings")
		}
	}

	if err := s.store.SetSetting(c.Request().Context(), key, req.Value); err != nil {
		return err
	}
	s.writeAudit(c, "settings.update", "settings", key, "Updated setting "+key, nil)
	st, err := s.store.GetSettingRow(c.Request().Context(), key)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, st)
}
