package mgmt

import (
	"net/http"
	"strings"
	"time"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/audit"
	"github.com/wsp-security/wsp/internal/auth"
	"github.com/wsp-security/wsp/internal/store"
)

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(c echo.Context) error {
	// Hard gate: no login until setup done (except setup endpoints).
	complete, err := s.isSetupComplete(c.Request().Context())
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "setup status unavailable")
	}
	if !complete {
		return echo.NewHTTPError(http.StatusConflict, "setup incomplete; complete first-run wizard")
	}

	if s.store == nil || s.sessions == nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, "auth unavailable")
	}

	var req loginRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "username and password are required")
	}

	user, err := s.store.GetUserByUsername(c.Request().Context(), req.Username)
	if err != nil || !auth.CheckPassword(user.PasswordHash, req.Password) {
		// Uniform error to avoid user enumeration.
		return echo.NewHTTPError(http.StatusUnauthorized, "invalid username or password")
	}
	if !user.Enabled {
		return echo.NewHTTPError(http.StatusForbidden, "user is disabled")
	}
	if user.Role != store.RoleAdmin {
		return echo.NewHTTPError(http.StatusForbidden, "admin role required")
	}

	token, err := s.sessions.Create(c.Request().Context(), user.ID, s.clientIP(c), c.Request().UserAgent())
	if err != nil {
		return err
	}
	_ = s.store.TouchUserLastLogin(c.Request().Context(), user.ID)

	s.setSessionCookie(c, token)

	// Actor for audit is the logging-in user (cookie not yet in context).
	id := user.ID
	if s.audit != nil {
		s.audit.LogBestEffort(c.Request().Context(), audit.Event{
			ActorUserID:   &id,
			ActorUsername: user.Username,
			Action:        "auth.login",
			TargetType:    "user",
			TargetID:      user.ID.String(),
			Summary:       "Admin login",
			IP:            s.clientIP(c),
		})
	}

	user.PasswordHash = ""
	return c.JSON(http.StatusOK, map[string]any{
		"user": publicUser(user),
	})
}

func (s *Server) handleLogout(c echo.Context) error {
	token, _ := c.Get(ctxTokenKey).(string)
	if token != "" && s.sessions != nil {
		_ = s.sessions.Revoke(c.Request().Context(), token)
	}
	s.clearSessionCookie(c)
	s.writeAudit(c, "auth.logout", "user", "", "Admin logout", nil)
	return c.JSON(http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleMe(c echo.Context) error {
	u := s.currentUser(c)
	if u == nil {
		return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
	}
	// Reload for fresh fields.
	if s.store != nil {
		fresh, err := s.store.GetUserByID(c.Request().Context(), u.ID)
		if err == nil {
			fresh.PasswordHash = ""
			return c.JSON(http.StatusOK, publicUser(fresh))
		}
	}
	return c.JSON(http.StatusOK, publicUser(*u))
}

func (s *Server) setSessionCookie(c echo.Context, token string) {
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookie,
		MaxAge:   int((24 * time.Hour).Seconds()),
	}
	c.SetCookie(cookie)
}

func (s *Server) clearSessionCookie(c echo.Context) {
	cookie := &http.Cookie{
		Name:     SessionCookieName,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Secure:   s.secureCookie,
		MaxAge:   -1,
	}
	c.SetCookie(cookie)
}

func publicUser(u store.User) map[string]any {
	m := map[string]any{
		"id":           u.ID,
		"username":     u.Username,
		"display_name": u.DisplayName,
		"role":         u.Role,
		"enabled":      u.Enabled,
		"created_at":   u.CreatedAt,
		"updated_at":   u.UpdatedAt,
	}
	if u.LastLoginAt != nil {
		m["last_login_at"] = u.LastLoginAt
	}
	return m
}
