package mgmt

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/store"
)

// loadSession reads the wsp_session cookie and attaches the user when valid.
// It never fails the request for missing/invalid sessions.
func (s *Server) loadSession(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		cookie, err := c.Cookie(SessionCookieName)
		if err == nil && cookie != nil && cookie.Value != "" && s.sessions != nil {
			user, err := s.sessions.UserFromToken(c.Request().Context(), cookie.Value)
			if err == nil && user != nil {
				c.Set(ctxUserKey, user)
				c.Set(ctxTokenKey, cookie.Value)
			}
		}
		return next(c)
	}
}

// requireAuth rejects unauthenticated requests.
func (s *Server) requireAuth(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		u := s.currentUser(c)
		if u == nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "authentication required")
		}
		if u.Role != store.RoleAdmin {
			// v1 management plane is admin-only.
			return echo.NewHTTPError(http.StatusForbidden, "admin role required")
		}
		return next(c)
	}
}

// requireSetupIncomplete blocks setup mutation endpoints once wizard finished.
func (s *Server) requireSetupIncomplete(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Allow GET /setup/status via dedicated route; mutations stay gated here.
		complete, err := s.isSetupComplete(c.Request().Context())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "setup status unavailable")
		}
		if complete {
			return echo.NewHTTPError(http.StatusConflict, "setup already completed")
		}
		return next(c)
	}
}

// requireSetupComplete blocks normal admin API until wizard is done.
func (s *Server) requireSetupComplete(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		complete, err := s.isSetupComplete(c.Request().Context())
		if err != nil {
			return echo.NewHTTPError(http.StatusInternalServerError, "setup status unavailable")
		}
		if !complete {
			return echo.NewHTTPError(http.StatusConflict, "setup incomplete; complete first-run wizard")
		}
		return next(c)
	}
}
