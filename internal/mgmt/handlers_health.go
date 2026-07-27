package mgmt

import (
	"net/http"

	"github.com/labstack/echo/v4"
)

// handleHealthz is unauthenticated process liveness.
func (s *Server) handleHealthz(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{"status": "ok"})
}

// handleHealth is authenticated detailed system health.
func (s *Server) handleHealth(c echo.Context) error {
	if s.health == nil {
		return c.JSON(http.StatusOK, map[string]any{
			"status":  "healthy",
			"version": s.version,
			"message": "health checker not configured",
		})
	}
	rep := s.health.Check(c.Request().Context())
	code := http.StatusOK
	if rep.Status == "critical" {
		code = http.StatusServiceUnavailable
	}
	return c.JSON(code, rep)
}
