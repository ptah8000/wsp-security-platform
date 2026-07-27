package mgmt

import (
	"net/http"
	"strconv"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/store"
)

func (s *Server) handleListAudit(c echo.Context) error {
	f := store.AuditListFilter{
		Action: c.QueryParam("action"),
	}
	if v := c.QueryParam("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Limit = n
		}
	}
	if v := c.QueryParam("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			f.Offset = n
		}
	}
	list, err := s.store.ListAuditLogs(c.Request().Context(), f)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"audit": list})
}
