package mgmt

import (
	"net/http"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/store"
)

func (s *Server) handleSearchRequestLogs(c echo.Context) error {
	f := store.RequestLogFilter{
		ClientIP: c.QueryParam("client_ip"),
		Username: c.QueryParam("username"),
		Host:     c.QueryParam("host"),
		Decision: c.QueryParam("decision"),
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
	if v := c.QueryParam("session_id"); v != "" {
		id, err := uuid.Parse(v)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid session_id")
		}
		f.SessionID = &id
	}
	if v := c.QueryParam("since"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "since must be RFC3339")
		}
		f.Since = &t
	}
	if v := c.QueryParam("until"); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "until must be RFC3339")
		}
		f.Until = &t
	}

	logs, err := s.store.SearchRequestLogs(c.Request().Context(), f)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"logs": logs})
}

func (s *Server) handleGetSessionDetail(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	sess, err := s.store.GetBrowsingSession(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "session not found")
		}
		return err
	}
	logs, err := s.store.ListRequestLogsBySession(c.Request().Context(), id, 500)
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{
		"session": sess,
		"logs":    logs,
	})
}
