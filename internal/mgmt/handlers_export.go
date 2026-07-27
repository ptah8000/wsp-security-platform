package mgmt

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/export"
)

func (s *Server) handleExportConfig(c echo.Context) error {
	bundle, err := export.Build(c.Request().Context(), s.store, s.version)
	if err != nil {
		return err
	}
	s.writeAudit(c, "export.config", "export", "", "Exported configuration bundle", nil)
	c.Response().Header().Set(echo.HeaderContentDisposition, `attachment; filename="wsp-config-export.json"`)
	return c.JSON(http.StatusOK, bundle)
}
