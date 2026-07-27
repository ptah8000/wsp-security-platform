package mgmt

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/store"
)

func (s *Server) handleListBlockPages(c echo.Context) error {
	list, err := s.store.ListBlockPages(c.Request().Context())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"block_pages": list})
}

func (s *Server) handleGetBlockPage(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	p, err := s.store.GetBlockPage(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "block page not found")
		}
		return err
	}
	return c.JSON(http.StatusOK, p)
}

type blockPageBody struct {
	Name string `json:"name"`
	HTML string `json:"html"`
}

func (s *Server) handleCreateBlockPage(c echo.Context) error {
	var req blockPageBody
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.HTML) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name and html are required")
	}
	p, err := s.store.CreateBlockPage(c.Request().Context(), store.BlockPage{
		Name: req.Name, HTML: req.HTML,
	})
	if err != nil {
		return err
	}
	s.writeAudit(c, "block_page.create", "block_page", p.ID.String(), "Created block page "+p.Name, nil)
	return c.JSON(http.StatusCreated, p)
}

func (s *Server) handleUpdateBlockPage(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	existing, err := s.store.GetBlockPage(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "block page not found")
		}
		return err
	}
	if existing.IsSystem {
		return echo.NewHTTPError(http.StatusForbidden, "system block pages cannot be modified")
	}
	var req blockPageBody
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	name := existing.Name
	if strings.TrimSpace(req.Name) != "" {
		name = req.Name
	}
	html := existing.HTML
	if strings.TrimSpace(req.HTML) != "" {
		html = req.HTML
	}
	p, err := s.store.UpdateBlockPage(c.Request().Context(), id, name, html)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "block page not found")
		}
		return err
	}
	s.writeAudit(c, "block_page.update", "block_page", id.String(), "Updated block page "+p.Name, nil)
	return c.JSON(http.StatusOK, p)
}

func (s *Server) handleDeleteBlockPage(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	existing, err := s.store.GetBlockPage(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "block page not found")
		}
		return err
	}
	if existing.IsSystem {
		return echo.NewHTTPError(http.StatusForbidden, "system block pages cannot be deleted")
	}
	if err := s.store.DeleteBlockPage(c.Request().Context(), id); err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "block page not found")
		}
		return err
	}
	s.writeAudit(c, "block_page.delete", "block_page", id.String(), "Deleted block page", nil)
	return c.NoContent(http.StatusNoContent)
}
