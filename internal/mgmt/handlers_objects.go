package mgmt

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/store"
)

func (s *Server) handleListObjects(c echo.Context) error {
	list, err := s.store.ListReusableObjects(c.Request().Context())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"objects": list})
}

func (s *Server) handleGetObject(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	o, err := s.store.GetReusableObject(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "object not found")
		}
		return err
	}
	return c.JSON(http.StatusOK, o)
}

type objectBody struct {
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Definition json.RawMessage `json:"definition"`
}

func (s *Server) handleCreateObject(c echo.Context) error {
	var req objectBody
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	if strings.TrimSpace(req.Name) == "" || strings.TrimSpace(req.Type) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name and type are required")
	}
	def := req.Definition
	if len(def) == 0 {
		def = json.RawMessage(`{}`)
	}
	if !json.Valid(def) {
		return echo.NewHTTPError(http.StatusBadRequest, "definition must be valid JSON")
	}
	o, err := s.store.CreateReusableObject(c.Request().Context(), store.ReusableObject{
		Name: req.Name, Type: req.Type, Definition: def,
	})
	if err != nil {
		return err
	}
	if err := s.reloadPolicyEngine(c); err != nil {
		return err
	}
	s.writeAudit(c, "object.create", "object", o.ID.String(), "Created object "+o.Name, nil)
	return c.JSON(http.StatusCreated, o)
}

func (s *Server) handleUpdateObject(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	existing, err := s.store.GetReusableObject(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "object not found")
		}
		return err
	}
	if existing.IsSystem {
		return echo.NewHTTPError(http.StatusForbidden, "system objects cannot be modified")
	}
	var req objectBody
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	name := existing.Name
	if strings.TrimSpace(req.Name) != "" {
		name = req.Name
	}
	typ := existing.Type
	if strings.TrimSpace(req.Type) != "" {
		typ = req.Type
	}
	def := existing.Definition
	if len(req.Definition) > 0 {
		if !json.Valid(req.Definition) {
			return echo.NewHTTPError(http.StatusBadRequest, "definition must be valid JSON")
		}
		def = req.Definition
	}
	o, err := s.store.UpdateReusableObject(c.Request().Context(), id, store.ReusableObject{
		Name: name, Type: typ, Definition: def,
	})
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "object not found")
		}
		return err
	}
	if err := s.reloadPolicyEngine(c); err != nil {
		return err
	}
	s.writeAudit(c, "object.update", "object", id.String(), "Updated object "+o.Name, nil)
	return c.JSON(http.StatusOK, o)
}

func (s *Server) handleDeleteObject(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	existing, err := s.store.GetReusableObject(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "object not found")
		}
		return err
	}
	if existing.IsSystem {
		return echo.NewHTTPError(http.StatusForbidden, "system objects cannot be deleted")
	}
	if err := s.store.DeleteReusableObject(c.Request().Context(), id); err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "object not found")
		}
		return err
	}
	if err := s.reloadPolicyEngine(c); err != nil {
		return err
	}
	s.writeAudit(c, "object.delete", "object", id.String(), "Deleted object", nil)
	return c.NoContent(http.StatusNoContent)
}
