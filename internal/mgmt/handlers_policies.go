package mgmt

import (
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/policy"
	"github.com/wsp-security/wsp/internal/proxy"
	"github.com/wsp-security/wsp/internal/store"
)

func (s *Server) handleListPolicies(c echo.Context) error {
	list, err := s.store.ListPolicies(c.Request().Context())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"policies": list})
}

func (s *Server) handleGetPolicy(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	p, err := s.store.GetPolicy(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "policy not found")
		}
		return err
	}
	return c.JSON(http.StatusOK, p)
}

type policyBody struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     *bool           `json:"enabled"`
	Priority    *int            `json:"priority"`
	Sections    json.RawMessage `json:"sections"`
}

func (s *Server) handleCreatePolicy(c echo.Context) error {
	var req policyBody
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	if strings.TrimSpace(req.Name) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "name is required")
	}
	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	priority := 500
	if req.Priority != nil {
		priority = *req.Priority
	}
	sections := req.Sections
	if len(sections) == 0 {
		sections = json.RawMessage(`{}`)
	}
	if !json.Valid(sections) {
		return echo.NewHTTPError(http.StatusBadRequest, "sections must be valid JSON")
	}
	// Validate sections decode into policy types.
	var sec policy.RuleSections
	if err := json.Unmarshal(sections, &sec); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid sections: "+err.Error())
	}

	row, err := s.store.CreatePolicy(c.Request().Context(), store.PolicyRow{
		Name:        req.Name,
		Description: req.Description,
		Enabled:     enabled,
		Priority:    priority,
		Sections:    sections,
	})
	if err != nil {
		return err
	}
	if err := s.reloadPolicyEngine(c); err != nil {
		return err
	}
	s.writeAudit(c, "policy.create", "policy", row.ID.String(), "Created policy "+row.Name, nil)
	return c.JSON(http.StatusCreated, row)
}

func (s *Server) handleUpdatePolicy(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	existing, err := s.store.GetPolicy(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "policy not found")
		}
		return err
	}
	var req policyBody
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	name := existing.Name
	if strings.TrimSpace(req.Name) != "" {
		name = req.Name
	}
	desc := existing.Description
	if req.Description != "" || req.Name != "" {
		// Allow clearing description when name provided in full update style.
		desc = req.Description
	}
	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	priority := existing.Priority
	if req.Priority != nil {
		priority = *req.Priority
	}
	sections := existing.Sections
	if len(req.Sections) > 0 {
		if !json.Valid(req.Sections) {
			return echo.NewHTTPError(http.StatusBadRequest, "sections must be valid JSON")
		}
		var sec policy.RuleSections
		if err := json.Unmarshal(req.Sections, &sec); err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, "invalid sections: "+err.Error())
		}
		sections = req.Sections
	}

	row, err := s.store.UpdatePolicy(c.Request().Context(), id, store.PolicyRow{
		Name: name, Description: desc, Enabled: enabled, Priority: priority, Sections: sections,
	})
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "policy not found")
		}
		return err
	}
	if err := s.reloadPolicyEngine(c); err != nil {
		return err
	}
	s.writeAudit(c, "policy.update", "policy", id.String(), "Updated policy "+row.Name, nil)
	return c.JSON(http.StatusOK, row)
}

func (s *Server) handleDeletePolicy(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	if err := s.store.DeletePolicy(c.Request().Context(), id); err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "policy not found")
		}
		return err
	}
	if err := s.reloadPolicyEngine(c); err != nil {
		return err
	}
	s.writeAudit(c, "policy.delete", "policy", id.String(), "Deleted policy", nil)
	return c.NoContent(http.StatusNoContent)
}

type reorderRequest struct {
	OrderedIDs []uuid.UUID `json:"ordered_ids"`
}

func (s *Server) handleReorderPolicies(c echo.Context) error {
	var req reorderRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	if len(req.OrderedIDs) == 0 {
		return echo.NewHTTPError(http.StatusBadRequest, "ordered_ids is required")
	}
	if err := s.store.ReorderPolicies(c.Request().Context(), req.OrderedIDs); err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, err.Error())
		}
		return err
	}
	if err := s.reloadPolicyEngine(c); err != nil {
		return err
	}
	s.writeAudit(c, "policy.reorder", "policy", "", "Reordered policies", map[string]any{
		"ordered_ids": req.OrderedIDs,
	})
	list, err := s.store.ListPolicies(c.Request().Context())
	if err != nil {
		return err
	}
	return c.JSON(http.StatusOK, map[string]any{"policies": list})
}

type simulateRequest struct {
	ClientIP  string `json:"client_ip"`
	Username  string `json:"username"`
	UserAgent string `json:"user_agent"`
	Method    string `json:"method"`
	URL       string `json:"url"`
}

func (s *Server) handleSimulate(c echo.Context) error {
	var req simulateRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	if strings.TrimSpace(req.URL) == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "url is required")
	}
	u, err := url.Parse(req.URL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "url must be absolute (scheme + host)")
	}
	method := req.Method
	if method == "" {
		method = http.MethodGet
	}

	// Load current policies/objects and simulate.
	rows, err := s.store.ListPolicies(c.Request().Context())
	if err != nil {
		return err
	}
	objs, err := s.store.ListReusableObjects(c.Request().Context())
	if err != nil {
		return err
	}
	rules := make([]policy.Rule, 0, len(rows))
	for _, row := range rows {
		var sections policy.RuleSections
		if len(row.Sections) > 0 {
			_ = json.Unmarshal(row.Sections, &sections)
		}
		rules = append(rules, policy.Rule{
			ID: row.ID, Name: row.Name, Description: row.Description,
			Enabled: row.Enabled, Priority: row.Priority, Sections: sections,
		})
	}
	objectMap := make(map[uuid.UUID]policy.Object, len(objs))
	for _, o := range objs {
		var def policy.ObjectDefinition
		if len(o.Definition) > 0 {
			_ = json.Unmarshal(o.Definition, &def)
		}
		objectMap[o.ID] = policy.Object{
			ID: o.ID, Name: o.Name, Type: o.Type, Definition: def, IsSystem: o.IsSystem,
		}
	}

	var clientIP net.IP
	if req.ClientIP != "" {
		clientIP = net.ParseIP(req.ClientIP)
	}
	in := policy.RequestInput{
		ClientIP:  clientIP,
		Username:  req.Username,
		UserAgent: req.UserAgent,
		Method:    method,
		URL:       u,
		Now:       time.Now().UTC(),
	}
	d := policy.Simulate(rules, objectMap, in)

	s.writeAudit(c, "policy.simulate", "policy", "", "Simulated policy evaluation", map[string]string{
		"url": req.URL, "decision": string(d.FinalAction),
	})

	return c.JSON(http.StatusOK, map[string]any{
		"input":    req,
		"decision": decisionJSON(d),
	})
}

func decisionJSON(d policy.Decision) map[string]any {
	return map[string]any{
		"final_action":        d.FinalAction,
		"block_reason":        d.BlockReason,
		"block_page_id":       d.BlockPageID,
		"tls_intercept":       d.TLSIntercept,
		"auth_mode":           d.AuthMode,
		"rbi_isolated":        d.RBIIsolated,
		"rbi_block_copy_from": d.RBIBlockCopyFrom,
		"rbi_block_copy_to":   d.RBIBlockCopyTo,
		"url_categories":      d.URLCategories,
		"malware_scan":        d.MalwareScan,
		"casb":                d.CASB,
		"header_mods":         d.HeaderMods,
		"matched_rule_ids":    d.MatchedRuleIDs,
		"evaluated_rule_ids":  d.EvaluatedRuleIDs,
	}
}

// reloadPolicyEngine recompiles policies from the store and swaps the engine.
func (s *Server) reloadPolicyEngine(c echo.Context) error {
	if s.engine == nil || s.store == nil {
		return nil
	}
	eng, err := proxy.LoadEngineFromStore(c.Request().Context(), s.store)
	if err != nil {
		return echo.NewHTTPError(http.StatusInternalServerError, "policy compile failed: "+err.Error())
	}
	// Swap compiled snapshot into the shared engine (hot reload for proxy).
	s.engine.Swap(eng.Load())
	return nil
}
