package mgmt

import (
	"net/http"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/policy"
)

// handleListURLCategories returns the built-in URL filter catalog used by
// destination conditions of type url_category.
func (s *Server) handleListURLCategories(c echo.Context) error {
	return c.JSON(http.StatusOK, map[string]any{
		"categories": policy.Categories,
		"model": map[string]any{
			"description": "URL filtering runs first (block / allow trusted). RBI isolation applies only after those layers (first explicit rbi.mode wins).",
			"recommended_order": []string{
				"1. Block malware / adult categories",
				"2. Allow trusted productivity (rbi.mode=not_isolated)",
				"3. Isolate news / social / streaming / uncategorized (rbi.mode=isolated)",
				"4. Anti-malware for remaining non-isolated allow traffic",
			},
			"destination_syntax": "category:<id>  e.g. category:malware  or condition type url_category",
		},
	})
}
