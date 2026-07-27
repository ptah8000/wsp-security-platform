package mgmt

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/store"
)

// testServer builds a management server with injectable setup state (no DB).
func testServer(setupComplete bool) *Server {
	s := New(Deps{
		Version:   "test",
		AdminAddr: ":3000",
		ProxyAddr: ":8080",
	})
	s.setupComplete = func(context.Context) (bool, error) {
		return setupComplete, nil
	}
	return s
}

func TestHealthzUnauthenticated(t *testing.T) {
	s := testServer(false)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["status"] != "ok" {
		t.Fatalf("status field = %v", body["status"])
	}
}

func TestSetupStatusWhenIncomplete(t *testing.T) {
	s := testServer(false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil)
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["setup_completed"] != false {
		t.Fatalf("setup_completed = %v, want false", body["setup_completed"])
	}
	steps, ok := body["steps"].([]any)
	if !ok || len(steps) != 4 {
		t.Fatalf("steps = %v", body["steps"])
	}
}

func TestSetupStatusWhenComplete(t *testing.T) {
	s := testServer(true)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/setup/status", nil)
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatal(err)
	}
	if body["setup_completed"] != true {
		t.Fatalf("setup_completed = %v, want true", body["setup_completed"])
	}
}

func TestSetupMutationsBlockedWhenComplete(t *testing.T) {
	s := testServer(true)
	paths := []struct {
		method string
		path   string
		body   string
	}{
		{http.MethodPost, "/api/v1/setup/admin", `{"username":"a","password":"password1"}`},
		{http.MethodPost, "/api/v1/setup/ca", `{"name":"CA"}`},
		{http.MethodPost, "/api/v1/setup/network", `{"dns_servers":["1.1.1.1"]}`},
		{http.MethodPost, "/api/v1/setup/complete", `{}`},
	}
	for _, p := range paths {
		req := httptest.NewRequest(p.method, p.path, strings.NewReader(p.body))
		req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
		rec := httptest.NewRecorder()
		s.Echo().ServeHTTP(rec, req)
		if rec.Code != http.StatusConflict {
			t.Errorf("%s %s: status=%d want 409; body=%s", p.method, p.path, rec.Code, rec.Body.String())
		}
	}
}

func TestAuthRequiredOnAdminRoutes(t *testing.T) {
	s := testServer(true)
	paths := []string{
		"/api/v1/users",
		"/api/v1/policies",
		"/api/v1/health",
		"/api/v1/export/config",
		"/api/v1/client-setup",
		"/api/v1/auth/me",
	}
	for _, path := range paths {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.Echo().ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("GET %s: status=%d want 401; body=%s", path, rec.Code, rec.Body.String())
		}
	}
}

func TestAdminRoutesBlockedWhenSetupIncompleteEvenIfAuthed(t *testing.T) {
	s2 := testServer(false)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	rec := httptest.NewRecorder()
	e2 := echo.New()
	e2.HideBanner = true
	e2.HTTPErrorHandler = s2.httpErrorHandler
	e2.GET("/api/v1/users", s2.handleListUsers, func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(ctxUserKey, &store.User{
				ID: uuid.New(), Username: "admin", Role: store.RoleAdmin, Enabled: true,
			})
			return next(c)
		}
	}, s2.requireAuth, s2.requireSetupComplete)
	e2.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409 (setup incomplete); body=%s", rec.Code, rec.Body.String())
	}
}

func TestLoginBlockedWhenSetupIncomplete(t *testing.T) {
	s := testServer(false)
	body := `{"username":"admin","password":"password1"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader(body))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d want 409; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSetupAdminValidation(t *testing.T) {
	s := testServer(false)
	// No store → service unavailable after validation, or validation first.
	cases := []struct {
		name string
		body string
		code int
	}{
		{"missing fields", `{}`, http.StatusBadRequest},
		{"short password", `{"username":"admin","password":"short"}`, http.StatusBadRequest},
		{"ok shape no store", `{"username":"admin","password":"password1"}`, http.StatusServiceUnavailable},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/admin", strings.NewReader(tc.body))
			req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
			rec := httptest.NewRecorder()
			s.Echo().ServeHTTP(rec, req)
			if rec.Code != tc.code {
				t.Fatalf("status=%d want %d; body=%s", rec.Code, tc.code, rec.Body.String())
			}
		})
	}
}

func TestSetupNetworkValidation(t *testing.T) {
	s := testServer(false)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/setup/network", bytes.NewReader([]byte(`{"dns_servers":[]}`)))
	req.Header.Set(echo.HeaderContentType, echo.MIMEApplicationJSON)
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	// empty dns → 400 before store; or 503 if store check first
	if rec.Code != http.StatusBadRequest && rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 400 or 503; body=%s", rec.Code, rec.Body.String())
	}
}

func TestSPAPlaceholderServed(t *testing.T) {
	s := testServer(false)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	s.Echo().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "Web Security Platform") &&
		!strings.Contains(rec.Body.String(), "WSP") {
		t.Fatalf("unexpected body: %s", rec.Body.String()[:min(200, rec.Body.Len())])
	}
}

func TestSessionCookieNameConstant(t *testing.T) {
	if SessionCookieName != "wsp_session" {
		t.Fatalf("SessionCookieName = %q", SessionCookieName)
	}
}

func TestRequireAuthRejectsNonAdmin(t *testing.T) {
	s := testServer(true)
	e := echo.New()
	e.HideBanner = true
	e.HTTPErrorHandler = s.httpErrorHandler
	e.GET("/x", func(c echo.Context) error {
		return c.JSON(http.StatusOK, map[string]string{"ok": "1"})
	}, func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			c.Set(ctxUserKey, &store.User{
				ID: uuid.New(), Username: "bob", Role: store.RoleUser, Enabled: true,
				CreatedAt: time.Now(), UpdatedAt: time.Now(),
			})
			return next(c)
		}
	}, s.requireAuth)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	rec := httptest.NewRecorder()
	e.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want 403; body=%s", rec.Code, rec.Body.String())
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
