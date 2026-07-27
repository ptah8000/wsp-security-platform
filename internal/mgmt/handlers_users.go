package mgmt

import (
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/wsp-security/wsp/internal/auth"
	"github.com/wsp-security/wsp/internal/store"
)

func (s *Server) handleListUsers(c echo.Context) error {
	users, err := s.store.ListUsers(c.Request().Context())
	if err != nil {
		return err
	}
	out := make([]map[string]any, 0, len(users))
	for _, u := range users {
		out = append(out, publicUser(u))
	}
	return c.JSON(http.StatusOK, map[string]any{"users": out})
}

func (s *Server) handleGetUser(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	u, err := s.store.GetUserByID(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "user not found")
		}
		return err
	}
	u.PasswordHash = ""
	return c.JSON(http.StatusOK, publicUser(u))
}

type createUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Role        string `json:"role"`
}

func (s *Server) handleCreateUser(c echo.Context) error {
	var req createUserRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}
	req.Username = strings.TrimSpace(req.Username)
	if req.Username == "" || req.Password == "" {
		return echo.NewHTTPError(http.StatusBadRequest, "username and password are required")
	}
	if len(req.Password) < 8 {
		return echo.NewHTTPError(http.StatusBadRequest, "password must be at least 8 characters")
	}
	role := req.Role
	if role == "" {
		role = store.RoleUser
	}
	if role != store.RoleAdmin && role != store.RoleUser {
		return echo.NewHTTPError(http.StatusBadRequest, "role must be admin or user")
	}
	hash, err := auth.HashPassword(req.Password)
	if err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}
	u, err := s.store.CreateUser(c.Request().Context(), store.User{
		Username:     req.Username,
		PasswordHash: hash,
		DisplayName:  req.DisplayName,
		Role:         role,
	})
	if err != nil {
		if strings.Contains(err.Error(), "duplicate") || strings.Contains(err.Error(), "unique") {
			return echo.NewHTTPError(http.StatusConflict, "username already taken")
		}
		return err
	}
	s.writeAudit(c, "user.create", "user", u.ID.String(), "Created user "+u.Username, map[string]string{
		"username": u.Username, "role": u.Role,
	})
	u.PasswordHash = ""
	return c.JSON(http.StatusCreated, publicUser(u))
}

type updateUserRequest struct {
	DisplayName *string `json:"display_name"`
	Role        *string `json:"role"`
	Enabled     *bool   `json:"enabled"`
	Password    *string `json:"password"`
}

func (s *Server) handleUpdateUser(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	existing, err := s.store.GetUserByID(c.Request().Context(), id)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "user not found")
		}
		return err
	}

	var req updateUserRequest
	if err := c.Bind(&req); err != nil {
		return echo.NewHTTPError(http.StatusBadRequest, "invalid JSON body")
	}

	displayName := existing.DisplayName
	if req.DisplayName != nil {
		displayName = *req.DisplayName
	}
	role := existing.Role
	if req.Role != nil {
		role = *req.Role
		if role != store.RoleAdmin && role != store.RoleUser {
			return echo.NewHTTPError(http.StatusBadRequest, "role must be admin or user")
		}
	}
	enabled := existing.Enabled
	if req.Enabled != nil {
		enabled = *req.Enabled
	}
	passwordHash := ""
	if req.Password != nil && *req.Password != "" {
		if len(*req.Password) < 8 {
			return echo.NewHTTPError(http.StatusBadRequest, "password must be at least 8 characters")
		}
		h, err := auth.HashPassword(*req.Password)
		if err != nil {
			return echo.NewHTTPError(http.StatusBadRequest, err.Error())
		}
		passwordHash = h
	}

	u, err := s.store.UpdateUser(c.Request().Context(), id, displayName, role, enabled, passwordHash)
	if err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "user not found")
		}
		return err
	}
	s.writeAudit(c, "user.update", "user", id.String(), "Updated user "+u.Username, nil)
	return c.JSON(http.StatusOK, publicUser(u))
}

func (s *Server) handleDeleteUser(c echo.Context) error {
	id, err := parseUUIDParam(c, "id")
	if err != nil {
		return err
	}
	// Prevent self-delete.
	if cur := s.currentUser(c); cur != nil && cur.ID == id {
		return echo.NewHTTPError(http.StatusBadRequest, "cannot delete your own account")
	}
	if err := s.store.DeleteUser(c.Request().Context(), id); err != nil {
		if storeNotFound(err) {
			return echo.NewHTTPError(http.StatusNotFound, "user not found")
		}
		return err
	}
	s.writeAudit(c, "user.delete", "user", id.String(), "Deleted user", nil)
	return c.NoContent(http.StatusNoContent)
}
