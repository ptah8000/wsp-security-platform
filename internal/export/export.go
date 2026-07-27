// Package export builds a configuration JSON bundle (no secrets / private keys).
package export

import (
	"context"
	"fmt"
	"time"

	"github.com/wsp-security/wsp/internal/store"
)

// Bundle is the v1 configuration export payload.
type Bundle struct {
	ExportedAt   time.Time               `json:"exported_at"`
	Version      string                  `json:"version"`
	Policies     []store.PolicyRow       `json:"policies"`
	Objects      []store.ReusableObject  `json:"objects"`
	Users        []UserExport            `json:"users"`
	Settings     []store.Setting         `json:"settings"`
	Certificates []store.CertificateMeta `json:"certificates"`
	BlockPages   []store.BlockPage       `json:"block_pages"`
}

// UserExport is a user without password material.
type UserExport struct {
	ID          string     `json:"id"`
	Username    string     `json:"username"`
	DisplayName string     `json:"display_name"`
	Role        string     `json:"role"`
	Enabled     bool       `json:"enabled"`
	CreatedAt   time.Time  `json:"created_at"`
	UpdatedAt   time.Time  `json:"updated_at"`
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`
}

// Build loads config entities from the store into a Bundle.
// Certificate private keys and password hashes are never included.
func Build(ctx context.Context, s *store.Store, version string) (Bundle, error) {
	if s == nil {
		return Bundle{}, fmt.Errorf("store is nil")
	}
	if version == "" {
		version = "0.1.0"
	}

	policies, err := s.ListPolicies(ctx)
	if err != nil {
		return Bundle{}, fmt.Errorf("policies: %w", err)
	}
	objects, err := s.ListReusableObjects(ctx)
	if err != nil {
		return Bundle{}, fmt.Errorf("objects: %w", err)
	}
	users, err := s.ListUsers(ctx)
	if err != nil {
		return Bundle{}, fmt.Errorf("users: %w", err)
	}
	settings, err := s.ListSettings(ctx)
	if err != nil {
		return Bundle{}, fmt.Errorf("settings: %w", err)
	}
	certs, err := s.ListCertificates(ctx)
	if err != nil {
		return Bundle{}, fmt.Errorf("certificates: %w", err)
	}
	pages, err := s.ListBlockPages(ctx)
	if err != nil {
		return Bundle{}, fmt.Errorf("block_pages: %w", err)
	}

	ue := make([]UserExport, 0, len(users))
	for _, u := range users {
		ue = append(ue, UserExport{
			ID:          u.ID.String(),
			Username:    u.Username,
			DisplayName: u.DisplayName,
			Role:        u.Role,
			Enabled:     u.Enabled,
			CreatedAt:   u.CreatedAt,
			UpdatedAt:   u.UpdatedAt,
			LastLoginAt: u.LastLoginAt,
		})
	}

	return Bundle{
		ExportedAt:   time.Now().UTC(),
		Version:      version,
		Policies:     policies,
		Objects:      objects,
		Users:        ue,
		Settings:     settings,
		Certificates: certs,
		BlockPages:   pages,
	}, nil
}
