package store

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// PolicyRow is a policies table row (sections kept as raw JSON for callers to decode).
type PolicyRow struct {
	ID          uuid.UUID       `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Enabled     bool            `json:"enabled"`
	Priority    int             `json:"priority"`
	Sections    json.RawMessage `json:"sections"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// ReusableObject is a reusable_objects table row.
type ReusableObject struct {
	ID         uuid.UUID       `json:"id"`
	Name       string          `json:"name"`
	Type       string          `json:"type"`
	Definition json.RawMessage `json:"definition"`
	IsSystem   bool            `json:"is_system"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
}

// BlockPage is a block_pages table row.
type BlockPage struct {
	ID        uuid.UUID `json:"id"`
	Name      string    `json:"name"`
	HTML      string    `json:"html"`
	IsSystem  bool      `json:"is_system"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// ListPolicies returns all policies ordered by priority ASC, name ASC.
func (s *Store) ListPolicies(ctx context.Context) ([]PolicyRow, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("store is nil")
	}
	const q = `
SELECT id, name, description, enabled, priority, sections, created_at, updated_at
FROM policies
ORDER BY priority ASC, name ASC, id ASC
`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	defer rows.Close()

	var out []PolicyRow
	for rows.Next() {
		var p PolicyRow
		var sections []byte
		if err := rows.Scan(
			&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
			&sections, &p.CreatedAt, &p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan policy: %w", err)
		}
		p.Sections = json.RawMessage(sections)
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list policies: %w", err)
	}
	return out, nil
}

// ListReusableObjects returns all reusable objects.
func (s *Store) ListReusableObjects(ctx context.Context) ([]ReusableObject, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("store is nil")
	}
	const q = `
SELECT id, name, type, definition, is_system, created_at, updated_at
FROM reusable_objects
ORDER BY name ASC, id ASC
`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list reusable objects: %w", err)
	}
	defer rows.Close()

	var out []ReusableObject
	for rows.Next() {
		var o ReusableObject
		var def []byte
		if err := rows.Scan(
			&o.ID, &o.Name, &o.Type, &def, &o.IsSystem, &o.CreatedAt, &o.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("scan reusable object: %w", err)
		}
		o.Definition = json.RawMessage(def)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list reusable objects: %w", err)
	}
	return out, nil
}

// GetBlockPage returns a block page by id.
func (s *Store) GetBlockPage(ctx context.Context, id uuid.UUID) (BlockPage, error) {
	if s == nil || s.pool == nil {
		return BlockPage{}, fmt.Errorf("store is nil")
	}
	const q = `
SELECT id, name, html, is_system, created_at, updated_at
FROM block_pages
WHERE id = $1
`
	var p BlockPage
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&p.ID, &p.Name, &p.HTML, &p.IsSystem, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BlockPage{}, fmt.Errorf("block page %s: %w", id, err)
		}
		return BlockPage{}, fmt.Errorf("get block page: %w", err)
	}
	return p, nil
}

// GetSystemDefaultBlockPage returns the first system block page (seed default).
func (s *Store) GetSystemDefaultBlockPage(ctx context.Context) (BlockPage, error) {
	if s == nil || s.pool == nil {
		return BlockPage{}, fmt.Errorf("store is nil")
	}
	const q = `
SELECT id, name, html, is_system, created_at, updated_at
FROM block_pages
WHERE is_system = TRUE
ORDER BY created_at ASC
LIMIT 1
`
	var p BlockPage
	err := s.pool.QueryRow(ctx, q).Scan(
		&p.ID, &p.Name, &p.HTML, &p.IsSystem, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BlockPage{}, fmt.Errorf("system block page: %w", err)
		}
		return BlockPage{}, fmt.Errorf("get system block page: %w", err)
	}
	return p, nil
}
