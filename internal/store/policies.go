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

// GetPolicy returns a policy by id.
func (s *Store) GetPolicy(ctx context.Context, id uuid.UUID) (PolicyRow, error) {
	if s == nil || s.pool == nil {
		return PolicyRow{}, fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return PolicyRow{}, fmt.Errorf("policy id is required")
	}
	const q = `
SELECT id, name, description, enabled, priority, sections, created_at, updated_at
FROM policies
WHERE id = $1
`
	var p PolicyRow
	var sections []byte
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&p.ID, &p.Name, &p.Description, &p.Enabled, &p.Priority,
		&sections, &p.CreatedAt, &p.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PolicyRow{}, fmt.Errorf("policy %s: %w", id, err)
		}
		return PolicyRow{}, fmt.Errorf("get policy: %w", err)
	}
	p.Sections = json.RawMessage(sections)
	return p, nil
}

// CreatePolicy inserts a policy row. Priority defaults to 500 when zero and name is set.
func (s *Store) CreatePolicy(ctx context.Context, p PolicyRow) (PolicyRow, error) {
	if s == nil || s.pool == nil {
		return PolicyRow{}, fmt.Errorf("store is nil")
	}
	if p.Name == "" {
		return PolicyRow{}, fmt.Errorf("policy name is required")
	}
	if len(p.Sections) == 0 {
		p.Sections = json.RawMessage(`{}`)
	}
	if !json.Valid(p.Sections) {
		return PolicyRow{}, fmt.Errorf("sections is not valid JSON")
	}

	const q = `
INSERT INTO policies (name, description, enabled, priority, sections)
VALUES ($1, $2, $3, $4, $5::jsonb)
RETURNING id, name, description, enabled, priority, sections, created_at, updated_at
`
	var out PolicyRow
	var sections []byte
	err := s.pool.QueryRow(ctx, q,
		p.Name, p.Description, p.Enabled, p.Priority, []byte(p.Sections),
	).Scan(
		&out.ID, &out.Name, &out.Description, &out.Enabled, &out.Priority,
		&sections, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return PolicyRow{}, fmt.Errorf("create policy: %w", err)
	}
	out.Sections = json.RawMessage(sections)
	return out, nil
}

// UpdatePolicy replaces mutable policy fields.
func (s *Store) UpdatePolicy(ctx context.Context, id uuid.UUID, p PolicyRow) (PolicyRow, error) {
	if s == nil || s.pool == nil {
		return PolicyRow{}, fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return PolicyRow{}, fmt.Errorf("policy id is required")
	}
	if p.Name == "" {
		return PolicyRow{}, fmt.Errorf("policy name is required")
	}
	if len(p.Sections) == 0 {
		p.Sections = json.RawMessage(`{}`)
	}
	if !json.Valid(p.Sections) {
		return PolicyRow{}, fmt.Errorf("sections is not valid JSON")
	}

	const q = `
UPDATE policies SET
  name = $2,
  description = $3,
  enabled = $4,
  priority = $5,
  sections = $6::jsonb,
  updated_at = now()
WHERE id = $1
RETURNING id, name, description, enabled, priority, sections, created_at, updated_at
`
	var out PolicyRow
	var sections []byte
	err := s.pool.QueryRow(ctx, q,
		id, p.Name, p.Description, p.Enabled, p.Priority, []byte(p.Sections),
	).Scan(
		&out.ID, &out.Name, &out.Description, &out.Enabled, &out.Priority,
		&sections, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return PolicyRow{}, fmt.Errorf("policy %s: %w", id, err)
		}
		return PolicyRow{}, fmt.Errorf("update policy: %w", err)
	}
	out.Sections = json.RawMessage(sections)
	return out, nil
}

// DeletePolicy removes a policy by id.
func (s *Store) DeletePolicy(ctx context.Context, id uuid.UUID) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return fmt.Errorf("policy id is required")
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM policies WHERE id = $1`, id)
	if err != nil {
		return fmt.Errorf("delete policy: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("policy %s: %w", id, pgx.ErrNoRows)
	}
	return nil
}

// ReorderPolicies sets priority for each id in order (index 0 = lowest priority value = first evaluated).
// Priorities are assigned as (i+1)*100 to leave room for inserts.
func (s *Store) ReorderPolicies(ctx context.Context, orderedIDs []uuid.UUID) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("store is nil")
	}
	if len(orderedIDs) == 0 {
		return fmt.Errorf("ordered_ids is required")
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin tx: %w", err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	const q = `UPDATE policies SET priority = $2, updated_at = now() WHERE id = $1`
	for i, id := range orderedIDs {
		if id == uuid.Nil {
			return fmt.Errorf("ordered_ids[%d] is nil", i)
		}
		priority := (i + 1) * 100
		tag, err := tx.Exec(ctx, q, id, priority)
		if err != nil {
			return fmt.Errorf("reorder policy %s: %w", id, err)
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("policy %s: %w", id, pgx.ErrNoRows)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit reorder: %w", err)
	}
	return nil
}

// GetReusableObject returns a reusable object by id.
func (s *Store) GetReusableObject(ctx context.Context, id uuid.UUID) (ReusableObject, error) {
	if s == nil || s.pool == nil {
		return ReusableObject{}, fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return ReusableObject{}, fmt.Errorf("object id is required")
	}
	const q = `
SELECT id, name, type, definition, is_system, created_at, updated_at
FROM reusable_objects
WHERE id = $1
`
	var o ReusableObject
	var def []byte
	err := s.pool.QueryRow(ctx, q, id).Scan(
		&o.ID, &o.Name, &o.Type, &def, &o.IsSystem, &o.CreatedAt, &o.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ReusableObject{}, fmt.Errorf("object %s: %w", id, err)
		}
		return ReusableObject{}, fmt.Errorf("get object: %w", err)
	}
	o.Definition = json.RawMessage(def)
	return o, nil
}

// CreateReusableObject inserts a reusable object (always non-system via API).
func (s *Store) CreateReusableObject(ctx context.Context, o ReusableObject) (ReusableObject, error) {
	if s == nil || s.pool == nil {
		return ReusableObject{}, fmt.Errorf("store is nil")
	}
	if o.Name == "" {
		return ReusableObject{}, fmt.Errorf("object name is required")
	}
	if o.Type == "" {
		return ReusableObject{}, fmt.Errorf("object type is required")
	}
	if len(o.Definition) == 0 {
		o.Definition = json.RawMessage(`{}`)
	}
	if !json.Valid(o.Definition) {
		return ReusableObject{}, fmt.Errorf("definition is not valid JSON")
	}

	const q = `
INSERT INTO reusable_objects (name, type, definition, is_system)
VALUES ($1, $2, $3::jsonb, FALSE)
RETURNING id, name, type, definition, is_system, created_at, updated_at
`
	var out ReusableObject
	var def []byte
	err := s.pool.QueryRow(ctx, q, o.Name, o.Type, []byte(o.Definition)).Scan(
		&out.ID, &out.Name, &out.Type, &def, &out.IsSystem, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return ReusableObject{}, fmt.Errorf("create object: %w", err)
	}
	out.Definition = json.RawMessage(def)
	return out, nil
}

// UpdateReusableObject updates a non-system object. System objects cannot be updated.
func (s *Store) UpdateReusableObject(ctx context.Context, id uuid.UUID, o ReusableObject) (ReusableObject, error) {
	if s == nil || s.pool == nil {
		return ReusableObject{}, fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return ReusableObject{}, fmt.Errorf("object id is required")
	}
	if o.Name == "" {
		return ReusableObject{}, fmt.Errorf("object name is required")
	}
	if o.Type == "" {
		return ReusableObject{}, fmt.Errorf("object type is required")
	}
	if len(o.Definition) == 0 {
		o.Definition = json.RawMessage(`{}`)
	}
	if !json.Valid(o.Definition) {
		return ReusableObject{}, fmt.Errorf("definition is not valid JSON")
	}

	const q = `
UPDATE reusable_objects SET
  name = $2,
  type = $3,
  definition = $4::jsonb,
  updated_at = now()
WHERE id = $1 AND is_system = FALSE
RETURNING id, name, type, definition, is_system, created_at, updated_at
`
	var out ReusableObject
	var def []byte
	err := s.pool.QueryRow(ctx, q, id, o.Name, o.Type, []byte(o.Definition)).Scan(
		&out.ID, &out.Name, &out.Type, &def, &out.IsSystem, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ReusableObject{}, fmt.Errorf("object %s: %w", id, err)
		}
		return ReusableObject{}, fmt.Errorf("update object: %w", err)
	}
	out.Definition = json.RawMessage(def)
	return out, nil
}

// DeleteReusableObject deletes a non-system object.
func (s *Store) DeleteReusableObject(ctx context.Context, id uuid.UUID) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return fmt.Errorf("object id is required")
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM reusable_objects WHERE id = $1 AND is_system = FALSE`, id)
	if err != nil {
		return fmt.Errorf("delete object: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("object %s: %w", id, pgx.ErrNoRows)
	}
	return nil
}

// ListBlockPages returns all block pages ordered by name.
func (s *Store) ListBlockPages(ctx context.Context) ([]BlockPage, error) {
	if s == nil || s.pool == nil {
		return nil, fmt.Errorf("store is nil")
	}
	const q = `
SELECT id, name, html, is_system, created_at, updated_at
FROM block_pages
ORDER BY name ASC, id ASC
`
	rows, err := s.pool.Query(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("list block pages: %w", err)
	}
	defer rows.Close()

	var out []BlockPage
	for rows.Next() {
		var p BlockPage
		if err := rows.Scan(&p.ID, &p.Name, &p.HTML, &p.IsSystem, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan block page: %w", err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list block pages: %w", err)
	}
	if out == nil {
		out = []BlockPage{}
	}
	return out, nil
}

// CreateBlockPage inserts a custom (non-system) block page.
func (s *Store) CreateBlockPage(ctx context.Context, p BlockPage) (BlockPage, error) {
	if s == nil || s.pool == nil {
		return BlockPage{}, fmt.Errorf("store is nil")
	}
	if p.Name == "" {
		return BlockPage{}, fmt.Errorf("block page name is required")
	}
	if p.HTML == "" {
		return BlockPage{}, fmt.Errorf("block page html is required")
	}

	const q = `
INSERT INTO block_pages (name, html, is_system)
VALUES ($1, $2, FALSE)
RETURNING id, name, html, is_system, created_at, updated_at
`
	var out BlockPage
	err := s.pool.QueryRow(ctx, q, p.Name, p.HTML).Scan(
		&out.ID, &out.Name, &out.HTML, &out.IsSystem, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		return BlockPage{}, fmt.Errorf("create block page: %w", err)
	}
	return out, nil
}

// UpdateBlockPage updates a non-system block page.
func (s *Store) UpdateBlockPage(ctx context.Context, id uuid.UUID, name, html string) (BlockPage, error) {
	if s == nil || s.pool == nil {
		return BlockPage{}, fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return BlockPage{}, fmt.Errorf("block page id is required")
	}
	if name == "" {
		return BlockPage{}, fmt.Errorf("block page name is required")
	}
	if html == "" {
		return BlockPage{}, fmt.Errorf("block page html is required")
	}

	const q = `
UPDATE block_pages SET name = $2, html = $3, updated_at = now()
WHERE id = $1 AND is_system = FALSE
RETURNING id, name, html, is_system, created_at, updated_at
`
	var out BlockPage
	err := s.pool.QueryRow(ctx, q, id, name, html).Scan(
		&out.ID, &out.Name, &out.HTML, &out.IsSystem, &out.CreatedAt, &out.UpdatedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return BlockPage{}, fmt.Errorf("block page %s: %w", id, err)
		}
		return BlockPage{}, fmt.Errorf("update block page: %w", err)
	}
	return out, nil
}

// DeleteBlockPage deletes a non-system block page.
func (s *Store) DeleteBlockPage(ctx context.Context, id uuid.UUID) error {
	if s == nil || s.pool == nil {
		return fmt.Errorf("store is nil")
	}
	if id == uuid.Nil {
		return fmt.Errorf("block page id is required")
	}
	tag, err := s.pool.Exec(ctx, `DELETE FROM block_pages WHERE id = $1 AND is_system = FALSE`, id)
	if err != nil {
		return fmt.Errorf("delete block page: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("block page %s: %w", id, pgx.ErrNoRows)
	}
	return nil
}
