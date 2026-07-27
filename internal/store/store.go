// Package store provides PostgreSQL persistence via pgx and a SQL migration runner.
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Store is the shared PostgreSQL access layer for the WSP monolith.
type Store struct {
	pool *pgxpool.Pool
}

// New opens a connection pool to databaseURL and verifies connectivity.
func New(ctx context.Context, databaseURL string) (*Store, error) {
	if databaseURL == "" {
		return nil, fmt.Errorf("database URL is empty")
	}

	cfg, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database URL: %w", err)
	}
	// Reasonable defaults for a single-host modular monolith.
	if cfg.MaxConns == 0 {
		cfg.MaxConns = 10
	}
	cfg.MinConns = 1
	cfg.MaxConnLifetime = time.Hour
	cfg.HealthCheckPeriod = 30 * time.Second

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("connect pool: %w", err)
	}

	s := &Store{pool: pool}
	if err := s.Ping(ctx); err != nil {
		pool.Close()
		return nil, err
	}
	return s, nil
}

// Close releases the connection pool.
func (s *Store) Close() {
	if s == nil || s.pool == nil {
		return
	}
	s.pool.Close()
}

// Ping checks database connectivity.
func (s *Store) Ping(ctx context.Context) error {
	if err := s.pool.Ping(ctx); err != nil {
		return fmt.Errorf("ping database: %w", err)
	}
	return nil
}

// Pool exposes the underlying pool for packages that need advanced queries.
// Prefer typed store methods when available.
func (s *Store) Pool() *pgxpool.Pool {
	return s.pool
}
