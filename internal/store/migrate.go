package store

import (
	"context"
	"fmt"
	"io/fs"
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/wsp-security/wsp/migrations"
)

// schemaMigrationsDDL tracks applied migration versions.
const schemaMigrationsDDL = `
CREATE TABLE IF NOT EXISTS schema_migrations (
    version    TEXT PRIMARY KEY,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
`

var upMigrationName = regexp.MustCompile(`^(\d{3,})_([a-z0-9_]+)\.up\.sql$`)

// Migrate applies all pending embedded *.up.sql migrations in version order.
// Migrations are embedded from the root migrations package (production path).
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrateFS(ctx, migrations.FS)
}

// migrateFS applies up migrations discovered in fsys (testable hook).
func (s *Store) migrateFS(ctx context.Context, fsys fs.FS) error {
	if _, err := s.pool.Exec(ctx, schemaMigrationsDDL); err != nil {
		return fmt.Errorf("ensure schema_migrations: %w", err)
	}

	ups, err := listUpMigrations(fsys)
	if err != nil {
		return err
	}

	applied, err := s.appliedVersions(ctx)
	if err != nil {
		return err
	}

	for _, m := range ups {
		if applied[m.version] {
			continue
		}
		body, err := fs.ReadFile(fsys, m.path)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", m.path, err)
		}
		if err := s.applyUp(ctx, m.version, string(body)); err != nil {
			return err
		}
	}
	return nil
}

type migrationFile struct {
	version string // e.g. "001"
	name    string // e.g. "init"
	path    string // path within embed FS
}

func listUpMigrations(fsys fs.FS) ([]migrationFile, error) {
	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}

	var out []migrationFile
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		m := upMigrationName.FindStringSubmatch(name)
		if m == nil {
			continue
		}
		out = append(out, migrationFile{
			version: m[1],
			name:    m[2],
			path:    path.Clean(name),
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].version != out[j].version {
			return out[i].version < out[j].version
		}
		return out[i].name < out[j].name
	})
	return out, nil
}

func (s *Store) appliedVersions(ctx context.Context) (map[string]bool, error) {
	rows, err := s.pool.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return nil, fmt.Errorf("list applied migrations: %w", err)
	}
	defer rows.Close()

	applied := make(map[string]bool)
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, fmt.Errorf("scan migration version: %w", err)
		}
		applied[v] = true
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate migration versions: %w", err)
	}
	return applied, nil
}

func (s *Store) applyUp(ctx context.Context, version, sqlBody string) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("acquire conn for migration %s: %w", version, err)
	}
	defer conn.Release()

	// Multi-statement SQL files require the simple query protocol.
	pgConn := conn.Conn().PgConn()
	if err := execSimple(ctx, pgConn, "BEGIN"); err != nil {
		return fmt.Errorf("begin migration %s: %w", version, err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = execSimple(context.Background(), pgConn, "ROLLBACK")
		}
	}()

	if err := execSimple(ctx, pgConn, sqlBody); err != nil {
		return fmt.Errorf("apply migration %s: %w", version, err)
	}

	tag, err := conn.Exec(ctx,
		`INSERT INTO schema_migrations (version) VALUES ($1)`,
		version,
	)
	if err != nil {
		return fmt.Errorf("record migration %s: %w", version, err)
	}
	if tag.RowsAffected() != 1 {
		return fmt.Errorf("record migration %s: expected 1 row, got %d", version, tag.RowsAffected())
	}

	if err := execSimple(ctx, pgConn, "COMMIT"); err != nil {
		return fmt.Errorf("commit migration %s: %w", version, err)
	}
	committed = true
	return nil
}

func execSimple(ctx context.Context, pgConn *pgconn.PgConn, sqlBody string) error {
	sqlBody = strings.TrimSpace(sqlBody)
	if sqlBody == "" {
		return nil
	}
	results, err := pgConn.Exec(ctx, sqlBody).ReadAll()
	if err != nil {
		return err
	}
	for _, r := range results {
		if r.Err != nil {
			return r.Err
		}
	}
	return nil
}
