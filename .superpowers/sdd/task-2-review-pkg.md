# Review package Task 2
BASE: faa8b7b3a3853fd14969725485ef3432633c6904
HEAD: 97e4ea2511bcf39d91e6bd6be943b1d9414fd49b

## Commits


## Stat
 cmd/wsp/main.go                          |  29 ++++-  go.mod                                   |  14 +++  go.sum                                   |  30 ++++++  internal/store/audit.go                  | 101 ++++++++++++++++++  internal/store/migrate.go                | 178 +++++++++++++++++++++++++++++++  internal/store/migrate_test.go           |  40 +++++++  internal/store/settings.go               |  96 +++++++++++++++++  internal/store/store.go                  |  68 ++++++++++++  internal/store/store_integration_test.go | 153 ++++++++++++++++++++++++++  internal/store/users.go                  | 104 ++++++++++++++++++  migrations/embed.go                      |   9 ++  11 files changed, 817 insertions(+), 5 deletions(-)

## Diff
diff --git a/cmd/wsp/main.go b/cmd/wsp/main.go
index 6ab05c0..b4d64b9 100644
--- a/cmd/wsp/main.go
+++ b/cmd/wsp/main.go
@@ -1,18 +1,21 @@
 package main
 
 import (
+	"context"
 	"flag"
 	"fmt"
 	"log/slog"
 	"os"
 	"strings"
+	"time"
 
 	"github.com/wsp-security/wsp/internal/config"
+	"github.com/wsp-security/wsp/internal/store"
 	_ "github.com/wsp-security/wsp/web" // embed admin UI assets (placeholder in v1 scaffold)
 )
 
 // Version is the binary version reported by --version.
 const Version = "0.1.0"
 
 func main() {
 	showVersion := flag.Bool("version", false, "print version and exit")
@@ -33,18 +36,17 @@ func main() {
 
 	slog.Info("wsp starting",
 		"version", Version,
 		"mode", cfg.Mode,
 		"proxy_addr", cfg.ProxyAddr,
 		"admin_addr", cfg.AdminAddr,
 	)
 
-	// migrate hook stub ΓÇö store layer lands in a later task
-	if err := runMigrationsStub(cfg); err != nil {
+	if err := runMigrations(cfg); err != nil {
 		slog.Error("migrations failed", "err", err)
 		os.Exit(1)
 	}
 
 	slog.Info("scaffold complete; listeners not started yet",
 		"hint", "subsequent tasks wire proxy and management API",
 	)
 }
@@ -59,13 +61,30 @@ func setupLogger(level string) {
 	case "error":
 		lv = slog.LevelError
 	default:
 		lv = slog.LevelInfo
 	}
 	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lv})))
 }
 
-// runMigrationsStub is a placeholder until internal/store implements migrations.
-func runMigrationsStub(cfg config.Config) error {
-	slog.Info("migrate hook stub", "database_url_set", cfg.DatabaseURL != "")
+// runMigrations opens the store, applies pending SQL migrations, and closes the pool.
+// Later tasks will keep a long-lived Store for listeners.
+func runMigrations(cfg config.Config) error {
+	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
+	defer cancel()
+
+	s, err := store.New(ctx, cfg.DatabaseURL)
+	if err != nil {
+		return fmt.Errorf("store: %w", err)
+	}
+	defer s.Close()
+
+	if err := s.Migrate(ctx); err != nil {
+		return err
+	}
+	complete, err := s.IsSetupComplete(ctx)
+	if err != nil {
+		return fmt.Errorf("setup status: %w", err)
+	}
+	slog.Info("migrations applied", "setup_complete", complete)
 	return nil
 }
diff --git a/go.mod b/go.mod
index ebc9cf8..2c26006 100644
--- a/go.mod
+++ b/go.mod
@@ -1,3 +1,17 @@
 module github.com/wsp-security/wsp
 
 go 1.22
+
+require (
+	github.com/google/uuid v1.6.0
+	github.com/jackc/pgx/v5 v5.7.4
+)
+
+require (
+	github.com/jackc/pgpassfile v1.0.0 // indirect
+	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
+	github.com/jackc/puddle/v2 v2.2.2 // indirect
+	golang.org/x/crypto v0.31.0 // indirect
+	golang.org/x/sync v0.10.0 // indirect
+	golang.org/x/text v0.21.0 // indirect
+)
diff --git a/go.sum b/go.sum
new file mode 100644
index 0000000..d95dea0
--- /dev/null
+++ b/go.sum
@@ -0,0 +1,30 @@
+github.com/davecgh/go-spew v1.1.0/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
+github.com/davecgh/go-spew v1.1.1 h1:vj9j/u1bqnvCEfJOwUhtlOARqs3+rkHYY13jYWTU97c=
+github.com/davecgh/go-spew v1.1.1/go.mod h1:J7Y8YcW2NihsgmVo/mv3lAwl/skON4iLHjSsI+c5H38=
+github.com/google/uuid v1.6.0 h1:NIvaJDMOsjHA8n1jAhLSgzrAzy1Hgr+hNrb57e+94F0=
+github.com/google/uuid v1.6.0/go.mod h1:TIyPZe4MgqvfeYDBFedMoGGpEw/LqOeaOT+nhxU+yHo=
+github.com/jackc/pgpassfile v1.0.0 h1:/6Hmqy13Ss2zCq62VdNG8tM1wchn8zjSGOBJ6icpsIM=
+github.com/jackc/pgpassfile v1.0.0/go.mod h1:CEx0iS5ambNFdcRtxPj5JhEz+xB6uRky5eyVu/W2HEg=
+github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 h1:iCEnooe7UlwOQYpKFhBabPMi4aNAfoODPEFNiAnClxo=
+github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761/go.mod h1:5TJZWKEWniPve33vlWYSoGYefn3gLQRzjfDlhSJ9ZKM=
+github.com/jackc/pgx/v5 v5.7.4 h1:9wKznZrhWa2QiHL+NjTSPP6yjl3451BX3imWDnokYlg=
+github.com/jackc/pgx/v5 v5.7.4/go.mod h1:ncY89UGWxg82EykZUwSpUKEfccBGGYq1xjrOpsbsfGQ=
+github.com/jackc/puddle/v2 v2.2.2 h1:PR8nw+E/1w0GLuRFSmiioY6UooMp6KJv0/61nB7icHo=
+github.com/jackc/puddle/v2 v2.2.2/go.mod h1:vriiEXHvEE654aYKXXjOvZM39qJ0q+azkZFrfEOc3H4=
+github.com/pmezard/go-difflib v1.0.0 h1:4DBwDE0NGyQoBHbLQYPwSUPoCMWR5BEzIk/f1lZbAQM=
+github.com/pmezard/go-difflib v1.0.0/go.mod h1:iKH77koFhYxTK1pcRnkKkqfTogsbg7gZNVY4sRDYZ/4=
+github.com/stretchr/objx v0.1.0/go.mod h1:HFkY916IF+rwdDfMAkV7OtwuqBVzrE8GR6GFx+wExME=
+github.com/stretchr/testify v1.3.0/go.mod h1:M5WIy9Dh21IEIfnGCwXGc5bZfKNJtfHm1UVUgZn+9EI=
+github.com/stretchr/testify v1.7.0/go.mod h1:6Fq8oRcR53rry900zMqJjRRixrwX3KX962/h/Wwjteg=
+github.com/stretchr/testify v1.8.1 h1:w7B6lhMri9wdJUVmEZPGGhZzrYTPvgJArz7wNPgYKsk=
+github.com/stretchr/testify v1.8.1/go.mod h1:w2LPCIKwWwSfY2zedu0+kehJoqGctiVI29o6fzry7u4=
+golang.org/x/crypto v0.31.0 h1:ihbySMvVjLAeSH1IbfcRTkD/iNscyz8rGzjF/E5hV6U=
+golang.org/x/crypto v0.31.0/go.mod h1:kDsLvtWBEx7MV9tJOj9bnXsPbxwJQ6csT/x4KIN4Ssk=
+golang.org/x/sync v0.10.0 h1:3NQrjDixjgGwUOCaF8w2+VYHv0Ve/vGYSbdkTa98gmQ=
+golang.org/x/sync v0.10.0/go.mod h1:Czt+wKu1gCyEFDUtn0jG5QVvpJ6rzVqr5aXyt9drQfk=
+golang.org/x/text v0.21.0 h1:zyQAAkrwaneQ066sspRyJaG9VNi/YJ1NfzcGB3hZ/qo=
+golang.org/x/text v0.21.0/go.mod h1:4IBbMaMmOPCJ8SecivzSH54+73PCFmPWxNTLm+vZkEQ=
+gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405/go.mod h1:Co6ibVJAznAaIkqp8huTwlJQCZ016jof/cbN4VW5Yz0=
+gopkg.in/yaml.v3 v3.0.0-20200313102051-9f266ea9e77c/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
+gopkg.in/yaml.v3 v3.0.1 h1:fxVm/GzAzEWqLHuvctI91KS9hhNmmWOoWu0XTYJS7CA=
+gopkg.in/yaml.v3 v3.0.1/go.mod h1:K4uyk7z7BCEPqu6E+C64Yfv1cQ7kz7rIZviUmN+EgEM=
diff --git a/internal/store/audit.go b/internal/store/audit.go
new file mode 100644
index 0000000..650e583
--- /dev/null
+++ b/internal/store/audit.go
@@ -0,0 +1,101 @@
+package store
+
+import (
+	"context"
+	"encoding/json"
+	"fmt"
+	"time"
+
+	"github.com/google/uuid"
+	"github.com/jackc/pgx/v5/pgtype"
+)
+
+// AuditEntry is a durable admin/system action record.
+type AuditEntry struct {
+	ID            uuid.UUID       `json:"id"`
+	TS            time.Time       `json:"ts"`
+	ActorUserID   *uuid.UUID      `json:"actor_user_id,omitempty"`
+	ActorUsername string          `json:"actor_username,omitempty"`
+	Action        string          `json:"action"`
+	TargetType    string          `json:"target_type,omitempty"`
+	TargetID      string          `json:"target_id,omitempty"`
+	Summary       string          `json:"summary,omitempty"`
+	Detail        json.RawMessage `json:"detail,omitempty"`
+	IP            string          `json:"ip,omitempty"`
+}
+
+// InsertAuditLog appends an audit_logs row and returns the stored entry (with id/ts).
+func (s *Store) InsertAuditLog(ctx context.Context, e AuditEntry) (AuditEntry, error) {
+	if e.Action == "" {
+		return AuditEntry{}, fmt.Errorf("audit action is required")
+	}
+
+	var detail any
+	if len(e.Detail) > 0 {
+		if !json.Valid(e.Detail) {
+			return AuditEntry{}, fmt.Errorf("audit detail is not valid JSON")
+		}
+		detail = []byte(e.Detail)
+	}
+
+	const q = `
+INSERT INTO audit_logs (
+    actor_user_id, actor_username, action, target_type, target_id, summary, detail, ip
+) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
+RETURNING id, ts, actor_user_id, actor_username, action, target_type, target_id, summary, detail, ip
+`
+	var (
+		out       AuditEntry
+		actorUser pgtype.UUID
+		actorName pgtype.Text
+		targetTyp pgtype.Text
+		targetID  pgtype.Text
+		summary   pgtype.Text
+		detailOut []byte
+		ip        pgtype.Text
+	)
+	err := s.pool.QueryRow(ctx, q,
+		e.ActorUserID,
+		nullIfEmpty(e.ActorUsername),
+		e.Action,
+		nullIfEmpty(e.TargetType),
+		nullIfEmpty(e.TargetID),
+		nullIfEmpty(e.Summary),
+		detail,
+		nullIfEmpty(e.IP),
+	).Scan(
+		&out.ID,
+		&out.TS,
+		&actorUser,
+		&actorName,
+		&out.Action,
+		&targetTyp,
+		&targetID,
+		&summary,
+		&detailOut,
+		&ip,
+	)
+	if err != nil {
+		return AuditEntry{}, fmt.Errorf("insert audit log: %w", err)
+	}
+	if actorUser.Valid {
+		id := uuid.UUID(actorUser.Bytes)
+		out.ActorUserID = &id
+	}
+	out.ActorUsername = actorName.String
+	out.TargetType = targetTyp.String
+	out.TargetID = targetID.String
+	out.Summary = summary.String
+	out.IP = ip.String
+	if len(detailOut) > 0 {
+		out.Detail = json.RawMessage(detailOut)
+	}
+	return out, nil
+}
+
+func nullIfEmpty(s string) any {
+	if s == "" {
+		return nil
+	}
+	return s
+}
diff --git a/internal/store/migrate.go b/internal/store/migrate.go
new file mode 100644
index 0000000..9f870c1
--- /dev/null
+++ b/internal/store/migrate.go
@@ -0,0 +1,178 @@
+package store
+
+import (
+	"context"
+	"fmt"
+	"io/fs"
+	"path"
+	"regexp"
+	"sort"
+	"strings"
+
+	"github.com/jackc/pgx/v5/pgconn"
+
+	"github.com/wsp-security/wsp/migrations"
+)
+
+// schemaMigrationsDDL tracks applied migration versions.
+const schemaMigrationsDDL = `
+CREATE TABLE IF NOT EXISTS schema_migrations (
+    version    TEXT PRIMARY KEY,
+    applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
+);
+`
+
+var upMigrationName = regexp.MustCompile(`^(\d{3,})_([a-z0-9_]+)\.up\.sql$`)
+
+// Migrate applies all pending embedded *.up.sql migrations in version order.
+// Migrations are embedded from the root migrations package (production path).
+func (s *Store) Migrate(ctx context.Context) error {
+	return s.migrateFS(ctx, migrations.FS)
+}
+
+// migrateFS applies up migrations discovered in fsys (testable hook).
+func (s *Store) migrateFS(ctx context.Context, fsys fs.FS) error {
+	if _, err := s.pool.Exec(ctx, schemaMigrationsDDL); err != nil {
+		return fmt.Errorf("ensure schema_migrations: %w", err)
+	}
+
+	ups, err := listUpMigrations(fsys)
+	if err != nil {
+		return err
+	}
+
+	applied, err := s.appliedVersions(ctx)
+	if err != nil {
+		return err
+	}
+
+	for _, m := range ups {
+		if applied[m.version] {
+			continue
+		}
+		body, err := fs.ReadFile(fsys, m.path)
+		if err != nil {
+			return fmt.Errorf("read migration %s: %w", m.path, err)
+		}
+		if err := s.applyUp(ctx, m.version, string(body)); err != nil {
+			return err
+		}
+	}
+	return nil
+}
+
+type migrationFile struct {
+	version string // e.g. "001"
+	name    string // e.g. "init"
+	path    string // path within embed FS
+}
+
+func listUpMigrations(fsys fs.FS) ([]migrationFile, error) {
+	entries, err := fs.ReadDir(fsys, ".")
+	if err != nil {
+		return nil, fmt.Errorf("list migrations: %w", err)
+	}
+
+	var out []migrationFile
+	for _, e := range entries {
+		if e.IsDir() {
+			continue
+		}
+		name := e.Name()
+		m := upMigrationName.FindStringSubmatch(name)
+		if m == nil {
+			continue
+		}
+		out = append(out, migrationFile{
+			version: m[1],
+			name:    m[2],
+			path:    path.Clean(name),
+		})
+	}
+	sort.Slice(out, func(i, j int) bool {
+		if out[i].version != out[j].version {
+			return out[i].version < out[j].version
+		}
+		return out[i].name < out[j].name
+	})
+	return out, nil
+}
+
+func (s *Store) appliedVersions(ctx context.Context) (map[string]bool, error) {
+	rows, err := s.pool.Query(ctx, `SELECT version FROM schema_migrations`)
+	if err != nil {
+		return nil, fmt.Errorf("list applied migrations: %w", err)
+	}
+	defer rows.Close()
+
+	applied := make(map[string]bool)
+	for rows.Next() {
+		var v string
+		if err := rows.Scan(&v); err != nil {
+			return nil, fmt.Errorf("scan migration version: %w", err)
+		}
+		applied[v] = true
+	}
+	if err := rows.Err(); err != nil {
+		return nil, fmt.Errorf("iterate migration versions: %w", err)
+	}
+	return applied, nil
+}
+
+func (s *Store) applyUp(ctx context.Context, version, sqlBody string) error {
+	conn, err := s.pool.Acquire(ctx)
+	if err != nil {
+		return fmt.Errorf("acquire conn for migration %s: %w", version, err)
+	}
+	defer conn.Release()
+
+	// Multi-statement SQL files require the simple query protocol.
+	pgConn := conn.Conn().PgConn()
+	if err := execSimple(ctx, pgConn, "BEGIN"); err != nil {
+		return fmt.Errorf("begin migration %s: %w", version, err)
+	}
+	committed := false
+	defer func() {
+		if !committed {
+			_ = execSimple(context.Background(), pgConn, "ROLLBACK")
+		}
+	}()
+
+	if err := execSimple(ctx, pgConn, sqlBody); err != nil {
+		return fmt.Errorf("apply migration %s: %w", version, err)
+	}
+
+	tag, err := conn.Exec(ctx,
+		`INSERT INTO schema_migrations (version) VALUES ($1)`,
+		version,
+	)
+	if err != nil {
+		return fmt.Errorf("record migration %s: %w", version, err)
+	}
+	if tag.RowsAffected() != 1 {
+		return fmt.Errorf("record migration %s: expected 1 row, got %d", version, tag.RowsAffected())
+	}
+
+	if err := execSimple(ctx, pgConn, "COMMIT"); err != nil {
+		return fmt.Errorf("commit migration %s: %w", version, err)
+	}
+	committed = true
+	return nil
+}
+
+func execSimple(ctx context.Context, pgConn *pgconn.PgConn, sqlBody string) error {
+	sqlBody = strings.TrimSpace(sqlBody)
+	if sqlBody == "" {
+		return nil
+	}
+	results, err := pgConn.Exec(ctx, sqlBody).ReadAll()
+	if err != nil {
+		return err
+	}
+	for _, r := range results {
+		if r.Err != nil {
+			return r.Err
+		}
+	}
+	return nil
+}
diff --git a/internal/store/migrate_test.go b/internal/store/migrate_test.go
new file mode 100644
index 0000000..e26ffac
--- /dev/null
+++ b/internal/store/migrate_test.go
@@ -0,0 +1,40 @@
+package store
+
+import (
+	"testing"
+	"testing/fstest"
+)
+
+func TestListUpMigrations(t *testing.T) {
+	fsys := fstest.MapFS{
+		"001_init.up.sql":   {Data: []byte("-- up")},
+		"001_init.down.sql": {Data: []byte("-- down")},
+		"002_extra.up.sql":  {Data: []byte("-- up2")},
+		"readme.txt":        {Data: []byte("ignore")},
+		"003_bad.up":        {Data: []byte("ignore")},
+	}
+
+	got, err := listUpMigrations(fsys)
+	if err != nil {
+		t.Fatalf("listUpMigrations: %v", err)
+	}
+	if len(got) != 2 {
+		t.Fatalf("len = %d, want 2: %+v", len(got), got)
+	}
+	if got[0].version != "001" || got[0].name != "init" {
+		t.Errorf("first = %+v, want version=001 name=init", got[0])
+	}
+	if got[1].version != "002" || got[1].name != "extra" {
+		t.Errorf("second = %+v, want version=002 name=extra", got[1])
+	}
+}
+
+func TestListUpMigrationsEmpty(t *testing.T) {
+	got, err := listUpMigrations(fstest.MapFS{})
+	if err != nil {
+		t.Fatalf("listUpMigrations: %v", err)
+	}
+	if len(got) != 0 {
+		t.Fatalf("len = %d, want 0", len(got))
+	}
+}
diff --git a/internal/store/settings.go b/internal/store/settings.go
new file mode 100644
index 0000000..40b17eb
--- /dev/null
+++ b/internal/store/settings.go
@@ -0,0 +1,96 @@
+package store
+
+import (
+	"context"
+	"encoding/json"
+	"errors"
+	"fmt"
+	"time"
+
+	"github.com/jackc/pgx/v5"
+)
+
+// Setting keys seeded by 001_init (and used by later tasks).
+const (
+	SettingSetupCompleted     = "setup_completed"
+	SettingLogRetentionDays   = "log_retention_days"
+	SettingAuditRetentionDays = "audit_retention_days"
+	SettingDNSServers         = "dns_servers"
+	SettingProxyListen        = "proxy_listen"
+	SettingAdminListen        = "admin_listen"
+	SettingPlatform           = "platform"
+)
+
+// Setting is a key/JSONB value row from the settings table.
+type Setting struct {
+	Key       string          `json:"key"`
+	Value     json.RawMessage `json:"value"`
+	UpdatedAt time.Time       `json:"updated_at"`
+}
+
+// IsSetupComplete reports whether the first-run wizard finished
+// (settings.setup_completed JSON boolean true).
+func (s *Store) IsSetupComplete(ctx context.Context) (bool, error) {
+	raw, err := s.GetSetting(ctx, SettingSetupCompleted)
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return false, nil
+		}
+		return false, err
+	}
+	var v bool
+	if err := json.Unmarshal(raw, &v); err != nil {
+		return false, fmt.Errorf("parse setup_completed: %w", err)
+	}
+	return v, nil
+}
+
+// GetSetting returns the JSON value for key.
+func (s *Store) GetSetting(ctx context.Context, key string) (json.RawMessage, error) {
+	const q = `SELECT value FROM settings WHERE key = $1`
+	var raw []byte
+	err := s.pool.QueryRow(ctx, q, key).Scan(&raw)
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return nil, fmt.Errorf("setting %q: %w", key, err)
+		}
+		return nil, fmt.Errorf("get setting %q: %w", key, err)
+	}
+	return json.RawMessage(raw), nil
+}
+
+// SetSetting upserts a JSON value for key.
+func (s *Store) SetSetting(ctx context.Context, key string, value json.RawMessage) error {
+	if key == "" {
+		return fmt.Errorf("setting key is required")
+	}
+	if !json.Valid(value) {
+		return fmt.Errorf("setting value is not valid JSON")
+	}
+	const q = `
+INSERT INTO settings (key, value, updated_at)
+VALUES ($1, $2::jsonb, now())
+ON CONFLICT (key) DO UPDATE
+SET value = EXCLUDED.value, updated_at = now()
+`
+	if _, err := s.pool.Exec(ctx, q, key, []byte(value)); err != nil {
+		return fmt.Errorf("set setting %q: %w", key, err)
+	}
+	return nil
+}
+
+// GetSettingRow returns the full settings row for key.
+func (s *Store) GetSettingRow(ctx context.Context, key string) (Setting, error) {
+	const q = `SELECT key, value, updated_at FROM settings WHERE key = $1`
+	var st Setting
+	var raw []byte
+	err := s.pool.QueryRow(ctx, q, key).Scan(&st.Key, &raw, &st.UpdatedAt)
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return Setting{}, fmt.Errorf("setting %q: %w", key, err)
+		}
+		return Setting{}, fmt.Errorf("get setting row %q: %w", key, err)
+	}
+	st.Value = json.RawMessage(raw)
+	return st, nil
+}
diff --git a/internal/store/store.go b/internal/store/store.go
new file mode 100644
index 0000000..76e8757
--- /dev/null
+++ b/internal/store/store.go
@@ -0,0 +1,68 @@
+// Package store provides PostgreSQL persistence via pgx and a SQL migration runner.
+package store
+
+import (
+	"context"
+	"fmt"
+	"time"
+
+	"github.com/jackc/pgx/v5/pgxpool"
+)
+
+// Store is the shared PostgreSQL access layer for the WSP monolith.
+type Store struct {
+	pool *pgxpool.Pool
+}
+
+// New opens a connection pool to databaseURL and verifies connectivity.
+func New(ctx context.Context, databaseURL string) (*Store, error) {
+	if databaseURL == "" {
+		return nil, fmt.Errorf("database URL is empty")
+	}
+
+	cfg, err := pgxpool.ParseConfig(databaseURL)
+	if err != nil {
+		return nil, fmt.Errorf("parse database URL: %w", err)
+	}
+	// Reasonable defaults for a single-host modular monolith.
+	if cfg.MaxConns == 0 {
+		cfg.MaxConns = 10
+	}
+	cfg.MinConns = 1
+	cfg.MaxConnLifetime = time.Hour
+	cfg.HealthCheckPeriod = 30 * time.Second
+
+	pool, err := pgxpool.NewWithConfig(ctx, cfg)
+	if err != nil {
+		return nil, fmt.Errorf("connect pool: %w", err)
+	}
+
+	s := &Store{pool: pool}
+	if err := s.Ping(ctx); err != nil {
+		pool.Close()
+		return nil, err
+	}
+	return s, nil
+}
+
+// Close releases the connection pool.
+func (s *Store) Close() {
+	if s == nil || s.pool == nil {
+		return
+	}
+	s.pool.Close()
+}
+
+// Ping checks database connectivity.
+func (s *Store) Ping(ctx context.Context) error {
+	if err := s.pool.Ping(ctx); err != nil {
+		return fmt.Errorf("ping database: %w", err)
+	}
+	return nil
+}
+
+// Pool exposes the underlying pool for packages that need advanced queries.
+// Prefer typed store methods when available.
+func (s *Store) Pool() *pgxpool.Pool {
+	return s.pool
+}
diff --git a/internal/store/store_integration_test.go b/internal/store/store_integration_test.go
new file mode 100644
index 0000000..5596353
--- /dev/null
+++ b/internal/store/store_integration_test.go
@@ -0,0 +1,153 @@
+//go:build integration
+
+package store_test
+
+import (
+	"context"
+	"encoding/json"
+	"errors"
+	"os"
+	"testing"
+	"time"
+
+	"github.com/google/uuid"
+	"github.com/jackc/pgx/v5"
+
+	"github.com/wsp-security/wsp/internal/store"
+)
+
+func testDatabaseURL(t *testing.T) string {
+	t.Helper()
+	url := os.Getenv("WSP_DATABASE_URL")
+	if url == "" {
+		t.Skip("WSP_DATABASE_URL not set; skipping store integration tests")
+	}
+	return url
+}
+
+func openMigratedStore(t *testing.T) *store.Store {
+	t.Helper()
+	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
+	t.Cleanup(cancel)
+
+	s, err := store.New(ctx, testDatabaseURL(t))
+	if err != nil {
+		t.Fatalf("store.New: %v", err)
+	}
+	t.Cleanup(s.Close)
+
+	if err := s.Migrate(ctx); err != nil {
+		t.Fatalf("Migrate: %v", err)
+	}
+	// Idempotent second pass.
+	if err := s.Migrate(ctx); err != nil {
+		t.Fatalf("Migrate (second): %v", err)
+	}
+	return s
+}
+
+func TestIntegration_MigratePingAndSettings(t *testing.T) {
+	s := openMigratedStore(t)
+	ctx := context.Background()
+
+	if err := s.Ping(ctx); err != nil {
+		t.Fatalf("Ping: %v", err)
+	}
+
+	complete, err := s.IsSetupComplete(ctx)
+	if err != nil {
+		t.Fatalf("IsSetupComplete: %v", err)
+	}
+	if complete {
+		t.Fatalf("IsSetupComplete = true, want false after fresh seed")
+	}
+
+	raw, err := s.GetSetting(ctx, store.SettingLogRetentionDays)
+	if err != nil {
+		t.Fatalf("GetSetting log_retention_days: %v", err)
+	}
+	var days int
+	if err := json.Unmarshal(raw, &days); err != nil {
+		t.Fatalf("unmarshal retention: %v", err)
+	}
+	if days != 30 {
+		t.Errorf("log_retention_days = %d, want 30", days)
+	}
+}
+
+func TestIntegration_CreateAndGetUser(t *testing.T) {
+	s := openMigratedStore(t)
+	ctx := context.Background()
+
+	username := "itest_" + uuid.NewString()[:8]
+	created, err := s.CreateUser(ctx, store.User{
+		Username:     username,
+		PasswordHash: "argon2id$test-hash-not-real",
+		DisplayName:  "Integration Tester",
+		Role:         store.RoleAdmin,
+		Enabled:      true,
+	})
+	if err != nil {
+		t.Fatalf("CreateUser: %v", err)
+	}
+	if created.ID == uuid.Nil {
+		t.Fatal("CreateUser returned nil id")
+	}
+	if created.Username != username {
+		t.Errorf("username = %q, want %q", created.Username, username)
+	}
+	if created.Role != store.RoleAdmin {
+		t.Errorf("role = %q, want admin", created.Role)
+	}
+	if !created.Enabled {
+		t.Error("enabled = false, want true")
+	}
+	if created.CreatedAt.IsZero() || created.UpdatedAt.IsZero() {
+		t.Error("expected non-zero timestamps")
+	}
+
+	got, err := s.GetUserByUsername(ctx, username)
+	if err != nil {
+		t.Fatalf("GetUserByUsername: %v", err)
+	}
+	if got.ID != created.ID {
+		t.Errorf("id = %v, want %v", got.ID, created.ID)
+	}
+	if got.PasswordHash != "argon2id$test-hash-not-real" {
+		t.Errorf("password_hash mismatch")
+	}
+
+	_, err = s.GetUserByUsername(ctx, "does-not-exist-"+uuid.NewString())
+	if err == nil {
+		t.Fatal("expected error for missing user")
+	}
+	if !errors.Is(err, pgx.ErrNoRows) {
+		t.Errorf("missing user error = %v, want wrapped pgx.ErrNoRows", err)
+	}
+}
+
+func TestIntegration_AuditLog(t *testing.T) {
+	s := openMigratedStore(t)
+	ctx := context.Background()
+
+	entry, err := s.InsertAuditLog(ctx, store.AuditEntry{
+		Action:     "test.integration",
+		TargetType: "settings",
+		TargetID:   "setup_completed",
+		Summary:    "integration test audit row",
+		Detail:     json.RawMessage(`{"ok":true}`),
+		IP:         "127.0.0.1",
+	})
+	if err != nil {
+		t.Fatalf("InsertAuditLog: %v", err)
+	}
+	if entry.ID == uuid.Nil {
+		t.Fatal("audit id is nil")
+	}
+	if entry.TS.IsZero() {
+		t.Fatal("audit ts is zero")
+	}
+	if entry.Action != "test.integration" {
+		t.Errorf("action = %q", entry.Action)
+	}
+}
diff --git a/internal/store/users.go b/internal/store/users.go
new file mode 100644
index 0000000..c1489f0
--- /dev/null
+++ b/internal/store/users.go
@@ -0,0 +1,104 @@
+package store
+
+import (
+	"context"
+	"errors"
+	"fmt"
+	"time"
+
+	"github.com/google/uuid"
+	"github.com/jackc/pgx/v5"
+)
+
+// User roles stored in the users.role column.
+const (
+	RoleAdmin = "admin"
+	RoleUser  = "user"
+)
+
+// User is a platform account (admin UI and/or proxy identity).
+type User struct {
+	ID           uuid.UUID  `json:"id"`
+	Username     string     `json:"username"`
+	PasswordHash string     `json:"-"`
+	DisplayName  string     `json:"display_name"`
+	Role         string     `json:"role"`
+	Enabled      bool       `json:"enabled"`
+	CreatedAt    time.Time  `json:"created_at"`
+	UpdatedAt    time.Time  `json:"updated_at"`
+	LastLoginAt  *time.Time `json:"last_login_at,omitempty"`
+}
+
+// CreateUser inserts a new user and returns the row as stored (including generated id/timestamps).
+// Callers must set Username and PasswordHash; Role defaults to "user" when empty.
+// Enabled is stored as provided (set true for normal accounts).
+func (s *Store) CreateUser(ctx context.Context, u User) (User, error) {
+	if u.Username == "" {
+		return User{}, fmt.Errorf("username is required")
+	}
+	if u.PasswordHash == "" {
+		return User{}, fmt.Errorf("password_hash is required")
+	}
+	if u.Role == "" {
+		u.Role = RoleUser
+	}
+	if u.Role != RoleAdmin && u.Role != RoleUser {
+		return User{}, fmt.Errorf("invalid role %q", u.Role)
+	}
+
+	const q = `
+INSERT INTO users (username, password_hash, display_name, role, enabled)
+VALUES ($1, $2, $3, $4, $5)
+RETURNING id, username, password_hash, display_name, role, enabled, created_at, updated_at, last_login_at
+`
+	var out User
+	err := s.pool.QueryRow(ctx, q,
+		u.Username,
+		u.PasswordHash,
+		u.DisplayName,
+		u.Role,
+		u.Enabled,
+	).Scan(
+		&out.ID,
+		&out.Username,
+		&out.PasswordHash,
+		&out.DisplayName,
+		&out.Role,
+		&out.Enabled,
+		&out.CreatedAt,
+		&out.UpdatedAt,
+		&out.LastLoginAt,
+	)
+	if err != nil {
+		return User{}, fmt.Errorf("create user: %w", err)
+	}
+	return out, nil
+}
+
+// GetUserByUsername returns the user with the given username.
+func (s *Store) GetUserByUsername(ctx context.Context, username string) (User, error) {
+	const q = `
+SELECT id, username, password_hash, display_name, role, enabled, created_at, updated_at, last_login_at
+FROM users
+WHERE username = $1
+`
+	var out User
+	err := s.pool.QueryRow(ctx, q, username).Scan(
+		&out.ID,
+		&out.Username,
+		&out.PasswordHash,
+		&out.DisplayName,
+		&out.Role,
+		&out.Enabled,
+		&out.CreatedAt,
+		&out.UpdatedAt,
+		&out.LastLoginAt,
+	)
+	if err != nil {
+		if errors.Is(err, pgx.ErrNoRows) {
+			return User{}, fmt.Errorf("user %q: %w", username, err)
+		}
+		return User{}, fmt.Errorf("get user by username: %w", err)
+	}
+	return out, nil
+}
diff --git a/migrations/embed.go b/migrations/embed.go
new file mode 100644
index 0000000..53adf3c
--- /dev/null
+++ b/migrations/embed.go
@@ -0,0 +1,9 @@
+// Package migrations embeds ordered SQL migration files for the store runner.
+package migrations
+
+import "embed"
+
+// FS contains *.sql migration files (NNN_name.up.sql / NNN_name.down.sql).
+//
+//go:embed *.sql
+var FS embed.FS
