// Package migrations embeds ordered SQL migration files for the store runner.
package migrations

import "embed"

// FS contains *.sql migration files (NNN_name.up.sql / NNN_name.down.sql).
//
//go:embed *.sql
var FS embed.FS
