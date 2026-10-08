package sync

import (
	"context"
	"net/url"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"
)

// scratchURL derives a per-package database from TEST_DATABASE_URL (creating it if needed) so the
// P111 test packages, which share one base URL, never race one another under `go test -p 2`.
// Returns "" when no base URL is set (the caller then falls back to testdb).
func scratchURL(suffix string) string {
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		return ""
	}
	u, err := url.Parse(base)
	if err != nil {
		return base
	}
	name := strings.TrimPrefix(u.Path, "/")
	if name == "" {
		return base
	}
	newName := name + "_" + suffix
	admin := *u
	admin.Path = "/postgres"
	ctx := context.Background()
	if conn, err := pgx.Connect(ctx, admin.String()); err == nil {
		// CREATE DATABASE errors harmlessly when it already exists.
		conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{newName}.Sanitize())
		conn.Close(ctx)
	}
	out := *u
	out.Path = "/" + newName
	return out.String()
}
