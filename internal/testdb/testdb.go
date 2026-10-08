// Package testdb gives every package's tests an isolated database (commons_t_<pkg>) created from
// TEST_PG_ADMIN_URL (default postgres://cx@127.0.0.1:55432/postgres), so parallel builders never race.
package testdb

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DefaultAdminURL is used when TEST_PG_ADMIN_URL is set to "default".
const DefaultAdminURL = "postgres://cx@127.0.0.1:55432/postgres?sslmode=disable"

var pkgRe = regexp.MustCompile(`[^a-z0-9_]+`)

// Name is the database name for a package: commons_t_<pkg> (lowercased, non [a-z0-9_] -> _).
func Name(pkg string) string {
	n := pkgRe.ReplaceAllString(strings.ToLower(pkg), "_")
	if len(n) > 50 {
		n = n[:50]
	}
	return "commons_t_" + strings.Trim(n, "_")
}

// AdminURL returns TEST_PG_ADMIN_URL ("default" -> DefaultAdminURL); empty when unset.
func AdminURL() string {
	u := os.Getenv("TEST_PG_ADMIN_URL")
	if u == "default" {
		return DefaultAdminURL
	}
	return u
}

// Open drops and recreates commons_t_<pkg>, connects a pool to it, runs migrate (when non-nil) and
// returns the pool plus a cleanup that closes it and drops the database. When TEST_PG_ADMIN_URL is
// unset it returns (nil, no-op) and the caller skips its DB tests.
func Open(pkg string, migrate func(context.Context, *pgxpool.Pool) error) (*pgxpool.Pool, func()) {
	admin := AdminURL()
	if admin == "" {
		return nil, func() {}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	name := Name(pkg)
	if err := recreate(ctx, admin, name); err != nil {
		panic(fmt.Sprintf("testdb %s: %v", name, err))
	}
	dbURL, err := withDatabase(admin, name)
	if err != nil {
		panic(err)
	}
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		panic(fmt.Sprintf("testdb %s: %v", name, err))
	}
	if migrate != nil {
		if err := migrate(ctx, pool); err != nil {
			pool.Close()
			panic(fmt.Sprintf("testdb %s migrate: %v", name, err))
		}
	}
	return pool, func() {
		pool.Close()
		dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dcancel()
		if conn, err := pgx.Connect(dctx, admin); err == nil {
			conn.Exec(dctx, `DROP DATABASE IF EXISTS `+pgx.Identifier{name}.Sanitize()+` WITH (FORCE)`)
			conn.Close(dctx)
		}
	}
}

// URL returns the connection URL of a package database (for tests that need a second pool).
func URL(pkg string) (string, error) {
	admin := AdminURL()
	if admin == "" {
		return "", fmt.Errorf("TEST_PG_ADMIN_URL unset")
	}
	return withDatabase(admin, Name(pkg))
}

func recreate(ctx context.Context, admin, name string) error {
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		return err
	}
	defer conn.Close(ctx)
	id := pgx.Identifier{name}.Sanitize()
	if _, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS `+id+` WITH (FORCE)`); err != nil {
		return err
	}
	_, err = conn.Exec(ctx, `CREATE DATABASE `+id)
	return err
}

func withDatabase(admin, name string) (string, error) {
	u, err := url.Parse(admin)
	if err != nil {
		return "", fmt.Errorf("TEST_PG_ADMIN_URL: %w", err)
	}
	u.Path = "/" + name
	return u.String(), nil
}
