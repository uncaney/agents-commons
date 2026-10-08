package core

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

//go:embed migrations/*.sql
var migrationFS embed.FS

// Q is satisfied by *pgxpool.Pool, *pgxpool.Conn and pgx.Tx so helpers work inside or outside a tx.
type Q interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// Pool timeouts (21.1): request pool 8 s / 2 s / 10 s, janitor+admin pool 25 s.
const (
	reqStatementTimeout = 8 * time.Second
	reqLockTimeout      = 2 * time.Second
	reqIdleTxTimeout    = 10 * time.Second
	opsTimeout          = 25 * time.Second
)

// connTimeouts returns an AfterConnect hook setting the session timeouts.
func connTimeouts(stmt, lock, idle time.Duration) func(context.Context, *pgx.Conn) error {
	ms := func(d time.Duration) string { return strconv.FormatInt(d.Milliseconds(), 10) }
	sql := fmt.Sprintf(`SET statement_timeout = '%sms'; SET lock_timeout = '%sms'; SET idle_in_transaction_session_timeout = '%sms'`,
		ms(stmt), ms(lock), ms(idle))
	return func(ctx context.Context, c *pgx.Conn) error {
		_, err := c.Exec(ctx, sql)
		return err
	}
}

// OpenDB connects the request pool (16 conns, 21.1 timeouts), pings and runs migrations on a
// dedicated connection.
func OpenDB(ctx context.Context, url string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 16
	cfg.MaxConnIdleTime = 5 * time.Minute
	cfg.AfterConnect = connTimeouts(reqStatementTimeout, reqLockTimeout, reqIdleTxTimeout)
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := pool.Ping(pctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("db ping: %w", err)
	}
	if err := Migrate(ctx, pool); err != nil {
		pool.Close()
		return nil, err
	}
	return pool, nil
}

// OpsPool derives the second pool (janitor + admin, MaxConns 2, 25 s timeouts) from a pool's config.
func OpsPool(ctx context.Context, pool *pgxpool.Pool) (*pgxpool.Pool, error) {
	cfg := pool.Config()
	cfg.MaxConns = 2
	cfg.MinConns = 0
	cfg.MaxConnIdleTime = time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	cfg.AfterConnect = connTimeouts(opsTimeout, opsTimeout, opsTimeout)
	return pgxpool.NewWithConfig(ctx, cfg)
}

const migrateLock = 0x636f6d6d6f6e73 // "commons"

// Migrate applies embedded migrations/NNNN_*.sql not yet in schema_migrations, in one
// transaction under an advisory lock, on a dedicated connection (never a pooled one) with
// lock_timeout 30 s and no statement timeout. Idempotent and safe across concurrent gateways.
func Migrate(ctx context.Context, pool *pgxpool.Pool) error {
	conn, err := pgx.ConnectConfig(ctx, pool.Config().ConnConfig)
	if err != nil {
		return fmt.Errorf("migrate connect: %w", err)
	}
	defer conn.Close(context.Background())
	if _, err := conn.Exec(ctx, `SET lock_timeout = '30s'; SET statement_timeout = 0; SET idle_in_transaction_session_timeout = 0`); err != nil {
		return err
	}
	return migrateOn(ctx, conn)
}

func migrateOn(ctx context.Context, conn *pgx.Conn) error {
	files, err := fs.Glob(migrationFS, "migrations/*.sql")
	if err != nil {
		return err
	}
	sort.Strings(files)
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1)`, int64(migrateLock)); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS schema_migrations (version int PRIMARY KEY, applied timestamptz NOT NULL DEFAULT now())`); err != nil {
		return err
	}
	applied := map[int]bool{}
	rows, err := tx.Query(ctx, `SELECT version FROM schema_migrations`)
	if err != nil {
		return err
	}
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			rows.Close()
			return err
		}
		applied[v] = true
	}
	rows.Close()
	for _, f := range files {
		base := strings.TrimPrefix(f, "migrations/")
		v, err := strconv.Atoi(strings.SplitN(base, "_", 2)[0])
		if err != nil {
			return fmt.Errorf("migration %s: bad version prefix", f)
		}
		if applied[v] {
			continue
		}
		sql, _ := migrationFS.ReadFile(f)
		if _, err := tx.Exec(ctx, string(sql)); err != nil {
			return fmt.Errorf("migration %s: %w", f, err)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, v); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Tx runs fn in a transaction, committing on nil error.
func Tx(ctx context.Context, pool *pgxpool.Pool, fn func(tx pgx.Tx) error) error {
	tx, err := pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// IsUniqueViolation reports a 23505 error.
func IsUniqueViolation(err error) bool {
	var pe *pgconn.PgError
	return errors.As(err, &pe) && pe.Code == "23505"
}
