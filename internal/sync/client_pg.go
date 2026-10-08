package sync

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// PgSink upserts rows into cx_mirror.<kind> (id text PK, seq bigint, at timestamptz, row jsonb);
// a delete removes the id. The schema and per-kind tables are created on demand.
type PgSink struct {
	Ctx   context.Context
	Conn  *pgx.Conn
	ready map[string]bool
}

// NewPgSink connects to url and returns a sink; the caller Closes it (which closes the conn).
func NewPgSink(ctx context.Context, url string) (*PgSink, error) {
	conn, err := pgx.Connect(ctx, url)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Exec(ctx, `CREATE SCHEMA IF NOT EXISTS cx_mirror`); err != nil {
		conn.Close(ctx)
		return nil, err
	}
	return &PgSink{Ctx: ctx, Conn: conn, ready: map[string]bool{}}, nil
}

// ensure creates cx_mirror.<kind> once per kind. The kind is from the fixed sync set, so the
// identifier is safe to interpolate; it is validated regardless.
func (p *PgSink) ensure(kind string) (string, error) {
	if !pathSafe(kind) {
		return "", fmt.Errorf("sync: bad kind %q", kind)
	}
	tbl := "cx_mirror." + pgx.Identifier{kind}.Sanitize()
	if p.ready[kind] {
		return tbl, nil
	}
	ddl := fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id text PRIMARY KEY, seq bigint NOT NULL, at timestamptz NOT NULL, row jsonb NOT NULL)`, tbl)
	if _, err := p.Conn.Exec(p.Ctx, ddl); err != nil {
		return "", err
	}
	p.ready[kind] = true
	return tbl, nil
}

func (p *PgSink) Upsert(l wireLine, _ map[string]any) error {
	tbl, err := p.ensure(l.Kind)
	if err != nil {
		return err
	}
	_, err = p.Conn.Exec(p.Ctx, fmt.Sprintf(`INSERT INTO %s (id, seq, at, row) VALUES ($1, $2, $3, $4)
		ON CONFLICT (id) DO UPDATE SET seq = EXCLUDED.seq, at = EXCLUDED.at, row = EXCLUDED.row
		WHERE %s.seq <= EXCLUDED.seq`, tbl, tbl), l.ID, l.Seq, l.At, []byte(l.Row))
	return err
}

func (p *PgSink) Delete(l wireLine) error {
	tbl, err := p.ensure(l.Kind)
	if err != nil {
		return err
	}
	_, err = p.Conn.Exec(p.Ctx, fmt.Sprintf(`DELETE FROM %s WHERE id = $1`, tbl), l.ID)
	return err
}

func (p *PgSink) Close() error {
	if p.Conn == nil {
		return nil
	}
	return p.Conn.Close(p.Ctx)
}
