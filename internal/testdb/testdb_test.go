package testdb

import (
	"context"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestName(t *testing.T) {
	for in, want := range map[string]string{"core": "commons_t_core", "P11-kb-core": "commons_t_p11_kb_core", "x.y/z": "commons_t_x_y_z"} {
		if got := Name(in); got != want {
			t.Errorf("Name(%q)=%q want %q", in, got, want)
		}
	}
}

func TestOpenCreatesAndDrops(t *testing.T) {
	admin := AdminURL()
	if admin == "" {
		t.Skip("TEST_PG_ADMIN_URL unset")
	}
	pkg := fmt.Sprintf("scratch_%d", os.Getpid())
	migrated := false
	pool, cleanup := Open(pkg, func(ctx context.Context, p *pgxpool.Pool) error {
		migrated = true
		_, err := p.Exec(ctx, `CREATE TABLE t_probe (id int)`)
		return err
	})
	if pool == nil || !migrated {
		t.Fatal("Open returned nil pool or skipped migrate")
	}
	ctx := context.Background()
	var db string
	if err := pool.QueryRow(ctx, `SELECT current_database()`).Scan(&db); err != nil || db != Name(pkg) {
		t.Fatalf("current_database=%q err=%v", db, err)
	}
	var n int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM t_probe`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	cleanup()
	conn, err := pgx.Connect(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var exists bool
	conn.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_database WHERE datname = $1)`, Name(pkg)).Scan(&exists)
	if exists {
		t.Fatal("database not dropped by cleanup")
	}
	if p, c := Open(pkg, nil); p == nil {
		t.Fatal("reopen without migrate")
	} else {
		c()
	}
}

func TestOpenSkipsWhenUnset(t *testing.T) {
	t.Setenv("TEST_PG_ADMIN_URL", "")
	pool, cleanup := Open("never", nil)
	if pool != nil {
		t.Fatal("expected nil pool")
	}
	cleanup()
}
