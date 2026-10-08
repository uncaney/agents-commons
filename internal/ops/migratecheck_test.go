package ops

import (
	"context"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// preflightDSN creates <test db>_pf next to the test database (dropped at cleanup) and returns its URL.
func preflightDSN(t *testing.T) string {
	t.Helper()
	u, err := url.Parse(testDSN)
	if err != nil {
		t.Fatal(err)
	}
	name := strings.TrimPrefix(u.Path, "/") + "_pf"
	admin := *u
	admin.Path = "/postgres"
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, admin.String())
	if err != nil {
		t.Fatal(err)
	}
	id := pgx.Identifier{name}.Sanitize()
	if _, err := conn.Exec(ctx, `DROP DATABASE IF EXISTS `+id+` WITH (FORCE)`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `CREATE DATABASE `+id); err != nil {
		t.Fatal(err)
	}
	conn.Close(ctx)
	t.Cleanup(func() {
		dctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if c, err := pgx.Connect(dctx, admin.String()); err == nil {
			c.Exec(dctx, `DROP DATABASE IF EXISTS `+id+` WITH (FORCE)`)
			c.Close(dctx)
		}
	})
	pf := *u
	pf.Path = "/" + name
	return pf.String()
}

func TestMigrateCheckReportsLockWait(t *testing.T) {
	dsn := preflightDSN(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	rep, err := MigrateCheck(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Before) != 0 || len(rep.Applied) == 0 || len(rep.After) != len(rep.Applied) || rep.Elapsed <= 0 {
		t.Fatalf("first run: %+v", rep)
	}
	has300 := false
	for _, v := range rep.Applied {
		has300 = has300 || v == 300
	}
	if !has300 || !strings.HasSuffix(rep.Database, "_pf") {
		t.Fatalf("applied %v db %q", rep.Applied, rep.Database)
	}
	if l := rep.Line(); !strings.HasPrefix(l, "migrate-check db="+rep.Database+" applied=") || !strings.Contains(l, "0300") || !strings.Contains(l, "lock_wait_max=") {
		t.Fatalf("line %q", l)
	}
	// Nothing pending: a second run applies nothing and still reports.
	rep, err = MigrateCheck(ctx, dsn)
	if err != nil || len(rep.Applied) != 0 || len(rep.Before) != len(rep.After) {
		t.Fatalf("idempotent run: %v %+v", err, rep)
	}
	// Contention: another session holds schema_migrations for 1.2 s; the check waits on it and
	// reports the longest lock wait it observed.
	holder, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close(context.Background())
	tx, err := holder.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `LOCK TABLE schema_migrations IN ACCESS EXCLUSIVE MODE`); err != nil {
		t.Fatal(err)
	}
	released := make(chan struct{})
	go func() {
		time.Sleep(1200 * time.Millisecond)
		tx.Rollback(ctx)
		close(released)
	}()
	start := time.Now()
	rep, err = MigrateCheck(ctx, dsn)
	<-released
	if err != nil {
		t.Fatal(err)
	}
	if took := time.Since(start); took < time.Second {
		t.Fatalf("check did not wait on the lock (took %s)", took)
	}
	if rep.LongestLockWait < 500*time.Millisecond || rep.WaitSamples == 0 {
		t.Fatalf("lock wait not reported: %+v", rep)
	}
	if !strings.Contains(rep.Line(), "lock_wait_max=1.") && !strings.Contains(rep.Line(), "lock_wait_max=2.") {
		t.Fatalf("line %q", rep.Line())
	}
	if _, err := MigrateCheck(ctx, "postgres://cx@127.0.0.1:1/nope?sslmode=disable&connect_timeout=1"); err == nil {
		t.Fatal("unreachable database must fail")
	}
}
