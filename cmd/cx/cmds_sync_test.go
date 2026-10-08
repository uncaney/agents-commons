package main

import (
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/export"
	"ekaii.fr/commons/internal/sign"
	csync "ekaii.fr/commons/internal/sync"
	"ekaii.fr/commons/internal/testdb"
)

// scratchSyncURL derives a per-package database from TEST_DATABASE_URL (creating it if needed) so
// the P111 test packages, which share one base URL, never race one another under `go test -p 2`.
func scratchSyncURL(suffix string) string {
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
		conn.Exec(ctx, "CREATE DATABASE "+pgx.Identifier{newName}.Sanitize())
		conn.Close(ctx)
	}
	out := *u
	out.Path = "/" + newName
	return out.String()
}

// syncServer brings up a real gateway (core + sign + export + sync) over a scratch database and
// returns its URL plus the pool, or skips when no database is reachable.
func syncServer(t *testing.T) (string, *pgxpool.Pool) {
	t.Helper()
	ctx := context.Background()
	var pool *pgxpool.Pool
	if url := scratchSyncURL("cxcmd"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			t.Fatal(err)
		}
		if err := core.Migrate(ctx, p); err != nil {
			t.Fatal(err)
		}
		pool = p
	} else if p, done := testdb.Open("cxcmd", core.Migrate); p != nil {
		pool = p
		t.Cleanup(done)
	} else {
		t.Skip("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping cx sync DB test")
	}
	t.Cleanup(pool.Close)
	for _, sql := range []string{
		`TRUNCATE sync_log, kb, kb_tombstones, tasks, claims, digests, events, identities CASCADE`,
		`UPDATE sync_cursor SET ev_seq = 0`,
		`DELETE FROM flags WHERE k LIKE 'sync:%' OR k LIKE 'export:%' OR k LIKE 'shed:%' OR k LIKE 'freeze:%'`,
	} {
		if _, err := pool.Exec(ctx, sql); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: dir,
		ExportDir: filepath.Join(dir, "export"), TrustCF: true, PublicURL: "https://agents.example",
		LicenseContent: "CC0-1.0", SignKID: 1, RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	if _, err := sign.Init(cfg); err != nil {
		t.Fatal(err)
	}
	d, err := core.NewDeps(ctx, cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	core.Register(mux, d)
	sign.Register(mux, d)
	export.Register(mux, d)
	csync.Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	return srv.URL, pool
}

func TestCxSyncCommand(t *testing.T) {
	url, pool := syncServer(t)
	ctx := context.Background()

	// A visible kb row and a hidden one, both distilled into the replication log.
	root := core.NewID('a')
	tok := make([]byte, 32)
	rand.Read(tok)
	if _, err := pool.Exec(ctx, `INSERT INTO identities (id, name, root, token_hash, rep, created, verified_noncompute)
		VALUES ($1, $1, $1, $2, 10, now() - interval '5 days', 1)`, root, tok); err != nil {
		t.Fatal(err)
	}
	id := core.NewID('k')
	if _, err := pool.Exec(ctx, `INSERT INTO kb (id, kind, title, symptom, cause, fix, versions, tags, author, author_root, ok_w,
		created, expires_at, hidden, quarantine, seed, space, superseded_by)
		VALUES ($1, 'fix', 'cx sync fix', 'symptom', 'cause', 'the fix body', '', '{}', $2, $2, 0,
		now() - interval '2 hours', now() + interval '100 days', false, false, false, '', '')`, id, root); err != nil {
		t.Fatal(err)
	}
	if err := core.Event(ctx, pool, "kb", id, "", "cx sync fix"); err != nil {
		t.Fatal(err)
	}
	if _, err := csync.Distill(ctx, pool); err != nil {
		t.Fatal(err)
	}

	// Drive the registered `cx sync` verb through the CLI, pointed at the test gateway.
	dir := t.TempDir()
	env := map[string]string{"CX_URL": url}
	c := newCLI(func(k string) string { return env[k] })
	var out strings.Builder
	c.stdout = &out
	if err := c.run(ctx, []string{"sync", "--to", "md", dir}); err != nil {
		t.Fatalf("cx sync: %v", err)
	}
	if !strings.Contains(out.String(), "synced") {
		t.Fatalf("unexpected output %q", out.String())
	}
	b, err := os.ReadFile(filepath.Join(dir, "kb", id+".md"))
	if err != nil {
		t.Fatalf("cx sync did not mirror the row: %v", err)
	}
	if !strings.Contains(string(b), `id: "`+id+`"`) || !strings.Contains(string(b), "the fix body") {
		t.Fatalf("front matter wrong:\n%s", b)
	}
	// The verb is registered and shows in help.
	if !strings.Contains(helpFor("sync"), "sync") {
		t.Fatalf("sync verb missing from help")
	}
}
