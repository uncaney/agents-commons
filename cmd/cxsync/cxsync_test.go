package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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

var testPool *pgxpool.Pool
var testURL string

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := scratchURL("cxsync"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, testURL, cleanup = pool, url, pool.Close
	} else if pool, done := testdb.Open("cxsync", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
		testURL = os.Getenv("TEST_DATABASE_URL")
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping cxsync DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	ctx := context.Background()
	for _, sql := range []string{
		`TRUNCATE sync_log, kb, kb_tombstones, tasks, claims, digests, events, identities CASCADE`,
		`UPDATE sync_cursor SET ev_seq = 0`,
		`DROP SCHEMA IF EXISTS cx_mirror CASCADE`,
		`DELETE FROM flags WHERE k LIKE 'sync:%' OR k LIKE 'export:%' OR k LIKE 'shed:%' OR k LIKE 'freeze:%'`,
	} {
		if _, err := testPool.Exec(ctx, sql); err != nil {
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
	d, err := core.NewDeps(ctx, cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
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
	return &tenv{d: d, srv: srv}
}

func (e *tenv) identity(t *testing.T) string {
	t.Helper()
	id := core.NewID('a')
	b := make([]byte, 32)
	rand.Read(b)
	_, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, root, token_hash, rep, created, verified_noncompute)
		VALUES ($1, $1, $1, $2, 10, now() - interval '5 days', 1)`, id, b)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *tenv) kb(t *testing.T, root, title string, hidden bool) string {
	t.Helper()
	ctx := context.Background()
	id := core.NewID('k')
	_, err := testPool.Exec(ctx, `INSERT INTO kb (id, kind, title, symptom, cause, fix, versions, tags, author, author_root, ok_w,
		created, expires_at, hidden, quarantine, seed, space, superseded_by)
		VALUES ($1, 'fix', $2, 'symptom', 'cause', 'the fix body', '', '{}', $3, $3, 0, now() - interval '2 hours',
		now() + interval '100 days', $4, false, false, '', '')`, id, title, root, hidden)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Event(ctx, testPool, "kb", id, "", title); err != nil {
		t.Fatal(err)
	}
	return id
}

func (e *tenv) distill(t *testing.T) {
	t.Helper()
	if _, err := csync.Distill(context.Background(), testPool); err != nil {
		t.Fatal(err)
	}
}

func runCx(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, func(string) string { return "" }, &out, &errb, http.DefaultClient)
	return code, out.String(), errb.String()
}

func TestCxsyncMdMirror(t *testing.T) {
	e := newEnv(t)
	root := e.identity(t)
	id := e.kb(t, root, "visible md fix", false)
	hid := e.kb(t, root, "hidden md fix", true)
	e.distill(t)

	dir := t.TempDir()
	code, _, errs := runCx(t, "--url", e.srv.URL, "--to", "md", dir)
	if code != 0 {
		t.Fatalf("cxsync exit %d: %s", code, errs)
	}
	// The visible row becomes a front-matter file; the hidden row never touches disk.
	p := filepath.Join(dir, "kb", id+".md")
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatalf("expected %s: %v", p, err)
	}
	s := string(b)
	if !strings.HasPrefix(s, "---\n") || !strings.Contains(s, `id: "`+id+`"`) || !strings.Contains(s, "the fix body") {
		t.Fatalf("front matter wrong:\n%s", s)
	}
	if _, err := os.Stat(filepath.Join(dir, "kb", hid+".md")); !os.IsNotExist(err) {
		t.Fatalf("hidden row leaked a file: %v", err)
	}
	// Cursor advanced; a re-run with no new rows applies nothing.
	if _, err := os.Stat(filepath.Join(dir, csync.CursorName)); err != nil {
		t.Fatalf("cursor file missing: %v", err)
	}
	// Hide the visible row, distill, re-run: the tombstone deletes the mirrored file.
	if _, err := testPool.Exec(context.Background(), `UPDATE kb SET hidden = true WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	if err := core.Event(context.Background(), testPool, "kb", id, "", "hidden now"); err != nil {
		t.Fatal(err)
	}
	e.distill(t)
	if code, _, errs := runCx(t, "--url", e.srv.URL, "--to", "md", dir); code != 0 {
		t.Fatalf("second cxsync exit %d: %s", code, errs)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Fatalf("tombstone did not remove the file: %v", err)
	}
}

func TestCxsyncPgMirror(t *testing.T) {
	if testURL == "" {
		t.Skip("TEST_DATABASE_URL unset: pg mirror needs a reachable url")
	}
	e := newEnv(t)
	root := e.identity(t)
	id := e.kb(t, root, "pg mirror fix", false)
	hid := e.kb(t, root, "pg hidden fix", true)
	e.distill(t)

	ctx := context.Background()
	dir := t.TempDir()
	code, _, errs := runCx(t, "--url", e.srv.URL, "--to", "pg", testURL, "--cursor", filepath.Join(dir, ".cur"))
	if code != 0 {
		t.Fatalf("cxsync pg exit %d: %s", code, errs)
	}
	conn, err := pgx.Connect(ctx, testURL)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close(ctx)
	var n int
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM cx_mirror.kb WHERE id = $1`, id).Scan(&n); err != nil {
		t.Fatalf("query mirror: %v", err)
	}
	if n != 1 {
		t.Fatalf("cx_mirror.kb has %d rows for the visible id, want 1", n)
	}
	// The hidden row is a delete: it must not appear in the mirror.
	if err := conn.QueryRow(ctx, `SELECT count(*) FROM cx_mirror.kb WHERE id = $1`, hid).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("hidden row present in mirror")
	}
	var origin string
	if err := conn.QueryRow(ctx, `SELECT row->>'origin' FROM cx_mirror.kb WHERE id = $1`, id).Scan(&origin); err != nil {
		t.Fatal(err)
	}
	if origin != "self" {
		t.Fatalf("mirrored row origin = %q, want self", origin)
	}
}

func TestCxsyncVerifiesSig(t *testing.T) {
	e := newEnv(t)
	root := e.identity(t)
	id := e.kb(t, root, "must verify", false)
	e.distill(t)

	// A wrong pinned key makes every signed row fail verification: nothing is written and the
	// tool fails loudly.
	wrong := make([]byte, 32)
	rand.Read(wrong)
	dir := t.TempDir()
	code, _, errs := runCx(t, "--url", e.srv.URL, "--to", "md", dir, "--key", hex.EncodeToString(wrong))
	if code == 0 {
		t.Fatalf("cxsync accepted a row under the wrong key")
	}
	if !strings.Contains(errs, "signature") {
		t.Fatalf("expected a signature error, got %q", errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "kb", id+".md")); !os.IsNotExist(err) {
		t.Fatalf("a file was written despite a bad signature: %v", err)
	}

	// The real server key (fetched from /.well-known/cx-key) verifies and writes.
	dir2 := t.TempDir()
	if code, _, errs := runCx(t, "--url", e.srv.URL, "--to", "md", dir2); code != 0 {
		t.Fatalf("cxsync with the real key failed: %d %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir2, "kb", id+".md")); err != nil {
		t.Fatalf("real key did not write the row: %v", err)
	}
}
