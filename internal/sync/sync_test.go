package sync

import (
	"bufio"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/export"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := scratchURL("sync"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("sync", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping sync DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	s   *Service
	srv *httptest.Server
	dir string
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	ctx := context.Background()
	for _, sql := range []string{
		`TRUNCATE sync_log, kb, kb_tombstones, tasks, claims, digests, events, identities CASCADE`,
		`UPDATE sync_cursor SET ev_seq = 0`,
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
	export.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	return &tenv{d: d, s: New(d), srv: srv, dir: cfg.ExportDir}
}

func randBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func (e *tenv) identity(t *testing.T) string {
	t.Helper()
	id := core.NewID('a')
	_, err := testPool.Exec(context.Background(), `INSERT INTO identities (id, name, root, token_hash, rep, created, verified_noncompute)
		VALUES ($1, $1, $1, $2, 10, now() - interval '5 days', 1)`, id, randBytes(32))
	if err != nil {
		t.Fatal(err)
	}
	return id
}

type kbIn struct {
	title, fix         string
	hidden, quarantine bool
}

// kbEntry inserts a kb row and emits its "kb" event, returning the id.
func (e *tenv) kbEntry(t *testing.T, root string, in kbIn) string {
	t.Helper()
	ctx := context.Background()
	id := core.NewID('k')
	if in.title == "" {
		in.title = "ECONNRESET during npm ci " + id
	}
	if in.fix == "" {
		in.fix = "retry with a clean cache"
	}
	_, err := testPool.Exec(ctx, `INSERT INTO kb (id, kind, title, symptom, cause, fix, versions, tags, author, author_root, ok_w,
		created, expires_at, hidden, quarantine, seed, space, superseded_by)
		VALUES ($1, 'fix', $2, 'symptom', 'cause', $3, '', '{}', $4, $4, 0, now() - interval '2 hours', now() + interval '100 days',
		$5, $6, false, '', '')`, id, in.title, in.fix, root, in.hidden, in.quarantine)
	if err != nil {
		t.Fatal(err)
	}
	if err := core.Event(ctx, testPool, "kb", id, "", in.title); err != nil {
		t.Fatal(err)
	}
	return id
}

// getSync fetches one page of /v1/sync and returns the parsed wire lines plus the raw body.
func (e *tenv) getSync(t *testing.T, query string) ([]wireLine, string, *http.Response) {
	t.Helper()
	resp, err := http.Get(e.srv.URL + "/v1/sync" + query)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	var lines []wireLine
	sc := bufio.NewScanner(strings.NewReader(string(body)))
	sc.Buffer(make([]byte, 1<<16), 1<<20)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		var l wireLine
		if err := json.Unmarshal(sc.Bytes(), &l); err != nil {
			t.Fatalf("bad NDJSON line %q: %v", sc.Text(), err)
		}
		lines = append(lines, l)
	}
	return lines, string(body), resp
}

func TestSyncLogFromEvents(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t)
	k1 := e.kbEntry(t, root, kbIn{title: "first fix"})
	k2 := e.kbEntry(t, root, kbIn{title: "second fix"})

	n, err := Distill(ctx, testPool)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("distilled %d rows, want 2", n)
	}
	// A second distill with no new events is a no-op.
	if n2, err := Distill(ctx, testPool); err != nil || n2 != 0 {
		t.Fatalf("re-distill n=%d err=%v, want 0/nil", n2, err)
	}
	var rows []struct {
		kind, id, op string
	}
	r, err := testPool.Query(ctx, `SELECT kind, id, op FROM sync_log ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	for r.Next() {
		var x struct{ kind, id, op string }
		if err := r.Scan(&x.kind, &x.id, &x.op); err != nil {
			t.Fatal(err)
		}
		rows = append(rows, x)
	}
	r.Close()
	if len(rows) != 2 {
		t.Fatalf("sync_log has %d rows, want 2", len(rows))
	}
	for _, x := range rows {
		if x.kind != "kb" || x.op != "upsert" || (x.id != k1 && x.id != k2) {
			t.Fatalf("unexpected sync_log row %+v", x)
		}
	}
}

func TestDeleteForNonIndexable(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t)
	hidden := e.kbEntry(t, root, kbIn{title: "secret leak token abc", hidden: true})
	quar := e.kbEntry(t, root, kbIn{title: "quarantined content", quarantine: true})
	ok := e.kbEntry(t, root, kbIn{title: "visible fix"})

	if _, err := Distill(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	// The log records deletes for the non-visible rows, an upsert for the visible one.
	ops := map[string]string{}
	r, _ := testPool.Query(ctx, `SELECT id, op FROM sync_log`)
	for r.Next() {
		var id, op string
		r.Scan(&id, &op)
		ops[id] = op
	}
	r.Close()
	if ops[hidden] != "delete" || ops[quar] != "delete" || ops[ok] != "upsert" {
		t.Fatalf("ops = %v", ops)
	}
	// Served NDJSON: hidden/quarantined carry no row content at all.
	lines, _, _ := e.getSync(t, "?kinds=kb&after=0")
	for _, l := range lines {
		if l.ID == ok {
			if l.Op != "upsert" || len(l.Row) == 0 {
				t.Fatalf("visible row served as %s row=%s", l.Op, l.Row)
			}
			continue
		}
		if l.Op != "delete" || len(l.Row) != 0 || l.Sig != "" {
			t.Fatalf("non-indexable row %s leaked content: op=%s row=%s sig=%s", l.ID, l.Op, l.Row, l.Sig)
		}
	}
	// Flip the visible row to hidden after distill: the stored op is upsert but the serve path
	// must downgrade it to a content-free delete.
	if _, err := testPool.Exec(ctx, `UPDATE kb SET hidden = true WHERE id = $1`, ok); err != nil {
		t.Fatal(err)
	}
	lines, _, _ = e.getSync(t, "?kinds=kb&after=0")
	for _, l := range lines {
		if l.ID == ok && (l.Op != "delete" || len(l.Row) != 0) {
			t.Fatalf("now-hidden row still carries content: op=%s row=%s", l.Op, l.Row)
		}
	}
}

func TestNDJSONSignedRows(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t)
	e.kbEntry(t, root, kbIn{title: "signed fix one"})
	e.kbEntry(t, root, kbIn{title: "signed fix two"})
	if _, err := Distill(ctx, testPool); err != nil {
		t.Fatal(err)
	}

	lines, body, resp := e.getSync(t, "?kinds=kb&after=0")
	if resp.Header.Get("Content-Type") != "application/x-ndjson" {
		t.Fatalf("content-type %q", resp.Header.Get("Content-Type"))
	}
	if resp.Header.Get("ETag") == "" || resp.Header.Get("X-Next") == "" {
		t.Fatalf("missing ETag/X-Next headers")
	}
	if len(body) > MaxBytes {
		t.Fatalf("body %d > 1 MiB", len(body))
	}
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2", len(lines))
	}
	signer := sign.Default()
	for _, l := range lines {
		if l.Op != "upsert" || len(l.Row) == 0 || l.Sig == "" {
			t.Fatalf("line %+v not a signed upsert", l)
		}
		if l.Seq == 0 || l.Kind != "kb" || l.ID == "" || l.At == "" {
			t.Fatalf("line missing fields: %+v", l)
		}
		// The first line is a JSON object with the required members.
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(mustLine(t, body, 0)), &obj); err != nil {
			t.Fatal(err)
		}
		for _, k := range []string{"seq", "op", "kind", "id", "row", "sig"} {
			if _, ok := obj[k]; !ok {
				t.Fatalf("first line missing %q", k)
			}
		}
		// The signature verifies over hex(sha256(the row bytes as received)).
		if _, ok := signer.Verify(SigType, rowDigest(l.Row), l.Sig); !ok {
			t.Fatalf("signature does not verify for %s", l.ID)
		}
		// Each row embeds origin and url.
		var row map[string]any
		if err := json.Unmarshal(l.Row, &row); err != nil {
			t.Fatal(err)
		}
		if row["origin"] != "self" || row["url"] == nil {
			t.Fatalf("row missing origin/url: %v", row)
		}
	}
}

func mustLine(t *testing.T, body string, i int) string {
	t.Helper()
	parts := strings.Split(strings.TrimRight(body, "\n"), "\n")
	if i >= len(parts) {
		t.Fatalf("no line %d in body", i)
	}
	return parts[i]
}

func TestCompactionAndRetention(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t)
	k := e.kbEntry(t, root, kbIn{title: "churny fix"})

	// Three historical upserts of the same object (older than the compaction window) plus a
	// recent one; and one ancient row beyond retention.
	for i := 0; i < 3; i++ {
		if _, err := testPool.Exec(ctx, `INSERT INTO sync_log (kind, id, op, at) VALUES ('kb', $1, 'upsert', now() - interval '30 days')`, k); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO sync_log (kind, id, op, at) VALUES ('kb', $1, 'upsert', now())`, k); err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(ctx, `INSERT INTO sync_log (kind, id, op, at) VALUES ('kb', 'kold', 'delete', now() - interval '200 days')`); err != nil {
		t.Fatal(err)
	}

	del, err := Compact(ctx, testPool)
	if err != nil {
		t.Fatal(err)
	}
	// All but the latest of the three old duplicates are removed (the recent one and the >90 d
	// row are left for Retain). The 200 d row has no newer sibling, so Compact keeps it.
	if del != 2 {
		t.Fatalf("compacted %d rows, want 2", del)
	}
	var perObj int
	testPool.QueryRow(ctx, `SELECT count(*) FROM sync_log WHERE id = $1 AND at < now() - interval '7 days'`, k).Scan(&perObj)
	if perObj != 1 {
		t.Fatalf("after compaction %d old rows remain for the object, want 1", perObj)
	}

	ret, err := Retain(ctx, testPool)
	if err != nil {
		t.Fatal(err)
	}
	if ret < 1 {
		t.Fatalf("retain removed %d rows, want >= 1 (the 200 d row)", ret)
	}
	var old int
	testPool.QueryRow(ctx, `SELECT count(*) FROM sync_log WHERE at < now() - interval '90 days'`).Scan(&old)
	if old != 0 {
		t.Fatalf("%d rows older than 90 d survived retention", old)
	}
}

func TestDeltaDump(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.identity(t)
	e.kbEntry(t, root, kbIn{title: "today fix"})
	if _, err := Distill(ctx, testPool); err != nil {
		t.Fatal(err)
	}

	if err := e.s.delta(ctx); err != nil {
		t.Fatal(err)
	}
	date := time.Now().UTC().Format(dateFmt)
	path := filepath.Join(e.dir, deltaName(date))
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("delta shard not materialised: %v", err)
	}
	// The shard is gzip NDJSON with at least one line.
	rows := readGzipLines(t, path)
	if len(rows) == 0 {
		t.Fatalf("delta shard is empty")
	}
	var l wireLine
	if err := json.Unmarshal([]byte(rows[0]), &l); err != nil {
		t.Fatalf("delta line not JSON: %v", err)
	}
	// ExtraFileFn lists the shard for the export manifest.
	extra, err := e.s.extraFiles(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range extra {
		if f.Name == deltaName(date) {
			found = true
		}
	}
	if !found {
		t.Fatalf("extraFiles did not list %s: %v", deltaName(date), extra)
	}
	// After an export regen the manifest carries the delta shard.
	if err := export.Regen(ctx); err != nil {
		t.Fatal(err)
	}
	mb, err := os.ReadFile(filepath.Join(e.dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mb), deltaName(date)) {
		t.Fatalf("manifest.json does not list the delta shard")
	}
}

func readGzipLines(t *testing.T, path string) []string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	defer gz.Close()
	b, _ := io.ReadAll(gz)
	var out []string
	for _, line := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if line != "" {
			out = append(out, line)
		}
	}
	return out
}

func TestShedFeeds(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	if err := e.d.SetFlag(ctx, "shed:feeds", true, ""); err != nil {
		t.Fatal(err)
	}
	resp, err := http.Get(e.srv.URL + "/v1/sync?kinds=kb")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("shed:feeds returned %d, want 503", resp.StatusCode)
	}
}
