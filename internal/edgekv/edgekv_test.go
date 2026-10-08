package edgekv

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	cleanup := func() {}
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		pool, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("edgekv", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping edgekv DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newDeps(t *testing.T) *core.Deps {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm", PowBits: 6,
		DataDir: t.TempDir(), PublicURL: "https://agents.example", RegPerHour: 1 << 20, TrustCF: true}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	ctx := context.Background()
	for _, tbl := range []string{"egress_outbox", "flags"} {
		if _, err := testPool.Exec(ctx, "DELETE FROM "+tbl); err != nil {
			t.Fatal(err)
		}
	}
	return d
}

// stub is a tiny mux whose files can change between sweeps.
type stub struct {
	mu    sync.Mutex
	files map[string]file
}

type file struct {
	ct, lastMod string
	body        []byte
}

func (s *stub) set(path, ct, lastMod, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.files[path] = file{ct: ct, lastMod: lastMod, body: []byte(body)}
}

func (s *stub) mux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		f, ok := s.files[r.URL.Path]
		s.mu.Unlock()
		if !ok {
			http.NotFound(w, r)
			return
		}
		if f.ct != "" {
			w.Header().Set("Content-Type", f.ct)
		}
		if f.lastMod != "" {
			w.Header().Set("Last-Modified", f.lastMod)
		}
		w.WriteHeader(200)
		w.Write(f.body)
	})
	return mux
}

// drain applies every live kv_mirror row's ResultFn (as a successful ack would) and marks it done,
// so the stored sha advances and the row stops being "in flight".
func drain(t *testing.T, d *core.Deps) int {
	t.Helper()
	ctx := context.Background()
	rows, err := d.DB.Query(ctx, `SELECT id, payload FROM egress_outbox WHERE kind = 'kv_mirror' AND done_at IS NULL ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	type row struct {
		id      int64
		payload json.RawMessage
	}
	var list []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.payload); err != nil {
			t.Fatal(err)
		}
		list = append(list, r)
	}
	rows.Close()
	for _, r := range list {
		result, _ := json.Marshal(map[string]any{"path": "ok", "bytes": 1})
		if err := KvMirrorResult(ctx, d, d.DB, r.payload, result); err != nil {
			t.Fatalf("KvMirrorResult: %v", err)
		}
		if _, err := d.DB.Exec(ctx, `UPDATE egress_outbox SET done_at = now() WHERE id = $1`, r.id); err != nil {
			t.Fatal(err)
		}
	}
	return len(list)
}

func liveRows(t *testing.T, d *core.Deps) []kvPayload {
	t.Helper()
	rows, err := d.DB.Query(context.Background(), `SELECT payload FROM egress_outbox WHERE kind = 'kv_mirror' AND done_at IS NULL ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []kvPayload
	for rows.Next() {
		var raw json.RawMessage
		if err := rows.Scan(&raw); err != nil {
			t.Fatal(err)
		}
		var p kvPayload
		json.Unmarshal(raw, &p)
		out = append(out, p)
	}
	return out
}

func TestWatcherCoalescesAndEnqueues(t *testing.T) {
	d := newDeps(t)
	ctx := context.Background()
	s := &stub{files: map[string]file{}}
	s.set("/robots.txt", "text/plain; charset=utf-8", "Tue, 07 Oct 2026 10:00:00 GMT", "User-agent: *\nAllow: /\n")
	s.set("/llms.txt", "text/plain; charset=utf-8", "Tue, 07 Oct 2026 10:00:00 GMT", "# agents.ekaii.fr\n")
	w := New(d, s.mux())

	// First sweep: both files are new, so both are enqueued with their content-type and Last-Modified.
	n, err := w.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("first sweep enqueued %d, want 2", n)
	}
	got := liveRows(t, d)
	if len(got) != 2 {
		t.Fatalf("live rows = %d, want 2", len(got))
	}
	byPath := map[string]kvPayload{}
	for _, p := range got {
		byPath[p.Path] = p
	}
	rp, ok := byPath["/robots.txt"]
	if !ok {
		t.Fatalf("no /robots.txt row; got %v", byPath)
	}
	if rp.CT != "text/plain; charset=utf-8" || rp.LastModified != "Tue, 07 Oct 2026 10:00:00 GMT" {
		t.Fatalf("robots row metadata wrong: %+v", rp)
	}
	if b, _ := base64.StdEncoding.DecodeString(rp.Body); string(b) != "User-agent: *\nAllow: /\n" {
		t.Fatalf("robots body = %q", b)
	}

	// Second sweep BEFORE the writes land: the files are already queued, so nothing is re-enqueued
	// (coalescing: one in-flight write per path).
	n, err = w.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("second sweep (in flight) enqueued %d, want 0", n)
	}

	// The writes land: the stored sha advances.
	if drain(t, d) != 2 {
		t.Fatal("expected 2 writes drained")
	}

	// Third sweep with unchanged content: nothing to do.
	n, err = w.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("third sweep (unchanged) enqueued %d, want 0", n)
	}

	// Change only robots.txt: exactly one new row, for that path.
	s.set("/robots.txt", "text/plain; charset=utf-8", "Tue, 07 Oct 2026 11:00:00 GMT", "User-agent: *\nDisallow: /h/\n")
	n, err = w.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("fourth sweep (robots changed) enqueued %d, want 1", n)
	}
	got = liveRows(t, d)
	if len(got) != 1 || got[0].Path != "/robots.txt" {
		t.Fatalf("expected one live /robots.txt row, got %+v", got)
	}
}

func TestWatcherRespectsDailyBudget(t *testing.T) {
	d := newDeps(t)
	ctx := context.Background()
	// Fill the rolling-day budget with unrelated kv_mirror rows.
	if _, err := d.DB.Exec(ctx, `INSERT INTO egress_outbox (kind, payload, done_at)
		SELECT 'kv_mirror', jsonb_build_object('path', '/x'||g), now() FROM generate_series(1, $1) g`, DailyWrites); err != nil {
		t.Fatal(err)
	}
	s := &stub{files: map[string]file{}}
	s.set("/robots.txt", "text/plain", "", "User-agent: *\n")
	w := New(d, s.mux())
	n, err := w.Sweep(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("sweep at budget enqueued %d, want 0", n)
	}
}
