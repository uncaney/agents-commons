package errsig

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/know"
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
	} else if pool, done := testdb.Open("errsig", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping errsig DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type env struct {
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *env {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	know.SetWantedSecret(cfg.ServerSecret)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	kb.Register(mux, d)
	kb.RegisterAka(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	return &env{d: d, srv: srv}
}

var idSeq atomic.Int64

// mkRoot inserts an identity directly and gives it the minimum standing of level lvl.
func (e *env) mkRoot(t *testing.T, lvl int) string {
	t.Helper()
	ctx := context.Background()
	id := core.NewID('p')
	var th [32]byte
	rand.Read(th[:])
	n := idSeq.Add(1)
	ip := fmt.Sprintf("10.%d.%d.9", 40+n/200%200, 1+n%200)
	if _, err := testPool.Exec(ctx, `INSERT INTO identities (id, name, root, token_hash, rep, reg_ip, created) VALUES ($1, $1, $1, $2, 0, $3, now())`,
		id, th[:], ip); err != nil {
		t.Fatal(err)
	}
	rep, days, vnc := 0, 0, 0
	switch lvl {
	case 1:
		rep, days = 1, 4
	case 2:
		rep, days, vnc = 5, 4, 1
	case 3:
		rep, days, vnc = 20, 31, 1
	}
	if _, err := testPool.Exec(ctx, `UPDATE identities SET rep = $2, created = now() - $3 * interval '1 day', verified_noncompute = $4 WHERE id = $1`,
		id, rep, days, vnc); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM identities WHERE id = $1`, id) })
	return id
}

func (e *env) mkEntry(t *testing.T, root, title string) string {
	t.Helper()
	c, err := kb.CreateEntry(context.Background(), e.d, kb.Input{Kind: "fix", Title: title, Symptom: "boom", Fix: "do the thing", Force: true},
		kb.Author{ID: root, Root: root})
	if err != nil {
		t.Fatalf("create entry %q: %v", title, err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM kb WHERE id = $1`, c.ID) })
	return c.ID
}

func (e *env) get(t *testing.T, path string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Header.Set("CF-Connecting-IP", "203.0.113.7")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b))
}

func hashOf(s string) string {
	sum := sha256.Sum256([]byte(kb.ErrSig(s)))
	return hex.EncodeToString(sum[:])
}

// TestHashLookupHitsEntriesAndAkas: a title hash resolves the entries that carry it (two titles with
// the same signature give hits=2), and an alias hash resolves the aliased entry with its marker.
func TestHashLookupHitsEntriesAndAkas(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	root := e.mkRoot(t, 2)

	a := e.mkEntry(t, root, "connection refused on port 54110")
	b := e.mkEntry(t, root, "connection refused on port 61999")
	// Same ErrSig (the ports collapse to N), so one hash resolves both.
	if kb.ErrSig("connection refused on port 54110") != kb.ErrSig("connection refused on port 61999") {
		t.Fatal("expected the two titles to share a signature")
	}
	if err := Backfill(ctx, testPool); err != nil {
		t.Fatal(err)
	}

	st, body := e.get(t, "/h/"+hashOf("connection refused on port 54110"))
	if st != 200 {
		t.Fatalf("title hash: %d %s", st, body)
	}
	if !strings.Contains(body, "hits=2") || !strings.Contains(body, a) || !strings.Contains(body, b) {
		t.Fatalf("title hash body missing both entries:\n%s", body)
	}

	// An alias on a third entry resolves by the alias hash and renders the (aka: …) marker.
	c := e.mkEntry(t, root, "mystery widget failure alpha")
	alias := "gizmo blew up during startup beta"
	if _, err := kb.AddAka(ctx, e.d, kb.AkaAuthor{ID: root, Root: root}, c, alias); err != nil {
		t.Fatalf("add aka: %v", err)
	}
	st, body = e.get(t, "/h/"+hashOf(alias))
	if st != 200 {
		t.Fatalf("alias hash: %d %s", st, body)
	}
	if !strings.Contains(body, c) || !strings.Contains(body, "aka:") {
		t.Fatalf("alias hash body missing entry or marker:\n%s", body)
	}
}

// TestHashMissRecordsWanted: an unknown hash answers 404 and records a wanted(kind h) demand row.
func TestHashMissRecordsWanted(t *testing.T) {
	e := newEnv(t)
	var rnd [32]byte
	rand.Read(rnd[:])
	miss := hex.EncodeToString(rnd[:])

	st, body := e.get(t, "/h/"+miss)
	if st != 404 {
		t.Fatalf("miss status: %d %s", st, body)
	}
	if !strings.Contains(body, "notfound") {
		t.Fatalf("miss body: %s", body)
	}
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM wanted WHERE kind = 'h' AND key = $1`, miss).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("wanted rows for the missed hash = %d, want 1", n)
	}
	testPool.Exec(context.Background(), `DELETE FROM wanted WHERE kind = 'h' AND key = $1`, miss)

	// A bad hash (not 64 lowercase hex) is a 400, not a miss.
	if st, _ := e.get(t, "/h/NOTHEX"); st != 400 {
		t.Fatalf("bad hash status = %d, want 400", st)
	}
}

// TestErrsigVectorsEmbedded: the 50 embedded vectors carry the server's own kb.ErrSig signatures and
// their sha256, and the published Python reference reproduces every signature (when python3 exists).
func TestErrsigVectorsEmbedded(t *testing.T) {
	vs := Vectors()
	if len(vs) != 50 {
		t.Fatalf("embedded vectors = %d, want 50", len(vs))
	}
	for _, v := range vs {
		if got := kb.ErrSig(v.Input); got != v.Sig {
			t.Fatalf("sig drift for %q: %q vs %q", v.Input, got, v.Sig)
		}
		sum := sha256.Sum256([]byte(v.Sig))
		if hex.EncodeToString(sum[:]) != v.SHA256 {
			t.Fatalf("sha drift for %q", v.Input)
		}
	}
	// The /errsig.tsv body is exactly the generated vectors.
	if VectorsTSV() == "" || strings.Count(VectorsTSV(), "\n") != 50 {
		t.Fatalf("tsv should have 50 lines")
	}

	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 not installed")
	}
	dir := t.TempDir()
	path := dir + "/errsig.py"
	if err := os.WriteFile(path, []byte(errsigPy), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, v := range vs {
		out, err := exec.Command(py, "-I", path, v.Input).Output()
		if err != nil {
			t.Fatalf("python reference on %q: %v", v.Input, err)
		}
		var sig string
		for _, line := range strings.Split(string(out), "\n") {
			if strings.HasPrefix(line, "sig: ") {
				sig = strings.TrimPrefix(line, "sig: ")
			}
		}
		if sig != v.Sig {
			t.Fatalf("python reference disagrees for %q: %q vs %q", v.Input, sig, v.Sig)
		}
	}
}
