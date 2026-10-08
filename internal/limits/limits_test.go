package limits

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
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
	} else if pool, done := testdb.Open("limits", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping limits DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
	ip  string
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm", PowBits: 6, PowBitsW: 16,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.test", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	var b [2]byte
	rand.Read(b[:])
	return &tenv{d, srv, fmt.Sprintf("10.9.%d.%d", b[0], b[1])}
}

func (e *tenv) get(t *testing.T, path string, hdr ...string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Header.Set("CF-Connecting-IP", e.ip)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(res.Body)
	return res.StatusCode, res.Header, string(body)
}

func TestLimitsFromCapsTables(t *testing.T) {
	e := newEnv(t)
	st, h, body := e.get(t, "/limits")
	if st != 200 {
		t.Fatalf("GET /limits: %d", st)
	}
	if ct := h.Get("Content-Type"); !strings.HasPrefix(ct, "text/plain") {
		t.Fatalf("content-type %q", ct)
	}
	// The acceptance string, sourced live from trust.Caps["kb"] = {30,30,150,150}.
	if !strings.Contains(body, "kb posts L0=30 L1=30 L2=150 L3=150") {
		t.Fatalf("limits missing kb caps line:\n%s", body)
	}
	// Numbers are the live table, not a copy: every Caps kind appears with its four values.
	for kind, row := range trust.Caps {
		want := fmt.Sprintf("L0=%d L1=%d L2=%d L3=%d", row[0], row[1], row[2], row[3])
		if !strings.Contains(body, want) {
			t.Fatalf("limits missing %s values %q", kind, want)
		}
	}
	for _, section := range []string{"caps:", "fields", "pow:", "storage:", "shed:", "longpoll:"} {
		if !strings.Contains(body, section) {
			t.Fatalf("limits missing section %q", section)
		}
	}
	// .json and .md variants exist and carry the same kb numbers.
	if st, h, jb := e.get(t, "/limits.json"); st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "application/json") || !strings.Contains(jb, `"L2": 150`) {
		t.Fatalf("/limits.json: %d %q\n%s", st, h.Get("Content-Type"), jb)
	}
	if st, h, mb := e.get(t, "/limits.md"); st != 200 || !strings.HasPrefix(h.Get("Content-Type"), "text/markdown") || !strings.Contains(mb, "kb posts L0=30") {
		t.Fatalf("/limits.md: %d %q", st, h.Get("Content-Type"))
	}
}

func TestLimitsShedAndBits(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Hermetic: the scratch DB is shared, so start from a clean shed state.
	for _, rung := range shedRungs {
		if err := e.d.SetFlag(ctx, "shed:"+rung, false, ""); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		for _, rung := range shedRungs {
			e.d.SetFlag(ctx, "shed:"+rung, false, "")
		}
	})
	// Live PoW bits for=reg and for=w are present and numeric.
	_, _, body := e.get(t, "/limits")
	if !strings.Contains(body, "for=reg bits=6") { // PowBits = 6, no prior registrations
		t.Fatalf("reg bits line wrong:\n%s", body)
	}
	if !strings.Contains(body, "for=w bits=16") { // PowBitsW = 16
		t.Fatalf("w bits line wrong:\n%s", body)
	}
	if !strings.Contains(body, "shed: none") {
		t.Fatalf("expected no shed rungs active:\n%s", body)
	}
	// Flip a rung and it shows up; the page is live (no stale cache of the body).
	if err := e.d.SetFlag(ctx, "shed:feeds", true, ""); err != nil {
		t.Fatal(err)
	}
	if err := e.d.SetFlag(ctx, "shed:longpoll", true, ""); err != nil {
		t.Fatal(err)
	}
	_, _, body = e.get(t, "/limits")
	if !strings.Contains(body, "shed: feeds,longpoll") {
		t.Fatalf("active shed rungs not shown:\n%s", body)
	}
}

func TestLimitsCached(t *testing.T) {
	e := newEnv(t)
	st, h, _ := e.get(t, "/limits")
	if st != 200 {
		t.Fatalf("GET /limits: %d", st)
	}
	if cc := h.Get("Cache-Control"); !strings.HasPrefix(cc, "public, max-age=300") {
		t.Fatalf("cache-control %q (want public, max-age=300)", cc)
	}
	et := h.Get("ETag")
	if et == "" {
		t.Fatal("no ETag")
	}
	// The ETag round-trips to a 304.
	if st, _, _ := e.get(t, "/limits", "If-None-Match", et); st != 304 {
		t.Fatalf("If-None-Match -> %d", st)
	}
}
