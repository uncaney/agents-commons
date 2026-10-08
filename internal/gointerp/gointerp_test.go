package gointerp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/core"
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
		if _, err := pool.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, pool); err != nil {
			panic(err)
		}
		testPool, cleanup = pool, pool.Close
	} else if pool, done := testdb.Open("gointerp", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping gointerp DB tests")
	}
	core.LevelFn = trust.LevelOf
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func newDeps(t *testing.T) *core.Deps {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, RegPerHour: 1 << 20, AdminToken: "cx-admin-test", PublicURL: "https://t.example", AdminBlobMax: 64 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

// TestOpAliasesFraming checks the three op aliases map to the right catalog
// service and that each builds the 15.4 {code,stdin} framing with its caps.
func TestOpAliasesFraming(t *testing.T) {
	want := map[string]string{"star": "cx-starlark", "jsg": "cx-goja", "expr": "cx-expr"}
	for alias, svc := range want {
		if interp[alias] != svc {
			t.Errorf("alias %s -> %q, want %q", alias, interp[alias], svc)
		}
	}
	ops := Ops(nil)
	for alias := range want {
		if ops[alias] == nil {
			t.Errorf("Ops missing %s", alias)
		}
	}
	if len(ops) != len(want) {
		t.Errorf("Ops has %d entries, want %d", len(ops), len(want))
	}

	// framing: {"code","stdin"} JSON, order-stable and round-trippable.
	got, err := frame("print(1)", "hi")
	if err != nil {
		t.Fatal(err)
	}
	if got != `{"code":"print(1)","stdin":"hi"}` {
		t.Errorf("frame = %q", got)
	}
	var back struct{ Code, Stdin string }
	if err := json.Unmarshal([]byte(got), &back); err != nil || back.Code != "print(1)" || back.Stdin != "hi" {
		t.Errorf("frame not round-trippable: %v %+v", err, back)
	}
	if _, err := frame("", ""); err == nil {
		t.Error("empty code must error")
	}
	if _, err := frame(strings.Repeat("x", maxCode+1), ""); err == nil {
		t.Error("oversize code must 413")
	}
	if _, err := frame("x", strings.Repeat("y", maxStdin+1)); err == nil {
		t.Error("oversize stdin must 413")
	}

	// end-to-end wiring: an alias call reaches catalog.Call, which reports the
	// resolved service name when the seed is not published yet.
	if testPool == nil {
		t.Skip("no DB: skipping the catalog.Call wiring check")
	}
	d := newDeps(t)
	defer func() { catalog.PyHintFn = nil }()
	id := mintIdent(t, d)
	for alias, svc := range want {
		_, err := Ops(d)[alias](context.Background(), id, json.RawMessage(`{"code":"1"}`))
		if err == nil {
			t.Errorf("%s{}: want notfound error (seed unpublished)", alias)
			continue
		}
		if !strings.Contains(err.Error(), svc) {
			t.Errorf("%s{} error %q does not name %q", alias, err.Error(), svc)
		}
	}
}

// TestSizesPageDescriptive checks GET /wasm/sizes serves the descriptive size
// table (the three modules and their measured ranges) as Markdown, noindex, and
// without imperative build commands.
func TestSizesPageDescriptive(t *testing.T) {
	s := &h{sizes: defaultSizes}
	for _, path := range []string{"/wasm/sizes", "/wasm/sizes.md", "/wasm/sizes.txt"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		s.hSizes(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", path, rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
			t.Errorf("%s: content-type %q", path, ct)
		}
		if rec.Header().Get("X-Robots-Tag") != "noindex" {
			t.Errorf("%s: not noindex", path)
		}
		body := rec.Body.String()
		for _, name := range []string{"cx-starlark", "cx-goja", "cx-expr", "MiB"} {
			if !strings.Contains(body, name) {
				t.Errorf("%s: body missing %q", path, name)
			}
		}
		// descriptive, not a command sheet: no shell prompt, no imperative build line.
		if strings.Contains(body, "$ ") || strings.Contains(body, "```") {
			t.Errorf("%s: sizes page should be descriptive, not a command block", path)
		}
	}
	// HEAD carries headers but no body.
	rec := httptest.NewRecorder()
	s.hSizes(rec, httptest.NewRequest(http.MethodHead, "/wasm/sizes", nil))
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Errorf("HEAD: status %d bodylen %d", rec.Code, rec.Body.Len())
	}
}

// TestPyHint checks the nil-safe seam: with no hint installed, cxpy's
// not-published error is bare; after Register installs it, the error gains the
// "try star{}" hint, and only cxpy (not cxjs/cxlua) gets it.
func TestPyHint(t *testing.T) {
	if testPool == nil {
		t.Skip("no DB: TestPyHint needs the services table")
	}
	ctx := context.Background()
	catalog.PyHintFn = nil
	_, err := catalog.Resolve(ctx, testPool, "cxpy")
	if err == nil || strings.Contains(err.Error(), "star") {
		t.Fatalf("baseline cxpy error should be hint-free: %v", err)
	}

	d := newDeps(t)
	mux := http.NewServeMux()
	Register(mux, d)
	defer func() { catalog.PyHintFn = nil }()

	_, err = catalog.Resolve(ctx, testPool, "cxpy")
	if err == nil || !strings.Contains(err.Error(), "try star{}") {
		t.Fatalf("cxpy error after Register should carry the hint, got: %v", err)
	}
	// the hint is cxpy-specific.
	if _, err := catalog.Resolve(ctx, testPool, "cxjs"); err == nil || strings.Contains(err.Error(), "star") {
		t.Fatalf("cxjs must not carry the py hint: %v", err)
	}
}

// mintIdent returns a non-banned identity; the wiring check fails at service
// resolution (before any credit or level use), so no DB row is needed.
func mintIdent(t *testing.T, d *core.Deps) *core.Ident {
	t.Helper()
	root := core.NewID('a')
	return &core.Ident{ID: root, Root: root, Credits: 1000}
}
