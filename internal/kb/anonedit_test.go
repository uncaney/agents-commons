package kb

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Anonymous author-key + confirmation acceptance tests (SPEC-v2 27.2, PLAN P78-kb-anon-ext).

// newExtEnv is a full env with the anonymous lane plus this package's extensions mounted and a cheap
// for=w floor (POW_BITS_W = 4).
func newExtEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, PowBitsW: 4, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	RegisterAnon(mux, d)
	RegisterAnonEdit(mux, d)
	RegisterAnonVotes(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	return &tenv{d: d, srv: srv, ip: nextIP(), cfg: cfg}
}

// mkAnon creates one anonymous quarantined entry directly (from a fresh random group so day
// counters never collide across runs) and returns its id and author key; the row is removed when the
// test ends.
func (e *tenv) mkAnon(t *testing.T) (id, key string) {
	t.Helper()
	ctx := context.Background()
	grp := nextIP()
	c, err := CreateEntry(ctx, e.d, Input{Kind: "fix", Title: uniq("anon edit key"), Symptom: uniq("boom"), Fix: "restart with the flag", Force: true},
		Author{Anon: true, Grp: grp, Super: core.IPSuper(grp)})
	if err != nil {
		t.Fatalf("create anon: %v", err)
	}
	key, err = AnonEditKey(ctx, e.d.DB, c.ID)
	if err != nil || key == "" {
		t.Fatalf("mint key: %v %q", err, key)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM kb WHERE id = $1`, c.ID) })
	return c.ID, key
}

func (e *tenv) entryField(t *testing.T, id, col string) any {
	t.Helper()
	var v any
	if err := testPool.QueryRow(context.Background(), `SELECT `+col+` FROM kb WHERE id = $1`, id).Scan(&v); err != nil {
		t.Fatalf("read %s: %v", col, err)
	}
	return v
}

// TestAnonPostCarriesEditKey covers the acceptance curl example end to end: POST /w/kb replies with
// `202 ok k… quarantine edit=<key>`, the key PATCHes the row, and a wrong key answers 404.
func TestAnonPostCarriesEditKey(t *testing.T) {
	e := newExtEnv(t)
	stubPoW(t)
	ip := nextIP()
	st, body, _ := e.wpost(t, ip, anonIn(uniq("edit key e2e")))
	if st != 202 {
		t.Fatalf("post: %d %s", st, body)
	}
	m := map[string]string{}
	for _, x := range kvRe.FindAllStringSubmatch(body, -1) {
		m[x[1]] = x[2]
	}
	id, key := strings.Fields(body)[1], m["edit"]
	if len(key) != editKeyLen || !strings.Contains(body, "quarantine edit=") {
		t.Fatalf("no edit key in %q", body)
	}
	if st, b, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": "patched via the handed-out key"}, "X-Edit", key); st != 200 || !strings.HasPrefix(first(b), "ok "+id+" rev=2") {
		t.Fatalf("patch with handed key: %d %s", st, b)
	}
	if st, _, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": "should be rejected here"}, "X-Edit", strings.Repeat("z", editKeyLen)); st != 404 {
		t.Fatalf("wrong key: %d, want 404", st)
	}
}

func TestEditKeyPatchWhileQuarantined(t *testing.T) {
	e := newExtEnv(t)
	id, key := e.mkAnon(t)

	st, body, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": "run the migration before starting it"}, "X-Edit", key)
	if st != 200 {
		t.Fatalf("patch: %d %s", st, body)
	}
	if h := first(body); !strings.HasPrefix(h, "ok "+id+" rev=2") {
		t.Fatalf("head = %q, want ok %s rev=2", h, id)
	}
	// The field changed and the row stayed quarantined.
	var fix string
	var quar bool
	if err := testPool.QueryRow(context.Background(), `SELECT fix, quarantine FROM kb WHERE id = $1`, id).Scan(&fix, &quar); err != nil {
		t.Fatal(err)
	}
	if fix != "run the migration before starting it" || !quar {
		t.Fatalf("fix=%q quarantine=%v", fix, quar)
	}
}

func TestEditKeyWrongIs404(t *testing.T) {
	e := newExtEnv(t)
	id, key := e.mkAnon(t)

	// Wrong key.
	wrong := strings.Repeat("a", len(key))
	if st, _, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": "x y z changed"}, "X-Edit", wrong); st != 404 {
		t.Fatalf("wrong key: %d, want 404", st)
	}
	// Absent key.
	if st, _, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": "x y z changed"}); st != 404 {
		t.Fatalf("absent key: %d, want 404", st)
	}
	// The right key still works (nothing was consumed by the 404s).
	if st, body, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": "x y z changed"}, "X-Edit", key); st != 200 {
		t.Fatalf("right key: %d %s", st, body)
	}
}

func TestEditCapFive(t *testing.T) {
	e := newExtEnv(t)
	id, key := e.mkAnon(t)
	for i := 0; i < 5; i++ {
		st, body, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": uniq("fix number")}, "X-Edit", key)
		if st != 200 {
			t.Fatalf("patch %d: %d %s", i+1, st, body)
		}
	}
	st, body, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": uniq("one too many")}, "X-Edit", key)
	if st != 429 {
		t.Fatalf("6th patch: %d %s, want 429", st, body)
	}
	if n := e.entryField(t, id, "anon_edits").(int32); n != 5 {
		t.Fatalf("anon_edits = %d, want 5", n)
	}
}

func TestDeleteWithin14d(t *testing.T) {
	e := newExtEnv(t)

	// Quarantined: the author may retract.
	id, key := e.mkAnon(t)
	if st, body, _ := e.do(t, "DELETE", "/w/kb/"+id, "", nil, "X-Edit", key); st != 200 {
		t.Fatalf("delete quarantined: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil); st != 410 {
		t.Fatalf("after retract: %d, want 410 gone", st)
	}

	// Promoted within 14 days: still retractable.
	id2, key2 := e.mkAnon(t)
	testPool.Exec(context.Background(), `UPDATE kb SET quarantine = false, confirmed_at = now() - interval '2 days' WHERE id = $1`, id2)
	if st, body, _ := e.do(t, "DELETE", "/w/kb/"+id2, "", nil, "X-Edit", key2); st != 200 {
		t.Fatalf("delete recent promotion: %d %s", st, body)
	}

	// Promoted more than 14 days ago: the window closed, same 404 as a missing row.
	id3, key3 := e.mkAnon(t)
	testPool.Exec(context.Background(), `UPDATE kb SET quarantine = false, confirmed_at = now() - interval '20 days' WHERE id = $1`, id3)
	if st, _, _ := e.do(t, "DELETE", "/w/kb/"+id3, "", nil, "X-Edit", key3); st != 404 {
		t.Fatalf("delete stale promotion: %d, want 404", st)
	}
}

func TestAdoptNoRetroRep(t *testing.T) {
	e := newExtEnv(t)
	id, key := e.mkAnon(t)
	root, tok := e.register(t, "adopter")
	// The root must be at least 1 h old.
	testPool.Exec(context.Background(), `UPDATE identities SET created = now() - interval '2 hours' WHERE id = $1`, root)

	st, body, _ := e.do(t, "POST", "/v1/kb/"+id+"/adopt", tok, map[string]any{"edit": key})
	if st != 200 {
		t.Fatalf("adopt: %d %s", st, body)
	}
	var author, wh any
	if err := testPool.QueryRow(context.Background(), `SELECT author_root, anon_wh FROM kb WHERE id = $1`, id).Scan(&author, &wh); err != nil {
		t.Fatal(err)
	}
	if author != root {
		t.Fatalf("author_root = %v, want %s", author, root)
	}
	if wh != nil {
		t.Fatalf("anon_wh = %v, want NULL after adopt", wh)
	}
	if r := e.rep(t, root); r != 0 {
		t.Fatalf("rep = %d, want 0 (no retroactive rep)", r)
	}
	// A fresh root cannot adopt.
	id2, key2 := e.mkAnon(t)
	_, young := e.register(t, "youngroot")
	if st, _, _ := e.do(t, "POST", "/v1/kb/"+id2+"/adopt", young, map[string]any{"edit": key2}); st != 403 {
		t.Fatalf("young adopt: %d, want 403", st)
	}
	// The key no longer works on the adopted row.
	if st, _, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": "x y z after adopt"}, "X-Edit", key); st != 404 {
		t.Fatalf("patch after adopt: %d, want 404", st)
	}
}

func TestEditKeyBurnedOnLeak(t *testing.T) {
	e := newExtEnv(t)
	id, key := e.mkAnon(t)
	ctx := context.Background()

	line, err := BurnLeakedEditKeys(ctx, testPool, "here is my key in the clear: edit="+key+" oops")
	if err != nil {
		t.Fatal(err)
	}
	if line != "edit key burned" {
		t.Fatalf("burn line = %q, want 'edit key burned'", line)
	}
	// The burned key no longer authorises an edit (same 404 as a missing row).
	if st, _, _ := e.do(t, "PATCH", "/w/kb/"+id, "", map[string]any{"fix": "x y z after burn"}, "X-Edit", key); st != 404 {
		t.Fatalf("patch after burn: %d, want 404", st)
	}
	// Content without a key burns nothing.
	if line, _ := BurnLeakedEditKeys(ctx, testPool, "no secrets here at all"); line != "" {
		t.Fatalf("no-key line = %q, want empty", line)
	}
}
