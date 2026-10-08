package waypoint

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
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
	} else if pool, done := testdb.Open("waypoint", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping waypoint DB tests")
		os.Exit(0)
	}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
	s   *svc
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	s := newSvc(d)
	// Mount through the service we keep a handle on, so tests can inspect the ByteLRU.
	mux.HandleFunc("POST /v1/anchor", s.post)
	mux.HandleFunc("GET /anchor/{key...}", s.page)
	d.RegisterScope("POST /v1/anchor", "w")
	d.RegisterTarget("an", core.Target{Exists: existsTarget, Hide: hideTarget, Restore: restoreTarget})
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, srv: srv, s: s}
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

// rsuf is a fresh 8-hex suffix so each run uses unique keys and does not collide with rows left by
// an earlier run in the shared scratch database.
func rsuf() string {
	var b [4]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (e *tenv) do(t *testing.T, method, path, token, body string) (int, string, http.Header) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", randIP())
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func newRoot(t *testing.T) (id, token string) {
	t.Helper()
	id, token, err := core.CreateRoot(context.Background(), testPool, "waypoint-test", randIP())
	if err != nil {
		t.Fatal(err)
	}
	return id, token
}

// --- unit: key grammar ---------------------------------------------------------------------------

func TestKeyGrammarNormalised(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{"gh:Acme/Widgets", "gh:acme/widgets", true},
		{"  GH:ACME/Widgets  ", "gh:acme/widgets", true}, // trimmed, lowercased, case-insensitive
		{"gh:acme/widgets.git", "gh:acme/widgets.git", true},
		{"gh:acme", "", false},     // no repo
		{"gh:/widgets", "", false}, // empty owner
		{"host:00112233aabbccdd", "host:00112233aabbccdd", true},
		{"HOST:00112233AABBCCDD", "host:00112233aabbccdd", true},
		{"host:zz112233aabbccdd", "", false}, // not hex
		{"host:00112233", "", false},         // wrong length
		{"dir:0123456789abcdef", "dir:0123456789abcdef", true},
		{"task:Fix  the   Auth Flow", "task:fix the auth flow", true}, // lowercased, whitespace collapsed
		{"task:" + strings.Repeat("x", 64), "task:" + strings.Repeat("x", 64), true},
		{"task:" + strings.Repeat("x", 65), "", false}, // > 64
		{"task:", "", false},
		{"nope:whatever", "", false}, // unknown prefix
		{"", "", false},
	}
	for _, c := range cases {
		got, h, err := NormKey(c.in)
		if c.ok != (err == nil) {
			t.Fatalf("NormKey(%q): ok=%v err=%v", c.in, c.ok, err)
		}
		if c.ok && got != c.want {
			t.Fatalf("NormKey(%q) = %q, want %q", c.in, got, c.want)
		}
		if c.ok && len(h) != 32 {
			t.Fatalf("NormKey(%q) hash len %d", c.in, len(h))
		}
	}
	// Normalisation converges: two spellings of one key share a hash.
	_, h1, _ := NormKey("gh:Acme/Widgets")
	_, h2, _ := NormKey("gh:acme/widgets")
	if string(h1) != string(h2) {
		t.Fatal("case variants did not converge on one hash")
	}
}

// --- claim caps and note lexicon -----------------------------------------------------------------

func TestClaimCapsAndNoteLexicon(t *testing.T) {
	e := newEnv(t)
	suf := rsuf()
	key := "gh:acme/claimcap" + suf
	// 16 distinct roots claim the key; the 17th is refused (full).
	for i := 0; i < MaxClaimants; i++ {
		_, tok := newRoot(t)
		st, body, _ := e.do(t, "POST", "/v1/anchor", tok, fmt.Sprintf(`{"key":%q,"note":"claimant %d"}`, key, i))
		if st != 201 {
			t.Fatalf("claim %d: status %d body %s", i, st, body)
		}
	}
	_, over := newRoot(t)
	if st, body, _ := e.do(t, "POST", "/v1/anchor", over, fmt.Sprintf(`{"key":%q,"note":"one too many"}`, key)); st != 409 {
		t.Fatalf("17th claimant: status %d body %s (want 409 full)", st, body)
	}

	// 10 live anchors per root; the 11th distinct key is refused (quota).
	_, tok := newRoot(t)
	for i := 0; i < LiveCap; i++ {
		k := fmt.Sprintf("task:live anchor %s %d", suf, i)
		if st, body, _ := e.do(t, "POST", "/v1/anchor", tok, fmt.Sprintf(`{"key":%q,"note":"x"}`, k)); st != 201 {
			t.Fatalf("live anchor %d: status %d body %s", i, st, body)
		}
	}
	if st, body, _ := e.do(t, "POST", "/v1/anchor", tok, fmt.Sprintf(`{"key":"task:one over the live cap %s","note":"x"}`, suf)); st != 429 {
		t.Fatalf("11th live anchor: status %d body %s (want 429 quota)", st, body)
	}
	// Re-claiming an already-held key is a refresh, never counts against the live cap.
	if st, body, _ := e.do(t, "POST", "/v1/anchor", tok, fmt.Sprintf(`{"key":"task:live anchor %s 0","note":"refreshed"}`, suf)); st != 201 {
		t.Fatalf("refresh held key: status %d body %s", st, body)
	}

	// A note whose injection-lexicon score reaches 2 is refused (not quarantined: anchors have no
	// quarantine). A markdown image scores 2.
	lexKey := "gh:acme/lex" + suf
	_, lexTok := newRoot(t)
	if st, body, _ := e.do(t, "POST", "/v1/anchor", lexTok, fmt.Sprintf(`{"key":%q,"note":"see ![pwn](http://evil)"}`, lexKey)); st != 400 || !strings.Contains(body, "scrub") {
		t.Fatalf("lexicon>=2 note: status %d body %s (want 400 scrub)", st, body)
	}
	// A plain note is accepted.
	if st, body, _ := e.do(t, "POST", "/v1/anchor", lexTok, fmt.Sprintf(`{"key":%q,"note":"tracing a 500 in login"}`, lexKey)); st != 201 {
		t.Fatalf("plain note: status %d body %s", st, body)
	}
}

// --- page: noindex + ByteLRU ---------------------------------------------------------------------

func TestAnchorPageNoindexLRU(t *testing.T) {
	e := newEnv(t)
	id, tok := newRoot(t)
	key := "gh:acme/pagecache" + rsuf()
	if st, body, _ := e.do(t, "POST", "/v1/anchor", tok, fmt.Sprintf(`{"key":%q,"note":"hello from %s"}`, key, id)); st != 201 {
		t.Fatalf("claim: status %d body %s", st, body)
	}
	// First anonymous read: 200, noindex, never edge-cached, and it populates the ByteLRU.
	st, body, hdr := e.do(t, "GET", "/anchor/"+key, "", "")
	if st != 200 {
		t.Fatalf("read: status %d body %s", st, body)
	}
	if !strings.Contains(hdr.Get("X-Robots-Tag"), "noindex") {
		t.Fatalf("X-Robots-Tag = %q, want noindex", hdr.Get("X-Robots-Tag"))
	}
	if cc := hdr.Get("Cache-Control"); !strings.Contains(cc, "no-store") {
		t.Fatalf("Cache-Control = %q, want no-store (outside the Cache Rule)", cc)
	}
	if !strings.Contains(body, id) || !strings.Contains(body, "claimants=1") {
		t.Fatalf("read body missing claimant: %s", body)
	}
	if e.s.cache.Len() == 0 {
		t.Fatal("ByteLRU not populated after an anonymous read")
	}
	// Delete the row behind the server's back; a second anonymous read is still served from the
	// ByteLRU (proving the cache, not the table, answered).
	if _, err := testPool.Exec(context.Background(), `DELETE FROM anchor_claims WHERE key = $1`, key); err != nil {
		t.Fatal(err)
	}
	st2, body2, _ := e.do(t, "GET", "/anchor/"+key, "", "")
	if st2 != 200 || !strings.Contains(body2, id) {
		t.Fatalf("cached read: status %d body %s (expected the cached claimant)", st2, body2)
	}
}

// --- "(you)" marker ------------------------------------------------------------------------------

func TestYouMarker(t *testing.T) {
	e := newEnv(t)
	idA, tokA := newRoot(t)
	idB, tokB := newRoot(t)
	key := "gh:acme/youmark" + rsuf()
	for _, tok := range []string{tokA, tokB} {
		if st, body, _ := e.do(t, "POST", "/v1/anchor", tok, fmt.Sprintf(`{"key":%q,"note":"hi"}`, key)); st != 201 {
			t.Fatalf("claim: status %d body %s", st, body)
		}
	}
	// A reads with its token: only A's line carries (you).
	st, body, _ := e.do(t, "GET", "/anchor/"+key, tokA, "")
	if st != 200 {
		t.Fatalf("read: status %d body %s", st, body)
	}
	for _, line := range strings.Split(body, "\n") {
		switch {
		case strings.HasPrefix(line, idA):
			if !strings.Contains(line, "(you)") {
				t.Fatalf("A's own line lacks (you): %q", line)
			}
		case strings.HasPrefix(line, idB):
			if strings.Contains(line, "(you)") {
				t.Fatalf("B's line wrongly marked (you): %q", line)
			}
		}
	}
	// An anonymous read marks no one.
	_, anon, _ := e.do(t, "GET", "/anchor/"+key, "", "")
	if strings.Contains(anon, "(you)") {
		t.Fatalf("anonymous read marked (you): %s", anon)
	}
}

// --- claim with a public checkpoint --------------------------------------------------------------

func TestClaimWithPublicCheckpoint(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id, tok := newRoot(t)
	key := "gh:acme/cp" + rsuf()
	cp := core.NewID('c')
	// A real anonymous-public (pub=all => pub=true) checkpoint owned by the root.
	if _, err := testPool.Exec(ctx, `INSERT INTO checkpoints (id, root, owner, name, seq, pub, pub_scope, expires_at)
		VALUES ($1, $2, $2, 'main', 1, true, 'all', now() + interval '1 day')`, cp, id); err != nil {
		t.Fatal(err)
	}
	if st, body, _ := e.do(t, "POST", "/v1/anchor", tok, fmt.Sprintf(`{"key":%q,"note":"see cp","cp":%q}`, key, cp)); st != 201 || !strings.Contains(body, "cp=/cp/"+cp) {
		t.Fatalf("claim with cp: status %d body %s", st, body)
	}
	_, page, _ := e.do(t, "GET", "/anchor/"+key, "", "")
	if !strings.Contains(page, "cp: /cp/"+cp) {
		t.Fatalf("anchor page missing cp link: %s", page)
	}
	// A private checkpoint (pub=false) is refused.
	priv := core.NewID('c')
	if _, err := testPool.Exec(ctx, `INSERT INTO checkpoints (id, root, owner, name, seq, pub, expires_at)
		VALUES ($1, $2, $2, 'priv', 1, false, now() + interval '1 day')`, priv, id); err != nil {
		t.Fatal(err)
	}
	if st, _, _ := e.do(t, "POST", "/v1/anchor", tok, fmt.Sprintf(`{"key":%q,"note":"x","cp":%q}`, key, priv)); st != 400 {
		t.Fatalf("private cp should be refused, got %d", st)
	}
	// Another root's public checkpoint is not yours: refused.
	id2, tok2 := newRoot(t)
	_ = id2
	if st, _, _ := e.do(t, "POST", "/v1/anchor", tok2, fmt.Sprintf(`{"key":%q,"note":"x","cp":%q}`, "gh:acme/cp2"+rsuf(), cp)); st != 400 {
		t.Fatalf("foreign cp should be refused, got %d", st)
	}
}

// --- TTL refresh and janitor ---------------------------------------------------------------------

func TestTTLRefresh(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	_, tokFresh := newRoot(t)
	_, tokStale := newRoot(t)
	key := "gh:acme/ttl" + rsuf()
	for _, tok := range []string{tokFresh, tokStale} {
		if st, body, _ := e.do(t, "POST", "/v1/anchor", tok, fmt.Sprintf(`{"key":%q,"note":"x"}`, key)); st != 201 {
			t.Fatalf("claim: status %d body %s", st, body)
		}
	}
	// Age both claims past the TTL.
	if _, err := testPool.Exec(ctx, `UPDATE anchor_claims SET at = now() - interval '200 days' WHERE key = $1`, key); err != nil {
		t.Fatal(err)
	}
	// The fresh root touches its claim: at is bumped back to now().
	if st, body, _ := e.do(t, "POST", "/v1/anchor", tokFresh, fmt.Sprintf(`{"key":%q,"note":"touched"}`, key)); st != 201 {
		t.Fatalf("touch: status %d body %s", st, body)
	}
	var fresh time.Time
	if err := testPool.QueryRow(ctx, `SELECT at FROM anchor_claims WHERE key = $1 AND note = 'touched'`, key).Scan(&fresh); err != nil {
		t.Fatal(err)
	}
	if time.Since(fresh) > time.Hour {
		t.Fatalf("touch did not refresh at: %s", fresh)
	}
	// The janitor removes the untouched (still-stale) claim and keeps the refreshed one.
	if err := Janitor(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	var live int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM anchor_claims WHERE key = $1`, key).Scan(&live); err != nil {
		t.Fatal(err)
	}
	if live != 1 {
		t.Fatalf("after janitor: %d claims, want 1 (the refreshed one)", live)
	}
}
