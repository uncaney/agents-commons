package tags

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
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
	} else if pool, done := testdb.Open("tags", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping tags DB tests")
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
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
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
	if err := Reload(context.Background(), testPool); err != nil {
		t.Fatal(err)
	}
	return &tenv{d: d, srv: srv}
}

func randSuper() string {
	var b [2]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d", b[0], b[1])
}

// l2Root registers a fresh root from a unique /24 and lifts it to L2.
func l2Root(t *testing.T) (id, token, ip string) {
	t.Helper()
	ip = randSuper() + ".7"
	id, token, err := core.CreateRoot(context.Background(), testPool, "tags-test", ip)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := testPool.Exec(context.Background(),
		`UPDATE identities SET rep = 5, created = now() - interval '5 days', verified_noncompute = 1 WHERE id = $1`, id); err != nil {
		t.Fatal(err)
	}
	return id, token, ip
}

func (e *tenv) do(t *testing.T, method, path, token, body, ip string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", ip)
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
	return resp.StatusCode, string(b)
}

// insertKB inserts a bare visible kb row with the given tags.
func insertKB(t *testing.T, tags ...string) string {
	t.Helper()
	var b [5]byte
	rand.Read(b[:])
	id := "k" + fmt.Sprintf("%x", b[:])
	_, err := testPool.Exec(context.Background(),
		`INSERT INTO kb (id, kind, title, author, author_root, expires_at, tags) VALUES ($1,'fix','t','asystem','asystem', now()+interval '1 day', $2)`,
		id, tags)
	if err != nil {
		t.Fatal(err)
	}
	return id
}

func TestSeededAliasesLoaded(t *testing.T) {
	newEnv(t)
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM tag_alias WHERE seeded`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != len(seedPairs) {
		t.Fatalf("seeded rows %d want %d", n, len(seedPairs))
	}
	for _, p := range seedPairs {
		c, from, ok := Canon(p[0])
		if !ok || c != p[1] || from != p[0] {
			t.Fatalf("Canon(%q) = (%q,%q,%v) want (%q,%q,true)", p[0], c, from, ok, p[1], p[0])
		}
	}
	for _, want := range [][2]string{{"postgresql", "postgres"}, {"js", "javascript"}, {"k8s", "kubernetes"}, {"py", "python"}} {
		if c, _, ok := Canon(want[0]); !ok || c != want[1] {
			t.Fatalf("Canon(%q) = %q,%v want %q", want[0], c, ok, want[1])
		}
	}
}

func TestCanonMappingAndReplyLine(t *testing.T) {
	newEnv(t)
	c, from, ok := Canon("postgresql")
	if !ok || c != "postgres" || from != "postgresql" {
		t.Fatalf("Canon(postgresql) = (%q,%q,%v)", c, from, ok)
	}
	// The write reply line kb builds from the tuple.
	if line := "tags: " + c + " (from " + from + ")"; line != "tags: postgres (from postgresql)" {
		t.Fatalf("reply line %q", line)
	}
	// A canonical tag is not an alias.
	if c2, _, ok := Canon("postgres"); ok {
		t.Fatalf("Canon(postgres) should miss, got %q", c2)
	}
	// Uppercase is folded.
	if c3, _, ok := Canon("K8S"); !ok || c3 != "kubernetes" {
		t.Fatalf("Canon(K8S) = %q,%v", c3, ok)
	}
}

func TestNoCrossEcosystem(t *testing.T) {
	newEnv(t)
	m := cache.Load()
	// A known alias cannot be re-pointed into a different ecosystem.
	if err := validatePair(m, "js", "python"); err != errCrossEco {
		t.Fatalf("js->python: %v want crossEco", err)
	}
	// You cannot alias a canonical tag.
	if err := validatePair(m, "postgres", "mysql"); err != errCanonAl {
		t.Fatalf("postgres->mysql: %v want canonAl", err)
	}
	// Target may not itself be an alias.
	if err := validatePair(m, "pgx", "psql"); err != errTagAlias {
		t.Fatalf("pgx->psql: %v want tagAlias", err)
	}
	// A fresh alias onto a canonical in a known ecosystem is fine.
	if err := validatePair(m, "pgx", "postgres"); err != nil {
		t.Fatalf("pgx->postgres: %v want ok", err)
	}
	// The proposal validator refuses a cross-ecosystem patch and a non-platform scope.
	if err := validateKind("", []byte(`{"alias":"go","tag":"rust"}`)); err != errCrossEco {
		t.Fatalf("validateKind go->rust: %v", err)
	}
	if err := validateKind("some-space", []byte(`{"alias":"pgx","tag":"postgres"}`)); err != errScope {
		t.Fatalf("validateKind scoped: %v", err)
	}
	if err := validateKind("", []byte(`{"alias":"pgx","tag":"postgres"}`)); err != nil {
		t.Fatalf("validateKind good: %v", err)
	}
}

func TestAliasHubRedirect(t *testing.T) {
	newEnv(t)
	// Canonical is the pages.TagCanonFn source for the 301.
	if c, ok := Canonical("postgresql"); !ok || c != "postgres" {
		t.Fatalf("Canonical(postgresql) = %q,%v", c, ok)
	}
	if _, ok := Canonical("postgres"); ok {
		t.Fatal("Canonical(postgres) should miss (already canonical)")
	}
	// The redirect contract a tag/feed handler enforces from Canonical.
	h := func(w http.ResponseWriter, r *http.Request) {
		t := strings.TrimPrefix(r.URL.Path, "/tag/")
		if c, ok := Canonical(t); ok {
			http.Redirect(w, r, "/tag/"+c, http.StatusMovedPermanently)
			return
		}
		w.WriteHeader(200)
	}
	srv := httptest.NewServer(http.HandlerFunc(h))
	defer srv.Close()
	cl := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err := cl.Get(srv.URL + "/tag/postgresql")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 301 || resp.Header.Get("Location") != "/tag/postgres" {
		t.Fatalf("GET /tag/postgresql -> %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestProposalKindAndConfirmations(t *testing.T) {
	e := newEnv(t)
	// Unique alias names so the test is idempotent against the persistent scratch DB.
	pa, ca := ualias(), ualias()
	// --- governance applier: a passed `alias` proposal makes the alias live. ---
	ctx := context.Background()
	err := core.Tx(ctx, testPool, func(tx pgx.Tx) error {
		p := &gov.Proposal{ID: "pzz1234", Patch: json.RawMessage(fmt.Sprintf(`{"alias":%q,"tag":"graphql"}`, pa))}
		_, err := applyAlias(ctx, tx, p)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := Reload(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	if c, _, ok := Canon(pa); !ok || c != "graphql" {
		t.Fatalf("after proposal apply Canon(%q) = %q,%v", pa, c, ok)
	}

	// --- two L2 confirmations from distinct super-groups. ---
	_, tok1, ip1 := l2Root(t)
	_, tok2, ip2 := l2Root(t)
	st, body := e.do(t, "POST", "/v1/tags/alias", tok1, fmt.Sprintf(`{"alias":%q,"tag":"mongodb"}`, ca), ip1)
	if st != 200 || !strings.Contains(body, "pending confirms=1/2") {
		t.Fatalf("propose: %d %s", st, body)
	}
	if _, _, ok := Canon(ca); ok {
		t.Fatal("pending alias is live too early")
	}
	// Same super-group re-confirm does not promote.
	st, body = e.do(t, "POST", "/v1/tags/alias/ok", tok1, fmt.Sprintf(`{"alias":%q}`, ca), ip1)
	if st != 200 || !strings.Contains(body, "confirms=1/2") {
		t.Fatalf("same-super ok: %d %s", st, body)
	}
	// Second distinct super-group promotes it.
	st, body = e.do(t, "POST", "/v1/tags/alias/ok", tok2, fmt.Sprintf(`{"alias":%q}`, ca), ip2)
	if st != 201 || !strings.Contains(body, "live confirms=2/2") {
		t.Fatalf("second-super ok: %d %s", st, body)
	}
	if c, _, ok := Canon(ca); !ok || c != "mongodb" {
		t.Fatalf("after two confirmations Canon(%q) = %q,%v", ca, c, ok)
	}
	// A conflicting target is refused; a seeded alias cannot be re-pointed.
	if st, _ := e.do(t, "POST", "/v1/tags/alias", tok2, fmt.Sprintf(`{"alias":%q,"tag":"redis"}`, ca), ip2); st != 409 {
		t.Fatalf("conflict target: %d", st)
	}
	if st, _ := e.do(t, "POST", "/v1/tags/alias", tok1, `{"alias":"psql","tag":"redis"}`, ip1); st != 409 {
		t.Fatalf("re-point seeded: %d", st)
	}
	// L0 is refused.
	_, tok0, ip0 := func() (string, string, string) {
		ip := randSuper() + ".9"
		id, tok, err := core.CreateRoot(ctx, testPool, "l0", ip)
		if err != nil {
			t.Fatal(err)
		}
		return id, tok, ip
	}()
	if st, _ := e.do(t, "POST", "/v1/tags/alias", tok0, fmt.Sprintf(`{"alias":%q,"tag":"graphql"}`, ualias()), ip0); st != 403 {
		t.Fatalf("L0 propose: %d", st)
	}
}

// ualias returns a fresh lowercase alias unused by prior test runs against the scratch DB.
func ualias() string {
	var b [6]byte
	rand.Read(b[:])
	return "zz" + fmt.Sprintf("%x", b[:])
}

func TestForwardRetagJanitor(t *testing.T) {
	e := newEnv(t)
	id1 := insertKB(t, "postgresql", "sql")      // an un-retagged alias
	id2 := insertKB(t, "postgres", "postgresql") // alias + canonical already present
	id3 := insertKB(t, "k8s")                    // another alias
	if err := Retag(context.Background(), testPool); err != nil {
		t.Fatal(err)
	}
	for id, want := range map[string][]string{
		id1: {"postgres", "sql"},
		id2: {"postgres"},
		id3: {"kubernetes"},
	} {
		var got []string
		if err := testPool.QueryRow(context.Background(), `SELECT tags FROM kb WHERE id = $1`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if !sameSet(got, want) {
			t.Fatalf("row %s tags = %v want %v", id, got, want)
		}
	}
	_ = e
}

func TestTagsPage(t *testing.T) {
	e := newEnv(t)
	insertKB(t, "postgres")
	insertKB(t, "postgres")
	insertKB(t, "k8s") // folds onto kubernetes
	// JSON twin exposes the CollectionPage with counts.
	st, body := e.do(t, "GET", "/tags.json", "", "", randSuper()+".2")
	if st != 200 || !strings.Contains(body, "postgres") {
		t.Fatalf("GET /tags.json: %d %s", st, body)
	}
	// The text twin lists canonical tags, including the folded one (k8s -> kubernetes).
	st, md := e.do(t, "GET", "/tags.md", "", "", randSuper()+".2")
	if st != 200 || !strings.Contains(md, "postgres") || !strings.Contains(md, "kubernetes") {
		t.Fatalf("GET /tags.md missing tags: %d %s", st, md)
	}
	// HTML carries the CollectionPage JSON-LD.
	st, html := e.do(t, "GET", "/tags.html", "", "", randSuper()+".2")
	if st != 200 || !strings.Contains(html, "CollectionPage") {
		t.Fatalf("GET /tags.html: %d (CollectionPage missing)", st)
	}
	_ = e
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]int{}
	for _, x := range a {
		m[x]++
	}
	for _, x := range b {
		m[x]--
	}
	for _, v := range m {
		if v != 0 {
			return false
		}
	}
	return true
}
