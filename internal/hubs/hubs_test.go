package hubs

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"

	"github.com/jackc/pgx/v5/pgxpool"
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
	} else if pool, done := testdb.Open("P80-hubs", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping hubs DB tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf
	core.RepLogger = trust.RecordRep
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
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &env{d: d, srv: srv}
}

func (e *env) get(t *testing.T, path string) (int, string) {
	t.Helper()
	res, err := http.Get(e.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b))
}

// insEntry inserts a seed (immediately indexable) fix. errClass "" leaves err_class classless,
// "NULL" leaves it unprocessed (NULL), anything else stores it. ageH backdates creation.
func insEntry(t *testing.T, id, title, symptom, errClass string, ageH int, tags []string) {
	t.Helper()
	ctx := context.Background()
	var ec any = errClass
	if errClass == "NULL" {
		ec = nil
	}
	if tags == nil {
		tags = []string{}
	}
	_, err := testPool.Exec(ctx, `INSERT INTO kb (id, kind, title, symptom, tags, author, author_root, seed, err_class, created, expires_at)
		VALUES ($1, 'fix', $2, $3, $4, 'seed', '', true, $5, now() - make_interval(hours => $6::int), now() + interval '60 days')`,
		id, title, symptom, tags, ec, ageH)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM kb WHERE id = $1`, id) })
}

func kid(seed string) string { return "k" + seed }

func TestErrClassExtractorFamilies(t *testing.T) {
	cases := []struct{ title, want string }{
		{"ECONNREFUSED: connection refused by 127.0.0.1:6379", "ECONNREFUSED"},
		{"ENOENT: no such file or directory, open 'x'", "ENOENT"},
		{"TypeError: cannot read properties of undefined", "TypeError"},
		{"NullPointerException at com.example.Main.run", "NullPointerException"},
		{"RuntimeWarning: coroutine was never awaited", "RuntimeWarning"},
		{"SegmentationFault in libc", "SegmentationFault"},
		{"error TS2345: argument of type string is not assignable", "TS2345"},
		{"E0432: unresolved import `serde`", "E0432"},
		{"ORA-00942: table or view does not exist", "ORA-00942"},
		{"SQLSTATE 23505: duplicate key value violates unique constraint", "SQLSTATE-23505"},
		{"build failed: exit status 1", ""},
		{"deployment hung with exit status 137 after OOM", ""},
		{"could not connect to the database server", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := ErrClass(c.title); got != c.want {
			t.Errorf("ErrClass(%q) = %q, want %q", c.title, got, c.want)
		}
	}
}

func TestHubIndexableThreshold(t *testing.T) {
	e := newEnv(t)
	insEntry(t, kid("thr2aa"), "connect timeout a", "ring", "ETIMEDOUT", 3, nil)
	insEntry(t, kid("thr2ab"), "connect timeout b", "ring", "ETIMEDOUT", 3, nil)
	// Two indexable members: page renders but is noindex.
	res, err := http.Get(e.srv.URL + "/err/ETIMEDOUT")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatalf("two members: status %d", res.StatusCode)
	}
	if res.Header.Get("X-Robots-Tag") != "noindex" {
		t.Fatalf("two members: want noindex, got %q", res.Header.Get("X-Robots-Tag"))
	}
	// A third makes the hub indexable.
	insEntry(t, kid("thr2ac"), "connect timeout c", "ring", "ETIMEDOUT", 3, nil)
	res, err = http.Get(e.srv.URL + "/err/ETIMEDOUT")
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 200 || res.Header.Get("X-Robots-Tag") == "noindex" {
		t.Fatalf("three members: status %d robots %q", res.StatusCode, res.Header.Get("X-Robots-Tag"))
	}
	// Zero visible members: 404.
	if st, _ := e.get(t, "/err/NOSUCHERRCLASS"); st != 404 {
		t.Fatalf("empty class: status %d want 404", st)
	}
	// The .md twin lists the count line.
	st, body := e.get(t, "/err/ETIMEDOUT.md")
	if st != 200 || !strings.Contains(body, "fixes=3") {
		t.Fatalf(".md twin: status %d body:\n%s", st, body)
	}
}

func TestNoQueryDerivedHub(t *testing.T) {
	e := newEnv(t)
	// A: title carries the class but the row is classless (err_class ''): it must NOT appear.
	insEntry(t, kid("nqda01"), "ECONNRESET while talking to upstream", "x", "", 3, nil)
	// B..D: stored err_class, titles that do not mention it: they define the hub.
	insEntry(t, kid("nqdb01"), "socket reset mid-stream one", "x", "ECONNRESET", 3, nil)
	insEntry(t, kid("nqdb02"), "socket reset mid-stream two", "x", "ECONNRESET", 3, nil)
	insEntry(t, kid("nqdb03"), "socket reset mid-stream three", "x", "ECONNRESET", 3, nil)
	st, body := e.get(t, "/err/ECONNRESET.md")
	if st != 200 {
		t.Fatalf("status %d", st)
	}
	if strings.Contains(body, kid("nqda01")) {
		t.Fatalf("hub leaked the title-matching but classless row:\n%s", body)
	}
	for _, id := range []string{kid("nqdb01"), kid("nqdb02"), kid("nqdb03")} {
		if !strings.Contains(body, id) {
			t.Fatalf("hub missing stored-class member %s:\n%s", id, body)
		}
	}
	if !strings.Contains(body, "fixes=3") {
		t.Fatalf("count should be 3 (stored class only):\n%s", body)
	}
}

func TestEcoHub(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// An indexable fix referencing npm:left-pad.
	insEntry(t, kid("ecoa01"), "left-pad regression", "x", "", 3, nil)
	if _, err := testPool.Exec(ctx, `INSERT INTO kb_versions (kb_id, lib, ver) VALUES ($1, 'npm:left-pad', '1.3.0')`, kid("ecoa01")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM kb_versions WHERE kb_id = $1`, kid("ecoa01")) })
	// A verified claim on pypi:requests (confirmed claim, no indexable entry needed).
	cid := "cecoaa"
	if _, err := testPool.Exec(ctx, `INSERT INTO claims (id, lib, kind, title, author, status, confirmed_at, expires_at)
		VALUES ($1, 'pypi:requests', 'deprecated', 'verify=False default changed', 'seed', 'verified', now(), now() + interval '60 days')`, cid); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM claims WHERE id = $1`, cid) })

	st, body := e.get(t, "/eco/npm.md")
	if st != 200 || !strings.Contains(body, "npm:left-pad") {
		t.Fatalf("eco npm: status %d body:\n%s", st, body)
	}
	st, body = e.get(t, "/eco/pypi.md")
	if st != 200 || !strings.Contains(body, "pypi:requests") {
		t.Fatalf("eco pypi: status %d body:\n%s", st, body)
	}
	// Unknown ecosystem: 404.
	if st, _ := e.get(t, "/eco/bogus"); st != 404 {
		t.Fatalf("unknown eco: status %d want 404", st)
	}
	// A known but empty ecosystem: 404.
	if st, _ := e.get(t, "/eco/gem"); st != 404 {
		t.Fatalf("empty eco: status %d want 404", st)
	}
}

func TestMonthlyArchiveNav(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	// Three entries spread across three months, all indexable.
	now := time.Now().UTC()
	mk := func(id string, monthsAgo int) string {
		d := now.AddDate(0, -monthsAgo, 0)
		ym := d.Format("2006-01")
		if _, err := testPool.Exec(ctx, `INSERT INTO kb (id, kind, title, author, author_root, seed, err_class, created, expires_at)
			VALUES ($1, 'fix', $2, 'seed', '', true, '', $3, now() + interval '90 days')`, id, "archive "+id, d); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM kb WHERE id = $1`, id) })
		return ym
	}
	ymNew := mk(kid("arcnew"), 1)
	ymMid := mk(kid("arcmid"), 2)
	ymOld := mk(kid("arcold"), 3)

	st, body := e.get(t, "/kb/"+ymMid+"/?f=md")
	if st != 200 {
		t.Fatalf("mid month: status %d body:\n%s", st, body)
	}
	if !strings.Contains(body, kid("arcmid")) {
		t.Fatalf("mid month missing its entry:\n%s", body)
	}
	// prev points at the older month, next at the newer.
	if !strings.Contains(body, "/kb/"+ymOld+"/") {
		t.Fatalf("mid month missing prev %s:\n%s", ymOld, body)
	}
	if !strings.Contains(body, "/kb/"+ymNew+"/") {
		t.Fatalf("mid month missing next %s:\n%s", ymNew, body)
	}
	// Month with no indexable entries: 404.
	gap := now.AddDate(-3, 0, 0).Format("2006-01")
	if st, _ := e.get(t, "/kb/"+gap+"/"); st != 404 {
		t.Fatalf("empty month: status %d want 404", st)
	}
}

func TestRelatedRefreshIndexableOnly(t *testing.T) {
	newEnv(t)
	ctx := context.Background()
	src := kid("relsrc")
	rel := kid("relidx") // indexable, shares a tag -> should be related
	hid := kid("relhid") // hidden -> never related
	insEntry(t, src, "postgres deadlock on upsert", "two transactions", "", 3, []string{"postgres"})
	insEntry(t, rel, "postgres deadlock detected again", "lock wait", "", 3, []string{"postgres"})
	insEntry(t, hid, "postgres deadlock hidden variant", "lock wait", "", 3, []string{"postgres"})
	if _, err := testPool.Exec(ctx, `UPDATE kb SET hidden = true WHERE id = $1`, hid); err != nil {
		t.Fatal(err)
	}
	// Source has a read (views >= 1).
	if _, err := testPool.Exec(ctx, `INSERT INTO kb_reads_daily (kb_id, day, views) VALUES ($1, current_date, 3)`, src); err != nil {
		t.Fatal(err)
	}
	if err := refreshRelated(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	ids := Related(ctx, testPool, src)
	foundRel, foundHid := false, false
	for _, id := range ids {
		if id == rel {
			foundRel = true
		}
		if id == hid {
			foundHid = true
		}
	}
	if !foundRel {
		t.Fatalf("related should include the indexable sibling, got %v", ids)
	}
	if foundHid {
		t.Fatalf("related must exclude the hidden sibling, got %v", ids)
	}
	// A source with zero views is never refreshed.
	noview := kid("relnov")
	insEntry(t, noview, "redis cluster down", "x", "", 3, []string{"redis"})
	if err := refreshRelated(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	if ids := Related(ctx, testPool, noview); ids != nil {
		t.Fatalf("unread source should have no related row, got %v", ids)
	}
}

func TestSitemapChildrenRegistered(t *testing.T) {
	e := newEnv(t)
	sm := e.d.Sitemaps()
	for _, name := range []string{"hubs", "tasks", "gov"} {
		if sm[name] == nil {
			t.Fatalf("sitemap child %q not registered", name)
		}
	}
	if e.d.Feeds()["err"] == nil {
		t.Fatalf("feed 'err' not registered")
	}
	// hubs.xml lists /err/, /eco/ and /kb/<ym>/ URLs built from stored data.
	ctx := context.Background()
	insEntry(t, kid("smpa01"), "sitemap member one", "x", "EPIPE", 3, nil)
	insEntry(t, kid("smpa02"), "sitemap member two", "x", "EPIPE", 3, nil)
	insEntry(t, kid("smpa03"), "sitemap member three", "x", "EPIPE", 3, nil)
	if _, err := testPool.Exec(ctx, `INSERT INTO kb_versions (kb_id, lib, ver) VALUES ($1, 'npm:ws', '8.0.0')`, kid("smpa01")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM kb_versions WHERE kb_id = $1`, kid("smpa01")) })
	urls, err := hubsSitemap(ctx, testPool)
	if err != nil {
		t.Fatal(err)
	}
	var hasErr, hasEco, hasMonth bool
	for _, u := range urls {
		switch {
		case strings.Contains(u.Loc, "/err/EPIPE"):
			hasErr = true
		case strings.Contains(u.Loc, "/eco/npm"):
			hasEco = true
		case strings.Contains(u.Loc, "/kb/") && strings.HasSuffix(u.Loc, "/"):
			hasMonth = true
		}
	}
	if !hasErr || !hasEco || !hasMonth {
		t.Fatalf("hubs.xml missing children: err=%v eco=%v month=%v (%d urls)", hasErr, hasEco, hasMonth, len(urls))
	}
}

func TestLandingTopHubs(t *testing.T) {
	newEnv(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		insEntry(t, kid(fmt.Sprintf("lnd0%d", i)), fmt.Sprintf("landing member %d", i), "x", "EACCES", 3, nil)
	}
	hubsList := LandingFn(ctx, testPool)
	found := false
	for _, h := range hubsList {
		if h == "/err/EACCES" {
			found = true
		}
	}
	if !found {
		t.Fatalf("landing should list /err/EACCES, got %v", hubsList)
	}
}
