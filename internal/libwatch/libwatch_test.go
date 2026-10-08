package libwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/know"
	"ekaii.fr/commons/internal/testdb"
)

var (
	testPool *pgxpool.Pool
	testD    *core.Deps
	mailCnt  atomic.Int64
	mailLast atomic.Value // string
)

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
	} else if pool, done := testdb.Open("libwatch", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL unset: skipping libwatch DB tests")
		os.Exit(0)
	}
	core.LevelFn = func(context.Context, core.Q, string) int { return 0 }
	core.SysMailFn = func(_ context.Context, _ core.Q, toRoot, subject, _ string) error {
		mailCnt.Add(1)
		mailLast.Store(toRoot + " " + subject)
		return nil
	}
	testD = &core.Deps{DB: testPool, Cfg: core.Config{ServerSecret: []byte("libwatch-test-secret-0123456789")}}
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// clean truncates this package's tables plus the know tables it reads.
func clean(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`TRUNCATE env_manifests, lib_releases, claims, claim_votes, libs`); err != nil {
		t.Fatal(err)
	}
}

var idSeq atomic.Int64

func insertClaim(t *testing.T, lib, kind, vto, status string, confirmed time.Time) {
	t.Helper()
	id := fmt.Sprintf("v%011d", idSeq.Add(1))
	_, err := testPool.Exec(context.Background(),
		`INSERT INTO claims (id, lib, kind, v_to, vkey_to, title, author, author_root, status, conf_w, confirmed_at, expires_at)
		 VALUES ($1,$2,$3,$4,$5,$6,'tester','',$7,1,$8, now() + interval '365 days')`,
		id, lib, kind, vto, know.VKey(vto), kind+" "+lib+" "+vto, status, confirmed)
	if err != nil {
		t.Fatal(err)
	}
}

func insertLib(t *testing.T, key, latest string, latestAt time.Time, versions string) {
	t.Helper()
	_, err := testPool.Exec(context.Background(),
		`INSERT INTO libs (key, latest, latest_at, versions, fetched_at) VALUES ($1,$2,$3,$4::jsonb, now())
		 ON CONFLICT (key) DO UPDATE SET latest=EXCLUDED.latest, latest_at=EXCLUDED.latest_at, versions=EXCLUDED.versions`,
		key, latest, latestAt, versions)
	if err != nil {
		t.Fatal(err)
	}
}

// --- TestParsersPerFormatBounded ---------------------------------------------------------------

func TestParsersPerFormatBounded(t *testing.T) {
	cases := []struct {
		format, body string
		want         map[string]string // name -> version
	}{
		{"pkg", `{"dependencies":{"react":"^18.2.0","@scope/pkg":"1.0.0"},"devDependencies":{"typescript":"~5.3.3"},"other":{"x":"9"}}`,
			map[string]string{"react": "18.2.0", "@scope/pkg": "1.0.0", "typescript": "5.3.3"}},
		{"req", "requests==2.31.0\nflask>=2.0  # comment\nnumpy==1.26.4\n-e .\n",
			map[string]string{"requests": "2.31.0", "numpy": "1.26.4"}},
		{"gomod", "module ekaii.fr/x\n\ngo 1.27\n\nrequire (\n\tgithub.com/jackc/pgx/v5 v5.11.0\n\tgolang.org/x/sync v0.17.0 // indirect\n)\n",
			map[string]string{"github.com/jackc/pgx/v5": "5.11.0", "golang.org/x/sync": "0.17.0"}},
		{"cargo", "[package]\nname = \"demo\"\nversion = \"0.1.0\"\n\n[dependencies]\nserde = \"1.0.197\"\ntokio = { version = \"1.36.0\", features = [\"full\"] }\n\n[profile.release]\nlto = true\n",
			map[string]string{"serde": "1.0.197", "tokio": "1.36.0"}},
		{"env", "node@22.9.0, pnpm@11.0.0 npm:react@18.2.0",
			map[string]string{"node": "22.9.0", "pnpm": "11.0.0", "npm:react": "18.2.0"}},
	}
	for _, c := range cases {
		deps, err := ParseFormat(c.format, []byte(c.body))
		if err != nil {
			t.Fatalf("%s: %v", c.format, err)
		}
		got := map[string]string{}
		for _, d := range deps {
			got[d.name] = d.ver
		}
		for name, ver := range c.want {
			if got[name] != ver {
				t.Errorf("%s: %q = %q, want %q (got %v)", c.format, name, got[name], ver, got)
			}
		}
		if len(deps) != len(c.want) {
			t.Errorf("%s: parsed %d deps, want %d: %v", c.format, len(deps), len(c.want), got)
		}
	}

	// Bounded: more than MaxLibs lines yields at most MaxLibs deps.
	var b strings.Builder
	for i := 0; i < MaxLibs+50; i++ {
		fmt.Fprintf(&b, "pkg%d==1.0.%d\n", i, i)
	}
	deps, err := ParseFormat("req", []byte(b.String()))
	if err != nil {
		t.Fatal(err)
	}
	if len(deps) > MaxLibs {
		t.Fatalf("req parsed %d deps, want <= %d", len(deps), MaxLibs)
	}
	if _, err := ParseFormat("toml", nil); err == nil {
		t.Fatal("unknown format should be a bad request")
	}
}

// --- TestDriftReportOrdering -------------------------------------------------------------------

func TestDriftReportOrdering(t *testing.T) {
	clean(t)
	ctx := context.Background()
	now := time.Now()
	// npm:a: one security claim. npm:b: two breaking claims. npm:c: no claims but behind latest.
	insertClaim(t, "npm:a", "security", "2.0.0", "verified", now)
	insertClaim(t, "npm:b", "breaking", "3.0.0", "verified", now)
	insertClaim(t, "npm:b", "breaking", "3.1.0", "verified", now)
	insertLib(t, "npm:c", "9.0.0", now, `[]`)

	entries := []entry{{"npm:a", "1.0.0"}, {"npm:b", "1.0.0"}, {"npm:c", "1.0.0"}}
	rep, err := buildReport(ctx, testPool, "default", entries, false, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.cnt != 3 {
		t.Fatalf("drift=%d, want 3 (%s)", rep.cnt, rep.Text())
	}
	if len(rep.lines) < 2 || rep.lines[0].Key != "npm:a" {
		t.Fatalf("security lib must sort first, got %v", keys(rep.lines))
	}
	if rep.lines[1].Key != "npm:b" || rep.lines[1].Brk != 2 {
		t.Fatalf("breaking lib (brk=2) must be second, got %v", rep.lines)
	}
	head := strings.SplitN(rep.Text(), "\n", 2)[0]
	if !strings.HasPrefix(head, "env default libs=3 known=") || !strings.Contains(head, "drift=3") {
		t.Fatalf("head line = %q", head)
	}
}

func keys(ls []libDrift) []string {
	out := make([]string, len(ls))
	for i, l := range ls {
		out[i] = l.Key
	}
	return out
}

// --- TestAnonymousEnvNothingStored -------------------------------------------------------------

func TestAnonymousEnvNothingStored(t *testing.T) {
	clean(t)
	insertClaim(t, "npm:react", "breaking", "19.0.0", "verified", time.Now())
	s := &svc{d: testD, anonCache: core.NewByteLRU(1 << 20), probeC: core.NewByteLRU(1 << 20)}
	r := httptest.NewRequest("GET", "/v/env?libs=npm:react@18.2.0,npm:vue@3.0.0", nil)
	w := httptest.NewRecorder()
	s.anon(w, r)
	if w.Code != 200 {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !strings.HasPrefix(w.Body.String(), "env (anon) libs=2") {
		t.Fatalf("body head = %q", w.Body.String())
	}
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM env_manifests`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatalf("anonymous read stored %d manifests, want 0", n)
	}
}

// --- TestAlertDigestOncePerDay -----------------------------------------------------------------

func TestAlertDigestOncePerDay(t *testing.T) {
	clean(t)
	ctx := context.Background()
	root := "a0000000alert"
	entries := []entry{{"npm:left", "1.0.0"}}
	if err := storeManifest(ctx, testD, root, "default", entries); err != nil {
		t.Fatal(err)
	}
	insertClaim(t, "npm:left", "breaking", "2.0.0", "verified", time.Now())
	mailCnt.Store(0)
	if err := AlertJanitor(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	if err := AlertJanitor(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	if got := mailCnt.Load(); got != 1 {
		t.Fatalf("sent %d digests, want exactly 1", got)
	}
	var la *time.Time
	if err := testPool.QueryRow(ctx, `SELECT last_alert FROM env_manifests WHERE root=$1`, root).Scan(&la); err != nil {
		t.Fatal(err)
	}
	if la == nil {
		t.Fatal("last_alert not advanced")
	}
}

// --- TestManifestPrivateExportPurge ------------------------------------------------------------

func TestManifestPrivateExportPurge(t *testing.T) {
	clean(t)
	ctx := context.Background()
	root := "a0000000export"
	if err := storeManifest(ctx, testD, root, "prod", []entry{{"npm:react", "18.2.0"}}); err != nil {
		t.Fatal(err)
	}
	if err := storeManifest(ctx, testD, "a0000000other", "prod", []entry{{"npm:vue", "3.0.0"}}); err != nil {
		t.Fatal(err)
	}
	var buf strings.Builder
	if err := export(ctx, testPool, root, &buf); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "env_manifest") || !strings.Contains(buf.String(), "npm:react") {
		t.Fatalf("export missing manifest: %q", buf.String())
	}
	if strings.Contains(buf.String(), "npm:vue") {
		t.Fatal("export leaked another root's manifest")
	}
	// one JSON line, parseable
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &map[string]any{}); err != nil {
		t.Fatalf("export line not JSON: %v", err)
	}
	if err := purge(ctx, testPool, root); err != nil {
		t.Fatal(err)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM env_manifests WHERE root=$1`, root).Scan(&n)
	if n != 0 {
		t.Fatalf("purge left %d manifests", n)
	}
	var other int
	testPool.QueryRow(ctx, `SELECT count(*) FROM env_manifests WHERE root='a0000000other'`).Scan(&other)
	if other != 1 {
		t.Fatal("purge removed another root's manifest")
	}
}

// --- TestLibReleasesFill -----------------------------------------------------------------------

func TestLibReleasesFill(t *testing.T) {
	clean(t)
	ctx := context.Background()
	insertClaim(t, "npm:claimed", "release", "4.2.0", "verified", time.Now())
	// effective date for the claim release.
	if _, err := testPool.Exec(ctx, `UPDATE claims SET effective = '2025-06-15' WHERE lib='npm:claimed'`); err != nil {
		t.Fatal(err)
	}
	insertLib(t, "npm:reg", "2.0.0", time.Now(), `[{"v":"1.0.0","at":"2024-01-10T00:00:00Z"},{"v":"2.0.0","at":"2025-02-20T00:00:00Z"},{"v":"0.0.0"}]`)
	if err := FillLibReleases(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	var claimN, regN int
	testPool.QueryRow(ctx, `SELECT count(*) FROM lib_releases WHERE src='claim'`).Scan(&claimN)
	testPool.QueryRow(ctx, `SELECT count(*) FROM lib_releases WHERE src='registry'`).Scan(&regN)
	if claimN != 1 {
		t.Fatalf("claim releases=%d, want 1", claimN)
	}
	if regN != 2 {
		t.Fatalf("registry releases=%d, want 2 (zero-date version dropped)", regN)
	}
	var released string
	testPool.QueryRow(ctx, `SELECT released::text FROM lib_releases WHERE key='npm:claimed'`).Scan(&released)
	if released != "2025-06-15" {
		t.Fatalf("claim released=%q, want 2025-06-15", released)
	}
	// idempotent
	if err := FillLibReleases(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	var total int
	testPool.QueryRow(ctx, `SELECT count(*) FROM lib_releases`).Scan(&total)
	if total != 3 {
		t.Fatalf("after re-run total=%d, want 3", total)
	}
}

// --- TestProbeDeterministicAndDecoys -----------------------------------------------------------

func seedReleases(t *testing.T, n int) {
	t.Helper()
	ctx := context.Background()
	for i := 0; i < n; i++ {
		month := time.Now().UTC().AddDate(0, -(i%34)-1, 0).Format("2006-01-02")
		_, err := testPool.Exec(ctx, `INSERT INTO lib_releases (key, ver, released, src) VALUES ($1,$2,$3::date,'registry') ON CONFLICT DO NOTHING`,
			fmt.Sprintf("npm:lib%d", i), fmt.Sprintf("%d.0.0", i), month)
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestProbeDeterministicAndDecoys(t *testing.T) {
	clean(t)
	ctx := context.Background()
	seedReleases(t, 30)
	secret := []byte("libwatch-test-secret-0123456789")
	day := time.Now().UTC().Truncate(24 * time.Hour)
	a, err := probeSample(ctx, testPool, secret, "seed-xyz", 12, day)
	if err != nil {
		t.Fatal(err)
	}
	b, err := probeSample(ctx, testPool, secret, "seed-xyz", 12, day)
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != 14 {
		t.Fatalf("items=%d, want 14 (12 real + 2 decoys)", len(a))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("non-deterministic at %d: %+v vs %+v", i, a[i], b[i])
		}
	}
	// exactly 2 decoys, and no decoy is a real release.
	decoys := 0
	present := map[string]bool{}
	rows, _ := testPool.Query(ctx, `SELECT key, ver FROM lib_releases`)
	for rows.Next() {
		var k, v string
		rows.Scan(&k, &v)
		present[k+"\x00"+v] = true
	}
	rows.Close()
	for _, it := range a {
		if it.Decoy {
			decoys++
			if present[it.Lib+"\x00"+it.Ver] {
				t.Fatalf("decoy %s %s is a real release", it.Lib, it.Ver)
			}
		} else if !present[it.Lib+"\x00"+it.Ver] {
			t.Fatalf("real item %s %s not in the pool", it.Lib, it.Ver)
		}
	}
	if decoys != 2 {
		t.Fatalf("decoys=%d, want 2", decoys)
	}
	// A different seed reorders.
	c, _ := probeSample(ctx, testPool, secret, "other-seed", 12, day)
	same := true
	for i := range a {
		if i < len(c) && (a[i].Lib != c[i].Lib || a[i].Ver != c[i].Ver) {
			same = false
		}
	}
	if same {
		t.Fatal("different seed produced the same sample")
	}
}

// --- TestProbeEstimate -------------------------------------------------------------------------

func TestProbeEstimate(t *testing.T) {
	// 10 real items: 3 known through 2025-03, then a sharp wall of unknowns from 2025-04 on, so
	// the latest month with >=60% of [m-2,m] known and <=30% of (m,m+3] known is 2025-03.
	mk := func(idx int, month string, decoy bool) ProbeItem {
		return ProbeItem{Idx: idx, Lib: "npm:x", Ver: "1", Month: month, Decoy: decoy}
	}
	items := []ProbeItem{
		mk(1, "2025-01", false), mk(2, "2025-02", false), mk(3, "2025-03", false),
		mk(4, "2025-04", false), mk(5, "2025-04", false), mk(6, "2025-04", false),
		mk(7, "2025-05", false), mk(8, "2025-05", false), mk(9, "2025-05", false),
		mk(10, "2025-06", false),
		mk(11, "", true), mk(12, "", true),
	}
	ans := map[int]byte{}
	for i := 1; i <= 3; i++ {
		ans[i] = 'y'
	}
	for i := 4; i <= 10; i++ {
		ans[i] = 'n'
	}
	est := estimate(items, ans)
	if est.Cutoff != "2025-03" {
		t.Fatalf("cutoff=%s, want 2025-03 (%s)", est.Cutoff, est.Text())
	}
	if est.Known != 3 || est.N != 10 {
		t.Fatalf("known=%d/%d, want 3/10", est.Known, est.N)
	}
	if est.DecoysYes != 0 {
		t.Fatalf("decoys_yes=%d, want 0", est.DecoysYes)
	}
	if !strings.Contains(est.Text(), "window=2025-01..2025-05") {
		t.Fatalf("text=%q, want window 2025-01..2025-05", est.Text())
	}
	// A decoy answered yes lowers confidence.
	ans[11] = 'y'
	est2 := estimate(items, ans)
	if est2.DecoysYes != 1 || est2.Conf >= est.Conf {
		t.Fatalf("decoy yes should lower conf: %s vs %s", est2.Text(), est.Text())
	}
}
