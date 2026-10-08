package ctlog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/notary"
	"ekaii.fr/commons/internal/sign"
	"ekaii.fr/commons/internal/trust"
)

var testPool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	url := os.Getenv("TEST_DATABASE_URL")
	if url == "" {
		fmt.Println("TEST_DATABASE_URL unset: skipping ctlog DB tests")
		os.Exit(0)
	}
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		panic(err)
	}
	if err := core.Migrate(ctx, pool); err != nil {
		panic(err)
	}
	testPool = pool
	core.LevelFn = trust.LevelOf
	code := m.Run()
	pool.Close()
	os.Exit(code)
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789abcdef"), SignKID: 1, PowBits: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	sign.Register(mux, d)
	notary.Register(mux, d)
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, srv: srv}
}

// reset truncates every table these tests touch so each runs against a clean log (the scratch DB
// is private to this package, SPEC-v2 test isolation).
func reset(t *testing.T) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`TRUNCATE ts, ts_days, ctlog_state, pins, jobs, replicas, service_votes, service_versions, services, events RESTART IDENTITY CASCADE`); err != nil {
		t.Fatalf("reset: %v", err)
	}
}

func (e *tenv) exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := testPool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

// mkVersion inserts a verified service version (owner = system) and returns its wasm hash.
func mkVersion(t *testing.T, name string, ver int, verifiedAgo time.Duration) string {
	t.Helper()
	wasm := hex.EncodeToString(sha256Of(name + "@" + strconv.Itoa(ver)))
	e := func(sql string, args ...any) {
		if _, err := testPool.Exec(context.Background(), sql, args...); err != nil {
			t.Fatalf("mkVersion %q: %v", sql, err)
		}
	}
	e(`INSERT INTO services (name, owner_root) VALUES ($1, $2) ON CONFLICT (name) DO NOTHING`, name, core.SystemID)
	e(`INSERT INTO service_versions (name, ver, wasm, state, verified_at) VALUES ($1, $2, $3, 'verified', now() - $4::interval)
		ON CONFLICT (name, ver) DO UPDATE SET state = 'verified', verified_at = now() - $4::interval`,
		name, ver, wasm, verifiedAgo.String())
	return wasm
}

func sha256Of(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func (e *tenv) get(t *testing.T, path string) (int, string) {
	t.Helper()
	resp, err := http.Get(e.srv.URL + path)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

// moveTo backdates ts rows (by 32-byte hash) to a past day, clearing their root so they re-seal.
func moveTo(t *testing.T, day time.Time, hs ...[]byte) {
	t.Helper()
	delta := int(truncDay(time.Now().UTC()).Sub(day).Hours() / 24)
	if _, err := testPool.Exec(context.Background(),
		`UPDATE ts SET t = t - make_interval(days => $2), day = $3, root = NULL WHERE h = ANY($1)`,
		hs, delta, day.Format("2006-01-02")); err != nil {
		t.Fatal(err)
	}
}

func truncDay(t time.Time) time.Time {
	y, m, d := t.UTC().Date()
	return time.Date(y, m, d, 0, 0, 0, 0, time.UTC)
}

func pastDay(n int) time.Time { return truncDay(time.Now().UTC()).AddDate(0, 0, -n) }

// ---- tests ------------------------------------------------------------------------------------

func TestLeavesForVersionsPinsAtts(t *testing.T) {
	reset(t)
	e := newEnv(t)
	ctx := context.Background()
	s := &svc{d: e.d}

	wasm := mkVersion(t, "cx-leaf", 2, 0)
	pinHex := hex.EncodeToString(sha256Of("pinmod"))
	e.exec(t, `INSERT INTO pins (hash, name) VALUES ($1, 'cx-leaf') ON CONFLICT (hash) DO NOTHING`, pinHex)
	attLine := "att1 j=jobleaf01 o=deadbeef t=1 k=1"
	e.exec(t, `INSERT INTO jobs (id, submitter, root, wasm, input, ms, mb, status, att, att_d)
		VALUES ('jobleaf01', $1, $1, $2, 'in', 10, 64, 'done', $3, true)`, core.SystemID, wasm, attLine)

	if err := s.janitor(ctx); err != nil {
		t.Fatalf("janitor: %v", err)
	}

	// Each leaf is in ts under its hash with the server note, and the cursor was recorded.
	for _, c := range []struct {
		h    []byte
		note string
		kind string
		ref  string
	}{
		{svcHash("cx-leaf", 2, wasm), "svc cx-leaf@2", "svc", "cx-leaf@2"},
		{pinHash(pinHex), "pin " + pinHex[:12], "pin", pinHex},
		{attHash(attLine), "att jobleaf01", "att", "jobleaf01"},
	} {
		var note, owner string
		if err := testPool.QueryRow(ctx, `SELECT note, owner FROM ts WHERE h = $1`, c.h).Scan(&note, &owner); err != nil {
			t.Fatalf("leaf %s not stamped: %v", c.kind, err)
		}
		if note != c.note || owner != core.SystemID {
			t.Fatalf("leaf %s note=%q owner=%q, want %q / %s", c.kind, note, owner, c.note, core.SystemID)
		}
		var cnt int
		testPool.QueryRow(ctx, `SELECT count(*) FROM ctlog_state WHERE kind = $1 AND ref = $2`, c.kind, c.ref).Scan(&cnt)
		if cnt != 1 {
			t.Fatalf("ctlog_state %s/%s rows = %d, want 1", c.kind, c.ref, cnt)
		}
	}

	// Idempotent: a second pass stamps nothing new.
	var before int
	testPool.QueryRow(ctx, `SELECT count(*) FROM ts`).Scan(&before)
	if err := s.janitor(ctx); err != nil {
		t.Fatalf("janitor 2: %v", err)
	}
	var after int
	testPool.QueryRow(ctx, `SELECT count(*) FROM ts`).Scan(&after)
	if after != before {
		t.Fatalf("second janitor added %d leaves", after-before)
	}
}

func TestChainedRoots(t *testing.T) {
	reset(t)
	e := newEnv(t)
	ctx := context.Background()
	s := &svc{d: e.d}

	// Two past days, each with its own leaf; seal them and chain them.
	d1, d2 := pastDay(3), pastDay(2)
	var h1, h2 [32]byte
	copy(h1[:], sha256Of("chain-a-"+d1.String()))
	copy(h2[:], sha256Of("chain-b-"+d2.String()))
	if _, _, err := notary.Stamp(ctx, testPool, h1[:], "a", ""); err != nil {
		t.Fatal(err)
	}
	if _, _, err := notary.Stamp(ctx, testPool, h2[:], "b", ""); err != nil {
		t.Fatal(err)
	}
	moveTo(t, d1, h1[:])
	moveTo(t, d2, h2[:])
	if _, err := notary.SealPending(ctx, e.d); err != nil {
		t.Fatalf("SealPending: %v", err)
	}
	if err := s.janitor(ctx); err != nil {
		t.Fatalf("janitor: %v", err)
	}

	// The signed root1 line of each day carries chain=; the column matches SHA256(prev || root).
	root1, chain1, line1 := dayRow(t, d1.Format("2006-01-02"))
	root2, chain2, line2 := dayRow(t, d2.Format("2006-01-02"))
	wantChain1 := chainStep(genesis, root1)
	wantChain2 := chainStep(wantChain1, root2)
	if !eq(chain1, wantChain1) || !eq(chain2, wantChain2) {
		t.Fatalf("chain mismatch: d1=%x (want %x) d2=%x (want %x)", chain1, wantChain1, chain2, wantChain2)
	}
	if !strings.Contains(line1, "chain="+hex.EncodeToString(wantChain1)+" k=1") {
		t.Fatalf("root1 of d1 missing chain: %q", line1)
	}
	if !strings.Contains(line2, "chain="+hex.EncodeToString(wantChain2)+" k=1") {
		t.Fatalf("root1 of d2 missing chain: %q", line2)
	}

	// /ts/chain.txt has one line per sealed day, oldest first.
	st, body := e.get(t, "/ts/chain.txt")
	if st != 200 {
		t.Fatalf("/ts/chain.txt status %d", st)
	}
	wantL1 := d1.Format("2006-01-02") + " " + hex.EncodeToString(wantChain1) + " " + hex.EncodeToString(root1)
	wantL2 := d2.Format("2006-01-02") + " " + hex.EncodeToString(wantChain2) + " " + hex.EncodeToString(root2)
	if !strings.Contains(body, wantL1+"\n") || !strings.Contains(body, wantL2+"\n") {
		t.Fatalf("chain.txt = %q, want lines %q and %q", body, wantL1, wantL2)
	}
	if strings.Index(body, wantL1) > strings.Index(body, wantL2) {
		t.Fatalf("chain.txt not oldest-first: %q", body)
	}
}

func dayRow(t *testing.T, day string) (root, chain []byte, line string) {
	t.Helper()
	if err := testPool.QueryRow(context.Background(), `SELECT root, chain, line FROM ts_days WHERE day = $1`, day).Scan(&root, &chain, &line); err != nil {
		t.Fatalf("day %s: %v", day, err)
	}
	return root, chain, line
}

func eq(a, b []byte) bool { return hex.EncodeToString(a) == hex.EncodeToString(b) }

func TestProofRouteVerifies(t *testing.T) {
	reset(t)
	e := newEnv(t)
	ctx := context.Background()
	s := &svc{d: e.d}

	// Publish and log several versions so the day's tree has more than one leaf.
	wasm := mkVersion(t, "cx-jq", 3, 0)
	mkVersion(t, "cx-jq", 1, 0)
	mkVersion(t, "cx-other", 1, 0)
	if err := s.janitor(ctx); err != nil {
		t.Fatalf("janitor: %v", err)
	}
	// Backdate every stamped leaf to a past day and seal it.
	var hs [][]byte
	rows, _ := testPool.Query(ctx, `SELECT h FROM ts`)
	for rows.Next() {
		var h []byte
		rows.Scan(&h)
		hs = append(hs, h)
	}
	rows.Close()
	moveTo(t, pastDay(1), hs...)
	if _, err := notary.SealPending(ctx, e.d); err != nil {
		t.Fatalf("SealPending: %v", err)
	}
	if err := s.janitor(ctx); err != nil {
		t.Fatalf("janitor 2: %v", err)
	}

	st, body := e.get(t, "/svc/cx-jq@3/proof")
	if st != 200 {
		t.Fatalf("/svc/cx-jq@3/proof status %d: %s", st, body)
	}
	f := fields(body)
	if f["name"] != "cx-jq" || f["ver"] != "3" || f["wasm"] != wasm {
		t.Fatalf("proof fields = %v", f)
	}
	// Recompute the leaf and verify inclusion against the day root.
	hb, _ := hex.DecodeString(f["h"])
	tu, _ := strconv.ParseInt(f["t"], 10, 64)
	n, _ := strconv.ParseInt(f["n"], 10, 64)
	idx, _ := strconv.Atoi(f["idx"])
	size, _ := strconv.Atoi(f["size"])
	root, _ := hex.DecodeString(f["root"])
	proof, err := notary.ParseProof(f["proof"])
	if err != nil {
		t.Fatalf("proof parse: %v", err)
	}
	leaf := notary.Leaf(hb, time.Unix(tu, 0), n)
	if !notary.VerifyProof(leaf, idx, size, proof, root) {
		t.Fatalf("inclusion proof does not verify: %v", f)
	}
	if f["h"] != hex.EncodeToString(svcHash("cx-jq", 3, wasm)) {
		t.Fatalf("leaf hash mismatch")
	}
	if len(f["chain"]) != 64 {
		t.Fatalf("chain missing from proof: %v", f)
	}
	// The root on the proof is the day root listed in /ts/roots.txt.
	_, roots := e.get(t, "/ts/roots.txt")
	if !strings.Contains(roots, "root="+f["root"]) {
		t.Fatalf("proof root not in roots.txt")
	}
}

func fields(line string) map[string]string {
	m := map[string]string{}
	for _, tok := range strings.Fields(strings.TrimSpace(line)) {
		if k, v, ok := strings.Cut(tok, "="); ok {
			m[k] = v
		}
	}
	return m
}

func TestUnloggedWarning(t *testing.T) {
	reset(t)
	e := newEnv(t)
	ctx := context.Background()
	s := &svc{d: e.d}

	// A version verified 49 h ago, never stamped: the page shows unlogged! and the janitor files
	// one inbox event to the owner.
	wasm := mkVersion(t, "cx-stale", 1, 49*time.Hour)
	_ = wasm

	lines := pageLines(ctx, testPool, "cx-stale")
	found := false
	for _, l := range lines {
		if strings.HasPrefix(l, "unlogged!") {
			found = true
		}
	}
	if !found {
		t.Fatalf("pageLines = %v, want an unlogged! line", lines)
	}

	var before int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ctlog' AND root_scope = $1`, core.SystemID).Scan(&before)
	if err := s.scanUnlogged(ctx); err != nil {
		t.Fatalf("scanUnlogged: %v", err)
	}
	var after int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ctlog' AND root_scope = $1 AND ref = 'cx-stale@1'`, core.SystemID).Scan(&after)
	if after != before+1 {
		t.Fatalf("unlogged inbox events = %d, want %d", after, before+1)
	}
	// Idempotent: a second scan does not re-file.
	if err := s.scanUnlogged(ctx); err != nil {
		t.Fatalf("scanUnlogged 2: %v", err)
	}
	var again int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ctlog' AND root_scope = $1 AND ref = 'cx-stale@1'`, core.SystemID).Scan(&again)
	if again != after {
		t.Fatalf("second scan re-filed: %d -> %d", after, again)
	}

	// Once stamped, the page flips to logged and no new warning fires.
	if err := s.stampVersions(ctx); err != nil {
		t.Fatalf("stampVersions: %v", err)
	}
	for _, l := range pageLines(ctx, testPool, "cx-stale") {
		if strings.HasPrefix(l, "unlogged!") {
			t.Fatalf("still unlogged after stamping: %v", l)
		}
		if !strings.HasPrefix(l, "logged:") {
			t.Fatalf("unexpected page line %q", l)
		}
	}
}
