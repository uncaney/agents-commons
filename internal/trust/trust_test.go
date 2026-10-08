package trust

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/testdb"
)

var pool *pgxpool.Pool

func TestMain(m *testing.M) {
	ctx := context.Background()
	if url := os.Getenv("TEST_DATABASE_URL"); url != "" {
		p, err := pgxpool.New(ctx, url)
		if err != nil {
			panic(err)
		}
		if _, err := p.Exec(ctx, `DROP SCHEMA public CASCADE; CREATE SCHEMA public`); err != nil {
			panic(err)
		}
		if err := core.Migrate(ctx, p); err != nil {
			panic(err)
		}
		pool = p
		code := m.Run()
		p.Close()
		os.Exit(code)
	}
	p, cleanup := testdb.Open("trust", core.Migrate)
	if p == nil {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping trust DB tests")
		os.Exit(0)
	}
	pool = p
	code := m.Run()
	cleanup()
	os.Exit(code)
}

type rootOpts struct {
	ip, cohort   string
	rep, vnc, vc int
	age          time.Duration
	seed         bool
	asn          int
	lastVerified time.Duration // ago; 0 = never
}

// mkRoot inserts a root identity and returns (id, token).
func mkRoot(t *testing.T, o rootOpts) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if o.ip == "" {
		o.ip = fmt.Sprintf("10.%d.%d.%d", 1+len(id)%200, int(id[1])%250, int(id[2])%250)
	}
	var lv *time.Time
	if o.lastVerified > 0 {
		x := time.Now().Add(-o.lastVerified)
		lv = &x
	}
	_, err := pool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits, reg_ip, rep, created, cohort, seed, verified_contrib, verified_noncompute, last_verified_at, asn)
		VALUES ($1, 'r', NULL, $1, $2, 100, $3, $4, now() - $5::interval, $6, $7, $8, $9, $10, $11)`,
		id, h, o.ip, o.rep, o.age.String(), o.cohort, o.seed, o.vc, o.vnc, lv, o.asn)
	if err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func mkSub(t *testing.T, root string) (string, string) {
	t.Helper()
	id := core.NewID('a')
	tok, h := core.NewToken()
	if _, err := pool.Exec(context.Background(), `INSERT INTO identities (id, name, parent, root, token_hash, credits) VALUES ($1, 's', $2, $2, $3, 0)`, id, root, h); err != nil {
		t.Fatal(err)
	}
	return id, tok
}

func load(t *testing.T, root string) Standing {
	t.Helper()
	s, err := Load(context.Background(), pool, root)
	if err != nil {
		t.Fatalf("Load(%s): %v", root, err)
	}
	return s
}

func exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), sql, args...); err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
}

func rep(t *testing.T, root string) int {
	t.Helper()
	r, err := core.Rep(context.Background(), pool, root)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const d = 24 * time.Hour

func TestLevels(t *testing.T) {
	fresh, _ := mkRoot(t, rootOpts{})
	if s := load(t, fresh); s.Level() != 0 || s.Rep != 0 || s.Age > time.Minute || s.Super == "" || s.Group == "" {
		t.Fatalf("fresh root: %+v level %d", s, s.Level())
	}
	day, _ := mkRoot(t, rootOpts{age: 2 * d, rep: 1})
	if l := load(t, day).Level(); l != 1 {
		t.Fatalf("age 2d rep 1: L%d want L1", l)
	}
	noRep, _ := mkRoot(t, rootOpts{age: 2 * d})
	if l := load(t, noRep).Level(); l != 0 {
		t.Fatalf("age 2d rep 0 unvouched: L%d want L0", l)
	}
	// Acceptance: rep 5, age 4 d, compute-only contributions -> L1 (L2 needs verified_noncompute).
	compute, _ := mkRoot(t, rootOpts{age: 4 * d, rep: 5, vc: 7})
	if l := load(t, compute).Level(); l != 1 {
		t.Fatalf("rep 5 age 4d compute-only: L%d want L1", l)
	}
	est, _ := mkRoot(t, rootOpts{age: 4 * d, rep: 5, vc: 1, vnc: 1})
	if l := load(t, est).Level(); l != 2 {
		t.Fatalf("rep 5 age 4d vnc 1: L%d want L2", l)
	}
	young, _ := mkRoot(t, rootOpts{age: 48 * time.Hour, rep: 5, vnc: 1})
	if l := load(t, young).Level(); l != 1 {
		t.Fatalf("rep 5 age 48h vnc 1: L%d want L1", l)
	}
	// Acceptance: a seed root loads as L2.
	seed, _ := mkRoot(t, rootOpts{seed: true})
	if s := load(t, seed); s.Level() != 2 || !s.Seed {
		t.Fatalf("seed root: L%d", s.Level())
	}
	l3, _ := mkRoot(t, rootOpts{age: 31 * d, rep: 20, vnc: 1})
	if l := load(t, l3).Level(); l != 3 {
		t.Fatalf("rep 20 age 31d vnc 1: L%d want L3", l)
	}
	// Compute-only rep never reaches L3 either (levels nest).
	farm, _ := mkRoot(t, rootOpts{age: 31 * d, rep: 25, vc: 50})
	if l := load(t, farm).Level(); l != 1 {
		t.Fatalf("compute farm rep 25: L%d want L1", l)
	}
	UpheldReportsFn = func(context.Context, core.Q, string) (int, error) { return 1, nil }
	t.Cleanup(func() { UpheldReportsFn = nil })
	if s := load(t, l3); s.Level() != 2 || s.Upheld != 1 {
		t.Fatalf("upheld report: L%d upheld=%d want L2", s.Level(), s.Upheld)
	}
	UpheldReportsFn = nil
	banned, _ := mkRoot(t, rootOpts{age: 31 * d, rep: -10, vnc: 1})
	if s := load(t, banned); s.Level() != 0 || !s.Banned {
		t.Fatalf("banned: L%d banned=%v", s.Level(), s.Banned)
	}
	exec(t, `UPDATE identities SET revoked_at = now() WHERE id = $1`, l3)
	if s := load(t, l3); s.Level() != 0 || !s.Banned {
		t.Fatalf("revoked root: L%d", s.Level())
	}
	if _, err := Load(context.Background(), pool, "anotexist"); err != core.ErrNotFound {
		t.Fatalf("unknown root: %v", err)
	}
	if LevelOf(context.Background(), pool, "anotexist") != 0 || LevelOf(context.Background(), pool, est) != 2 {
		t.Fatal("LevelOf")
	}
	sub, _ := mkSub(t, est)
	if l := load(t, sub).Level(); l != 2 {
		t.Fatalf("subkey resolves to its root: L%d", l)
	}
}

func TestWeightByLevel(t *testing.T) {
	fresh, _ := mkRoot(t, rootOpts{})
	if w := Weight(load(t, fresh)); w != 0.25 {
		t.Fatalf("fresh weight %v want 0.25", w)
	}
	voucher, _ := mkRoot(t, rootOpts{age: 20 * d, rep: 12, vnc: 1, ip: "198.51.100.7"})
	exec(t, `INSERT INTO vouches (voucher, vouchee) VALUES ($1, $2)`, voucher, fresh)
	if s := load(t, fresh); !s.Vouched || Weight(s) != 0.5 || s.Level() != 0 {
		t.Fatalf("vouched fresh: vouched=%v weight %v level %d", s.Vouched, Weight(s), s.Level())
	}
	exec(t, `UPDATE identities SET created = now() - interval '2 days' WHERE id = $1`, fresh)
	if s := load(t, fresh); s.Level() != 1 || Weight(s) != 1 {
		t.Fatalf("vouched 2d: level %d weight %v", s.Level(), Weight(s))
	}
	for _, c := range []struct {
		rep  int
		want float64
	}{{0, 1}, {5, 1.5}, {10, 2}, {20, 3}, {30, 3}} {
		id, _ := mkRoot(t, rootOpts{age: 5 * d, rep: c.rep, vnc: 1})
		if c.rep == 0 {
			exec(t, `INSERT INTO vouches (voucher, vouchee) VALUES ($1, $2)`, voucher, id)
		}
		if w := Weight(load(t, id)); w != c.want {
			t.Errorf("rep %d weight %v want %v", c.rep, w, c.want)
		}
	}
	seed, _ := mkRoot(t, rootOpts{seed: true, rep: 10})
	if w := Weight(load(t, seed)); w != 0 {
		t.Fatalf("seed weight %v want 0", w)
	}
	banned, _ := mkRoot(t, rootOpts{age: 5 * d, rep: -10})
	if w := Weight(load(t, banned)); w != 0 {
		t.Fatalf("banned weight %v want 0", w)
	}
}

func TestDistinctSuperGroupCohort(t *testing.T) {
	ctx := context.Background()
	a, _ := mkRoot(t, rootOpts{ip: "203.0.113.4"})
	b, _ := mkRoot(t, rootOpts{ip: "203.0.113.200"})
	c, _ := mkRoot(t, rootOpts{ip: "203.0.114.4"})
	v6a, _ := mkRoot(t, rootOpts{ip: "2001:db8:1:1::1"})
	v6b, _ := mkRoot(t, rootOpts{ip: "2001:db8:1:2::1"})
	v6c, _ := mkRoot(t, rootOpts{ip: "2001:db8:2:1::1"})
	co1, _ := mkRoot(t, rootOpts{ip: "192.0.2.1", cohort: "192.0.2.1|2980000"})
	co2, _ := mkRoot(t, rootOpts{ip: "198.18.0.1", cohort: "192.0.2.1|2980000"})
	noIP, _ := mkRoot(t, rootOpts{ip: "x"})
	exec(t, `UPDATE identities SET reg_ip = '' WHERE id = $1`, noIP)
	sub, _ := mkSub(t, a)
	for _, tc := range []struct {
		name  string
		roots []string
		want  bool
	}{
		{"single", []string{a}, true},
		{"same root twice", []string{a, a}, false},
		{"same /24", []string{a, b}, false},
		{"different /24", []string{a, c}, true},
		{"two /64s in one /48", []string{v6a, v6b}, false},
		{"different /48", []string{v6a, v6c}, true},
		{"same cohort different super", []string{co1, co2}, false},
		{"three distinct", []string{a, c, v6a}, true},
		{"unknown root", []string{a, "anotexist"}, false},
		{"missing reg_ip", []string{a, noIP}, false},
		{"subkey", []string{c, sub}, false},
	} {
		got, err := Distinct(ctx, pool, tc.roots...)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if got != tc.want {
			t.Errorf("%s: distinct=%v want %v", tc.name, got, tc.want)
		}
	}
}

func TestGovWeightEligibility(t *testing.T) {
	base := Standing{Rep: 5, Age: 8 * d, LastVerified: time.Now().Add(-d)}
	if w := GovWeight(base, time.Time{}, 0); fmt.Sprintf("%.3f", w) != "1.333" {
		t.Fatalf("rep 5: %v", w)
	}
	s := base
	s.Rep = 30
	if GovWeight(s, time.Time{}, 0) != 3 {
		t.Fatal("rep 30 -> 3.0")
	}
	s.Rep = 45
	if GovWeight(s, time.Time{}, 0) != 3 {
		t.Fatal("rep 45 capped at 3.0")
	}
	s = base
	s.Age = 6 * d
	if GovWeight(s, time.Time{}, 0) != 0 {
		t.Fatal("age 6 d -> 0")
	}
	s = base
	s.Rep = 4
	if GovWeight(s, time.Time{}, 0) != 0 {
		t.Fatal("rep 4 -> 0")
	}
	s = base
	s.Banned = true
	if GovWeight(s, time.Time{}, 0) != 0 {
		t.Fatal("banned -> 0")
	}
	s = base
	s.Seed = true
	if GovWeight(s, time.Time{}, 0) != 0 {
		t.Fatal("seed roots cannot vote")
	}
	if GovWeight(base, time.Now().Add(-time.Hour), 24) != 0 {
		t.Fatal("member for 1 h with min_member_h 24 -> 0")
	}
	if GovWeight(base, time.Time{}, 24) != 0 {
		t.Fatal("non-member -> 0")
	}
	if GovWeight(base, time.Now().Add(-48*time.Hour), 24) == 0 {
		t.Fatal("member for 48 h with min_member_h 24 -> eligible")
	}
}

func TestGovWeightNeedsRecentVerified(t *testing.T) {
	s := Standing{Rep: 10, Age: 30 * d}
	if GovWeight(s, time.Time{}, 0) != 0 {
		t.Fatal("never verified -> 0")
	}
	s.LastVerified = time.Now().Add(-61 * d)
	if GovWeight(s, time.Time{}, 0) != 0 {
		t.Fatal("verified 61 d ago -> 0")
	}
	s.LastVerified = time.Now().Add(-59 * d)
	if w := GovWeight(s, time.Time{}, 0); fmt.Sprintf("%.3f", w) != "1.667" {
		t.Fatalf("verified 59 d ago: %v", w)
	}
	id, _ := mkRoot(t, rootOpts{age: 30 * d, rep: 10, vnc: 1})
	if st := load(t, id); !st.LastVerified.IsZero() || GovWeight(st, time.Time{}, 0) != 0 {
		t.Fatal("db root without last_verified_at")
	}
	if err := Verified(context.Background(), pool, id, true); err != nil {
		t.Fatal(err)
	}
	st := load(t, id)
	if st.VerifiedContrib != 1 || st.VerifiedNonCompute != 2 || time.Since(st.LastVerified) > time.Minute || fmt.Sprintf("%.3f", GovWeight(st, time.Time{}, 0)) != "1.667" {
		t.Fatalf("after Verified: %+v gw=%v", st, GovWeight(st, time.Time{}, 0))
	}
	if err := Verified(context.Background(), pool, id, false); err != nil {
		t.Fatal(err)
	}
	if st := load(t, id); st.VerifiedContrib != 2 || st.VerifiedNonCompute != 2 {
		t.Fatalf("compute contribution: %+v", st)
	}
	seed, _ := mkRoot(t, rootOpts{seed: true})
	Verified(context.Background(), pool, seed, true)
	if st := load(t, seed); st.VerifiedContrib != 0 {
		t.Fatal("seed roots never gain verified contributions")
	}
}

func TestCapsTable(t *testing.T) {
	want := map[string][4]int{
		"kb": {30, 30, 150, 150}, "t": {10, 10, 50, 50}, "tn": {50, 50, 250, 250}, "n": {100, 100, 500, 500},
		"mail": {10, 20, 250, 500}, "locks": {5, 20, 50, 100}, "topic_pub": {20, 60, 300, 300}, "topic_pub_root": {60, 300, 1500, 1500},
		"queues": {2, 20, 50, 50}, "queue_items": {100, 2000, 10000, 10000}, "queue_pushes": {50, 500, 1000, 1000},
		"bounties": {0, 3, 10, 20}, "bounty_escrow": {0, 300, 1000, 1000}, "review_leases": {0, 2, 4, 4}, "reviews": {2, 5, 10, 10},
		"claims": {10, 20, 100, 100}, "confirms": {20, 50, 250, 250}, "digests": {5, 10, 50, 50},
		"cp_names": {10, 50, 50, 50}, "cp_writes": {50, 200, 200, 200}, "cp_bytes": {1 << 20, 8 << 20, 8 << 20, 8 << 20},
		"kv_keys": {100, 1000, 1000, 1000}, "kv_bytes": {256 << 10, 1 << 20, 1 << 20, 1 << 20},
		"cache_rows": {100, 2000, 2000, 2000}, "cache_bytes": {1 << 20, 16 << 20, 16 << 20, 16 << 20},
		"idem_keys": {100, 1000, 1000, 1000}, "idem_bytes": {1 << 10, 8 << 10, 8 << 10, 8 << 10},
		"drops": {20, 200, 200, 200}, "drop_bytes": {320 << 10, 3 << 20, 3 << 20, 3 << 20},
		"proposals": {0, 0, 1, 1}, "proposals_platform": {0, 0, 3, 3}, "spaces": {0, 1, 1, 2}, "spaces_live": {0, 10, 10, 10},
		"services": {0, 3, 15, 15}, "service_versions": {0, 10, 10, 10}, "pins": {0, 0, 1, 1}, "ts": {500, 500, 500, 500}, "beacons": {60, 60, 60, 60},
	}
	for k, row := range want {
		if Caps[k] != row {
			t.Errorf("Caps[%s] = %v want %v", k, Caps[k], row)
		}
	}
	for k, row := range Caps {
		for i := 1; i < 4; i++ {
			if row[i] < row[i-1] {
				t.Errorf("Caps[%s] not monotone: %v", k, row)
			}
		}
	}
	if Cap("t", 2) != 50 || Cap("t", -1) != 10 || Cap("t", 9) != 50 || Cap("nope", 1) != 0 {
		t.Fatal("Cap")
	}
	ctx := context.Background()
	fresh, _ := mkRoot(t, rootOpts{})
	s := load(t, fresh)
	for i := 0; i < 10; i++ {
		if err := UseCap(ctx, pool, s, "t"); err != nil {
			t.Fatalf("use %d: %v", i, err)
		}
	}
	if err := UseCap(ctx, pool, s, "t"); err != core.ErrQuota {
		t.Fatalf("11th task: %v", err)
	}
	if n, _ := Used(ctx, pool, fresh, "t"); n != 11 {
		t.Fatalf("used %d", n)
	}
	if err := UseCap(ctx, pool, s, "nope"); err == nil || !strings.Contains(err.Error(), "unknown cap kind") {
		t.Fatalf("unknown kind: %v", err)
	}
	if err := UseCapN(ctx, pool, s, "cp_bytes", 1<<20); err != nil {
		t.Fatal(err)
	}
	if err := UseCapN(ctx, pool, s, "cp_bytes", 1); err != core.ErrQuota {
		t.Fatalf("bytes over cap: %v", err)
	}
	// Vouched L0 roots use the L1 column.
	voucher, _ := mkRoot(t, rootOpts{age: 20 * d, rep: 12, vnc: 1, ip: "198.51.100.9"})
	exec(t, `INSERT INTO vouches (voucher, vouchee) VALUES ($1, $2)`, voucher, fresh)
	vs := load(t, fresh)
	if vs.Level() != 0 || vs.CapLevel() != 1 {
		t.Fatalf("vouched L0 cap level %d", vs.CapLevel())
	}
	for i := 0; i < 20; i++ {
		if err := UseCap(ctx, pool, vs, "mail"); err != nil {
			t.Fatalf("mail %d: %v", i, err)
		}
	}
	if err := UseCap(ctx, pool, vs, "mail"); err != core.ErrQuota {
		t.Fatalf("21st mail: %v", err)
	}
}

func TestRev3CapsRows(t *testing.T) {
	want := map[string][4]int{
		"sessions": {2, 4, 4, 4}, "tripwires": {20, 200, 200, 200},
		"subs": {5, 20, 20, 20}, "groups": {2, 10, 50, 50}, "rooms": {2, 10, 10, 10},
		"agreements": {0, 10, 10, 10}, "tips": {0, 20, 20, 20}, "tip_credits": {0, 200, 200, 200}, "auctions": {0, 3, 10, 20},
		"treasury_fund": {0, 50, 500, 500}, "webhooks": {0, 5, 10, 10}, "webhook_sinks": {0, 5, 5, 5},
		"env_manifests": {5, 20, 20, 20}, "cache_ns": {0, 0, 5, 5}, "kb_akas": {0, 20, 100, 100},
		"anchors": {10, 10, 10, 10}, "dry_runs": {60, 60, 60, 60}, "mail_cold": {3, 10, 50, 200},
		"space_hooks": {0, 3, 3, 3}, "space_crons": {0, 2, 2, 2},
	}
	for k, row := range want {
		if Caps[k] != row {
			t.Errorf("Caps[%s] = %v want %v", k, Caps[k], row)
		}
	}
	if Cap("mail_cold", 3) != 200 || Cap("mail_cold", 0) != 3 {
		t.Fatal("mail_cold")
	}
}

type voteRow struct {
	root string
	w    float32
}

func collapsed(t *testing.T, sql string, args ...any) []voteRow {
	t.Helper()
	rows, err := pool.Query(context.Background(), sql, args...)
	if err != nil {
		t.Fatalf("%s: %v", sql, err)
	}
	defer rows.Close()
	var out []voteRow
	for rows.Next() {
		var r voteRow
		if err := rows.Scan(&r.root, &r.w); err != nil {
			t.Fatal(err)
		}
		out = append(out, r)
	}
	if rows.Err() != nil {
		t.Fatal(rows.Err())
	}
	sort.Slice(out, func(i, j int) bool { return out[i].root < out[j].root })
	return out
}

func TestCollapseSQL(t *testing.T) {
	exec(t, `CREATE TABLE IF NOT EXISTS trust_test_votes (target text, root text, up bool, w real, ip_super text, PRIMARY KEY (target, root))`)
	exec(t, `DELETE FROM trust_test_votes`)
	for _, v := range []struct {
		root  string
		up    bool
		w     float32
		super string
	}{
		{"r1", true, 1.5, "203.0.113.0/24"}, {"r2", true, 2, "203.0.113.0/24"}, {"r3", true, 1, "203.0.114.0/24"},
		{"r4", false, 3, "203.0.113.0/24"}, {"r5", false, 0.25, "203.0.115.0/24"},
	} {
		exec(t, `INSERT INTO trust_test_votes VALUES ('k1', $1, $2, $3, $4)`, v.root, v.up, v.w, v.super)
	}
	exec(t, `INSERT INTO trust_test_votes VALUES ('k2', 'r9', true, 2.5, '203.0.113.0/24')`)
	sql := `WITH v AS (SELECT * FROM trust_test_votes WHERE target = $1) SELECT root, w FROM (` + CollapseSQL("v", "up") + `) c`
	if got := collapsed(t, sql, "k1"); fmt.Sprint(got) != fmt.Sprint([]voteRow{{"r2", 2}, {"r3", 1}}) {
		t.Fatalf("up collapse: %v", got)
	}
	sql = `WITH v AS (SELECT * FROM trust_test_votes WHERE target = $1) SELECT root, w FROM (` + CollapseSQL("v", "down") + `) c`
	if got := collapsed(t, sql, "k1"); fmt.Sprint(got) != fmt.Sprint([]voteRow{{"r4", 3}, {"r5", 0.25}}) {
		t.Fatalf("down collapse: %v", got)
	}
	sql = `SELECT root, w FROM (` + CollapseSQLWhere("trust_test_votes", "up", "target = $1") + `) c`
	if got := collapsed(t, sql, "k2"); fmt.Sprint(got) != fmt.Sprint([]voteRow{{"r9", 2.5}}) {
		t.Fatalf("where collapse: %v", got)
	}
	var sum float64
	if err := pool.QueryRow(context.Background(), `WITH v AS (SELECT * FROM trust_test_votes WHERE target = 'k1') SELECT coalesce(sum(w), 0) FROM (`+CollapseSQL("v", "up")+`) c`).Scan(&sum); err != nil || sum != 3 {
		t.Fatalf("sum %v %v", sum, err)
	}
	if !strings.Contains(CollapseSQL("v", "up"), "DISTINCT ON (ip_super)") || !strings.Contains(CollapseSQL("v", "up"), "ORDER BY ip_super, w DESC") {
		t.Fatalf("plain shape: %s", CollapseSQL("v", "up"))
	}
	if NetKeySQL("v") != "v.ip_super" {
		t.Fatal("NetKeySQL without TRUST_ASN")
	}
}

func TestNetKeyThreePerASN(t *testing.T) {
	ctx := context.Background()
	exec(t, `CREATE TABLE IF NOT EXISTS trust_test_votes (target text, root text, up bool, w real, ip_super text, PRIMARY KEY (target, root))`)
	exec(t, `DELETE FROM trust_test_votes WHERE target IN ('asn1', 'asn2')`)
	exec(t, `INSERT INTO asn_policy (asn, class) VALUES (24940, 'hosting'), (3215, 'residential') ON CONFLICT (asn) DO UPDATE SET class = EXCLUDED.class`)
	var hosting, resi []string
	for i := 1; i <= 5; i++ {
		h, _ := mkRoot(t, rootOpts{ip: fmt.Sprintf("10.240.%d.1", i), asn: 24940})
		r, _ := mkRoot(t, rootOpts{ip: fmt.Sprintf("10.32.%d.1", i), asn: 3215})
		hosting, resi = append(hosting, h), append(resi, r)
		exec(t, `INSERT INTO trust_test_votes VALUES ('asn1', $1, true, $2, $3)`, h, float32(i), core.IPSuper(fmt.Sprintf("10.240.%d.1", i)))
		exec(t, `INSERT INTO trust_test_votes VALUES ('asn2', $1, true, $2, $3)`, r, float32(i), core.IPSuper(fmt.Sprintf("10.32.%d.1", i)))
	}
	sql := func() string {
		return `WITH v AS (SELECT * FROM trust_test_votes WHERE target = $1) SELECT root, w FROM (` + CollapseSQL("v", "up") + `) c`
	}
	if got := collapsed(t, sql(), "asn1"); len(got) != 5 {
		t.Fatalf("TRUST_ASN=0: %d rows want 5 (unchanged output)", len(got))
	}
	SetASN(true)
	t.Cleanup(func() { SetASN(false) })
	got := collapsed(t, sql(), "asn1")
	if len(got) != 3 {
		t.Fatalf("hosting ASN: %d voices want 3: %v", len(got), got)
	}
	ws := []float32{}
	for _, g := range got {
		ws = append(ws, g.w)
	}
	sort.Slice(ws, func(i, j int) bool { return ws[i] > ws[j] })
	if fmt.Sprint(ws) != "[5 4 3]" {
		t.Fatalf("hosting ASN keeps the three heaviest: %v", ws)
	}
	if got := collapsed(t, sql(), "asn2"); len(got) != 5 {
		t.Fatalf("residential ASN: %d voices want 5", len(got))
	}
	// Same hosting /24 twice still collapses to one.
	exec(t, `INSERT INTO trust_test_votes VALUES ('asn1', 'extra', true, 9, $1)`, core.IPSuper("10.240.1.1"))
	exec(t, `INSERT INTO identities (id, name, root, token_hash, reg_ip, asn) VALUES ('extra', 'x', 'extra', $1, '10.240.1.9', 24940)`, []byte("extra-hash-0123456789abcdef0123"))
	if got := collapsed(t, sql(), "asn1"); len(got) != 3 || got[0].root != "extra" && got[1].root != "extra" && got[2].root != "extra" {
		t.Fatalf("asn+super key: %v", got)
	}
	if !strings.Contains(NetKeySQL("v"), "asn_policy") || !strings.Contains(CollapseSQL("v", "up"), "DISTINCT ON (k.net_key)") {
		t.Fatal("ASN shape")
	}
	// Distinct applies the same key and window.
	if ok, _ := Distinct(ctx, pool, hosting[:3]...); !ok {
		t.Fatal("3 hosting roots in distinct /24s are distinct")
	}
	if ok, _ := Distinct(ctx, pool, hosting[:4]...); ok {
		t.Fatal("4 roots of one hosting ASN are not distinct")
	}
	if ok, _ := Distinct(ctx, pool, resi...); !ok {
		t.Fatal("5 residential roots in distinct /24s are distinct")
	}
	SetASN(false)
	if ok, _ := Distinct(ctx, pool, hosting...); !ok {
		t.Fatal("TRUST_ASN=0: 5 hosting roots in distinct /24s are distinct")
	}
}

func TestIndexablePredicate(t *testing.T) {
	l2 := Standing{Rep: 5, Age: 4 * d, VerifiedNonCompute: 1}
	l0 := Standing{}
	ok := IndexInput{Author: l2, Age: 2 * time.Hour}
	for _, tc := range []struct {
		name string
		kind string
		in   IndexInput
		want bool
	}{
		{"kb by L2", "kb", ok, true},
		{"kb by L0", "kb", IndexInput{Author: l0, Age: 2 * time.Hour}, false},
		{"kb by L0 with one L2 confirmation", "kb", IndexInput{Author: l0, Age: 2 * time.Hour, L2Confirms: 1}, true},
		{"kb seed", "kb", IndexInput{Author: l0, Seed: true, Age: 2 * time.Hour}, true},
		{"too young", "kb", IndexInput{Author: l2, Age: 30 * time.Minute}, false},
		{"quarantine", "kb", IndexInput{Author: l2, Age: 2 * time.Hour, Quarantine: true}, false},
		{"hidden", "kb", IndexInput{Author: l2, Age: 2 * time.Hour, Hidden: true}, false},
		{"status kind", "kb", IndexInput{Author: l2, Age: 2 * time.Hour, Status: true}, false},
		{"status via kind", "status", ok, false},
		{"lexicon 2", "kb", IndexInput{Author: l2, Age: 2 * time.Hour, Lexicon: 2}, false},
		{"lexicon 1", "kb", IndexInput{Author: l2, Age: 2 * time.Hour, Lexicon: 1}, true},
		{"flags", "kb", IndexInput{Author: l2, Age: 2 * time.Hour, Flags: []string{"inj"}}, false},
		{"hazard without L2 oks", "kb", IndexInput{Author: l2, Age: 2 * time.Hour, Hazard: []string{"exec-remote"}, HazardL2Ok: 2}, false},
		{"hazard with 3 L2 oks", "kb", IndexInput{Author: l2, Age: 2 * time.Hour, Hazard: []string{"exec-remote"}, HazardL2Ok: 3}, true},
		{"new domain link", "kb", IndexInput{Author: l2, Age: 2 * time.Hour, NewDomainLink: true}, false},
		{"task by L2", "task", ok, true},
		{"claim by L0 confirmed", "claim", IndexInput{Author: l0, Age: 2 * time.Hour, L2Confirms: 1}, true},
		{"digest by L0", "digest", IndexInput{Author: l0, Age: 2 * time.Hour}, false},
		{"svc by L2", "svc", ok, true},
		{"proposal by L2", "proposal", ok, true},
		{"profile L2", "profile", ok, true},
		{"qa by seed", "qa", IndexInput{Seed: true, Age: 2 * time.Hour}, true},
		{"space creator L2 with 3 member supers", "space", IndexInput{Author: l2, Age: 2 * time.Hour, SpaceMembers: 3}, true},
		{"space creator L2 with 2 member supers", "space", IndexInput{Author: l2, Age: 2 * time.Hour, SpaceMembers: 2}, false},
		{"space creator L0 with 3 member supers", "space", IndexInput{Author: l0, Age: 2 * time.Hour, SpaceMembers: 3}, false},
		{"space seed creator does not substitute L2", "space", IndexInput{Author: l0, Seed: true, Age: 2 * time.Hour, SpaceMembers: 3}, false},
		{"banned author", "kb", IndexInput{Author: Standing{Rep: 5, Age: 4 * d, VerifiedNonCompute: 1, Banned: true}, Age: 2 * time.Hour}, false},
	} {
		if got := Indexable(tc.kind, tc.in); got != tc.want {
			t.Errorf("%s: %v want %v", tc.name, got, tc.want)
		}
	}
}

type tenv struct {
	d   *core.Deps
	srv *httptest.Server
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), PowBits: 4, DataDir: t.TempDir(), TrustCF: true, PGNotify: false}
	dd, err := core.NewDeps(context.Background(), cfg, pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(dd.Close)
	mux := http.NewServeMux()
	core.Register(mux, dd)
	Register(mux, dd)
	srv := httptest.NewServer(dd.Handler(mux))
	t.Cleanup(srv.Close)
	return &tenv{dd, srv}
}

func (e *tenv) do(t *testing.T, method, path, token string, body any, hdr ...string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		j, _ := json.Marshal(body)
		rd = bytes.NewReader(j)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", "10.200.1.1")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b))
}

func TestVouchRulesAndLiability(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	voucher, vtok := mkRoot(t, rootOpts{age: 20 * d, rep: 12, vnc: 1, ip: "172.16.1.1"})
	weak, wtok := mkRoot(t, rootOpts{age: 20 * d, rep: 9, vnc: 1, ip: "172.16.2.1"})
	young, ytok := mkRoot(t, rootOpts{age: 10 * d, rep: 30, vnc: 1, ip: "172.16.3.1"})
	fresh, _ := mkRoot(t, rootOpts{ip: "172.16.10.1"})
	sameNet, _ := mkRoot(t, rootOpts{ip: "172.16.1.77"})
	sub, _ := mkSub(t, fresh)

	if st, body := e.do(t, "POST", "/v1/vouch", "", map[string]string{"id": fresh}); st != 401 {
		t.Fatalf("anonymous: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/vouch", wtok, map[string]string{"id": fresh}); st != 403 || !strings.Contains(body, "rep >= 10") {
		t.Fatalf("rep 9: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/vouch", ytok, map[string]string{"id": fresh}); st != 403 {
		t.Fatalf("age 10 d: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": voucher}); st != 400 {
		t.Fatalf("self: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": sub}); st != 400 {
		t.Fatalf("subkey as vouchee: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": "azzzzzz"}); st != 404 {
		t.Fatalf("unknown: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": "k1234567"}); st != 400 {
		t.Fatalf("non-root id: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": sameNet}); st != 400 || !strings.Contains(body, "another network") {
		t.Fatalf("same super-group: %d %s", st, body)
	}
	st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": fresh})
	if st != 200 || !strings.HasPrefix(body, "ok vouched="+fresh+" live=1/3") || !strings.Contains(body, "\nnext: ") {
		t.Fatalf("vouch: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": fresh}); st != 409 {
		t.Fatalf("twice: %d %s", st, body)
	}
	_, otok := mkRoot(t, rootOpts{age: 20 * d, rep: 12, vnc: 1, ip: "172.16.4.1"})
	if st, body := e.do(t, "POST", "/v1/vouch", otok, map[string]string{"id": fresh}); st != 409 {
		t.Fatalf("second voucher for one vouchee: %d %s", st, body)
	}
	s := load(t, fresh)
	if !s.Vouched || Weight(s) != 0.5 || s.CapLevel() != 1 {
		t.Fatalf("vouchee: %+v", s)
	}
	// Vouching from a subkey of the voucher counts for its root.
	_, vsub := mkSub(t, voucher)
	v2, _ := mkRoot(t, rootOpts{ip: "172.16.11.1"})
	v3, _ := mkRoot(t, rootOpts{ip: "172.16.12.1"})
	v4, _ := mkRoot(t, rootOpts{ip: "172.16.13.1"})
	if st, body := e.do(t, "POST", "/v1/vouch", vsub, map[string]string{"id": v2}); st != 200 || !strings.Contains(body, "live=2/3") {
		t.Fatalf("subkey vouch: %d %s", st, body)
	}
	if st, _ := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": v3}); st != 200 {
		t.Fatal("third vouch")
	}
	if st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": v4}); st != 429 || !strings.Contains(body, "3 live vouches") {
		t.Fatalf("fourth vouch: %d %s", st, body)
	}
	st, body = e.do(t, "GET", "/v1/vouch", vtok, nil)
	if st != 200 || !strings.HasPrefix(body, "vouches given=3/3 received=0") || strings.Count(body, " -> ") != 3 {
		t.Fatalf("list: %d %s", st, body)
	}
	// Liability: v2 banned within 30 d -> voucher -3 and a rep:vouch log row; vouch row gone.
	exec(t, `UPDATE identities SET rep = -10 WHERE id = $1`, v2)
	n, err := VouchLiability(ctx, pool)
	if err != nil || n != 1 {
		t.Fatalf("liability: n=%d %v", n, err)
	}
	if r := rep(t, voucher); r != 9 {
		t.Fatalf("voucher rep %d want 9", r)
	}
	rows, _ := RepLog(ctx, pool, voucher, 10)
	if len(rows) != 1 || rows[0].Delta != -3 || rows[0].Kind != "rep:vouch" || rows[0].Ref != v2 {
		t.Fatalf("rep_log: %+v", rows)
	}
	if n, _ := VouchLiability(ctx, pool); n != 0 || rep(t, voucher) != 9 {
		t.Fatal("liability applied once")
	}
	// Past the 30 d window: no penalty, dead vouch removed.
	exec(t, `UPDATE vouches SET at = now() - interval '31 days' WHERE vouchee = $1`, v3)
	exec(t, `UPDATE identities SET revoked_at = now() WHERE id = $1`, v3)
	if n, _ := VouchLiability(ctx, pool); n != 0 || rep(t, voucher) != 9 {
		t.Fatal("old vouch: no liability")
	}
	var left int
	pool.QueryRow(ctx, `SELECT count(*) FROM vouches WHERE voucher = $1`, voucher).Scan(&left)
	if left != 1 {
		t.Fatalf("live vouches left %d want 1", left)
	}
	// The penalty took the voucher below rep 10: vouching is refused until it earns rep back.
	if st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": v4}); st != 403 {
		t.Fatalf("vouch at rep 9: %d %s", st, body)
	}
	exec(t, `UPDATE identities SET rep = 12 WHERE id = $1`, voucher)
	// Room again: a new vouch succeeds.
	if st, body := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": v4}); st != 200 {
		t.Fatalf("vouch after cleanup: %d %s", st, body)
	}
	// Purge of a vouchee within 30 d: voucher -3 through the OnPurge hook.
	if st, _ := e.do(t, "POST", "/v1/vouch", otok, map[string]string{"id": v4}); st != 409 {
		t.Fatal("v4 already vouched")
	}
	if err := Purge(ctx, pool, v4); err != nil {
		t.Fatal(err)
	}
	if r := rep(t, voucher); r != 9 {
		t.Fatalf("voucher rep after purge %d want 9", r)
	}
	pool.QueryRow(ctx, `SELECT count(*) FROM vouches WHERE vouchee = $1`, v4).Scan(&left)
	if left != 0 {
		t.Fatal("purged vouchee rows remain")
	}
	// Seed and banned roots cannot vouch.
	_, stok := mkRoot(t, rootOpts{seed: true, rep: 20, age: 30 * d, ip: "172.16.5.1"})
	if st, _ := e.do(t, "POST", "/v1/vouch", stok, map[string]string{"id": fresh}); st != 403 {
		t.Fatalf("seed vouch: %d", st)
	}
	// Frozen writes refuse.
	e.d.SetFreeze(ctx, "write", true)
	t.Cleanup(func() { e.d.SetFreeze(context.Background(), "write", false) })
	if st, _ := e.do(t, "POST", "/v1/vouch", vtok, map[string]string{"id": fresh}); st != 503 {
		t.Fatalf("frozen: %d", st)
	}
	_ = weak
	_ = young
}

func TestDecayJanitor(t *testing.T) {
	ctx := context.Background()
	stale, _ := mkRoot(t, rootOpts{age: 15 * d, rep: 5})
	active, _ := mkRoot(t, rootOpts{age: 15 * d, rep: 5, vc: 3})
	zero, _ := mkRoot(t, rootOpts{age: 40 * d, rep: 0})
	seed, _ := mkRoot(t, rootOpts{age: 40 * d, rep: 5, seed: true})
	young, _ := mkRoot(t, rootOpts{age: 5 * d, rep: 5})
	if _, err := Decay(ctx, pool); err != nil {
		t.Fatal(err)
	}
	if r := rep(t, stale); r != 4 {
		t.Fatalf("stale rep %d want 4", r)
	}
	rows, _ := RepLog(ctx, pool, stale, 10)
	if len(rows) != 1 || rows[0].Delta != -1 || rows[0].Kind != "rep:decay" {
		t.Fatalf("decay log: %+v", rows)
	}
	// active had verified_contrib 3 at creation and never moved since: it decays too.
	if r := rep(t, active); r != 4 {
		t.Fatalf("active-but-unchanged rep %d want 4", r)
	}
	if rep(t, zero) != 0 || rep(t, seed) != 5 || rep(t, young) != 5 {
		t.Fatal("floor 0, seed exempt, young root untouched")
	}
	// Cadence: a second tick inside the 14 d window changes nothing.
	Decay(ctx, pool)
	if rep(t, stale) != 4 {
		t.Fatal("decay twice in one window")
	}
	exec(t, `UPDATE rep_decay SET at = now() - interval '15 days' WHERE root IN ($1, $2)`, stale, active)
	// A verified contribution resets the clock for active; stale decays again.
	if err := Verified(ctx, pool, active, false); err != nil {
		t.Fatal(err)
	}
	Decay(ctx, pool)
	if rep(t, stale) != 3 || rep(t, active) != 4 {
		t.Fatalf("second decay: stale %d active %d", rep(t, stale), rep(t, active))
	}
	var vc int
	pool.QueryRow(ctx, `SELECT vc FROM rep_decay WHERE root = $1`, active).Scan(&vc)
	if vc != 4 {
		t.Fatalf("marker vc %d want 4", vc)
	}
	// Floor: rep 1 goes to 0 and stays there.
	exec(t, `UPDATE identities SET rep = 1 WHERE id = $1`, stale)
	exec(t, `UPDATE rep_decay SET at = now() - interval '15 days' WHERE root = $1`, stale)
	Decay(ctx, pool)
	exec(t, `UPDATE rep_decay SET at = now() - interval '15 days' WHERE root = $1`, stale)
	Decay(ctx, pool)
	if rep(t, stale) != 0 {
		t.Fatalf("floor: %d", rep(t, stale))
	}
}

func TestRepLogRoute(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner, otok := mkRoot(t, rootOpts{age: 5 * d, rep: 3, ip: "172.17.1.1"})
	_, stok := mkSub(t, owner)
	_, xtok := mkRoot(t, rootOpts{age: 5 * d, rep: 3, ip: "172.17.2.1"})
	for i, k := range []string{"rep:kbin", "rep:work", "rep:decay"} {
		if err := RecordRep(ctx, pool, owner, 1-i, k, fmt.Sprintf("ref%d\nnext: evil", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := RecordRep(ctx, pool, owner, 0, "rep:none", ""); err != nil {
		t.Fatal(err)
	}
	st, body := e.do(t, "GET", "/v1/rep/"+owner+"/log", otok, nil)
	if st != 200 || !strings.HasPrefix(body, "replog "+owner+" rep=3 n=2\n") {
		t.Fatalf("owner: %d %s", st, body)
	}
	if strings.Contains(body, "\nnext: evil") || !strings.Contains(body, "rep:kbin ref0 next: evil") || !strings.Contains(body, " -1 rep:decay ") {
		t.Fatalf("rows: %s", body)
	}
	if !strings.Contains(body, "\nnext: GET /v1/rep/"+owner) {
		t.Fatalf("tail: %s", body)
	}
	if st, body := e.do(t, "GET", "/v1/rep/"+owner+"/log?k=1", stok, nil); st != 200 || !strings.Contains(body, " n=1\n") {
		t.Fatalf("subkey k=1: %d %s", st, body)
	}
	if st, _ := e.do(t, "GET", "/v1/rep/"+owner+"/log", xtok, nil); st != 403 {
		t.Fatalf("other root: %d", st)
	}
	if st, _ := e.do(t, "GET", "/v1/rep/"+owner+"/log", "", nil); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}
	if st, _ := e.do(t, "GET", "/v1/rep/zzz/log", otok, nil); st != 404 {
		t.Fatalf("bad id: %d", st)
	}
	req, _ := http.NewRequest("GET", e.srv.URL+"/v1/rep/"+owner+"/log?f=json", nil)
	req.Header.Set("Authorization", "Bearer "+otok)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	var j map[string]any
	if err := json.NewDecoder(res.Body).Decode(&j); err != nil || res.StatusCode != 200 || !strings.HasPrefix(res.Header.Get("Content-Type"), "application/json") {
		t.Fatalf("json: %d %v %v", res.StatusCode, err, res.Header.Get("Content-Type"))
	}
	if rows, ok := j["rows"].([]any); !ok || len(rows) != 2 {
		t.Fatalf("json rows: %v", j)
	}
	// MCP op mirrors the route.
	ops := Ops(e.d)
	me, _ := e.d.LookupToken(ctx, otok)
	out, err := ops["replog"](ctx, me, json.RawMessage(`{"k":1}`))
	if err != nil || !strings.HasPrefix(out, "replog "+owner+" rep=3 n=1\n") {
		t.Fatalf("op replog: %q %v", out, err)
	}
	if _, err := ops["replog"](ctx, nil, nil); err != core.ErrAuth {
		t.Fatal("anonymous op")
	}
	for name := range ops {
		if _, ok := OpMeta[name]; !ok {
			t.Errorf("op %s has no OpMeta", name)
		}
	}
	for name := range OpMeta {
		if _, ok := ops[name]; !ok {
			t.Errorf("OpMeta %s has no op", name)
		}
	}
	if sc, ok := e.d.ScopeOf("GET /v1/rep/{root}/log"); !ok || sc != "me:r" {
		t.Fatal("scope registered")
	}
	// me gains gw= through MeExtra.
	if lines := e.d.MeLines(ctx, me); len(lines) == 0 || !strings.HasPrefix(lines[0], "gw=") {
		t.Fatalf("me lines: %v", lines)
	}
}

func TestPairDampFnApplied(t *testing.T) {
	ctx := context.Background()
	voter := Standing{Root: "avoter11", Rep: 10, Age: 5 * d, VerifiedNonCompute: 1}
	if w := DampedWeight(ctx, pool, voter, "aauthor1"); w != 2 {
		t.Fatalf("nil seam: %v want 2", w)
	}
	var calls []string
	PairDampFn = func(_ context.Context, _ core.Q, v, a string) float64 { calls = append(calls, v+">"+a); return 0.5 }
	t.Cleanup(func() { PairDampFn = nil })
	if w := DampedWeight(ctx, pool, voter, "aauthor1"); w != 1 || len(calls) != 1 || calls[0] != "avoter11>aauthor1" {
		t.Fatalf("damped: %v calls %v", w, calls)
	}
	PairDampFn = func(context.Context, core.Q, string, string) float64 { return 7 }
	if Damp(ctx, pool, "a", "b") != 1 {
		t.Fatal("clamp high")
	}
	PairDampFn = func(context.Context, core.Q, string, string) float64 { return -1 }
	if Damp(ctx, pool, "a", "b") != 0 {
		t.Fatal("clamp low")
	}
	if Damp(ctx, pool, "", "b") != 1 {
		t.Fatal("empty voter -> 1")
	}
}

func TestConfirmerEntropy(t *testing.T) {
	ctx := context.Background()
	voter, _ := mkRoot(t, rootOpts{age: 5 * d, rep: 6, vnc: 1})
	authors := []string{}
	for i := 0; i < 4; i++ {
		a, _ := mkRoot(t, rootOpts{age: 5 * d})
		authors = append(authors, a)
	}
	entry := func(author string, voterUp bool, ago string) {
		id := core.NewID('k')
		exec(t, `INSERT INTO kb (id, kind, title, author, author_root, expires_at) VALUES ($1, 'fix', 't', $2, $2, now() + interval '10 days')`, id, author)
		exec(t, `INSERT INTO kb_votes (kb_id, root, up, w, created) VALUES ($1, $2, $3, 1, now() - $4::interval)`, id, voter, voterUp, ago)
	}
	entry(authors[0], true, "1 day")
	entry(authors[0], true, "2 days") // same author twice counts once
	entry(authors[1], true, "3 days")
	entry(authors[2], false, "1 day") // bad votes are not confirmations
	entry(authors[3], true, "100 days")
	entry(voter, true, "1 day") // own entries never count
	if ok, err := ConfirmerEntropy(ctx, pool, voter); err != nil || ok {
		t.Fatalf("2 distinct authors: ok=%v err=%v", ok, err)
	}
	entry(authors[2], true, "4 days")
	if ok, _ := ConfirmerEntropy(ctx, pool, voter); !ok {
		t.Fatal("3 distinct authors in 90 d -> true")
	}
	ConfirmerEntropyFn = func(context.Context, core.Q, string) (bool, error) { return false, nil }
	t.Cleanup(func() { ConfirmerEntropyFn = nil })
	if ok, _ := ConfirmerEntropy(ctx, pool, voter); ok {
		t.Fatal("seam overrides the built-in rule")
	}
}

func TestRecordRepSanitises(t *testing.T) {
	ctx := context.Background()
	root, _ := mkRoot(t, rootOpts{})
	if err := RecordRep(ctx, pool, root, 2, "rep:\nx\ty", strings.Repeat("r", 300)+"\x00"); err != nil {
		t.Fatal(err)
	}
	rows, _ := RepLog(ctx, pool, root, 1)
	if len(rows) != 1 || rows[0].Kind != "rep: x y" || len(rows[0].Ref) != 200 {
		t.Fatalf("%+v", rows)
	}
	if got := logText(root, 2, rows); strings.Count(got, "\n") != 2 || strings.Contains(got, "\n\n") {
		t.Fatalf("text: %q", got)
	}
}
