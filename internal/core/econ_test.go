package core

import (
	"context"
	"crypto/rand"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// newEcon is newAuthEnv with every admin token kind configured and the admin v2 routes mounted.
func newEcon(t *testing.T, mod func(*Config), routes func(*http.ServeMux, *Deps)) *tenv {
	t.Helper()
	return newAuthEnv(t, func(c *Config) {
		c.PollToken, c.OpsToken, c.CheckToken = "poll-token", "ops-token", "check-token"
		if mod != nil {
			mod(c)
		}
	}, func(mux *http.ServeMux, d *Deps) {
		RegisterAdminV2(mux, d)
		if routes != nil {
			routes(mux, d)
		}
	})
}

func randIP() string {
	var b [3]byte
	rand.Read(b[:])
	return fmt.Sprintf("10.%d.%d.%d", b[0], b[1], b[2])
}

// audit reads the books of the shared test database (no escrows, no freeze side effects).
func audit(t *testing.T) AuditReport {
	t.Helper()
	a, err := LedgerAudit(context.Background(), testPool, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// conserve balances the shared database before an absolute conservation test: other tests may
// move credits outside the ledger (direct UPDATEs), so one correcting row is written when needed.
func conserve(t *testing.T) {
	t.Helper()
	a := audit(t)
	if d := a.Delta(); d != 0 {
		t.Logf("shared database unbalanced by %d before this test (fixed with a ledger row)", d)
		ctx := context.Background()
		var err error
		if d > 0 {
			err = Ledger(ctx, testPool, LedgerMint, "test-fix", "grant", d, "test-fix", "")
		} else {
			err = Ledger(ctx, testPool, "test-fix", LedgerBurn, "grant", -d, "test-fix", "")
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	if a = audit(t); !a.OK() {
		t.Fatalf("could not balance the test database: %s", a.Line())
	}
}

func assertConserved(t *testing.T, step string) {
	t.Helper()
	if a := audit(t); !a.OK() {
		t.Fatalf("after %s: %s", step, a.Line())
	}
}

func balance(t *testing.T, id string) (credits, earned int64) {
	t.Helper()
	if err := testPool.QueryRow(context.Background(), `SELECT credits, earned FROM identities WHERE id = $1`, id).Scan(&credits, &earned); err != nil {
		t.Fatal(err)
	}
	return
}

func ledgerSum(t *testing.T, q Q, where string, args ...any) int64 {
	t.Helper()
	var n int64
	if err := q.QueryRow(context.Background(), `SELECT coalesce(sum(amount), 0) FROM ledger WHERE `+where, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLedgerConservation(t *testing.T) {
	e := newEcon(t, nil, nil)
	ctx := context.Background()
	conserve(t)
	root, rtok := e.register(t, "ledg")
	if got := ledgerSum(t, testPool, `from_id = 'mint' AND to_id = $1 AND reason = 'register' AND class = 'grant'`, root); got != 100 {
		t.Fatalf("register mint row = %d", got)
	}
	assertConserved(t, "register")

	st, body := e.do(t, "POST", "/v1/subkey", rtok, map[string]any{"credits": 30})
	if st != 201 {
		t.Fatalf("subkey: %d %s", st, body)
	}
	sub := kv(body)["id"]
	if c, _ := balance(t, root); c != 70 {
		t.Fatalf("root after subkey = %d", c)
	}
	if got := ledgerSum(t, testPool, `from_id = $1 AND to_id = 'hold' AND reason = 'reserve'`, root); got != 30 {
		t.Fatalf("subkey reserve row = %d", got)
	}
	if got := ledgerSum(t, testPool, `from_id = 'hold' AND to_id = $1 AND reason = 'subkey'`, sub); got != 30 {
		t.Fatalf("subkey transfer row = %d", got)
	}
	assertConserved(t, "subkey")

	// A job reserves 10 from the subkey; the reservation sits in jobs.reserved while it runs.
	jid := NewID('j')
	err := Tx(ctx, testPool, func(tx pgx.Tx) error {
		if err := Reserve(ctx, tx, sub, 10); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO jobs (id, submitter, root, wasm, input, ms, mb, reserved, status) VALUES ($1, $2, $3, 'w', 'i', 3000, 64, 10, 'running')`, jid, sub, root)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	if c, _ := balance(t, sub); c != 20 {
		t.Fatalf("sub after reserve = %d", c)
	}
	assertConserved(t, "reserve")

	// Finalize: one worker earns 4, the submitter gets 5 back, the 1-credit remainder is burnt.
	worker, _ := e.register(t, "wrk")
	err = Tx(ctx, testPool, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE jobs SET status = 'done', used_ms = 2500, finished_at = now() WHERE id = $1`, jid); err != nil {
			return err
		}
		if err := Earn(ctx, tx, worker, 4); err != nil {
			return err
		}
		if err := Refund(ctx, tx, sub, 5); err != nil {
			return err
		}
		return BurnHeld(ctx, tx, 1, "fee", jid)
	})
	if err != nil {
		t.Fatal(err)
	}
	if c, earned := balance(t, worker); c != 104 || earned != 4 {
		t.Fatalf("worker = %d/%d", c, earned)
	}
	if c, earned := balance(t, sub); c != 25 || earned != 0 {
		t.Fatalf("sub after refund = %d/%d", c, earned)
	}
	if got := ledgerSum(t, testPool, `from_id = 'hold' AND to_id = 'burn' AND reason = 'fee' AND ref = $1`, jid); got != 1 {
		t.Fatalf("fee burn = %d", got)
	}
	assertConserved(t, "finalize")

	// A payout to a purged identity cannot land: it is burnt as unpayable.
	ghost, _ := e.register(t, "ghost")
	if err := Reserve(ctx, testPool, root, 3); err != nil {
		t.Fatal(err)
	}
	if st, body := e.do(t, "POST", "/admin/purge", "adm-token", map[string]any{"id": ghost}); st != 200 || body != "ok purged=1" {
		t.Fatalf("purge ghost: %d %s", st, body)
	}
	if got := ledgerSum(t, testPool, `from_id = $1 AND to_id = 'burn' AND reason = 'purge'`, ghost); got != 100 {
		t.Fatalf("ghost burn = %d", got)
	}
	if err := Earn(ctx, testPool, ghost, 3); err != nil {
		t.Fatal(err)
	}
	if got := ledgerSum(t, testPool, `to_id = 'burn' AND reason = 'unpayable' AND ref = $1`, ghost); got != 3 {
		t.Fatalf("unpayable burn = %d", got)
	}
	assertConserved(t, "unpayable")

	// Revoking the subkey returns its balance to the root (auth.go path), then the root is purged
	// together with a still-running job: balance and reservation are both burnt.
	if st, body := e.do(t, "DELETE", "/v1/subkey/"+sub, rtok, nil); st != 200 {
		t.Fatalf("revoke: %d %s", st, body)
	}
	assertConserved(t, "revoke")
	if err := Tx(ctx, testPool, func(tx pgx.Tx) error {
		if err := Reserve(ctx, tx, root, 6); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO jobs (id, submitter, root, wasm, input, ms, mb, reserved, status) VALUES ($1, $2, $2, 'w', 'i', 1000, 64, 6, 'queued')`, NewID('j'), root)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	credits, _ := balance(t, root)
	if st, body := e.do(t, "POST", "/admin/purge", "adm-token", map[string]any{"id": root}); st != 200 || body != "ok purged=1" {
		t.Fatalf("purge root: %d %s", st, body)
	}
	if got := ledgerSum(t, testPool, `from_id = $1 AND to_id = 'burn' AND reason = 'purge'`, root); got != credits {
		t.Fatalf("root burn = %d want %d", got, credits)
	}
	if got := ledgerSum(t, testPool, `from_id = 'hold' AND to_id = 'burn' AND reason = 'purge' AND ref = $1`, root); got != 6 {
		t.Fatalf("reservation burn = %d", got)
	}
	assertConserved(t, "purge")
	if st, _ := e.do(t, "POST", "/admin/purge", "adm-token", map[string]any{"id": SystemID}); st != 400 {
		t.Fatalf("system root purge: %d", st)
	}
}

func TestEarnedClassAndReserveEarned(t *testing.T) {
	e := newEcon(t, nil, nil)
	ctx := context.Background()
	root, tok := e.register(t, "earn")
	if err := ReserveEarned(ctx, testPool, root, 5); err != ErrEarned {
		t.Fatalf("grant-only root: %v", err)
	}
	if err := Earn(ctx, testPool, root, 10); err != nil {
		t.Fatal(err)
	}
	if c, earned := balance(t, root); c != 110 || earned != 10 {
		t.Fatalf("after earn = %d/%d", c, earned)
	}
	id, err := e.d.LookupToken(ctx, tok)
	if err != nil || id.Earned != 10 || id.Credits != 110 {
		t.Fatalf("ident earned: %+v %v", id, err)
	}
	// Reserve takes grant first (100), then earned (5): two ledger rows, one per class.
	if err := Reserve(ctx, testPool, root, 105); err != nil {
		t.Fatal(err)
	}
	if c, earned := balance(t, root); c != 5 || earned != 5 {
		t.Fatalf("after reserve = %d/%d", c, earned)
	}
	if g := ledgerSum(t, testPool, `from_id = $1 AND reason = 'reserve' AND class = 'grant'`, root); g != 100 {
		t.Fatalf("grant part = %d", g)
	}
	if x := ledgerSum(t, testPool, `from_id = $1 AND reason = 'reserve' AND class = 'earned'`, root); x != 5 {
		t.Fatalf("earned part = %d", x)
	}
	if err := RefundEarned(ctx, testPool, root, 5); err != nil {
		t.Fatal(err)
	}
	if err := Refund(ctx, testPool, root, 100); err != nil {
		t.Fatal(err)
	}
	if c, earned := balance(t, root); c != 110 || earned != 10 {
		t.Fatalf("after refunds = %d/%d", c, earned)
	}
	if err := ReserveEarned(ctx, testPool, root, 10); err != nil {
		t.Fatal(err)
	}
	if c, earned := balance(t, root); c != 100 || earned != 0 {
		t.Fatalf("after reserve earned = %d/%d", c, earned)
	}
	if err := ReserveEarned(ctx, testPool, root, 1); err != ErrEarned {
		t.Fatalf("over earned: %v", err)
	}
	if err := Reserve(ctx, testPool, root, 101); err != ErrCredits {
		t.Fatalf("over credits: %v", err)
	}
	for _, f := range []func() error{
		func() error { return Reserve(ctx, testPool, root, -1) },
		func() error { return ReserveEarned(ctx, testPool, root, -1) },
		func() error { return Ledger(ctx, testPool, root, LedgerHold, "grant", 0, "x", "") },
		func() error { return Ledger(ctx, testPool, root, LedgerHold, "bonus", 1, "x", "") },
	} {
		if err := f(); err == nil {
			t.Fatal("bad amount or class accepted")
		}
	}
	if err := Reserve(ctx, testPool, root, 0); err != nil || Earn(ctx, testPool, root, 0) != nil {
		t.Fatal("zero moves must be no-ops")
	}
	if err := RefundEarned(ctx, testPool, root, 10); err != nil {
		t.Fatal(err)
	}
	if c, earned := balance(t, root); c != 110 || earned != 10 {
		t.Fatalf("restored = %d/%d", c, earned)
	}
}

// v1DB simulates an upgrade: a schema with only the v1 migrations applied, v1-shaped rows, then
// core.Migrate's loop on that schema (0040, 0041, 0042 with the opening balance, 0080, 0110). It
// returns a pool bound to the schema so a Deps + server can run against it.
type v1DB struct {
	schema string
	conn   *pgx.Conn
	pool   *pgxpool.Pool
}

func newV1DB(t *testing.T, schema string) *v1DB {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.ConnectConfig(ctx, testPool.Config().ConnConfig)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		conn.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE`)
		conn.Close(ctx)
	})
	if _, err := conn.Exec(ctx, `DROP SCHEMA IF EXISTS `+schema+` CASCADE; CREATE SCHEMA `+schema+`; SET search_path = `+schema+`, public`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Exec(ctx, `CREATE TABLE schema_migrations (version int PRIMARY KEY, applied timestamptz NOT NULL DEFAULT now())`); err != nil {
		t.Fatal(err)
	}
	files, _ := fs.Glob(migrationFS, "migrations/*.sql")
	sort.Strings(files)
	for _, f := range files {
		v, _ := strconv.Atoi(strings.SplitN(strings.TrimPrefix(f, "migrations/"), "_", 2)[0])
		if v >= 40 {
			continue
		}
		sql, _ := migrationFS.ReadFile(f)
		if _, err := conn.Exec(ctx, string(sql)); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		if _, err := conn.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES ($1)`, v); err != nil {
			t.Fatal(err)
		}
	}
	return &v1DB{schema: schema, conn: conn}
}

// migrate applies the pending v2 migrations on the schema and opens a pool bound to it.
func (v *v1DB) migrate(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	if err := migrateOn(ctx, v.conn); err != nil {
		t.Fatal(err)
	}
	cfg, err := pgxpool.ParseConfig(testPool.Config().ConnString())
	if err != nil {
		t.Fatal(err)
	}
	cfg.MaxConns = 4
	cfg.ConnConfig.RuntimeParams["search_path"] = v.schema + ",public"
	if v.pool, err = pgxpool.NewWithConfig(ctx, cfg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(v.pool.Close)
}

// serve mounts core + admin v2 on the schema's pool.
func (v *v1DB) serve(t *testing.T) *tenv {
	t.Helper()
	cfg := Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PollToken: "poll-token", PowBits: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := NewDeps(context.Background(), cfg, v.pool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	Register(mux, d)
	RegisterAuthV2(mux, d)
	RegisterAdminV2(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	return &tenv{d, srv, randIP()}
}

// seedV1 writes v1-shaped rows: roots with balances, a subkey, a running job with a reservation,
// a done job with two agreeing replicas (worker payouts to recover) and one disagreeing replica.
func (v *v1DB) seedV1(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	for _, s := range []string{
		`INSERT INTO identities (id, name, parent, root, token_hash, credits, rep, reg_ip) VALUES
		   ('aroot01', 'a', NULL, 'aroot01', sha256('t1'::bytea), 80, 0, '10.0.0.1'),
		   ('asub001', 'a-sub', 'aroot01', 'aroot01', sha256('t2'::bytea), 15, 0, ''),
		   ('aroot02', 'b', NULL, 'aroot02', sha256('t3'::bytea), 0, 2, '10.0.0.2'),
		   ('awork01', 'w1', NULL, 'awork01', sha256('t4'::bytea), 100, 7, '10.0.0.3'),
		   ('awork02', 'w2', NULL, 'awork02', sha256('t5'::bytea), 3, 1, '10.0.0.4'),
		   ('awork03', 'w3', NULL, 'awork03', sha256('t6'::bytea), 50, 0, '10.0.0.5'),
		   ('arevokd', 'gone', NULL, 'arevokd', sha256('t7'::bytea), 0, 0, '10.0.0.6')`,
		`UPDATE identities SET revoked_at = now() WHERE id = 'arevokd'`,
		`INSERT INTO jobs (id, submitter, root, wasm, input, ms, mb, reserved, status) VALUES
		   ('jrun001', 'aroot02', 'aroot02', 'w', 'i', 4000, 64, 12, 'running'),
		   ('jdone01', 'aroot01', 'aroot01', 'w', 'i', 5000, 64, 0, 'done')`,
		`UPDATE jobs SET out = repeat('a', 64), used_ms = 2500, code = 0 WHERE id = 'jdone01'`,
		`INSERT INTO replicas (job, state, worker, worker_root, status, code, out, ms, reported_at) VALUES
		   ('jdone01', 'reported', 'awork01', 'awork01', 'ok', 0, repeat('a', 64), 2500, now()),
		   ('jdone01', 'reported', 'awork02', 'awork02', 'ok', 0, repeat('a', 64), 2400, now()),
		   ('jdone01', 'reported', 'awork03', 'awork03', 'ok', 0, repeat('b', 64), 2400, now())`,
	} {
		if _, err := v.conn.Exec(ctx, s); err != nil {
			t.Fatalf("%s: %v", s[:40], err)
		}
	}
}

func TestOpeningBalanceFromV1Rows(t *testing.T) {
	v := newV1DB(t, "econ_v1a")
	v.seedV1(t)
	v.migrate(t)
	ctx := context.Background()
	q := v.conn
	// Per-root grant rows: balance plus active reservations; nothing for zero balances.
	for id, want := range map[string]int64{"aroot01": 80, "aroot02": 12, "awork01": 100, "awork02": 3, "awork03": 50, "arevokd": 0, SystemID: 0} {
		if got := ledgerSum(t, q, `from_id = 'mint' AND to_id = $1 AND reason = 'v1-opening' AND class = 'grant'`, id); got != want {
			t.Errorf("opening row %s = %d want %d", id, got, want)
		}
	}
	if got := ledgerSum(t, q, `from_id = 'mint' AND to_id = 'subkeys' AND reason = 'v1-opening'`); got != 15 {
		t.Errorf("subkeys aggregate = %d", got)
	}
	var n int
	q.QueryRow(ctx, `SELECT count(*) FROM ledger`).Scan(&n)
	if n != 6 {
		t.Errorf("ledger rows = %d want 6", n)
	}
	// earned backfill: ceil(2.5 s) + 1 = 4 per agreeing replica, capped at credits; the
	// disagreeing worker recovers nothing.
	for id, want := range map[string]int64{"awork01": 4, "awork02": 3, "awork03": 0, "aroot01": 0} {
		var earned int64
		q.QueryRow(ctx, `SELECT earned FROM identities WHERE id = $1`, id).Scan(&earned)
		if earned != want {
			t.Errorf("earned %s = %d want %d", id, earned, want)
		}
	}
	a, err := LedgerAudit(ctx, q, nil)
	if err != nil || !a.OK() || a.Mint != 260 || a.Burn != 0 || a.Reserved != 12 || a.Credits != 248 {
		t.Fatalf("audit after migration: %+v %v", a, err)
	}
	// The register trigger covers rows inserted after the migration; the clamp keeps earned <= credits.
	if _, err := q.Exec(ctx, `INSERT INTO identities (id, name, parent, root, token_hash, credits) VALUES ('anewreg', 'n', NULL, 'anewreg', sha256('t8'::bytea), 10)`); err != nil {
		t.Fatal(err)
	}
	if got := ledgerSum(t, q, `from_id = 'mint' AND to_id = 'anewreg' AND reason = 'register'`); got != 10 {
		t.Fatalf("register trigger row = %d", got)
	}
	if _, err := q.Exec(ctx, `UPDATE identities SET credits = 2 WHERE id = 'awork01'`); err != nil {
		t.Fatal(err)
	}
	var earned int64
	q.QueryRow(ctx, `SELECT earned FROM identities WHERE id = 'awork01'`).Scan(&earned)
	if earned != 2 {
		t.Fatalf("clamp: earned = %d", earned)
	}
	q.Exec(ctx, `UPDATE identities SET credits = 100, earned = 4 WHERE id = 'awork01'`)

	// Acceptance: GET /admin/audit with the poll token right after the upgrade.
	e := v.serve(t)
	st, body := e.do(t, "GET", "/admin/audit", "poll-token", nil)
	if st != 200 || body != "ok conserved mint=270 burn=0" {
		t.Fatalf("audit: %d %q", st, body)
	}
	if st, body := e.do(t, "GET", "/admin/audit?f=json", "poll-token", nil); st != 200 || !strings.Contains(body, `"ok":true`) || !strings.Contains(body, `"mint":270`) {
		t.Fatalf("audit json: %d %s", st, body)
	}
	// Registered escrows count: 4 earned credits move into a bounty-like escrow.
	if err := ReserveEarned(ctx, v.pool, "awork01", 4); err != nil {
		t.Fatal(err)
	}
	if a, _ := e.d.RunLedgerAudit(ctx); a.OK() {
		t.Fatal("escrow outside the audit must show")
	}
	e.d.OnEscrow(`SELECT 4::bigint`)
	a, err = e.d.RunLedgerAudit(ctx)
	if err != nil || !a.OK() || a.Escrow != 4 {
		t.Fatalf("audit with escrow: %+v %v", a, err)
	}
	// The mismatch run above froze compute (flags live in this schema only); lift for the next test.
	e.d.SetFreeze(ctx, "freeze:compute", false)
	e.d.SetFreeze(ctx, "freeze:bounties", false)
}

func TestAuditMismatchFreezes(t *testing.T) {
	v := newV1DB(t, "econ_v1b")
	v.seedV1(t)
	v.migrate(t)
	e := v.serve(t)
	ctx := context.Background()
	if st, body := e.do(t, "GET", "/admin/audit", "poll-token", nil); st != 200 || !strings.HasPrefix(body, "ok conserved mint=") {
		t.Fatalf("audit: %d %s", st, body)
	}
	if e.d.Frozen("compute") || e.d.Frozen("bounties") {
		t.Fatal("frozen before the mismatch")
	}
	if _, err := v.pool.Exec(ctx, `UPDATE identities SET credits = credits + 1 WHERE id = 'aroot01'`); err != nil {
		t.Fatal(err)
	}
	st, body := e.do(t, "GET", "/admin/audit", "poll-token", nil)
	if st != 200 || !strings.HasPrefix(body, "MISMATCH delta=1 ") {
		t.Fatalf("mismatch: %d %s", st, body)
	}
	if !e.d.Frozen("compute") || !e.d.Frozen("bounties") || e.d.Frozen("write") {
		t.Fatal("mismatch must freeze compute and bounties only")
	}
	var fails, events int
	v.pool.QueryRow(ctx, `SELECT count(*) FROM audit_fail WHERE detail LIKE 'MISMATCH delta=1 %'`).Scan(&fails)
	v.pool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'audit_fail'`).Scan(&events)
	if fails != 1 || events != 1 {
		t.Fatalf("audit_fail=%d events=%d", fails, events)
	}
	// Repairing the books does not lift the freeze (operator decision), but the audit is ok again.
	v.pool.Exec(ctx, `UPDATE identities SET credits = credits - 1 WHERE id = 'aroot01'`)
	if st, body := e.do(t, "GET", "/admin/audit", "poll-token", nil); st != 200 || !strings.HasPrefix(body, "ok conserved") {
		t.Fatalf("repaired: %d %s", st, body)
	}
	if !e.d.Frozen("compute") {
		t.Fatal("freeze lifted automatically")
	}
	// The daily janitor task runs the same audit once per day.
	v.pool.Exec(ctx, `UPDATE identities SET credits = credits + 2 WHERE id = 'aroot02'`)
	v.pool.Exec(ctx, `DELETE FROM audit_fail`)
	e.d.Janitor.RunOnce(ctx)
	e.d.Janitor.RunOnce(ctx)
	v.pool.QueryRow(ctx, `SELECT count(*) FROM audit_fail WHERE detail LIKE 'MISMATCH delta=2 %'`).Scan(&fails)
	if fails != 1 {
		t.Fatalf("janitor audit_fail rows = %d want 1 (once per day)", fails)
	}
}

func TestTokenKindsAndScopes(t *testing.T) {
	okh := func(w http.ResponseWriter, r *http.Request) { OK(w, r, "ok", nil) }
	e := newEcon(t, nil, func(mux *http.ServeMux, d *Deps) {
		mux.HandleFunc("GET /admin/t-ops", d.OpsOnly(okh))
		mux.HandleFunc("GET /admin/t-check", d.CheckOnly(okh))
	})
	conserve(t)
	cleanFlags(t, e.d, "freeze:compute", "freeze:bounties")
	freeze := map[string]any{"what": "reg", "on": false}
	cases := []struct {
		token string
		want  map[string]int // path -> status
	}{
		{"adm-token", map[string]int{"GET /admin/stats": 200, "GET /admin/audit": 200, "POST /admin/freeze": 200, "GET /admin/t-ops": 200, "GET /admin/t-check": 200}},
		{"ops-token", map[string]int{"GET /admin/stats": 200, "GET /admin/audit": 200, "POST /admin/freeze": 401, "GET /admin/t-ops": 200, "GET /admin/t-check": 401}},
		{"poll-token", map[string]int{"GET /admin/stats": 200, "GET /admin/audit": 200, "POST /admin/freeze": 401, "POST /admin/credits": 401, "GET /admin/t-ops": 401, "GET /admin/t-check": 401}},
		{"check-token", map[string]int{"GET /admin/t-check": 200, "GET /admin/stats": 401, "GET /admin/audit": 401, "POST /admin/freeze": 401}},
		{"", map[string]int{"GET /admin/stats": 401, "GET /admin/audit": 401, "POST /admin/freeze": 401, "GET /admin/t-check": 401}},
		{"adm-tokem", map[string]int{"GET /admin/stats": 401, "POST /admin/freeze": 401}},
	}
	for _, c := range cases {
		e.ip = randIP() // one IP group per token kind: budgets and failure windows stay apart
		for route, want := range c.want {
			method, path, _ := strings.Cut(route, " ")
			var body any
			if method == "POST" {
				body = freeze
			}
			if st, out := e.do(t, method, path, c.token, body); st != want {
				t.Errorf("%q %s: %d %s want %d", c.token, route, st, out, want)
			}
		}
	}
	// Admin disabled when no kind is configured: everything is 401, nothing panics.
	off := newAuthEnv(t, func(c *Config) { c.AdminToken = "" }, RegisterAdminV2)
	if st, _ := off.do(t, "GET", "/admin/stats", "", nil); st != 401 {
		t.Fatalf("unset admin: %d", st)
	}
	if st, _ := off.do(t, "GET", "/admin/audit", "", nil); st != 401 {
		t.Fatalf("unset poll with empty bearer: %d", st)
	}
}

func TestAdminFailuresRateLimitedNoLockout(t *testing.T) {
	e := newEcon(t, nil, nil)
	conserve(t)
	cleanFlags(t, e.d, "freeze:compute", "freeze:bounties")
	for i := 0; i < adminFailPerMin; i++ {
		if st, body := e.do(t, "POST", "/admin/freeze", "bad-"+strconv.Itoa(i), map[string]any{"what": "reg", "on": false}); st != 401 || body != "err auth admin" {
			t.Fatalf("failure %d: %d %s", i, st, body)
		}
	}
	start := time.Now()
	st, body, h := e.doH(t, "POST", "/admin/freeze", "bad-11", `{"what":"reg","on":false}`)
	took := time.Since(start)
	if st != 429 || body != "err rate admin" || took < 900*time.Millisecond || took > 5*time.Second {
		t.Fatalf("11th failure: %d %s after %s", st, body, took)
	}
	if ra, err := strconv.Atoi(h.Get("Retry-After")); err != nil || ra < 1 || ra > 60 {
		t.Fatalf("Retry-After=%q", h.Get("Retry-After"))
	}
	// No lockout: a correct token from the same group passes at once.
	start = time.Now()
	if st, body := e.do(t, "POST", "/admin/freeze", "adm-token", map[string]any{"what": "reg", "on": false}); st != 200 || time.Since(start) > 500*time.Millisecond {
		t.Fatalf("valid after failures: %d %s in %s", st, body, time.Since(start))
	}
	if st, _ := e.do(t, "GET", "/admin/audit", "poll-token", nil); st != 200 {
		t.Fatalf("poll after failures: %d", st)
	}
	// Another group is unaffected.
	other := e.ip
	e.ip = randIP()
	if st, _ := e.do(t, "POST", "/admin/freeze", "bad-x", map[string]any{"what": "reg"}); st != 401 {
		t.Fatalf("other group: %d", st)
	}
	e.ip = other
	// Still inside the minute: bad attempts keep answering 429 (and are not logged).
	adminFailDelay = 10 * time.Millisecond
	t.Cleanup(func() { adminFailDelay = time.Second })
	if st, _ := e.do(t, "POST", "/admin/freeze", "bad-12", map[string]any{"what": "reg"}); st != 429 {
		t.Fatalf("12th: %d", st)
	}
	var logged int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM admin_log WHERE ip_group = $1 AND token_kind = 'none'`, e.ip).Scan(&logged)
	if logged != adminFailPerMin {
		t.Fatalf("failure rows logged = %d want %d", logged, adminFailPerMin)
	}
}

func TestValidTokenAlwaysPasses(t *testing.T) {
	e := newEcon(t, nil, nil)
	conserve(t)
	cleanFlags(t, e.d, "freeze:compute", "freeze:bounties")
	// The failure window is exhausted directly (no HTTP, no waits).
	now := time.Now()
	for i := 0; i <= adminFailPerMin; i++ {
		adminFails.fail(e.ip, now)
	}
	if over, retry := adminFails.fail(e.ip, now); !over || retry < 1 || retry > 60 {
		t.Fatalf("window: over=%v retry=%d", over, retry)
	}
	for _, c := range []struct{ tok, path string }{{"adm-token", "/admin/stats"}, {"poll-token", "/admin/audit"}, {"ops-token", "/admin/stats"}} {
		start := time.Now()
		if st, body := e.do(t, "GET", c.path, c.tok, nil); st != 200 || time.Since(start) > 500*time.Millisecond {
			t.Fatalf("%s %s: %d %s in %s", c.tok, c.path, st, body, time.Since(start))
		}
	}
	adminFailDelay = 10 * time.Millisecond
	t.Cleanup(func() { adminFailDelay = time.Second })
	if st, _ := e.do(t, "GET", "/admin/stats", "wrong", nil); st != 429 {
		t.Fatalf("bad token in an exhausted window: %d", st)
	}
	// A minute later the window resets: failures answer 401 again.
	if over, _ := adminFails.fail(e.ip, now.Add(61*time.Second)); over {
		t.Fatal("window did not reset")
	}
	adminFails.sweep(time.Now().Add(3 * time.Minute))
	adminFails.mu.Lock()
	n := len(adminFails.m)
	adminFails.mu.Unlock()
	if n != 0 {
		t.Fatalf("sweep left %d windows", n)
	}
}

func adminRows(t *testing.T, ip string, want int) []string {
	t.Helper()
	var out []string
	for i := 0; i < 40; i++ {
		rows, err := testPool.Query(context.Background(), `SELECT token_kind, action, arg FROM admin_log WHERE ip_group = $1 ORDER BY at, action`, ip)
		if err != nil {
			t.Fatal(err)
		}
		out = out[:0]
		for rows.Next() {
			var k, a, g string
			rows.Scan(&k, &a, &g)
			out = append(out, k+" "+a+" "+g)
		}
		rows.Close()
		if len(out) >= want {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	return out
}

func TestAdminLog(t *testing.T) {
	e := newEcon(t, nil, nil)
	root, _ := e.register(t, "logged")
	if st, _ := e.do(t, "GET", "/admin/stats", "poll-token", nil); st != 200 {
		t.Fatal("stats")
	}
	if st, body := e.do(t, "POST", "/admin/credits", "adm-token", map[string]any{"id": root, "n": 7}); st != 200 {
		t.Fatalf("credits: %d %s", st, body)
	}
	if st, _ := e.do(t, "POST", "/admin/freeze", "nope", map[string]any{"what": "reg"}); st != 401 {
		t.Fatal("bad token")
	}
	if st, _ := e.do(t, "POST", "/admin/freeze", "poll-token", map[string]any{"what": "reg"}); st != 401 {
		t.Fatal("poll on admin route")
	}
	got := adminRows(t, e.ip, 4)
	want := []string{"poll GET /admin/stats ", "admin POST /admin/credits id=" + root + " n=7", "none POST /admin/freeze denied", "none POST /admin/freeze denied:poll"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("admin_log:\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFaucetLogged(t *testing.T) {
	e := newEcon(t, nil, nil)
	ctx := context.Background()
	conserve(t)
	before, _ := balance(t, SystemID)
	mintBefore := ledgerSum(t, testPool, `from_id = 'mint' AND to_id = $1 AND reason = 'faucet'`, SystemID)
	st, body := e.do(t, "POST", "/admin/credits", "adm-token", map[string]any{"id": SystemID, "n": 50})
	if st != 200 || body != fmt.Sprintf("ok id=asystem credits=%d minted=50", before+50) {
		t.Fatalf("faucet: %d %s", st, body)
	}
	if after, earned := balance(t, SystemID); after != before+50 || earned != 0 {
		t.Fatalf("system balance %d/%d", after, earned)
	}
	if got := ledgerSum(t, testPool, `from_id = 'mint' AND to_id = $1 AND reason = 'faucet'`, SystemID); got != mintBefore+50 {
		t.Fatalf("faucet ledger = %d", got)
	}
	var events int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'faucet:asystem'`).Scan(&events)
	if events == 0 {
		t.Fatal("no faucet event")
	}
	assertConserved(t, "faucet")
	if got := adminRows(t, e.ip, 1); len(got) != 1 || got[0] != "admin POST /admin/credits id=asystem n=50" {
		t.Fatalf("admin_log: %v", got)
	}
	for _, c := range []struct {
		tok  string
		body map[string]any
		want int
	}{
		{"adm-token", map[string]any{"id": SystemID, "n": 0}, 400},
		{"adm-token", map[string]any{"id": SystemID, "n": faucetMax + 1}, 400},
		{"adm-token", map[string]any{"id": "a222222", "n": 5}, 404},
		{"adm-token", map[string]any{"id": "k000000", "n": 5}, 400},
		{"poll-token", map[string]any{"id": SystemID, "n": 5}, 401},
		{"ops-token", map[string]any{"id": SystemID, "n": 5}, 401},
	} {
		if st, body := e.do(t, "POST", "/admin/credits", c.tok, c.body); st != c.want {
			t.Errorf("%v: %d %s want %d", c.body, st, body, c.want)
		}
	}
	assertConserved(t, "refused faucets")
	// The system root spends its faucet credits like any identity (system jobs reserve from it);
	// spend them here so the shared row ends the test at zero, still conserved.
	if err := Tx(ctx, testPool, func(tx pgx.Tx) error {
		if err := Reserve(ctx, tx, SystemID, 50); err != nil {
			return err
		}
		return BurnHeld(ctx, tx, 50, "test-spend", "")
	}); err != nil {
		t.Fatal(err)
	}
	if after, _ := balance(t, SystemID); after != before {
		t.Fatalf("system balance after spend = %d want %d", after, before)
	}
	assertConserved(t, "system spend")
}

func TestSeedRootTrusted(t *testing.T) {
	e := newEcon(t, nil, nil)
	ctx := context.Background()
	root, tok := e.register(t, "seedy")
	_, body := e.do(t, "POST", "/v1/subkey", tok, map[string]any{"credits": 1})
	sub := kv(body)["id"]
	id, _ := e.d.LookupToken(ctx, tok)
	if id.Seed || id.Established() || Limit(id, 10) != 10 {
		t.Fatal("fresh root should not be established")
	}
	if st, body := e.do(t, "POST", "/admin/seed-root", "adm-token", map[string]any{"id": root, "on": true}); st != 200 || body != "ok id="+root+" seed=1" {
		t.Fatalf("seed-root: %d %s", st, body)
	}
	if id, _ = e.d.LookupToken(ctx, tok); !id.Seed || !id.Established() || Limit(id, 10) != 50 {
		t.Fatalf("seed root not established: %+v", id)
	}
	if st, body := e.do(t, "POST", "/admin/trusted", "adm-token", map[string]any{"id": root, "on": true}); st != 200 || body != "ok id="+root+" trusted=1" {
		t.Fatalf("trusted: %d %s", st, body)
	}
	var trusted, seed bool
	testPool.QueryRow(ctx, `SELECT trusted, seed FROM identities WHERE id = $1`, root).Scan(&trusted, &seed)
	if !trusted || !seed {
		t.Fatalf("flags trusted=%v seed=%v", trusted, seed)
	}
	if st, body := e.do(t, "POST", "/admin/trusted", "adm-token", map[string]any{"id": root, "on": false}); st != 200 || body != "ok id="+root+" trusted=0" {
		t.Fatalf("untrust: %d %s", st, body)
	}
	testPool.QueryRow(ctx, `SELECT trusted FROM identities WHERE id = $1`, root).Scan(&trusted)
	if trusted {
		t.Fatal("still trusted")
	}
	for _, c := range []struct {
		path, tok string
		body      map[string]any
		want      int
	}{
		{"/admin/seed-root", "adm-token", map[string]any{"id": sub, "on": true}, 404},
		{"/admin/trusted", "adm-token", map[string]any{"id": "a222222", "on": true}, 404},
		{"/admin/trusted", "adm-token", map[string]any{"id": "bad", "on": true}, 400},
		{"/admin/seed-root", "poll-token", map[string]any{"id": root, "on": true}, 401},
		{"/admin/trusted", "ops-token", map[string]any{"id": root, "on": true}, 401},
	} {
		if st, body := e.do(t, "POST", c.path, c.tok, c.body); st != c.want {
			t.Errorf("%s %v: %d %s want %d", c.path, c.body, st, body, c.want)
		}
	}
	if got := adminRows(t, e.ip, 3); len(got) < 3 || got[0] != "admin POST /admin/seed-root id="+root+" on=true" {
		t.Fatalf("admin_log: %v", got)
	}
}

func TestASNAdmin(t *testing.T) {
	e := newEcon(t, func(c *Config) { c.TrustASN, c.EdgeSecret = true, "edge-secret" }, nil)
	ctx := context.Background()
	st, body := e.do(t, "POST", "/admin/asn", "adm-token", map[string]any{"asn": 64512, "class": "blocked", "note": "test\nrange"})
	if st != 200 || body != "ok asn=64512 class=blocked" {
		t.Fatalf("asn: %d %s", st, body)
	}
	var class, note string
	testPool.QueryRow(ctx, `SELECT class, note FROM asn_policy WHERE asn = 64512`).Scan(&class, &note)
	if class != "blocked" || note != "test range" {
		t.Fatalf("row %q %q", class, note)
	}
	// A registration announced from that ASN by the edge is refused.
	edge := []string{"X-CX-Edge", "edge-secret", "X-ASN", "64512"}
	c, nonce := e.challenge(t)
	if st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "blocked"}, edge...); st != 429 || body != "err quota asn" {
		t.Fatalf("blocked asn register: %d %s", st, body)
	}
	if st, body := e.do(t, "POST", "/admin/asn", "adm-token", map[string]any{"asn": 64512, "class": "shared"}); st != 200 || body != "ok asn=64512 class=shared" {
		t.Fatalf("reclass: %d %s", st, body)
	}
	c, nonce = e.challenge(t)
	if st, body := e.do(t, "POST", "/v1/register", "", map[string]string{"c": c, "nonce": nonce, "name": "shared"}, edge...); st != 201 {
		t.Fatalf("shared asn register: %d %s", st, body)
	}
	var updated int
	testPool.QueryRow(ctx, `SELECT count(*) FROM asn_policy WHERE asn = 64512 AND note = ''`).Scan(&updated)
	if updated != 1 {
		t.Fatal("upsert did not replace the note")
	}
	for _, c := range []struct {
		tok  string
		body map[string]any
		want int
	}{
		{"adm-token", map[string]any{"asn": 64512, "class": "vip"}, 400},
		{"adm-token", map[string]any{"asn": 0, "class": "hosting"}, 400},
		{"adm-token", map[string]any{"asn": 1 << 33, "class": "hosting"}, 400},
		{"poll-token", map[string]any{"asn": 64512, "class": "hosting"}, 401},
	} {
		if st, body := e.do(t, "POST", "/admin/asn", c.tok, c.body); st != c.want {
			t.Errorf("%v: %d %s want %d", c.body, st, body, c.want)
		}
	}
	testPool.Exec(ctx, `DELETE FROM asn_policy WHERE asn = 64512`)
}

func TestLedgerRetentionRollup(t *testing.T) {
	e := newEcon(t, nil, nil)
	ctx := context.Background()
	t.Cleanup(func() { testPool.Exec(ctx, `DELETE FROM ledger WHERE reason = 'rollup' OR ref = 'tretention'`) })
	for _, s := range []string{
		`INSERT INTO ledger (ts, from_id, to_id, class, amount, reason, ref) VALUES (now() - interval '13 months', 'mint', 'aoldone', 'grant', 50, 'register', 'tretention')`,
		`INSERT INTO ledger (ts, from_id, to_id, class, amount, reason, ref) VALUES (now() - interval '13 months', 'aoldone', 'burn', 'grant', 20, 'purge', 'tretention')`,
		`INSERT INTO ledger (ts, from_id, to_id, class, amount, reason, ref) VALUES (now() - interval '13 months', 'aoldone', 'hold', 'grant', 5, 'reserve', 'tretention')`,
		`INSERT INTO ledger (ts, from_id, to_id, class, amount, reason, ref) VALUES (now() - interval '1 day', 'mint', 'arecent', 'grant', 7, 'register', 'tretention')`,
	} {
		if _, err := testPool.Exec(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	before := audit(t)
	if err := e.d.ledgerRetention(ctx); err != nil {
		t.Fatal(err)
	}
	after := audit(t)
	if after.Mint != before.Mint || after.Burn != before.Burn {
		t.Fatalf("totals moved: %+v -> %+v", before, after)
	}
	var old, recent, rollMint, rollBurn int64
	testPool.QueryRow(ctx, `SELECT count(*) FROM ledger WHERE ref = 'tretention' AND ts < now() - interval '12 months'`).Scan(&old)
	testPool.QueryRow(ctx, `SELECT count(*) FROM ledger WHERE ref = 'tretention'`).Scan(&recent)
	rollMint = ledgerSum(t, testPool, `from_id = 'mint' AND to_id = 'rollup' AND reason = 'rollup'`)
	rollBurn = ledgerSum(t, testPool, `from_id = 'rollup' AND to_id = 'burn' AND reason = 'rollup'`)
	if old != 0 || recent != 1 || rollMint != 50 || rollBurn != 20 {
		t.Fatalf("old=%d recent=%d rollMint=%d rollBurn=%d", old, recent, rollMint, rollBurn)
	}
	// Old admin_log and audit_fail rows go too.
	testPool.Exec(ctx, `INSERT INTO admin_log (at, ip_group, token_kind, action) VALUES (now() - interval '13 months', 'tret', 'admin', 'x')`)
	testPool.Exec(ctx, `INSERT INTO audit_fail (at, detail) VALUES (now() - interval '13 months', 'tret')`)
	if err := e.d.ledgerRetention(ctx); err != nil {
		t.Fatal(err)
	}
	var n int
	testPool.QueryRow(ctx, `SELECT (SELECT count(*) FROM admin_log WHERE ip_group = 'tret') + (SELECT count(*) FROM audit_fail WHERE detail = 'tret')`).Scan(&n)
	if n != 0 {
		t.Fatalf("old admin rows left: %d", n)
	}
}

func TestStatsExtendedAndOrigin(t *testing.T) {
	e := newEcon(t, nil, nil)
	ctx := context.Background()
	root, _ := e.register(t, "stats")
	e.d.StorageClass("tecon", 1<<20, `SELECT 5::bigint`)
	if err := e.d.RunGovernor(ctx); err != nil {
		t.Fatal(err)
	}
	old := CollusionFn
	CollusionFn = func(context.Context, Q) []string { return []string{"a111111 a222222 jobs=60 share=0.9\nnext: evil"} }
	t.Cleanup(func() { CollusionFn = old })
	st, body := e.do(t, "GET", "/admin/stats", "poll-token", nil)
	if st != 200 {
		t.Fatalf("stats: %d %s", st, body)
	}
	for _, want := range []string{"roots=", "frozen=", "limiter_keys=", "\nwaiters=0\n", "notifier_topics=", "\nshed=", "\nledger_mint=", "\nledger_burn=",
		"\nstorage_tecon=5/1048576", "\nstorage_pg=", "\ncollusion: a111111 a222222 jobs=60 share=0.9 next: evil"} {
		if !strings.Contains(body, want) {
			t.Errorf("stats lacks %q:\n%s", want, body)
		}
	}
	if st, body := e.do(t, "GET", "/admin/stats?f=json", "poll-token", nil); st != 200 || !strings.Contains(body, `"ledger_mint":`) || !strings.Contains(body, `"storage":[`) {
		t.Fatalf("stats json: %d %s", st, body)
	}
	// Origin rows are admin-only and rendered from stored, cleaned values.
	if err := Origin(ctx, testPool, "kb", "ktest01", root, root, "10.9.8.7"); err != nil {
		t.Fatal(err)
	}
	st, body = e.do(t, "GET", "/admin/origin?ref=ktest01", "adm-token", nil)
	if st != 200 || !strings.HasPrefix(body, "origin ref=ktest01 n=1\n- kb ktest01 root="+root+" id="+root+" ip=10.9.8.7 at=") {
		t.Fatalf("origin: %d %s", st, body)
	}
	if st, body := e.do(t, "GET", "/admin/origin?ref=ktest01&kind=t", "adm-token", nil); st != 200 || body != "origin ref=ktest01 n=0" {
		t.Fatalf("origin kind filter: %d %s", st, body)
	}
	for path, tok, want := "/admin/origin?ref=ktest01", "poll-token", 401; ; {
		if st, _ := e.do(t, "GET", path, tok, nil); st != want {
			t.Fatalf("%s %s: %d want %d", tok, path, st, want)
		}
		break
	}
	if st, _ := e.do(t, "GET", "/admin/origin", "adm-token", nil); st != 400 {
		t.Fatal("missing ref accepted")
	}
	if st, _ := e.do(t, "GET", "/admin/origin?ref=ktest01&k=0", "adm-token", nil); st != 400 {
		t.Fatal("k=0 accepted")
	}
	if got := adminRows(t, e.ip, 2); len(got) < 2 || !strings.Contains(strings.Join(got, "|"), "admin GET /admin/origin ref=ktest01") {
		t.Fatalf("admin_log: %v", got)
	}
}

func TestAddRepLogs(t *testing.T) {
	e := newEcon(t, nil, nil)
	ctx := context.Background()
	root, _ := e.register(t, "replog")
	var logged []string
	old := RepLogger
	RepLogger = func(_ context.Context, _ Q, r string, delta int, kind, ref string) error {
		logged = append(logged, fmt.Sprintf("%s %d %s %q", r, delta, kind, ref))
		return nil
	}
	t.Cleanup(func() { RepLogger = old })
	if n, err := AddRep(ctx, testPool, root, 2, "rep:test", 20); err != nil || n != 2 {
		t.Fatalf("+2: %d %v", n, err)
	}
	if n, err := AddRep(ctx, testPool, root, -1, "", 0); err != nil || n != -1 {
		t.Fatalf("-1: %d %v", n, err)
	}
	if n, err := AddRep(ctx, testPool, root, 30, "rep:test", 20); err != nil || n != 18 {
		t.Fatalf("capped: %d %v", n, err)
	}
	if n, err := AddRep(ctx, testPool, root, 1, "rep:test", 20); err != nil || n != 0 {
		t.Fatalf("over cap: %d %v", n, err)
	}
	if _, err := AddRep(ctx, testPool, "a000000", 1, "", 0); err != nil {
		t.Fatal(err)
	}
	want := []string{root + ` 2 rep:test ""`, root + ` -1 rep ""`, root + ` 18 rep:test ""`}
	if strings.Join(logged, "|") != strings.Join(want, "|") {
		t.Fatalf("rep log %v", logged)
	}
	if rep, _ := Rep(ctx, testPool, root); rep != 19 {
		t.Fatalf("rep = %d", rep)
	}
}
