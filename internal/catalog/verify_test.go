package catalog

// Acceptance tests of P51-catalog-verify (SPEC-v2 15.2 verification parts, 18.1 svc-bless awaiting
// operator). They drive the real weekly re-verification (recheck from the system root through
// compute.SystemSubmit), the publish-time under-replication rule, the nondeterminism / auto-hide
// stats hook, and the svc-bless / svc-transfer governance appliers.

import (
	"context"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/gov"
)

// setStable backdates a verified version and makes it the stable pointer so the weekly re-check
// janitor (coalesce(rechecked_at, verified_at, created) < now - 7 d) picks it up.
func (e *env) setStable(name string, ver int) {
	e.t.Helper()
	if _, err := testPool.Exec(context.Background(),
		`UPDATE services SET stable_ver = $2 WHERE name = $1`, name, ver); err != nil {
		e.t.Fatal(err)
	}
	if _, err := testPool.Exec(context.Background(),
		`UPDATE service_versions SET verified_at = now() - interval '8 days' WHERE name = $1 AND ver = $2`, name, ver); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) recheck() {
	e.t.Helper()
	if err := e.s.recheck(context.Background()); err != nil {
		e.t.Fatal(err)
	}
}

// TestWeeklyReverifyFlipsFailing: a stable version whose weekly KAT now disagrees with its declared
// hash flips to failing with a failing_since date, the list line carries the badge, and the run is
// recorded in svc_kat_runs.
func TestWeeklyReverifyFlipsFailing(t *testing.T) {
	e := newEnv(t)
	e.fundSystem()
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("weekly")
	e.verified(tok, name, wasm, []map[string]any{kat("a", "A\n")}, map[string]string{sha([]byte("a")): "A\n"}, nil)
	e.setStable(name, 1)

	e.recheck()
	v := e.version(name, 1)
	if v.RecheckJob == "" {
		t.Fatalf("recheck job not queued: %+v", v.State)
	}
	// the module now returns the wrong answer under both donors (a regression after cutoff).
	if n := e.work(e.workers(2), constOut("WRONG\n")); n == 0 {
		t.Fatal("recheck job not leased")
	}
	e.verify() // settles the recheck
	v = e.version(name, 1)
	if v.State != "failing" || v.FailingSince == nil {
		t.Fatalf("state=%s failing_since=%v (want failing since <date>)", v.State, v.FailingSince)
	}
	if v.RecheckJob != "" || v.Rechecked == nil {
		t.Fatalf("recheck not cleared: job=%q rechecked=%v", v.RecheckJob, v.Rechecked)
	}
	st, body, _ := e.do("GET", "/v1/svc?q="+name[:8], "", nil)
	if st != 200 || !strings.Contains(body, "[failing since ") {
		t.Fatalf("list line missing failing badge: %d %s", st, body)
	}
	// the KAT history recorder appends the settled run.
	if err := recordKATRuns(context.Background(), e.d); err != nil {
		t.Fatal(err)
	}
	var runs int
	testPool.QueryRow(context.Background(), `SELECT count(*) FROM svc_kat_runs WHERE name = $1 AND ver = 1`, name).Scan(&runs)
	if runs == 0 {
		t.Fatal("no svc_kat_runs rows recorded")
	}
}

// TestSystemRootUnfundedSkips: with the system root short of credits the weekly re-check queues
// nothing and leaves an inbox (ops) event; the stable version is untouched.
func TestSystemRootUnfundedSkips(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	wasm := e.put(tok, minWasm(id))
	name := uname("unfunded")
	e.verified(tok, name, wasm, []map[string]any{kat("a", "A\n")}, map[string]string{sha([]byte("a")): "A\n"}, nil)
	e.setStable(name, 1)

	ctx := context.Background()
	if _, err := testPool.Exec(ctx, `UPDATE identities SET credits = 0 WHERE id = $1`, core.SystemID); err != nil {
		t.Fatal(err)
	}
	var before int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'unfunded'`).Scan(&before)
	e.recheck()
	if v := e.version(name, 1); v.RecheckJob != "" {
		t.Fatalf("recheck job queued while unfunded: %q", v.RecheckJob)
	}
	var after int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'ops' AND ref = 'unfunded'`).Scan(&after)
	if after <= before {
		t.Fatalf("no unfunded inbox event raised (%d -> %d)", before, after)
	}
}

// TestPendingNeverRejectedUnderReplicated: a KAT that cannot reach two distinct donor groups keeps
// the version pending forever (never rejected), both for a single replica and for two replicas in
// the same super-group (d=0), even after the retries are exhausted.
func TestPendingNeverRejectedUnderReplicated(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)

	// one replica only: no consensus, stays pending across repeated janitor passes.
	name := uname("one")
	e.mustPublish(tok, name, e.put(tok, minWasm(id)), manifest([]map[string]any{kat("a", "A")}, nil))
	e.work(e.workers(1), constOut("A"))
	for i := 0; i < 4; i++ {
		e.verify()
		if v := e.version(name, 1); v.State != "pending" {
			t.Fatalf("single replica flipped to %s", v.State)
		}
	}

	// two replicas in one /24 agree but are not distinct (d=0): re-queued, never rejected even
	// past katRetries.
	ip := randIP()
	_, a := e.registerIP("same-a", ip)
	_, b := e.registerIP("same-b", ip[:strings.LastIndex(ip, ".")]+".88")
	name2 := uname("samegroup")
	e.mustPublish(tok, name2, e.put(tok, minWasm(id+"2")), manifest([]map[string]any{kat("a", "A")}, nil))
	for i := 0; i < katRetries+3; i++ {
		e.work([]string{a, b}, constOut("A"))
		e.verify()
		if v := e.version(name2, 1); v.State == "rejected" {
			t.Fatalf("d=0 KAT was rejected at pass %d (%s)", i, v.Tested)
		}
	}
	if v := e.version(name2, 1); v.State != "pending" {
		t.Fatalf("d=0 final state %s, want pending", v.State)
	}
}

// TestNondeterminismThreshold: the done hook flags nondeterministic only once nocons/calls reaches
// 5 % over at least 20 calls.
func TestNondeterminismThreshold(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	ctx := context.Background()

	// below 20 calls: a no-consensus does not flag.
	low := uname("ndlow")
	e.verified(tok, low, e.put(tok, minWasm(id)), []map[string]any{kat("a", "A\n")}, map[string]string{sha([]byte("a")): "A\n"}, nil)
	if _, err := testPool.Exec(ctx, `UPDATE service_versions SET calls = 10 WHERE name = $1 AND ver = 1`, low); err != nil {
		t.Fatal(err)
	}
	if err := OnDone(ctx, testPool, &compute.Job{ID: "jtest-nd-low", Svc: low + "@1", Kind: "job", Status: "failed", Reason: "noconsensus"}); err != nil {
		t.Fatal(err)
	}
	if v := e.version(low, 1); v.Nondeterministic {
		t.Fatal("flagged below the 20-call minimum")
	}

	// at/over 20 calls and >= 5 %: flagged, with the Status() word and an event.
	hi := uname("ndhi")
	e.verified(tok, hi, e.put(tok, minWasm(id+"h")), []map[string]any{kat("a", "A\n")}, map[string]string{sha([]byte("a")): "A\n"}, nil)
	if _, err := testPool.Exec(ctx, `UPDATE service_versions SET calls = 20 WHERE name = $1 AND ver = 1`, hi); err != nil {
		t.Fatal(err)
	}
	if err := OnDone(ctx, testPool, &compute.Job{ID: "jtest-nd-hi", Svc: hi + "@1", Kind: "job", Status: "failed", Reason: "noconsensus"}); err != nil {
		t.Fatal(err)
	}
	v := e.version(hi, 1)
	if !v.Nondeterministic || v.Status() != "nondeterministic" {
		t.Fatalf("not flagged: nondet=%v status=%s", v.Nondeterministic, v.Status())
	}
	var evs int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind = 'svc' AND ref = $1 AND title LIKE '%nondeterministic%'`, hi+"@1").Scan(&evs)
	if evs == 0 {
		t.Fatal("no nondeterministic event raised")
	}
}

// TestAutoHideAfterFailures: ten consecutive failed-consensus calls hide the service; the ninth
// does not.
func TestAutoHideAfterFailures(t *testing.T) {
	e := newEnv(t)
	id, tok := e.register("pub")
	e.l1(id)
	ctx := context.Background()
	name := uname("autohide")
	e.verified(tok, name, e.put(tok, minWasm(id)), []map[string]any{kat("a", "A\n")}, map[string]string{sha([]byte("a")): "A\n"}, nil)

	hidden := func() bool {
		var h bool
		testPool.QueryRow(ctx, `SELECT hidden FROM services WHERE name = $1`, name).Scan(&h)
		return h
	}
	for i := 1; i <= hideNocons; i++ {
		j := &compute.Job{ID: "jtest-hide-" + name + "-" + string(rune('a'+i)), Svc: name + "@1", Kind: "job", Status: "failed", Reason: "noconsensus"}
		if err := OnDone(ctx, testPool, j); err != nil {
			t.Fatal(err)
		}
		switch {
		case i < hideNocons && hidden():
			t.Fatalf("hidden after only %d consecutive failures", i)
		case i == hideNocons && !hidden():
			t.Fatalf("not hidden after %d consecutive failures", i)
		}
	}
	// a success resets the streak (nocons_run back to 0).
	if err := OnDone(ctx, testPool, &compute.Job{ID: "jtest-hide-ok-" + name, Svc: name + "@1", Kind: "job", Status: "done", UsedMs: 5}); err != nil {
		t.Fatal(err)
	}
	var run int
	testPool.QueryRow(ctx, `SELECT nocons_run FROM services WHERE name = $1`, name).Scan(&run)
	if run != 0 {
		t.Fatalf("streak not reset by a success: nocons_run=%d", run)
	}
}

// insertAwaiting inserts a passed proposal sitting in awaiting_operator, as the tally leaves an
// await-operator kind before the operator decides.
func (e *env) insertAwaiting(kind, target string, patch, authorRoot string) string {
	e.t.Helper()
	pid := core.NewID('p')
	if _, err := testPool.Exec(context.Background(),
		`INSERT INTO proposals (id, scope, kind, target, patch, author, author_root, closes_at, state, passed_at, escrow_state)
		 VALUES ($1, '', $2, $3, $4::jsonb, $5, $5, now(), 'awaiting_operator', now(), 'none')`,
		pid, kind, target, patch, authorRoot); err != nil {
		e.t.Fatal(err)
	}
	return pid
}

// TestBlessOnlyViaOperatorDecision: a svc-bless proposal that passed its vote does not list the
// service until the operator says yes; a no leaves it unblessed.
func TestBlessOnlyViaOperatorDecision(t *testing.T) {
	e := newEnv(t)
	RegisterVerify(e.d)
	id, tok := e.register("pub")
	e.l1(id)
	ctx := context.Background()
	name := uname("bless")
	e.verified(tok, name, e.put(tok, minWasm(id)), []map[string]any{kat("a", "A\n")}, map[string]string{sha([]byte("a")): "A\n"}, nil)
	e.setStable(name, 1)

	blessed := func() bool {
		for _, n := range blessedNames(ctx, e.d) {
			if n == name {
				return true
			}
		}
		return false
	}

	// awaiting the operator: not blessed yet.
	pidNo := e.insertAwaiting("svc-bless", "svc:"+name, `{"name":"`+name+`"}`, id)
	if blessed() {
		t.Fatal("blessed while still awaiting the operator")
	}
	// operator declines: still not blessed.
	if _, err := gov.Decide(ctx, e.d, pidNo, "no", "not yet", gov.DecideExtra{}); err != nil {
		t.Fatalf("decide no: %v", err)
	}
	if blessed() {
		t.Fatal("blessed after an operator no")
	}
	var st string
	testPool.QueryRow(ctx, `SELECT state FROM proposals WHERE id = $1`, pidNo).Scan(&st)
	if st != "declined" {
		t.Fatalf("no decision state %s, want declined", st)
	}

	// operator yes: blessed and listed in /llms-full.txt.
	pidYes := e.insertAwaiting("svc-bless", "svc:"+name, `{"name":"`+name+`"}`, id)
	if _, err := gov.Decide(ctx, e.d, pidYes, "yes", "", gov.DecideExtra{}); err != nil {
		t.Fatalf("decide yes: %v", err)
	}
	testPool.QueryRow(ctx, `SELECT state FROM proposals WHERE id = $1`, pidYes).Scan(&st)
	if st != "applied" {
		t.Fatalf("yes decision state %s, want applied", st)
	}
	if !blessed() {
		t.Fatal("not blessed after an operator yes")
	}
	if full := e.s.llms(ctx); !strings.Contains(full, name) {
		t.Fatalf("blessed service absent from /llms-full.txt: %q", full)
	}
}

// TestTransferApplier: a passed svc-transfer moves owner_root only after 90 d of inactivity; an
// active service fails the apply.
func TestTransferApplier(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	id, tok := e.register("owner")
	e.l1(id)
	to, _ := e.register("heir")
	name := uname("transfer")
	e.verified(tok, name, e.put(tok, minWasm(id)), []map[string]any{kat("a", "A\n")}, map[string]string{sha([]byte("a")): "A\n"}, nil)

	apply := TransferApplier(e.d)
	p := &gov.Proposal{ID: core.NewID('p'), Kind: "svc-transfer", Target: "svc:" + name, Patch: []byte(`{"to":"` + to + `"}`)}

	// active service: refused, owner unchanged.
	if _, err := apply(ctx, testPool, p); err == nil {
		t.Fatal("transfer of an active service was allowed")
	}
	if owner := ownerOf(name); owner != id {
		t.Fatalf("owner changed on a refused transfer: %s", owner)
	}

	// 90 d inactive: transfer applies, prev carries the old owner.
	if _, err := testPool.Exec(ctx, `UPDATE services SET created = now() - interval '120 days', last_other_call = now() - interval '100 days' WHERE name = $1`, name); err != nil {
		t.Fatal(err)
	}
	prev, err := apply(ctx, testPool, p)
	if err != nil {
		t.Fatalf("transfer after inactivity: %v", err)
	}
	if owner := ownerOf(name); owner != to {
		t.Fatalf("owner not transferred: %s, want %s", owner, to)
	}
	if !strings.Contains(string(prev), id) {
		t.Fatalf("prev snapshot missing the old owner: %s", prev)
	}
}

func ownerOf(name string) string {
	var o string
	testPool.QueryRow(context.Background(), `SELECT owner_root FROM services WHERE name = $1`, name).Scan(&o)
	return o
}
