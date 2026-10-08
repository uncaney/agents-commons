package machineclaims

import (
	"context"
	"testing"

	"ekaii.fr/commons/internal/know"
)

// TestDisputePausesProduct: when know hides a machine row after three disputes it calls the wired
// hook, which pauses the product (both kinds) for 30 days and raises an operator inbox event; a
// paused product is skipped by the enqueue.
func TestDisputePausesProduct(t *testing.T) {
	d := newDeps(t)
	ctx := context.Background()
	if know.MachineDisputedFn == nil {
		t.Fatal("Register did not wire MachineDisputedFn")
	}
	// Simulate the dispute trigger know fires inside its transaction.
	know.MachineDisputedFn(ctx, d.DB, "pypi:requests", "v0000000")

	for _, kind := range []string{"osv", "eol"} {
		paused, err := Paused(ctx, d.DB, kind, "pypi:requests")
		if err != nil || !paused {
			t.Fatalf("%s paused=%v err=%v, want true", kind, paused, err)
		}
	}
	var far bool
	if err := testPool.QueryRow(ctx, `SELECT paused_until > now() + interval '29 days' FROM machine_state WHERE kind='osv' AND key='pypi:requests'`).Scan(&far); err != nil || !far {
		t.Fatalf("pause window far=%v err=%v, want ~30d", far, err)
	}
	// The operator inbox event was raised.
	var events int
	testPool.QueryRow(ctx, `SELECT count(*) FROM events WHERE kind='machine_paused'`).Scan(&events)
	if events == 0 {
		t.Fatal("no machine_paused event raised")
	}

	// A paused, otherwise-eligible lib is not enqueued.
	seedLib(t, d, "pypi:requests", true, []know.Release{{V: "2.30.0"}})
	if err := EnqueueOSV(ctx, d); err != nil {
		t.Fatal(err)
	}
	if n := countEgress(t, "osv"); n != 0 {
		t.Fatalf("osv jobs for a paused lib = %d, want 0", n)
	}
}

// TestDailyCaps: no more than DailyCap jobs of a kind are enqueued per day.
func TestDailyCaps(t *testing.T) {
	d := newDeps(t)
	ctx := context.Background()
	old := DailyCap
	DailyCap = 2
	t.Cleanup(func() { DailyCap = old })

	for _, name := range []string{"requests", "flask", "httpx", "click", "rich"} {
		seedLib(t, d, "pypi:"+name, true, []know.Release{{V: "1.0.0"}})
	}
	if err := EnqueueOSV(ctx, d); err != nil {
		t.Fatal(err)
	}
	if n := countEgress(t, "osv"); n != 2 {
		t.Fatalf("osv jobs = %d, want DailyCap=2", n)
	}
	// Already at the cap: a further pass enqueues nothing more.
	if err := EnqueueOSV(ctx, d); err != nil {
		t.Fatal(err)
	}
	if n := countEgress(t, "osv"); n != 2 {
		t.Fatalf("osv jobs after cap = %d, want 2", n)
	}

	// The cap is per kind: eol has its own budget.
	if err := EnqueueEOL(ctx, d); err != nil {
		t.Fatal(err)
	}
	if n := countEgress(t, "eol"); n != 2 {
		t.Fatalf("eol jobs = %d, want DailyCap=2", n)
	}
}
