package kb

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/know"
)

// "Also known as" recall-repair acceptance tests (SPEC-v2 27.9, PLAN P76-kb-recall).

// mkRootL registers a root and gives it level lvl; returns the root id.
func (e *tenv) mkRootL(t *testing.T, lvl int) string {
	t.Helper()
	id, _ := e.register(t, strings.ReplaceAll(uniq("aka-root"), " ", "-"))
	if lvl > 0 {
		e.setLevel(t, id, lvl)
	}
	return id
}

// mkEntryBy creates a live entry authored by root (Force bypasses the dup check) and returns its id.
func (e *tenv) mkEntryBy(t *testing.T, root, title string) string {
	t.Helper()
	c, err := CreateEntry(context.Background(), e.d, Input{Kind: "fix", Title: title, Symptom: uniq("sym"), Fix: "restart it", Force: true},
		Author{ID: root, Root: root})
	if err != nil {
		t.Fatalf("create %q: %v", title, err)
	}
	e.roots = append(e.roots, root)
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM kb WHERE id = $1`, c.ID) })
	return c.ID
}

func akaRow(t *testing.T, kid, text string) (quar bool, exists bool) {
	t.Helper()
	h := akaHash(text)
	err := testPool.QueryRow(context.Background(), `SELECT quarantine FROM kb_aka WHERE kb_id = $1 AND h = $2`, kid, h).Scan(&quar)
	if errors.Is(err, context.Canceled) || err != nil {
		return false, false
	}
	return quar, true
}

func akaText(t *testing.T, kid string) string {
	t.Helper()
	var s string
	testPool.QueryRow(context.Background(), `SELECT aka_text FROM kb WHERE id = $1`, kid).Scan(&s)
	return s
}

// TestAkaLiveL1QuarantinedL0: an L1 author's alias is live at once; an L0 author's is quarantined
// until one L2 root in another super-group confirms it.
func TestAkaLiveL1QuarantinedL0(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner := e.mkRootL(t, 2)
	kid := e.mkEntryBy(t, owner, uniq("live aka entry"))

	l1 := e.mkRootL(t, 1)
	res, err := AddAka(ctx, e.d, AkaAuthor{ID: l1, Root: l1}, kid, "the pool starts before postgres is ready")
	if err != nil {
		t.Fatalf("L1 aka: %v", err)
	}
	if res.Quarantine {
		t.Fatalf("L1 aka should be live, got %+v", res)
	}
	if quar, ok := akaRow(t, kid, "the pool starts before postgres is ready"); !ok || quar {
		t.Fatalf("L1 aka row ok=%v quar=%v, want live", ok, quar)
	}
	if !strings.Contains(akaText(t, kid), "pool starts before postgres") {
		t.Fatalf("live aka must join into aka_text, got %q", akaText(t, kid))
	}

	l0 := e.mkRootL(t, 0)
	pend := "db handle opened too early at boot"
	res, err = AddAka(ctx, e.d, AkaAuthor{ID: l0, Root: l0}, kid, pend)
	if err != nil {
		t.Fatalf("L0 aka: %v", err)
	}
	if !res.Quarantine {
		t.Fatalf("L0 aka should be quarantined, got %+v", res)
	}
	if quar, ok := akaRow(t, kid, pend); !ok || !quar {
		t.Fatalf("L0 aka row ok=%v quar=%v, want quarantined", ok, quar)
	}
	if strings.Contains(akaText(t, kid), "opened too early") {
		t.Fatalf("quarantined aka must not be in aka_text")
	}

	// An L1 root cannot promote it; an L2 root in another super-group can.
	l1b := e.mkRootL(t, 1)
	if _, err := AkaOk(ctx, e.d, &core.Ident{ID: l1b, Root: l1b}, kid, hexs(akaHash(pend))); !errors.Is(err, errAkaNoL2) {
		t.Fatalf("L1 ok: %v, want errAkaNoL2", err)
	}
	l2 := e.mkRootL(t, 2)
	if _, err := AkaOk(ctx, e.d, &core.Ident{ID: l2, Root: l2}, kid, hexs(akaHash(pend))); err != nil {
		t.Fatalf("L2 ok: %v", err)
	}
	if quar, _ := akaRow(t, kid, pend); quar {
		t.Fatalf("after L2 ok the aka must be live")
	}
	if !strings.Contains(akaText(t, kid), "opened too early") {
		t.Fatalf("promoted aka must join aka_text, got %q", akaText(t, kid))
	}
}

// TestAkaDupAgainstTitlesAndAkas: an alias within similarity 0.6 of another visible entry's title
// or of another entry's alias is refused 409.
func TestAkaDupAgainstTitlesAndAkas(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner := e.mkRootL(t, 2)

	title := "kafka consumer rebalance storm under high lag spikes"
	a := e.mkEntryBy(t, owner, title)
	b := e.mkEntryBy(t, owner, uniq("unrelated widget fault"))

	// Too close to entry a's title.
	if _, err := AddAka(ctx, e.d, AkaAuthor{ID: owner, Root: owner}, b, "kafka consumer rebalance storm under high lag"); !isDup(err) {
		t.Fatalf("title-dup aka: %v, want 409 dup", err)
	}

	// A legitimate alias on a, then a near-copy of it proposed on b.
	alias := "zookeeper session expiry triggers mass rebalancing churn"
	if _, err := AddAka(ctx, e.d, AkaAuthor{ID: owner, Root: owner}, a, alias); err != nil {
		t.Fatalf("seed alias: %v", err)
	}
	if _, err := AddAka(ctx, e.d, AkaAuthor{ID: owner, Root: owner}, b, "zookeeper session expiry triggers mass rebalancing"); !isDup(err) {
		t.Fatalf("alias-dup aka: %v, want 409 dup", err)
	}
}

func isDup(err error) bool {
	var ae *core.APIError
	return errors.As(err, &ae) && ae.Status == 409
}

// TestAkaFillsWanted: accepting an alias whose ErrSig hash matches an open wanted row deletes it and
// reports the fill on the reply line (through the kb.FilledHook seam).
func TestAkaFillsWanted(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	know.SetWantedSecret(e.cfg.ServerSecret)
	old := FilledHook
	FilledHook = know.FillWantedHash
	t.Cleanup(func() { FilledHook = old })

	owner := e.mkRootL(t, 2)
	kid := e.mkEntryBy(t, owner, uniq("fills wanted entry"))

	alias := "redis connection pool exhausted after failover"
	sig := ErrSig(alias)
	// Record the demand (a wanted kind e row keyed by sha256(sig)).
	grp := nextIP()
	if err := know.RecordMiss(ctx, e.d.DB, "e", sig, core.IPSuper(grp), ""); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256([]byte(sig))
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM wanted WHERE h = $1`, h[:]) })

	res, err := AddAka(ctx, e.d, AkaAuthor{ID: owner, Root: owner}, kid, alias)
	if err != nil {
		t.Fatalf("add aka: %v", err)
	}
	if !strings.Contains(res.Filled, "filled wanted") {
		t.Fatalf("reply should report the fill, got %q (line %q)", res.Filled, res.Line())
	}
	var n int
	testPool.QueryRow(ctx, `SELECT count(*) FROM wanted WHERE h = $1`, h[:]).Scan(&n)
	if n != 0 {
		t.Fatalf("wanted row should be deleted, %d left", n)
	}
}

// TestAkaCapsAndInheritance: at most 3 own-entry akas per author, and akas inherit the entry's
// quarantine state (an alias on a quarantined entry is quarantined whatever the author's level).
func TestAkaCapsAndInheritance(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner := e.mkRootL(t, 2)
	kid := e.mkEntryBy(t, owner, uniq("caps entry"))

	for i := 0; i < akaOwnPerEntry; i++ {
		if _, err := AddAka(ctx, e.d, AkaAuthor{ID: owner, Root: owner}, kid, uniq("own alias phrasing")); err != nil {
			t.Fatalf("own aka %d: %v", i, err)
		}
	}
	if _, err := AddAka(ctx, e.d, AkaAuthor{ID: owner, Root: owner}, kid, uniq("own alias phrasing")); !errors.Is(err, errAkaOwn) {
		t.Fatalf("4th own aka: %v, want errAkaOwn", err)
	}

	// Inheritance: a quarantined entry (anonymous author) makes even an L1 author's alias quarantined.
	grp := nextIP()
	qc, err := CreateEntry(ctx, e.d, Input{Kind: "fix", Title: uniq("quarantined parent"), Symptom: uniq("s"), Fix: "x", Force: true},
		Author{Anon: true, Grp: grp, Super: core.IPSuper(grp)})
	if err != nil {
		t.Fatalf("anon entry: %v", err)
	}
	t.Cleanup(func() { testPool.Exec(context.Background(), `DELETE FROM kb WHERE id = $1`, qc.ID) })
	l1 := e.mkRootL(t, 1)
	res, err := AddAka(ctx, e.d, AkaAuthor{ID: l1, Root: l1}, qc.ID, uniq("alias on a pending entry"))
	if err != nil {
		t.Fatalf("aka on quarantined entry: %v", err)
	}
	if !res.Quarantine {
		t.Fatalf("alias on a quarantined entry must inherit quarantine, got %+v", res)
	}
}

// TestSearchHitViaAkaRendersMarker: Search matches an entry through a live alias and renders the
// (aka: …) marker on the hit (the entry's own title does not contain the query words).
func TestSearchHitViaAkaRendersMarker(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	owner := e.mkRootL(t, 2)
	kid := e.mkEntryBy(t, owner, "opaque title zzqq about nothing searchable")

	alias := "gunicorn worker timeout boot failure saturn"
	if _, err := AddAka(ctx, e.d, AkaAuthor{ID: owner, Root: owner}, kid, alias); err != nil {
		t.Fatalf("add aka: %v", err)
	}
	hits, err := SearchV2(ctx, e.d.DB, SearchOpts{Q: "gunicorn worker timeout saturn", K: 5, Anon: true})
	if err != nil {
		t.Fatal(err)
	}
	var found *Hit
	for i := range hits {
		if hits[i].ID == kid {
			found = &hits[i]
		}
	}
	if found == nil {
		t.Fatalf("alias search did not return the entry; hits=%+v", hits)
	}
	if found.Aka == "" {
		t.Fatalf("hit should carry the matched alias, got %+v", *found)
	}
	if !strings.Contains(found.Line(), "aka:") {
		t.Fatalf("hit line should render the aka marker, got %q", found.Line())
	}
}
