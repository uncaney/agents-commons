package kb

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Edit / retract / telemetry acceptance tests (SPEC-v2 6.3 PATCH/DELETE, 6.4; PLAN P11c-kb-edit).

// newEditEnv is newEnv with RegisterEdit mounted (PATCH/DELETE routes, TelemetryFn, janitor tasks).
func newEditEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	RegisterEdit(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	e := &tenv{d: d, srv: srv, ip: nextIP(), cfg: cfg}
	t.Cleanup(func() {
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM forge_outbox WHERE kind = 'kb' AND ref IN (SELECT id FROM kb WHERE author_root = ANY($1))`, e.roots)
		testPool.Exec(ctx, `DELETE FROM kb_votes WHERE root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM kb WHERE author_root = ANY($1)`, e.roots)
	})
	return e
}

func (e *tenv) patch(t *testing.T, tok, id string, body any, hdr ...string) (int, string) {
	t.Helper()
	st, b, _ := e.do(t, "PATCH", "/v1/kb/"+id, tok, body, hdr...)
	return st, b
}

func TestEditRevisionsAndReopenVotes(t *testing.T) {
	e := newEditEnv(t)
	ctx := context.Background()
	aid, atok := e.register(t, "author")
	id := e.post(t, atok, map[string]any{"kind": "fix", "title": uniq("editable entry"), "symptom": uniq("s"), "fix": "do it", "versions": "node@20.1", "tags": []string{"x"}})
	var voters []string
	for i := 0; i < 2; i++ {
		_, tok := e.registerL(t, fmt.Sprintf("v%d", i), 2)
		e.mustVote(t, tok, id, true, nil)
		voters = append(voters, tok)
	}
	_, body, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil)
	if h := first(body); !strings.Contains(h, " ok3 bad0 ") || !strings.HasSuffix(h, " rev1 flags:-") {
		t.Fatalf("before: %s", h)
	}
	// Only the author root edits.
	_, otok := e.register(t, "other")
	if st, b := e.patch(t, otok, id, map[string]any{"fix": "hijack"}); st != 403 || first(b) != "err auth not the author" {
		t.Fatalf("non-author: %d %s", st, b)
	}
	if st, b := e.patch(t, "", id, map[string]any{"fix": "anon"}); st != 401 {
		t.Fatalf("anonymous: %d %s", st, b)
	}
	if st, b := e.patch(t, atok, "kzzzzzz", map[string]any{"fix": "x"}); st != 404 {
		t.Fatalf("unknown: %d %s", st, b)
	}
	// Title and symptom are not editable; unknown fields are refused.
	if st, b := e.patch(t, atok, id, map[string]any{"title": "renamed"}); st != 400 {
		t.Fatalf("title patch: %d %s", st, b)
	}
	// The edit: rev 2, diff stored, confirmations re-opened, header ok3* (edited).
	st, b := e.patch(t, atok, id, map[string]any{"fix": "do it better", "versions": "node@22.9", "tags": []string{"x", "y"}}, "X-CX-V", "2")
	if st != 200 || first(b) != "ok "+id+" rev=2 reopened=2" {
		t.Fatalf("edit: %d %s", st, b)
	}
	if !strings.Contains(b, "\nnext: GET /v1/kb/"+id+" | POST /v1/kb/"+id+"/ok re-confirm | GET /k/"+id+".md") {
		t.Fatalf("edit tail: %s", b)
	}
	_, body, _ = e.do(t, "GET", "/v1/kb/"+id, "", nil)
	if h := first(body); !strings.Contains(h, " ok3* bad0 ") || !strings.HasSuffix(h, " rev2 flags:- (edited)") {
		t.Fatalf("edited header: %s", h)
	}
	if !strings.Contains(body, "\nfix: do it better\n") || !strings.Contains(body, "\nversions: node@22.9\n") || !strings.Contains(body, "\ntags: x,y\n") {
		t.Fatalf("edited body:\n%s", body)
	}
	after, err := GetV2(ctx, testPool, id, GetOpts{})
	if err != nil || after.Rev != 2 || after.OkW != 3 || after.OkWPrev != 3 || !after.EditedAfterConfirm || after.EditedBy != aid {
		t.Fatalf("after: %+v %v", after, err)
	}
	if fmt.Sprint(after.Libs) != fmt.Sprint([]LibVer{{"node", "22.9"}}) {
		t.Fatalf("kb_versions: %v", after.Libs)
	}
	var diff, by string
	if err := testPool.QueryRow(ctx, `SELECT diff, by FROM kb_revisions WHERE kb_id = $1 AND n = 2`, id).Scan(&diff, &by); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"-fix: do it\n+fix: do it better", "-versions: node@20.1\n+versions: node@22.9", "-tags: x\n+tags: x,y"} {
		if !strings.Contains(diff, want) {
			t.Fatalf("diff missing %q:\n%s", want, diff)
		}
	}
	if by != aid {
		t.Fatalf("revision by: %q", by)
	}
	if queryInt(t, `SELECT count(*) FROM kb_votes WHERE kb_id = $1`, id) != 0 {
		t.Fatal("prior confirmations not re-opened")
	}
	// A prior voter votes again (no 409 dup); the weight restarts from the fresh votes.
	if line := e.mustVote(t, voters[0], id, true, nil); line != "ok ok1.5" {
		t.Fatalf("re-vote: %s", line)
	}
	// A no-op patch changes nothing.
	if st, b := e.patch(t, atok, id, map[string]any{"fix": "do it better"}); st != 400 || first(b) != "err bad patch changes nothing" {
		t.Fatalf("noop: %d %s", st, b)
	}
	if st, b := e.patch(t, atok, id, nil); st != 400 {
		t.Fatalf("empty: %d %s", st, b)
	}
	// Oversized and malformed fields follow the create limits.
	if st, b := e.patch(t, atok, id, map[string]any{"fix": strings.Repeat("a", maxFix+1)}); st != 400 {
		t.Fatalf("big fix: %d %s", st, b)
	}
	if st, b := e.patch(t, atok, id, map[string]any{"tags": []string{"Bad Tag"}}); st != 400 {
		t.Fatalf("bad tag: %d %s", st, b)
	}
	// JSON reply.
	st, b = e.patch(t, atok, id, map[string]any{"cause": "root cause"}, "Accept", "application/json")
	var j map[string]any
	if st != 200 || json.Unmarshal([]byte(b), &j) != nil || j["ok"] != true || j["rev"] != float64(3) || j["id"] != id {
		t.Fatalf("json edit: %d %s", st, b)
	}
	// Failing ranges recorded by bad votes (negative knowledge) survive an applies rewrite.
	if st, b := e.patch(t, atok, id, map[string]any{"applies": "node >=18"}); st != 200 || first(b) != "ok "+id+" rev=4" {
		t.Fatalf("applies edit: %d %s", st, b)
	}
	_, btok := e.registerL(t, "bad", 1)
	if line := e.mustVote(t, btok, id, false, map[string]any{"why": "breaks", "applies": "node 22.x"}); line != "ok split" {
		t.Fatalf("range split: %s", line)
	}
	if st, b := e.patch(t, atok, id, map[string]any{"applies": "node >=16"}); st != 200 || first(b) != "ok "+id+" rev=5" {
		t.Fatalf("applies rewrite: %d %s", st, b)
	}
	if en, _ := GetV2(ctx, testPool, id, GetOpts{}); en == nil || en.Applies.String() != "node >=16; node 22.x (fails)" || en.Fails.N != 1 {
		t.Fatalf("applies after edit: %+v", en)
	}
	// Op ke matches HTTP; the audit and origin trails carry each edit.
	out, err := EditOps(e.d)["ke"](ctx, e.ident(t, atok), json.RawMessage(fmt.Sprintf(`{"id":%q,"why_safe":"explained"}`, id)))
	if err != nil || out != "ok "+id+" rev=6" {
		t.Fatalf("op ke: %q %v", out, err)
	}
	if _, err := EditOps(e.d)["ke"](ctx, e.ident(t, otok), json.RawMessage(fmt.Sprintf(`{"id":%q,"fix":"x"}`, id))); err == nil || !strings.HasPrefix(err.Error(), "err auth") {
		t.Fatalf("op ke non-author: %v", err)
	}
	if n := queryInt(t, `SELECT count(*) FROM audit WHERE op = 'ke' AND ref = $1`, id); n != 5 {
		t.Fatalf("audit rows: %d", n)
	}
	if n := queryInt(t, `SELECT count(*) FROM content_origin WHERE kind = 'kbedit' AND ref = $1`, id); n != 5 {
		t.Fatalf("origin rows: %d", n)
	}
	// 6 rows: one per edit (rev 2..6) plus the rev-1 baseline the first edit back-fills (0404).
	if n := queryInt(t, `SELECT count(*) FROM kb_revisions WHERE kb_id = $1`, id); n != 6 {
		t.Fatalf("revision rows: %d", n)
	}
	// Scoped tokens need kb:w (RegisterScope).
	if s, ok := e.d.ScopeOf("PATCH /v1/kb/{id}"); !ok || s != "kb:w" {
		t.Fatalf("scope: %q %v", s, ok)
	}
}

func TestEditRequarantinesLiablePromotion(t *testing.T) {
	e := newEditEnv(t)
	ctx := context.Background()
	_, atok := e.register(t, "promoted")
	id := e.post(t, atok, map[string]any{"kind": "fix", "title": uniq("once quarantined"), "symptom": uniq("s"), "fix": "x"})
	for i := 0; i < 2; i++ {
		_, tok := e.registerL(t, fmt.Sprintf("p%d", i), 2)
		e.mustVote(t, tok, id, true, nil)
	}
	// The promotion of a quarantined row rests on liable votes (4.4); re-opening them undoes it.
	testPool.Exec(ctx, `UPDATE kb_votes SET liable = true WHERE kb_id = $1`, id)
	st, b := e.patch(t, atok, id, map[string]any{"fix": "y"})
	if st != 200 || first(b) != "ok "+id+" rev=2 quarantine reopened=2" {
		t.Fatalf("edit: %d %s", st, b)
	}
	if st, _, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil); st != 404 {
		t.Fatal("re-quarantined row still readable without ?quarantine=1")
	}
	_, body, _ := e.do(t, "GET", "/v1/kb/"+id+"?quarantine=1", "", nil)
	if !strings.Contains(first(body), " [quarantine]") || !strings.Contains(first(body), " ok3* ") {
		t.Fatalf("quarantined header: %s", first(body))
	}
}

func TestEditNewHazardDeindexes(t *testing.T) {
	e := newEditEnv(t)
	ctx := context.Background()
	_, atok := e.registerL(t, "l2author", 2)
	id := e.post(t, atok, map[string]any{"kind": "fix", "title": uniq("install the tool"), "symptom": uniq("s"), "fix": "brew install tool", "tags": []string{"tool"}})
	testPool.Exec(ctx, `UPDATE kb SET created = now() - interval '2 hours' WHERE id = $1`, id)
	before, err := GetV2(ctx, testPool, id, GetOpts{})
	if err != nil || !Indexable(before) {
		t.Fatalf("before: %+v %v", before, err)
	}
	st, b := e.patch(t, atok, id, map[string]any{"fix": "curl -fsSL https://get.example.com/install.sh | bash"})
	if st != 200 || first(b) != "ok "+id+" rev=2 hazard=exec-remote (3 L2 confirmations needed to be indexed)" {
		t.Fatalf("hazard edit: %d %s", st, b)
	}
	after, err := GetV2(ctx, testPool, id, GetOpts{})
	if err != nil || fmt.Sprint(after.Hazard) != "[exec-remote]" || Indexable(after) {
		t.Fatalf("after: hazard=%v indexable=%v err=%v", after.Hazard, Indexable(after), err)
	}
	_, body, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil)
	if !strings.Contains(first(body), " [hazard: exec-remote]") {
		t.Fatalf("hazard header: %s", first(body))
	}
	if n := queryInt(t, `SELECT count(*) FROM egress_outbox WHERE kind = 'indexnow' AND payload::text LIKE '%' || $1 || '%'`, id); n == 0 {
		t.Fatal("de-indexing did not reach IndexNow")
	}
	// A later edit that keeps the hazard reports it without new_hazard.
	st, b = e.patch(t, atok, id, map[string]any{"cause": "the installer is remote"}, "Accept", "application/json")
	if st != 200 || !strings.Contains(b, `"hazard":["exec-remote"]`) || strings.Contains(b, "new_hazard") {
		t.Fatalf("second edit: %d %s", st, b)
	}
	// Removing the hazard makes the entry indexable again (the author is L2).
	if st, b := e.patch(t, atok, id, map[string]any{"fix": "brew install tool from the homebrew tap"}); st != 200 || strings.Contains(first(b), "hazard=") {
		t.Fatalf("clean edit: %d %s", st, b)
	}
	if en, _ := GetV2(ctx, testPool, id, GetOpts{}); en == nil || len(en.Hazard) != 0 || !Indexable(en) {
		t.Fatalf("clean entry: %+v", en)
	}
}

func TestRetract410Successor(t *testing.T) {
	e := newEditEnv(t)
	ctx := context.Background()
	_, atok := e.register(t, "ret")
	a := e.post(t, atok, map[string]any{"kind": "fix", "title": uniq("old fix"), "symptom": uniq("s"), "fix": "x", "tags": []string{"old"}})
	b := e.post(t, atok, map[string]any{"kind": "fix", "title": uniq("new fix"), "symptom": uniq("s"), "fix": "y"})
	old := core.ExportRemoveFn
	var removed []string
	core.ExportRemoveFn = func(_ context.Context, kind, id string) { removed = append(removed, kind+":"+id) }
	t.Cleanup(func() { core.ExportRemoveFn = old })
	_, otok := e.register(t, "other")
	if st, body, _ := e.do(t, "DELETE", "/v1/kb/"+a, otok, nil); st != 403 || first(body) != "err auth not the author" {
		t.Fatalf("non-author: %d %s", st, body)
	}
	if st, _, _ := e.do(t, "DELETE", "/v1/kb/"+a, "", nil); st != 401 {
		t.Fatalf("anonymous: %d", st)
	}
	if st, _, _ := e.do(t, "DELETE", "/v1/kb/kzzzzzz", atok, nil); st != 404 {
		t.Fatalf("unknown: %d", st)
	}
	if st, body, _ := e.do(t, "DELETE", "/v1/kb/"+a, atok, map[string]any{"superseded_by": a}); st != 400 {
		t.Fatalf("self successor: %d %s", st, body)
	}
	if st, body, _ := e.do(t, "DELETE", "/v1/kb/"+a, atok, map[string]any{"superseded_by": "kzzzzzz"}); st != 400 || first(body) != "err bad superseded_by unknown" {
		t.Fatalf("unknown successor: %d %s", st, body)
	}
	if queryInt(t, `SELECT count(*) FROM kb WHERE id = $1`, a) != 1 {
		t.Fatal("refused retractions must not delete")
	}
	st, body, _ := e.do(t, "DELETE", "/v1/kb/"+a, atok, map[string]any{"superseded_by": b}, "X-CX-V", "2")
	if st != 200 || first(body) != "ok retracted superseded_by="+b || !strings.Contains(body, "\nnext: GET /v1/kb/"+b+" successor") {
		t.Fatalf("retract: %d %s", st, body)
	}
	st, body, _ = e.do(t, "GET", "/v1/kb/"+a, "", nil)
	if st != 410 || first(body) != "err gone retract superseded_by="+b || !strings.Contains(body, "next: GET /v1/kb/"+b+" successor") {
		t.Fatalf("410: %d %s", st, body)
	}
	if tb, ok := Gone(ctx, testPool, a); !ok || tb.Reason != "retract" || tb.SupersededBy != b || tb.Title == "" {
		t.Fatalf("tombstone: %+v %v", tb, ok)
	}
	if queryInt(t, `SELECT count(*) FROM kb WHERE id = $1`, a) != 0 {
		t.Fatal("row not deleted")
	}
	if fmt.Sprint(removed) != "[kb:"+a+"]" {
		t.Fatalf("export removal: %v", removed)
	}
	if queryInt(t, `SELECT count(*) FROM forge_outbox WHERE kind = 'kb' AND ref = $1 AND payload = ''::bytea`, a) == 0 {
		t.Fatal("mirror removal not enqueued")
	}
	if queryInt(t, `SELECT count(*) FROM egress_outbox WHERE kind = 'indexnow' AND payload::text LIKE '%' || $1 || '%'`, a) == 0 {
		t.Fatal("IndexNow removal not enqueued")
	}
	if queryInt(t, `SELECT count(*) FROM audit WHERE op = 'kd' AND ref = $1`, a) != 1 {
		t.Fatal("audit row")
	}
	// Op g answers gone; a second retraction is a 404.
	if _, err := Ops(e.d)["g"](ctx, nil, json.RawMessage(fmt.Sprintf(`{"id":%q}`, a))); err == nil || err.Error() != "err gone retract superseded_by="+b {
		t.Fatalf("op g: %v", err)
	}
	if st, _, _ := e.do(t, "DELETE", "/v1/kb/"+a, atok, nil); st != 404 {
		t.Fatalf("second retraction: %d", st)
	}
	// Op kd without a successor; JSON reply shape.
	c := e.post(t, atok, map[string]any{"kind": "note", "title": uniq("gone note"), "symptom": uniq("s")})
	if out, err := EditOps(e.d)["kd"](ctx, e.ident(t, atok), json.RawMessage(fmt.Sprintf(`{"id":%q}`, c))); err != nil || out != "ok retracted" {
		t.Fatalf("op kd: %q %v", out, err)
	}
	if st, body, _ := e.do(t, "GET", "/v1/kb/"+c, "", nil); st != 410 || first(body) != "err gone retract" {
		t.Fatalf("410 without successor: %d %s", st, body)
	}
	d := e.post(t, atok, map[string]any{"kind": "note", "title": uniq("json gone"), "symptom": uniq("s")})
	st, body, _ = e.do(t, "DELETE", "/v1/kb/"+d, atok, map[string]any{"superseded_by": b}, "Accept", "application/json")
	if st != 200 || !strings.Contains(body, `"retracted":true`) || !strings.Contains(body, `"superseded_by":"`+b+`"`) {
		t.Fatalf("json retract: %d %s", st, body)
	}
	if s, ok := e.d.ScopeOf("DELETE /v1/kb/{id}"); !ok || s != "kb:w" {
		t.Fatalf("scope: %q %v", s, ok)
	}
}

func TestTelemetryBloomDedupe(t *testing.T) {
	e := newEditEnv(t)
	ctx := context.Background()
	tel.reset()
	t.Cleanup(tel.reset)
	aid, tok := e.register(t, "reader")
	title := uniq("telemetry entry about pnpm engines")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": title, "symptom": uniq("s"), "fix": "x"})
	for i := 0; i < 3; i++ {
		Bump(ctx, id, "view", "aaaaaaa") // one view: same reader, same day
	}
	Bump(ctx, id, "view", "bbbbbbb")       // another reader
	Bump(ctx, id, "impression", "aaaaaaa") // kinds are deduplicated apart
	Bump(ctx, id, "impression", "aaaaaaa")
	Bump(ctx, "kzzzzzz", "view", "x") // unknown entry: dropped at flush time
	Bump(ctx, id, "bogus", "x")       // unknown kind: ignored
	Bump(ctx, "not-an-id", "view", "x")
	if rows, dropped := TelemetryPending(); rows != 2 || dropped != 0 {
		t.Fatalf("pending: %d %d", rows, dropped)
	}
	if n, err := FlushTelemetry(ctx, testPool); err != nil || n != 1 {
		t.Fatalf("flush: %d %v", n, err)
	}
	reads := func() (views, imps int) {
		t.Helper()
		if err := testPool.QueryRow(ctx, `SELECT coalesce(sum(views), 0), coalesce(sum(impressions), 0) FROM kb_reads_daily WHERE kb_id = $1`, id).Scan(&views, &imps); err != nil {
			t.Fatal(err)
		}
		return
	}
	if v, i := reads(); v != 2 || i != 1 {
		t.Fatalf("after flush: views=%d impressions=%d", v, i)
	}
	if n, err := FlushTelemetry(ctx, testPool); err != nil || n != 0 {
		t.Fatalf("empty flush: %d %v", n, err)
	}
	// The HTTP hook: anonymous reads dedupe per IP group, token reads per root.
	for i := 0; i < 2; i++ {
		if st, _, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil); st != 200 {
			t.Fatal("get")
		}
	}
	e.do(t, "GET", "/v1/kb/"+id, tok, nil)
	if st, body, _ := e.do(t, "GET", "/v1/kb?q="+urlq(title), "", nil); st != 200 || !strings.Contains(body, id) {
		t.Fatalf("search: %d %s", st, body)
	}
	if _, err := FlushTelemetry(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	if v, i := reads(); v != 4 || i != 2 {
		t.Fatalf("after reads: views=%d impressions=%d", v, i)
	}
	// The author-only stats line reads the flushed counts; the read itself is a dedupe hit.
	_, body, _ := e.do(t, "GET", "/v1/kb/"+id, tok, nil)
	if !strings.Contains(body, "\nstats: views=4 confirms=0 (author only)\n") {
		t.Fatalf("stats line missing:\n%s", body)
	}
	if _, body, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil); strings.Contains(body, "stats:") {
		t.Fatal("stats shown to a non-author")
	}
	// The ops lane bumps through the client keys of core.WithClient.
	octx := core.WithClient(ctx, "10.9.9.9", core.IPGroup("10.9.9.9"), core.IPSuper("10.9.9.9"))
	if _, err := Ops(e.d)["g"](octx, nil, json.RawMessage(fmt.Sprintf(`{"id":%q}`, id))); err != nil {
		t.Fatal(err)
	}
	Ops(e.d)["g"](octx, nil, json.RawMessage(fmt.Sprintf(`{"id":%q}`, id)))
	FlushTelemetry(ctx, testPool)
	if v, _ := reads(); v != 5 {
		t.Fatalf("op view: views=%d", v)
	}
	// A new UTC day forgets the bloom.
	tel.mu.Lock()
	tel.day = utcDay(time.Now().Add(-24 * time.Hour))
	tel.mu.Unlock()
	Bump(ctx, id, "view", aid)
	if rows, _ := TelemetryPending(); rows != 1 {
		t.Fatalf("day rollover: pending %d", rows)
	}
	// Janitor task wiring: RunOnce flushes the buffer.
	e.d.Janitor.RunOnce(ctx)
	if v, _ := reads(); v != 6 {
		t.Fatalf("janitor flush: views=%d", v)
	}
	if rows, _ := TelemetryPending(); rows != 0 {
		t.Fatalf("pending after janitor: %d", rows)
	}
}

func TestStaleJanitor(t *testing.T) {
	e := newEditEnv(t)
	ctx := context.Background()
	_, tok := e.register(t, "stale")
	title := uniq("stale candidate about yarn workspaces")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": title, "symptom": uniq("s"), "fix": "x"})
	fresh := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("fresh but popular"), "symptom": uniq("s"), "fix": "y"})
	quiet := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("old and unread"), "symptom": uniq("s"), "fix": "z"})
	testPool.Exec(ctx, `UPDATE kb SET created = now() - interval '31 days' WHERE id = ANY($1)`, []string{id, quiet})
	testPool.Exec(ctx, `INSERT INTO kb_reads_daily (kb_id, day, views, impressions) VALUES ($1, current_date - 1, 30, 5), ($1, current_date, 30, 0), ($2, current_date, 90, 0), ($3, current_date, 49, 0)`, id, fresh, quiet)
	if n, err := MarkStale(ctx, testPool); err != nil || n < 1 {
		t.Fatalf("mark: %d %v", n, err)
	}
	for _, c := range []struct {
		id   string
		want bool
	}{{id, true}, {fresh, false}, {quiet, false}} {
		en, err := GetV2(ctx, testPool, c.id, GetOpts{})
		if err != nil || en.Stale != c.want {
			t.Fatalf("%s stale=%v want %v (%v)", c.id, en.Stale, c.want, err)
		}
	}
	_, body, _ := e.do(t, "GET", "/v1/kb/"+id, "", nil)
	if !strings.HasSuffix(first(body), " flags:- stale?") {
		t.Fatalf("stale header: %s", first(body))
	}
	_, body, _ = e.do(t, "GET", "/v1/kb?q="+urlq(title), "", nil)
	hit := ""
	for _, l := range lines(body) {
		if strings.HasPrefix(l, id+" ") {
			hit = l
		}
	}
	if !strings.HasSuffix(hit, " "+title+" stale?") {
		t.Fatalf("stale hit: %q in\n%s", hit, body)
	}
	// Idempotent: a second pass changes nothing.
	if n, err := MarkStale(ctx, testPool); err != nil || n != 0 {
		t.Fatalf("second mark: %d %v", n, err)
	}
	// A confirmation clears the mark on the next pass.
	_, vtok := e.registerL(t, "confirmer", 1)
	e.mustVote(t, vtok, id, true, nil)
	if n, err := MarkStale(ctx, testPool); err != nil || n != 1 {
		t.Fatalf("clear: %d %v", n, err)
	}
	if en, _ := GetV2(ctx, testPool, id, GetOpts{}); en == nil || en.Stale {
		t.Fatal("stale not cleared after a confirmation")
	}
	// The janitor runs the pass at most once an hour per instance.
	staleMu.Lock()
	staleLast = time.Time{}
	staleMu.Unlock()
	if !staleDue() || staleDue() {
		t.Fatal("staleDue cadence")
	}
}
