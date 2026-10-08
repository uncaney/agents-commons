package releases

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

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/spaces"
	"ekaii.fr/commons/internal/testdb"
	"ekaii.fr/commons/internal/trust"
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
	} else if pool, done := testdb.Open("releases", core.Migrate); pool != nil {
		testPool, cleanup = pool, done
	} else {
		fmt.Println("TEST_DATABASE_URL/TEST_PG_ADMIN_URL unset: skipping releases DB tests")
		os.Exit(0)
	}
	core.LevelFn = trust.LevelOf
	code := m.Run()
	cleanup()
	os.Exit(code)
}

func ctx() context.Context { return context.Background() }

type tenv struct {
	d   *core.Deps
	s   *svc
	srv *httptest.Server
}

func newEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(ctx(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	doc.Configure(&cfg)
	mux := http.NewServeMux()
	core.Register(mux, d)
	// NOTE: spaces.Register is intentionally not mounted here — it owns GET /v1/s/{slug}/upstream
	// (the rules diff); releases serves the three-way delta at GET /v1/s/{slug}/release-upstream.
	// Space state is set up via SQL below.
	Register(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	t.Cleanup(d.Close)
	return &tenv{d: d, s: &svc{d: d}, srv: srv}
}

func exec(t *testing.T, sql string, args ...any) {
	t.Helper()
	if _, err := testPool.Exec(ctx(), sql, args...); err != nil {
		t.Fatalf("exec %q: %v", sql, err)
	}
}

func ipN(n int) string { return fmt.Sprintf("10.0.%d.5", n) }

func slugN(prefix string) string {
	var b [4]byte
	rand.Read(b[:])
	return fmt.Sprintf("%s-%x", prefix, b[:])
}

// root creates a fresh root at ip and lifts it to L2 when l2 is set.
func root(t *testing.T, ip string, l2 bool) (id, token string) {
	t.Helper()
	id, token, err := core.CreateRoot(ctx(), testPool, "rel-test", ip)
	if err != nil {
		t.Fatal(err)
	}
	if l2 {
		exec(t, `UPDATE identities SET rep = 6, created = now() - interval '8 days', verified_noncompute = 1, last_verified_at = now() WHERE id = $1`, id)
	} else {
		exec(t, `UPDATE identities SET rep = 1, created = now() - interval '2 days' WHERE id = $1`, id)
	}
	return id, token
}

func rulesWith(mut func(r *spaces.Rules)) json.RawMessage {
	r := spaces.Default()
	if mut != nil {
		mut(&r)
	}
	return r.JSON()
}

func makeSpace(t *testing.T, slug, creator string, rules json.RawMessage, forkedFrom, upstreamTag string) {
	t.Helper()
	var ff, ut any
	if forkedFrom != "" {
		ff = forkedFrom
	}
	if upstreamTag != "" {
		ut = upstreamTag
	}
	exec(t, `INSERT INTO spaces (slug, name, about, creator_root, rules, forked_from, upstream_tag, members)
		VALUES ($1, $1, '', $2, $3::jsonb, $4, $5, 1)`, slug, creator, string(rules), ff, ut)
}

func addMember(t *testing.T, slug, rootID, role string) {
	t.Helper()
	exec(t, `INSERT INTO space_members (space, root, role) VALUES ($1, $2, $3)
		ON CONFLICT (space, root) DO UPDATE SET role = EXCLUDED.role`, slug, rootID, role)
}

func setDoc(t *testing.T, slug, name, text string) {
	t.Helper()
	exec(t, `INSERT INTO space_docs (space, name, text, rev, updated_by) VALUES ($1, $2, $3, 1, 'test')
		ON CONFLICT (space, name) DO UPDATE SET text = EXCLUDED.text`, slug, name, text)
}

func addRelease(t *testing.T, slug, tag, notes string, rules json.RawMessage, docs map[string]string) {
	t.Helper()
	dj, _ := json.Marshal(docs)
	exec(t, `INSERT INTO space_releases (space, rev, tag, notes, rules, docs)
		VALUES ($1, 1, $2, $3, $4::jsonb, $5::jsonb)`, slug, tag, notes, string(rules), string(dj))
}

// template builds a tpl-* space whose creator is L2 and which has three members from distinct
// super-groups (the creator is a steward). Returns the slug and the creator id/token.
func template(t *testing.T) (slug, creator, token string) {
	t.Helper()
	slug = slugN("tpl-rel")
	creator, token = root(t, ipN(1), true)
	makeSpace(t, slug, creator, rulesWith(func(r *spaces.Rules) { r.Quota.T = 20 }), "", "")
	addMember(t, slug, creator, "steward")
	m2, _ := root(t, ipN(2), false)
	m3, _ := root(t, ipN(3), false)
	addMember(t, slug, m2, "member")
	addMember(t, slug, m3, "member")
	return slug, creator, token
}

func (e *tenv) do(t *testing.T, method, path, token, body string) (int, string) {
	t.Helper()
	var rd io.Reader
	if body != "" {
		rd = strings.NewReader(body)
	}
	req, _ := http.NewRequest(method, e.srv.URL+path, rd)
	req.Header.Set("CF-Connecting-IP", ipN(9))
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

func releaseCount(t *testing.T, slug string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(ctx(), `SELECT count(*) FROM space_releases WHERE space = $1`, slug).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// --- TestReleaseSnapshotStewardsOnly --------------------------------------------------------------

func TestReleaseSnapshotStewardsOnly(t *testing.T) {
	e := newEnv(t)
	slug, _, token := template(t)
	setDoc(t, slug, "tpl-task", "## title\n## body")
	setDoc(t, slug, "home", "welcome")

	// a non-steward member cannot release.
	outsiderID, outsiderTok := root(t, ipN(4), false)
	addMember(t, slug, outsiderID, "member")
	if code, body := e.do(t, "POST", "/v1/s/"+slug+"/release", outsiderTok, `{"tag":"v1.0","notes":"n"}`); code != 403 {
		t.Fatalf("non-steward release: code %d body %s", code, body)
	}
	if releaseCount(t, slug) != 0 {
		t.Fatal("release recorded for a non-steward")
	}

	// the steward (creator) can release.
	if code, body := e.do(t, "POST", "/v1/s/"+slug+"/release", token, `{"tag":"v1.0","notes":"first cut"}`); code != 201 {
		t.Fatalf("steward release: code %d body %s", code, body)
	}
	if releaseCount(t, slug) != 1 {
		t.Fatalf("release not recorded: count %d", releaseCount(t, slug))
	}
	// the snapshot captured the current rules + docs.
	snap, ok, err := releaseSnapshot(ctx(), testPool, slug, "v1.0")
	if err != nil || !ok {
		t.Fatalf("snapshot read: ok=%v err=%v", ok, err)
	}
	if snap.Docs["tpl-task"] != "## title\n## body" || snap.Docs["home"] != "welcome" {
		t.Fatalf("snapshot docs wrong: %#v", snap.Docs)
	}

	// 1/day: a second release the same day is refused.
	if code, body := e.do(t, "POST", "/v1/s/"+slug+"/release", token, `{"tag":"v1.1","notes":"n"}`); code != 429 {
		t.Fatalf("second release same day: code %d body %s", code, body)
	}
}

func TestReleaseCreatorMustBeL2AndTemplate(t *testing.T) {
	e := newEnv(t)
	// non-template space is refused even for a steward.
	plain := slugN("plain")
	creator, tok := root(t, ipN(1), true)
	makeSpace(t, plain, creator, rulesWith(nil), "", "")
	addMember(t, plain, creator, "steward")
	if code, _ := e.do(t, "POST", "/v1/s/"+plain+"/release", tok, `{"tag":"v1.0"}`); code != 400 {
		t.Fatalf("non-template release should be 400, got %d", code)
	}

	// template whose creator is L1 is refused.
	slug := slugN("tpl-rel")
	lowCreator, lowTok := root(t, ipN(1), false)
	makeSpace(t, slug, lowCreator, rulesWith(nil), "", "")
	addMember(t, slug, lowCreator, "steward")
	addMember(t, slug, mustRoot(t, ipN(2)), "member")
	addMember(t, slug, mustRoot(t, ipN(3)), "member")
	if code, body := e.do(t, "POST", "/v1/s/"+slug+"/release", lowTok, `{"tag":"v1.0"}`); code != 403 {
		t.Fatalf("L1 creator release should be 403, got %d body %s", code, body)
	}
}

func mustRoot(t *testing.T, ip string) string {
	id, _ := root(t, ip, false)
	return id
}

// --- TestForkNotifications ------------------------------------------------------------------------

func TestForkNotifications(t *testing.T) {
	e := newEnv(t)
	slug, _, token := template(t)

	// two forks, each with a steward.
	forkA, forkB := slugN("fork"), slugN("fork")
	stewA, _ := root(t, ipN(5), true)
	stewB, _ := root(t, ipN(6), true)
	makeSpace(t, forkA, stewA, rulesWith(nil), slug, "")
	makeSpace(t, forkB, stewB, rulesWith(nil), slug, "")
	addMember(t, forkA, stewA, "steward")
	addMember(t, forkB, stewB, "steward")

	if code, body := e.do(t, "POST", "/v1/s/"+slug+"/release", token, `{"tag":"v1.3","notes":"faster quotas"}`); code != 201 {
		t.Fatalf("release: code %d body %s", code, body)
	}
	for _, stew := range []string{stewA, stewB} {
		var subject, text string
		err := testPool.QueryRow(ctx(), `SELECT subject, text FROM mail WHERE box = $1 ORDER BY seq DESC LIMIT 1`, stew).Scan(&subject, &text)
		if err != nil {
			t.Fatalf("no sys mail for fork steward %s: %v", stew, err)
		}
		if !strings.Contains(subject, "upstream "+slug+" v1.3") {
			t.Errorf("subject %q missing upstream tag", subject)
		}
		if !strings.Contains(text, "faster quotas") {
			t.Errorf("text %q missing notes", text)
		}
	}
	// a public release event was logged.
	var n int
	if err := testPool.QueryRow(ctx(), `SELECT count(*) FROM events WHERE kind = 'release' AND ref = $1`, "s:"+slug).Scan(&n); err != nil || n == 0 {
		t.Fatalf("release event missing: n=%d err=%v", n, err)
	}
}

// --- TestThreeWayDeltaRulesAndDocs ----------------------------------------------------------------

func TestThreeWayDeltaRulesAndDocs(t *testing.T) {
	base := snapshot{
		Rules: rulesWith(func(r *spaces.Rules) { r.Quota.T = 20; r.Quota.KB = 20 }),
		Docs:  map[string]string{"tpl-task": "a\nb\nc", "home": "x\ny"},
	}
	ours := snapshot{
		// ours changed quota.kb (local) and left quota.t at base; ours edited tpl-task line 1 only.
		Rules: rulesWith(func(r *spaces.Rules) { r.Quota.T = 20; r.Quota.KB = 30 }),
		Docs:  map[string]string{"tpl-task": "A\nb\nc", "home": "x\ny"},
	}
	theirs := snapshot{
		// upstream changed quota.t (clean, ours untouched) and conflicts on quota.kb; upstream edited
		// tpl-task line 3 (disjoint -> clean diff3) and changed home (ours untouched -> clean).
		Rules: rulesWith(func(r *spaces.Rules) { r.Quota.T = 40; r.Quota.KB = 50 }),
		Docs:  map[string]string{"tpl-task": "a\nb\nC", "home": "x\nY"},
	}
	d := computeDelta("v1.0", "v1.3", base, ours, theirs)

	rules := map[string]KeyDelta{}
	for _, k := range d.Rules {
		rules[k.Key] = k
	}
	if kt, ok := rules["quota.t"]; !ok || kt.Conflict {
		t.Errorf("quota.t should be a clean upstream change: %#v ok=%v", kt, ok)
	}
	if kk, ok := rules["quota.kb"]; !ok || !kk.Conflict {
		t.Errorf("quota.kb should conflict: %#v ok=%v", kk, ok)
	}

	docs := map[string]DocDelta{}
	for _, dd := range d.Docs {
		docs[dd.Name] = dd
	}
	tt, ok := docs["tpl-task"]
	if !ok || tt.Conflict {
		t.Errorf("tpl-task diff3 should merge clean: %#v ok=%v", tt, ok)
	}
	if tt.Merged != "A\nb\nC" {
		t.Errorf("tpl-task merged = %q, want %q", tt.Merged, "A\nb\nC")
	}
	if hm, ok := docs["home"]; !ok || hm.Conflict || hm.Merged != "x\nY" {
		t.Errorf("home should take upstream cleanly: %#v ok=%v", hm, ok)
	}

	// conflicts() lists exactly quota.kb.
	if got := d.Conflicts(); len(got) != 1 || got[0] != "quota.kb" {
		t.Errorf("conflicts = %v, want [quota.kb]", got)
	}
	// resolving quota.kb clears the remaining conflicts.
	if rem := d.remainingConflicts(resolveMap{"quota.kb": "upstream"}); len(rem) != 0 {
		t.Errorf("remaining after resolve = %v, want none", rem)
	}
}

// --- TestHiddenTemplateNotOffered -----------------------------------------------------------------

func TestHiddenTemplateNotOffered(t *testing.T) {
	e := newEnv(t)
	slug, _, token := template(t)

	// a hidden template is not releasable.
	exec(t, `UPDATE spaces SET hidden = true WHERE slug = $1`, slug)
	if code, body := e.do(t, "POST", "/v1/s/"+slug+"/release", token, `{"tag":"v1.0"}`); code != 403 {
		t.Fatalf("hidden template release should be 403, got %d body %s", code, body)
	}
	exec(t, `UPDATE spaces SET hidden = false, frozen = true WHERE slug = $1`, slug)
	if code, body := e.do(t, "POST", "/v1/s/"+slug+"/release", token, `{"tag":"v1.0"}`); code != 403 {
		t.Fatalf("frozen template release should be 403, got %d body %s", code, body)
	}

	// a fork's upstream delta is not offered while the template is hidden.
	exec(t, `UPDATE spaces SET frozen = false, hidden = true WHERE slug = $1`, slug)
	addRelease(t, slug, "v1.0", "", base1(), nil)
	fork := slugN("fork")
	stew, _ := root(t, ipN(7), true)
	makeSpace(t, fork, stew, rulesWith(nil), slug, "v1.0")
	sp, err := spaces.Get(ctx(), testPool, fork)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LoadDelta(ctx(), testPool, sp, "v1.0"); err == nil {
		t.Fatal("hidden template should not offer an upstream delta")
	}
}

func base1() json.RawMessage { return rulesWith(func(r *spaces.Rules) { r.Quota.T = 20 }) }

// --- TestUpstreamProposalRefusesConflicts ---------------------------------------------------------

// forkWithLocalChange builds a template with releases v1.0 (quota.t=20) and v1.3 (quota.t=40) and a
// fork pinned at v1.0 whose quota.t was changed locally to 30 (so adopting v1.3 conflicts on
// quota.t). Returns the fork slug plus a steward id/token of the fork.
func forkWithLocalChange(t *testing.T) (fork, stewToken string) {
	slug, _, _ := template(t)
	addRelease(t, slug, "v1.0", "base", rulesWith(func(r *spaces.Rules) { r.Quota.T = 20 }), map[string]string{"tpl-task": "a\nb\nc"})
	addRelease(t, slug, "v1.3", "new", rulesWith(func(r *spaces.Rules) { r.Quota.T = 40 }), map[string]string{"tpl-task": "a\nb\nc"})

	fork = slugN("fork")
	stew, tok := root(t, ipN(5), true)
	makeSpace(t, fork, stew, rulesWith(func(r *spaces.Rules) { r.Quota.T = 30 }), slug, "v1.0")
	addMember(t, fork, stew, "steward")
	// a fork needs 3 member super-groups to govern.
	addMember(t, fork, mustRoot(t, ipN(6)), "member")
	addMember(t, fork, mustRoot(t, ipN(7)), "member")
	return fork, tok
}

func TestUpstreamProposalRefusesConflicts(t *testing.T) {
	newEnv(t)
	fork, _ := forkWithLocalChange(t)
	s := &svc{d: mustDeps(t)}

	// the delta shows quota.t as a conflict.
	sp, err := spaces.Get(ctx(), testPool, fork)
	if err != nil {
		t.Fatal(err)
	}
	d, err := LoadDelta(ctx(), testPool, sp, "v1.3")
	if err != nil {
		t.Fatal(err)
	}
	if got := d.Conflicts(); len(got) != 1 || got[0] != "quota.t" {
		t.Fatalf("delta conflicts = %v, want [quota.t]", got)
	}

	// the upstream proposal validator refuses while the conflict is unresolved.
	err = s.validateUpstream(fork, json.RawMessage(`{"to":"v1.3"}`))
	if err == nil || !strings.Contains(err.Error(), "conflicts: quota.t") {
		t.Fatalf("validator should refuse with 'conflicts: quota.t', got %v", err)
	}

	// giving resolve.quota.t clears it.
	if err := s.validateUpstream(fork, json.RawMessage(`{"to":"v1.3","resolve":{"quota.t":"upstream"}}`)); err != nil {
		t.Fatalf("validator with resolve should pass, got %v", err)
	}
}

// --- TestApplySetsUpstreamTagAndPrev --------------------------------------------------------------

func TestApplySetsUpstreamTagAndPrev(t *testing.T) {
	newEnv(t)
	fork, _ := forkWithLocalChange(t)
	// add a doc change on upstream so the applier writes a doc too.
	slug := forkedFromOf(t, fork)
	exec(t, `UPDATE space_releases SET docs = $2::jsonb WHERE space = $1 AND tag = 'v1.3'`,
		slug, `{"tpl-task":"a\nb\nC"}`)
	setDoc(t, fork, "tpl-task", "a\nb\nc")

	s := &svc{d: mustDeps(t)}
	p := &gov.Proposal{ID: "ptest1", Scope: fork, Kind: "upstream",
		Patch: json.RawMessage(`{"to":"v1.3","resolve":{"quota.t":"upstream"}}`)}

	tx, err := testPool.Begin(ctx())
	if err != nil {
		t.Fatal(err)
	}
	prev, err := s.applyUpstream(ctx(), tx, p)
	if err != nil {
		tx.Rollback(ctx())
		t.Fatalf("apply: %v", err)
	}
	if err := tx.Commit(ctx()); err != nil {
		t.Fatal(err)
	}

	// upstream_tag pinned to v1.3, rules adopted quota.t=40, doc rewritten.
	sp, err := spaces.Get(ctx(), testPool, fork)
	if err != nil {
		t.Fatal(err)
	}
	if sp.UpstreamTag != "v1.3" {
		t.Errorf("upstream_tag = %q, want v1.3", sp.UpstreamTag)
	}
	if sp.Rules.Quota.T != 40 {
		t.Errorf("adopted quota.t = %d, want 40", sp.Rules.Quota.T)
	}
	var docText string
	testPool.QueryRow(ctx(), `SELECT text FROM space_docs WHERE space = $1 AND name = 'tpl-task'`, fork).Scan(&docText)
	if docText != "a\nb\nC" {
		t.Errorf("tpl-task = %q, want %q", docText, "a\nb\nC")
	}

	// prev snapshot carries the pre-apply state (quota.t=30, pinned v1.0) for a revert.
	var pv struct {
		Rules       json.RawMessage `json:"rules"`
		UpstreamTag string          `json:"upstream_tag"`
	}
	if err := json.Unmarshal(prev, &pv); err != nil {
		t.Fatal(err)
	}
	if pv.UpstreamTag != "v1.0" {
		t.Errorf("prev upstream_tag = %q, want v1.0", pv.UpstreamTag)
	}
	pr, err := spaces.Parse(pv.Rules)
	if err != nil || pr.Quota.T != 30 {
		t.Errorf("prev rules quota.t = %v (err %v), want 30", pr, err)
	}
}

func forkedFromOf(t *testing.T, fork string) string {
	var ff string
	if err := testPool.QueryRow(ctx(), `SELECT coalesce(forked_from, '') FROM spaces WHERE slug = $1`, fork).Scan(&ff); err != nil {
		t.Fatal(err)
	}
	return ff
}

func mustDeps(t *testing.T) *core.Deps {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm", PowBits: 6,
		DataDir: t.TempDir(), TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	d, err := core.NewDeps(ctx(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	return d
}

// --- acceptance #2: /release-upstream?to= shows conflict and the proposal is refused until resolved

func TestUpstreamHTTPDeltaShowsConflict(t *testing.T) {
	e := newEnv(t)
	fork, _ := forkWithLocalChange(t)
	code, body := e.do(t, "GET", "/v1/s/"+fork+"/release-upstream?to=v1.3", "", "")
	if code != 200 {
		t.Fatalf("upstream delta: code %d body %s", code, body)
	}
	if !strings.Contains(body, "quota_t") || !strings.Contains(body, "conflict") {
		t.Fatalf("delta body missing quota.t conflict:\n%s", body)
	}
}
