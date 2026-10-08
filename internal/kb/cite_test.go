package kb

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// newCiteEnv is newEnv with the page, edit and cite routes mounted. It restores the global
// PageLinksFn after the test so it never contaminates other packages' page expectations.
func newCiteEnv(t *testing.T) *tenv {
	t.Helper()
	cfg := core.Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(),
		TrustCF: true, PublicURL: "https://agents.example", RegPerHour: 1 << 20}
	doc.Configure(&cfg)
	d, err := core.NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	old := PageLinksFn
	mux := http.NewServeMux()
	core.Register(mux, d)
	Register(mux, d)
	RegisterPages(mux, d)
	RegisterEdit(mux, d)
	RegisterCite(mux, d)
	srv := httptest.NewServer(d.Handler(mux))
	t.Cleanup(srv.Close)
	e := &tenv{d: d, srv: srv, ip: nextIP(), cfg: cfg}
	t.Cleanup(func() {
		PageLinksFn = old
		ctx := context.Background()
		testPool.Exec(ctx, `DELETE FROM forge_outbox WHERE kind = 'kb' AND ref IN (SELECT id FROM kb WHERE author_root = ANY($1))`, e.roots)
		testPool.Exec(ctx, `DELETE FROM kb_votes WHERE root = ANY($1)`, e.roots)
		testPool.Exec(ctx, `DELETE FROM kb WHERE author_root = ANY($1)`, e.roots)
	})
	return e
}

// TestRevisionSnapshotTrigger checks 0052 + 0404: a snapshot is upserted onto the edit's own
// kb_revisions row for every rev-bumping edit, and the first such edit also back-fills the rev-1
// baseline it leaves behind (0404). No rows exist until the first edit (the trigger fires on rev
// change only, never on insert); each snapshot carries the row's content at that revision, is frozen
// by later edits, and has the internal columns stripped.
func TestRevisionSnapshotTrigger(t *testing.T) {
	e := newCiteEnv(t)
	_, tok := e.register(t, "author")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("snapshot me"), "symptom": uniq("s"), "fix": "first fix"})
	ctx := context.Background()
	// create does not write a kb_revisions row (the trigger fires on rev change only).
	if n := countRevs(t, id); n != 0 {
		t.Fatalf("after create: %d revision rows, want 0", n)
	}
	if st, _ := e.patch(t, tok, id, map[string]any{"fix": "second fix"}); st != 200 {
		t.Fatalf("edit: %d", st)
	}
	if st, _ := e.patch(t, tok, id, map[string]any{"fix": "third fix"}); st != 200 {
		t.Fatalf("edit: %d", st)
	}
	rows, err := testPool.Query(ctx, `SELECT n, snapshot->>'fix', snapshot ? 'author_root', snapshot ? 'scrub_v' FROM kb_revisions WHERE kb_id = $1 ORDER BY n`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[int]string{}
	for rows.Next() {
		var n int
		var fix string
		var hasRoot, hasScrub bool
		if err := rows.Scan(&n, &fix, &hasRoot, &hasScrub); err != nil {
			t.Fatal(err)
		}
		if hasRoot || hasScrub {
			t.Fatalf("rev %d leaks internal columns (author_root=%v scrub_v=%v)", n, hasRoot, hasScrub)
		}
		got[n] = fix
	}
	if got[1] != "first fix" {
		t.Fatalf("rev 1 snapshot fix = %q, want first fix (rev-1 baseline, frozen by later edits)", got[1])
	}
	if got[2] != "second fix" {
		t.Fatalf("rev 2 snapshot fix = %q, want second fix (frozen by the rev-3 edit)", got[2])
	}
	if got[3] != "third fix" {
		t.Fatalf("rev 3 snapshot fix = %q, want third fix", got[3])
	}
}

// TestRev1SnapshotAfterEdit is the P79-kb-cite-delta regression: before 0404 the snapshot trigger
// fired AFTER UPDATE OF rev only, so the rev-1 baseline of an entry that is later edited was never
// snapshotted and GET /kb/{id}/r1 (plus the delta package's diff?from=1, which reads
// kb.RevisionContent) answered 404. After the fix, rev 1 is snapshotted at creation and both resolve.
func TestRev1SnapshotAfterEdit(t *testing.T) {
	e := newCiteEnv(t)
	_, tok := e.register(t, "author")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("rev1 me"), "symptom": uniq("s"), "fix": "original remedy"})
	if st, _ := e.patch(t, tok, id, map[string]any{"fix": "revised remedy"}); st != 200 { // -> rev 2
		t.Fatalf("edit: %d", st)
	}
	// /kb/{id}/r1 renders the frozen rev-1 content (not the current rev-2 live row).
	st, body, _ := e.do(t, "GET", "/kb/"+id+"/r1.md", "", nil)
	if st != 200 {
		t.Fatalf("r1 after edit: %d %s (want 200 — rev-1 baseline must be snapshotted)", st, body)
	}
	if !strings.Contains(body, "original remedy") || strings.Contains(body, "revised remedy") {
		t.Fatalf("r1 not frozen at rev 1:\n%s", body)
	}
	// diff?from=1 reads kb.RevisionContent(id, 1): the rev-1 snapshot must be found and diffable.
	txt, resolved, found, err := RevisionContent(context.Background(), testPool, id, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !found || resolved != 1 {
		t.Fatalf("RevisionContent(id, 1): found=%v resolved=%d, want found=true resolved=1 (diff?from=1)", found, resolved)
	}
	if !strings.Contains(txt, "original remedy") {
		t.Fatalf("rev-1 content lacks the original fix:\n%s", txt)
	}
}

func countRevs(t *testing.T, id string) int {
	t.Helper()
	var n int
	if err := testPool.QueryRow(context.Background(), `SELECT count(*) FROM kb_revisions WHERE kb_id = $1`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// TestPinnedRenditionImmutable checks that /kb/{id}/r{n} renders the content frozen at revision n,
// that a later edit does not change an earlier retained revision, that the current revision renders
// from the live row, and that renditions are noindex with a canonical link to the live entry and a
// Memento-Datetime.
func TestPinnedRenditionImmutable(t *testing.T) {
	e := newCiteEnv(t)
	_, tok := e.register(t, "author")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("pin me"), "symptom": uniq("s"), "fix": "original remedy"})
	if st, _ := e.patch(t, tok, id, map[string]any{"fix": "revised remedy"}); st != 200 { // -> rev 2
		t.Fatalf("edit: %d", st)
	}
	if st, _ := e.patch(t, tok, id, map[string]any{"fix": "third remedy"}); st != 200 { // -> rev 3
		t.Fatalf("edit: %d", st)
	}
	// r2 is a retained historical revision rendered from its snapshot.
	st, body, hdr := e.do(t, "GET", "/kb/"+id+"/r2.md", "", nil)
	if st != 200 {
		t.Fatalf("r2: %d %s", st, body)
	}
	if !strings.Contains(body, "revised remedy") || strings.Contains(body, "third remedy") {
		t.Fatalf("r2 not frozen at rev 2:\n%s", body)
	}
	if hdr.Get("X-Robots-Tag") != "noindex" {
		t.Fatalf("r2 not noindex: %q", hdr.Get("X-Robots-Tag"))
	}
	if hdr.Get("Memento-Datetime") == "" {
		t.Fatal("r2 missing Memento-Datetime")
	}
	if !strings.Contains(strings.Join(hdr.Values("Link"), "\n"), `/kb/`+id+`>; rel="canonical"`) {
		t.Fatalf("r2 missing canonical link: %v", hdr.Values("Link"))
	}
	// r3 is the current revision, rendered from the live row.
	st, body3, _ := e.do(t, "GET", "/kb/"+id+"/r3.md", "", nil)
	if st != 200 || !strings.Contains(body3, "third remedy") {
		t.Fatalf("r3: %d %s", st, body3)
	}
	// a fourth edit must not disturb the retained r2.
	if st, _ := e.patch(t, tok, id, map[string]any{"fix": "fourth remedy"}); st != 200 {
		t.Fatalf("edit4: %d", st)
	}
	_, body, _ = e.do(t, "GET", "/kb/"+id+"/r2.md", "", nil)
	if !strings.Contains(body, "revised remedy") || strings.Contains(body, "fourth remedy") {
		t.Fatalf("r2 changed after later edit:\n%s", body)
	}
	// unknown revision -> 404
	if st, _, _ := e.do(t, "GET", "/kb/"+id+"/r99.md", "", nil); st != 404 {
		t.Fatalf("r99: want 404, got %d", st)
	}
}

// TestCiteLinksAndDigest checks the Content-Digest on the .md/.txt/.jsonld twins and the
// cite-as / latest-version / predecessor-version link set, plus the cite: footer on the .md body.
func TestCiteLinksAndDigest(t *testing.T) {
	e := newCiteEnv(t)
	_, tok := e.register(t, "author")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("cite me"), "symptom": uniq("s"), "fix": "do the thing"})
	e.patch(t, tok, id, map[string]any{"fix": "do the thing well"}) // now at rev 2

	st, body, hdr := e.do(t, "GET", "/kb/"+id+"/r2.md", "", nil)
	if st != 200 {
		t.Fatalf("r2.md: %d", st)
	}
	if !strings.HasPrefix(hdr.Get("Content-Digest"), "sha-256=:") {
		t.Fatalf("missing Content-Digest: %q", hdr.Get("Content-Digest"))
	}
	links := strings.Join(hdr.Values("Link"), "\n")
	for _, want := range []string{`rel="cite-as"`, `rel="latest-version"`, `rel="predecessor-version"`} {
		if !strings.Contains(links, want) {
			t.Fatalf("missing %s in Link: %s", want, links)
		}
	}
	if !strings.Contains(links, `/kb/`+id+`/r2>; rel="latest-version"`) {
		t.Fatalf("latest-version should point at r2: %s", links)
	}
	if !strings.Contains(links, `/kb/`+id+`/r1>; rel="predecessor-version"`) {
		t.Fatalf("predecessor-version should point at r1: %s", links)
	}
	if !strings.Contains(body, "\ncite: "+doc.Base()+"/k/"+id+"/r2 sha256=") {
		t.Fatalf("missing cite footer:\n%s", body)
	}
	// A fresh, unedited entry at rev 1 (current, rendered from the live row): Content-Digest on the
	// .txt twin and no predecessor-version link.
	id1 := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("fresh cite"), "symptom": uniq("s"), "fix": "x"})
	_, _, thdr := e.do(t, "GET", "/kb/"+id1+"/r1.txt", "", nil)
	if !strings.HasPrefix(thdr.Get("Content-Digest"), "sha-256=:") {
		t.Fatalf("txt missing Content-Digest: %q", thdr.Get("Content-Digest"))
	}
	tlinks := strings.Join(thdr.Values("Link"), "\n")
	if strings.Contains(tlinks, `rel="predecessor-version"`) {
		t.Fatal("r1 must not advertise a predecessor")
	}
	if !strings.Contains(tlinks, `/kb/`+id1+`/r1>; rel="latest-version"`) {
		t.Fatalf("r1 latest-version: %s", tlinks)
	}
}

// TestJsonldTwinAndTombstone checks the .jsonld rendition is the @graph alone with a Content-Digest,
// and that after retraction the .jsonld rendition returns tombstone metadata only (no @graph).
func TestJsonldTwinAndTombstone(t *testing.T) {
	e := newCiteEnv(t)
	_, tok := e.register(t, "author")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("jsonld me"), "symptom": uniq("s"), "fix": "graph fix"})

	st, body, hdr := e.do(t, "GET", "/kb/"+id+"/r1.jsonld", "", nil)
	if st != 200 {
		t.Fatalf("jsonld: %d %s", st, body)
	}
	if !strings.Contains(hdr.Get("Content-Type"), "application/ld+json") {
		t.Fatalf("content-type: %q", hdr.Get("Content-Type"))
	}
	if !strings.HasPrefix(hdr.Get("Content-Digest"), "sha-256=:") {
		t.Fatalf("jsonld missing Content-Digest: %q", hdr.Get("Content-Digest"))
	}
	if !strings.Contains(body, `"@graph"`) {
		t.Fatalf("jsonld not a @graph:\n%s", body)
	}
	// retract, then the jsonld rendition is tombstone metadata only
	if st, _, _ := e.do(t, "DELETE", "/v1/kb/"+id, tok, nil); st != 200 {
		t.Fatalf("retract: %d", st)
	}
	st, body, _ = e.do(t, "GET", "/kb/"+id+"/r1.jsonld", "", nil)
	if st != 410 {
		t.Fatalf("tombstone jsonld: want 410, got %d %s", st, body)
	}
	if strings.Contains(body, `"@graph"`) || strings.Contains(body, "graph fix") {
		t.Fatalf("tombstone leaks content:\n%s", body)
	}
	if !strings.Contains(body, `"creativeWorkStatus":"removed"`) {
		t.Fatalf("tombstone missing status:\n%s", body)
	}
}

// TestRevision410 checks that a retracted entry's revision renditions answer 410 across formats.
func TestRevision410(t *testing.T) {
	e := newCiteEnv(t)
	_, tok := e.register(t, "author")
	id := e.post(t, tok, map[string]any{"kind": "fix", "title": uniq("gone soon"), "symptom": uniq("s"), "fix": "x"})
	if st, _, _ := e.do(t, "DELETE", "/v1/kb/"+id, tok, nil); st != 200 {
		t.Fatalf("retract: %d", st)
	}
	for _, suf := range []string{".md", ".txt", ""} {
		st, body, _ := e.do(t, "GET", "/kb/"+id+"/r1"+suf, "", nil)
		if st != 410 {
			t.Fatalf("r1%s: want 410, got %d %s", suf, st, body)
		}
	}
}
