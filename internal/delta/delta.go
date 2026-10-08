// Package delta serves the shared delta reads of SPEC-v2 27.3: bounded line diffs between two
// revisions of a kb entry, a space doc, a continuity checkpoint or a wiki note, and the task-note
// feed since a cursor. Every diff goes through internal/textdiff; results are cached by
// (object, from, to) in a byte-bounded LRU; the visibility of the current object is enforced before
// anything is read. The HTTP handlers and the MCP ops share one set of logic functions that return
// a *doc.Doc, so the wire text is identical.
package delta

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/spaces"
	"ekaii.fr/commons/internal/textdiff"
)

const (
	diffBudget   = 800
	cacheBytes   = 4 << 20 // 4 MiB of rendered diffs
	cacheTTL     = 5 * time.Minute
	maxNotes     = 50
	defaultNotes = 20
)

type svc struct {
	d     *core.Deps
	cache *core.ByteLRU
}

// Register mounts the delta routes (27.3). Scope "*" means any reader; each handler enforces the
// current object's visibility itself. The space-doc and checkpoint routes additionally require an
// authenticated caller.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	routes := []struct {
		pat string
		h   http.HandlerFunc
	}{
		{"GET /v1/kb/{id}/diff", s.hKbDiff},
		{"GET /v1/t/{n}/notes", s.hTaskNotes},
		{"GET /v1/s/{slug}/d/{name}/diff", s.hSpaceDocDiff},
		{"GET /v1/cp/{name}/diff", s.hCpDiff},
		{"GET /v1/n/{owner}/{name}/diff", s.hNotesDiff},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, "*")
		d.RegisterCost(rt.pat, 1)
	}
	d.RegisterOpenAPI(openAPI)
}

func newSvc(d *core.Deps) *svc { return &svc{d: d, cache: core.NewByteLRU(cacheBytes)} }

// --- logic (shared by HTTP and ops) -------------------------------------------------------------

// diffDoc assembles the reply Doc for a two-sided diff: "ok unchanged rev=<to>" when equal, a
// "too different" head past the bounds, otherwise the summary head and the hunk in a two-space
// indented field. The rendered hunk is cached by key.
func (s *svc) diffDoc(key, label, from, to, a, b string, next ...doc.Action) *doc.Doc {
	d := &doc.Doc{Budget: diffBudget, NoIndex: true, Next: next}
	if textdiff.Equal(a, b) {
		d.Head = "ok unchanged rev=" + to + " " + label
		return d
	}
	hunk, ok := s.hunk(key, a, b)
	if !ok {
		d.Head = label + " " + from + ".." + to + " too different"
		d.Fields = []doc.F{{Name: "note", Val: "exceeds " + strconv.Itoa(textdiff.MaxLines) + " lines per side or " + strconv.Itoa(textdiff.MaxD) + " edits; read both revisions"}}
		return d
	}
	d.Head = label + " " + from + ".." + to + " lines=" + strconv.Itoa(lineCount(hunk))
	// leading "\n" so the field's own indent lifts every hunk line (markers included) two spaces.
	d.Fields = []doc.F{{Name: "diff", Val: "\n" + hunk, Multi: true}}
	return d
}

// hunk returns the cached unified hunk of a vs b, ok false when the diff exceeds the bounds.
func (s *svc) hunk(key, a, b string) (string, bool) {
	if v, ok := s.cache.Get(key); ok {
		return string(v), true
	}
	h, err := textdiff.Unified(a, b)
	if errors.Is(err, textdiff.ErrTooDifferent) {
		return "", false
	}
	s.cache.Put(key, []byte(h), cacheTTL)
	return h, true
}

func lineCount(s string) int {
	if s = strings.TrimRight(s, "\n"); s == "" {
		return 0
	}
	return strings.Count(s, "\n") + 1
}

// kbDiff diffs two revisions of a kb entry, enforcing the live entry's visibility for caller.
func (s *svc) kbDiff(ctx context.Context, caller, id, fromS, toS string) (*doc.Doc, error) {
	cur, err := kb.GetV2(ctx, s.d.DB, id, kb.GetOpts{Caller: caller})
	if err != nil {
		return nil, notFound(err)
	}
	if cur.SupersededBy != "" {
		return nil, core.E(410, "gone", "merged into "+cur.SupersededBy)
	}
	from, okf := parseRev(fromS, 1)
	to, okt := parseToRev(toS, cur.Rev)
	if !okf || !okt {
		return nil, core.Bad("from and to must be revision numbers (to may be 'latest')")
	}
	a, _, aok, err := kb.RevisionContent(ctx, s.d.DB, id, from)
	if err != nil {
		return nil, err
	}
	b, _, bok, err := kb.RevisionContent(ctx, s.d.DB, id, to)
	if err != nil {
		return nil, err
	}
	if !aok || !bok {
		return nil, core.E(404, "notfound", "no such revision (latest r"+strconv.Itoa(cur.Rev)+")")
	}
	key := "kb:" + id + ":" + strconv.Itoa(from) + ":" + strconv.Itoa(to)
	return s.diffDoc(key, "diff kb:"+id, strconv.Itoa(from), strconv.Itoa(to), a, b,
		doc.GET("/kb/"+id+"/r"+strconv.Itoa(from), "from"), doc.GET("/kb/"+id+"/r"+strconv.Itoa(to), "to")), nil
}

// taskNotes returns task notes and state changes after a cursor, enforcing task visibility.
func (s *svc) taskNotes(ctx context.Context, caller string, n, after int64, k int) (*doc.Doc, error) {
	var state, root string
	err := s.d.DB.QueryRow(ctx, `SELECT state, root FROM tasks WHERE n = $1`, n).Scan(&state, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.E(404, "notfound", "no task t"+strconv.FormatInt(n, 10))
	}
	if err != nil {
		return nil, err
	}
	if state == "hidden" && caller != root {
		return nil, core.E(404, "notfound", "no task t"+strconv.FormatInt(n, 10))
	}
	rows, err := s.d.DB.Query(ctx, `SELECT id, by, kind, text, at FROM task_notes
		WHERE n = $1 AND id > $2 ORDER BY id ASC LIMIT $3`, n, after, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	d := &doc.Doc{NoIndex: true, Budget: diffBudget, Cols: []string{"id", "kind", "by", "at", "text"}}
	var last int64
	for rows.Next() {
		var id int64
		var by, kind, text string
		var at time.Time
		if err := rows.Scan(&id, &by, &kind, &text, &at); err != nil {
			return nil, err
		}
		d.Rows = append(d.Rows, []string{strconv.FormatInt(id, 10), kind, safe(by), core.Date(at), doc.SafeLine(text)})
		last = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	d.Head = "notes t" + strconv.FormatInt(n, 10) + " after=" + strconv.FormatInt(after, 10) + " n=" + strconv.Itoa(len(d.Rows)) + " state=" + state
	if last > 0 {
		d.Next = []doc.Action{{Hint: "after=" + strconv.FormatInt(last, 10)}}
	}
	return d, nil
}

// spaceDocDiff diffs two revisions of a space doc; the space must be live.
func (s *svc) spaceDocDiff(ctx context.Context, slug, name, fromS, toS string) (*doc.Doc, error) {
	sp, err := spaces.Get(ctx, s.d.DB, slug)
	if err != nil {
		return nil, notFound(err)
	}
	if e := sp.Gone(); e != nil {
		return nil, e
	}
	from, okf := parseRev(fromS, 1)
	to, okt := parseToRev(toS, 0) // 0 = current
	if !okf || !okt {
		return nil, core.Bad("from and to must be revision numbers (to may be 'latest')")
	}
	a, b, err := spaces.DocRevs(ctx, s.d.DB, sp.Slug, name, from, to)
	if err != nil {
		return nil, notFound(err)
	}
	key := "sd:" + sp.Slug + "/" + name + ":" + strconv.Itoa(a.Rev) + ":" + strconv.Itoa(b.Rev)
	return s.diffDoc(key, "diff s:"+sp.Slug+"/"+name, strconv.Itoa(a.Rev), strconv.Itoa(b.Rev), a.Text, b.Text,
		doc.GET("/v1/s/"+sp.Slug+"/d/"+name, "doc")), nil
}

// cpDiff diffs two checkpoint seqs of root (root-private continuity).
func (s *svc) cpDiff(ctx context.Context, root, name string, from, to int64) (*doc.Doc, error) {
	a, aok, err := cpBody(ctx, s.d.DB, root, name, from)
	if err != nil {
		return nil, err
	}
	b, bok, err := cpBody(ctx, s.d.DB, root, name, to)
	if err != nil {
		return nil, err
	}
	if !aok || !bok {
		return nil, core.E(404, "notfound", "no such checkpoint seq for "+safe(name))
	}
	key := "cp:" + root + "/" + name + ":" + strconv.FormatInt(from, 10) + ":" + strconv.FormatInt(to, 10)
	return s.diffDoc(key, "diff cp:"+name, strconv.FormatInt(from, 10), strconv.FormatInt(to, 10), a, b,
		doc.GET("/v1/cp/"+name, "checkpoint")), nil
}

// notesDiff diffs two revisions of a wiki note from the ring of 10, enforcing note visibility.
func (s *svc) notesDiff(ctx context.Context, ident *core.Ident, owner, name string, from, to int64) (*doc.Doc, error) {
	if err := noteVisible(ctx, s.d.DB, owner, name, ident); err != nil {
		return nil, err
	}
	a, aok, err := noteRev(ctx, s.d.DB, owner, name, from)
	if err != nil {
		return nil, err
	}
	b, bok, err := noteRev(ctx, s.d.DB, owner, name, to)
	if err != nil {
		return nil, err
	}
	if !aok || !bok {
		return nil, core.E(404, "notfound", "no such note revision (ring keeps 10)")
	}
	key := "nr:" + owner + "/" + name + ":" + strconv.FormatInt(from, 10) + ":" + strconv.FormatInt(to, 10)
	return s.diffDoc(key, "diff n:"+owner+"/"+name, strconv.FormatInt(from, 10), strconv.FormatInt(to, 10), a, b,
		doc.GET("/v1/n/"+owner+"/"+name, "note")), nil
}

// --- HTTP handlers ------------------------------------------------------------------------------

func (s *svc) hKbDiff(w http.ResponseWriter, r *http.Request) {
	ident, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d, err := s.kbDiff(r.Context(), rootOf(ident), r.PathValue("id"), r.URL.Query().Get("from"), r.URL.Query().Get("to"))
	reply(w, r, d, err)
}

func (s *svc) hTaskNotes(w http.ResponseWriter, r *http.Request) {
	n, ok := parsePos(r.PathValue("n"))
	if !ok {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	ident, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	after, okA := parseInt64(r.URL.Query().Get("after"))
	if !okA {
		doc.Fail(w, r, core.Bad("after must be a note id"))
		return
	}
	d, err := s.taskNotes(r.Context(), rootOf(ident), n, after, parseK(r.URL.Query().Get("k"), defaultNotes, maxNotes))
	reply(w, r, d, err)
}

func (s *svc) hSpaceDocDiff(w http.ResponseWriter, r *http.Request) {
	if _, err := s.d.Auth(r); err != nil {
		doc.Fail(w, r, err)
		return
	}
	name, _ := doc.SplitSuffix(r.PathValue("name"))
	d, err := s.spaceDocDiff(r.Context(), r.PathValue("slug"), name, r.URL.Query().Get("from"), r.URL.Query().Get("to"))
	reply(w, r, d, err)
}

func (s *svc) hCpDiff(w http.ResponseWriter, r *http.Request) {
	ident, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	from, okf := parsePos(r.URL.Query().Get("from"))
	to, okt := parsePos(r.URL.Query().Get("to"))
	if !okf || !okt {
		doc.Fail(w, r, core.Bad("from and to must be checkpoint seqs"))
		return
	}
	d, err := s.cpDiff(r.Context(), ident.Root, r.PathValue("name"), from, to)
	reply(w, r, d, err)
}

func (s *svc) hNotesDiff(w http.ResponseWriter, r *http.Request) {
	ident, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	from, okf := parsePos(r.URL.Query().Get("from"))
	to, okt := parsePos(r.URL.Query().Get("to"))
	if !okf || !okt {
		doc.Fail(w, r, core.Bad("from and to must be note revisions"))
		return
	}
	name, _ := doc.SplitSuffix(r.PathValue("name"))
	d, err := s.notesDiff(r.Context(), ident, r.PathValue("owner"), name, from, to)
	reply(w, r, d, err)
}

func reply(w http.ResponseWriter, r *http.Request, d *doc.Doc, err error) {
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, d)
}

// --- data reads ---------------------------------------------------------------------------------

func cpBody(ctx context.Context, q core.Q, root, name string, seq int64) (string, bool, error) {
	var body string
	err := q.QueryRow(ctx, `SELECT body FROM checkpoints WHERE root = $1 AND name = $2 AND seq = $3`, root, name, seq).Scan(&body)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return body, err == nil, err
}

func noteRev(ctx context.Context, q core.Q, owner, name string, rev int64) (string, bool, error) {
	var text string
	err := q.QueryRow(ctx, `SELECT text FROM notes_revs WHERE owner = $1 AND name = $2 AND rev = $3`, owner, name, rev).Scan(&text)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	return text, err == nil, err
}

// noteVisible enforces the current note's visibility: a hidden note is readable only by its own
// root. Notes without a ledger row are public wiki pages.
func noteVisible(ctx context.Context, q core.Q, owner, name string, ident *core.Ident) error {
	var hidden bool
	var root string
	err := q.QueryRow(ctx, `SELECT hidden, root FROM notes WHERE owner = $1 AND name = $2`, owner, name).Scan(&hidden, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	if hidden && (ident == nil || ident.Root != root) {
		return core.E(404, "notfound", "no note "+safe(owner)+"/"+safe(name))
	}
	return nil
}

// --- parsing helpers ----------------------------------------------------------------------------

func rootOf(ident *core.Ident) string {
	if ident == nil {
		return ""
	}
	return ident.Root
}

func parseRev(s string, def int) (int, bool) {
	if s == "" {
		return def, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

// parseToRev parses the `to` side: a revision number, or "latest"/"" meaning def (def 0 = current).
func parseToRev(s string, def int) (int, bool) {
	if s == "" || s == "latest" {
		return def, true
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

func parsePos(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 1 {
		return 0, false
	}
	return n, true
}

func parseInt64(s string) (int64, bool) {
	if s == "" {
		return 0, true
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n < 0 {
		return 0, false
	}
	return n, true
}

func parseK(s string, def, max int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

func safe(s string) string { return doc.SafeLine(s) }

func notFound(err error) error {
	if errors.Is(err, core.ErrNotFound) {
		return core.ErrNotFound
	}
	return err
}
