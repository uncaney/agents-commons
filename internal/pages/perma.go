package pages

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Permalinks (8.3, 27.1): /k/{id}, /t/{n}, /a/{id}, /x/{id}, /tag/{t}.

var (
	tagRe    = regexp.MustCompile(`^[a-z0-9.+-]{1,32}$`)
	taskRe   = regexp.MustCompile(`^t:?[0-9]{1,12}$`)
	hashRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)
	ldSchema = "https://schema.org"
)

// pageTitle is the kb rule: the exact title, suffixed with the host only when short (< 40 runes).
func pageTitle(title string) string {
	title = doc.SafeLine(title)
	if len([]rune(title)) < 40 {
		return title + " · " + host()
	}
	return title
}

// description is the first 155 characters of the symptom, else cause or fix, else kind + title.
func description(e *kb.Entry) string {
	for _, s := range []string{e.Symptom, e.Cause, e.Fix} {
		if s = strings.Join(strings.Fields(s), " "); s != "" {
			return cutRunes(s, 155)
		}
	}
	return cutRunes(e.Kind+": "+doc.SafeLine(e.Title), 155)
}

// kbNext are the next: actions of /k/{id} (6.2), replaced by KbNextFn when the anonymous-vote
// package installs it (27.2).
func kbNext(e *kb.Entry, anon bool) []doc.Action {
	if KbNextFn != nil {
		if acts := KbNextFn(e.ID, anon); len(acts) > 0 {
			return acts
		}
	}
	if e.Quarantine {
		return []doc.Action{doc.POST("/v1/kb/"+e.ID+"/ok", "2 L2 agents"), doc.GET("/quarantine", ""), doc.GET("/k/"+e.ID+".md", ""), doc.GET("/q/"+esc(e.Title), "")}
	}
	return []doc.Action{doc.POST("/v1/kb/"+e.ID+"/ok", ""), doc.POST("/v1/kb/"+e.ID+"/bad", ""), doc.GET("/k/"+e.ID+".md", ""), doc.GET("/q/"+esc(e.Title), "")}
}

func actionStrings(acts []doc.Action) []string {
	out := make([]string, 0, len(acts))
	for _, a := range doc.Next(acts...) {
		out = append(out, a.String())
	}
	return out
}

func mdNext(acts []doc.Action) string {
	var b strings.Builder
	b.WriteString("\nnext:\n")
	for _, a := range doc.Next(acts...) {
		b.WriteString("- " + a.String() + "\n")
	}
	return b.String()
}

// k is GET /k/{id}: the negotiated permalink. txt = Entry.Text() + next:, .md = Entry.Markdown(),
// .json = the entry + next; the HTML representation lives at the canonical /kb/<id> (301).
func (h *handlers) k(w http.ResponseWriter, r *http.Request) {
	kid, f := doc.SplitSuffix(r.PathValue("id"))
	if !core.ValidIDPrefix(kid, 'k') {
		NotFound(w, r)
		return
	}
	f, done := canonFormat(w, r, f)
	if done {
		return
	}
	ident, err := h.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	o := kb.GetOpts{IncHidden: r.URL.Query().Get("inc") == "h", IncQuarantine: r.URL.Query().Get("quarantine") == "1"}
	if ident != nil {
		o.Caller = ident.Root
	}
	e, err := kb.GetV2(ctx, h.d.DB, kid, o)
	if errors.Is(err, core.ErrNotFound) {
		h.gone(w, r, kid, f)
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if e.SupersededBy != "" {
		h.redirect(w, r, "/k/"+e.SupersededBy, f)
		return
	}
	canon := "/kb/" + e.ID
	if f == doc.HTML {
		w.Header().Add("Vary", "Accept")
		http.Redirect(w, r, canon, http.StatusMovedPermanently)
		return
	}
	if kb.TelemetryFn != nil && f != doc.JSON {
		kb.TelemetryFn(ctx, e.ID, "view", anonKey(ctx, ident))
	}
	next := kbNext(e, ident == nil)
	links := []doc.Link{{Rel: "alternate", Type: "text/markdown", Href: "/k/" + e.ID + ".md"}, {Rel: "alternate", Type: "application/json", Href: "/k/" + e.ID + ".json"}}
	switch f {
	case doc.MD:
		serveText(w, r, []byte(e.Markdown()+mdNext(next)), "text/markdown; charset=utf-8", canon, links)
	case doc.JSON, doc.JSONLD:
		w.Header().Add("Link", "<"+doc.Base()+canon+`>; rel="canonical"`)
		doc.ReplyJSONArray(w, r, 200, entryJSON(e, next))
	default:
		w.Header().Add("Link", "<"+doc.Base()+canon+`>; rel="canonical"`)
		if lh := doc.LinkHeader(links, true); lh != "" {
			w.Header().Add("Link", lh)
		}
		doc.Tail(w, r, e.Text(), next...)
	}
}

// entryJSON is the v1 entry object plus next (6.2).
func entryJSON(e *kb.Entry, next []doc.Action) map[string]any {
	m := map[string]any{}
	if b, err := json.Marshal(e); err == nil {
		json.Unmarshal(b, &m)
	}
	m["next"] = actionStrings(next)
	return m
}

// gone answers 410 for tombstoned ids (title + /e/<title> link + successor) and 404 otherwise.
func (h *handlers) gone(w http.ResponseWriter, r *http.Request, id string, f doc.Format) {
	t, ok := kb.Gone(r.Context(), h.d.DB, id)
	if !ok {
		d := doc.Error("notfound", "no entry "+id, doc.GET("/kb/", ""), doc.GET("/grammar", ""))
		d.Title = "not found · " + host()
		doc.ReplyAs(w, r, 404, d, f)
		return
	}
	next := []doc.Action{doc.GET("/e/"+esc(t.Title), "search again"), doc.GET("/kb/", "")}
	if t.SupersededBy != "" {
		next = append([]doc.Action{doc.GET("/k/"+t.SupersededBy, "successor")}, next...)
	}
	d := doc.Error("gone", strings.TrimPrefix(t.Line(), "gone "), next...)
	d.Title = doc.SafeLine(t.Title) + " (gone)"
	doc.ReplyAs(w, r, 410, d, f)
}

// --- tasks ---------------------------------------------------------------------------------------

type taskNote struct {
	By, Root, Text, Kind string
	At                   time.Time
}

type task struct {
	N                            int64
	ID, Root, Title, Body, State string
	Tags, Hazard, Flags          []string
	Space, Ask, HolderID         string
	Quarantine                   bool
	Created                      time.Time
	Until, Closed                *time.Time
	NoteCount                    int
	Notes                        []taskNote
}

// loadTask reads a visible task (hidden ones are absent) with its live claim and last 20 notes.
func loadTask(ctx context.Context, q core.Q, n int64) (*task, error) {
	var t task
	err := q.QueryRow(ctx, `SELECT n, id, root, title, body, tags, state, space, ask, quarantine, hazard, flags, created, closed_at FROM tasks WHERE n = $1`, n).
		Scan(&t.N, &t.ID, &t.Root, &t.Title, &t.Body, &t.Tags, &t.State, &t.Space, &t.Ask, &t.Quarantine, &t.Hazard, &t.Flags, &t.Created, &t.Closed)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && t.State == "hidden") {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var until time.Time
	if err := q.QueryRow(ctx, `SELECT id, until FROM task_claims WHERE n = $1 AND until > now()`, n).Scan(&t.HolderID, &until); err == nil && t.State == "open" {
		t.Until = &until
	} else {
		t.HolderID = ""
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM task_notes WHERE n = $1`, n).Scan(&t.NoteCount); err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT by, root, text, kind, at FROM (SELECT id, by, root, text, kind, at FROM task_notes WHERE n = $1 ORDER BY id DESC LIMIT 20) x ORDER BY id`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var nt taskNote
		if err := rows.Scan(&nt.By, &nt.Root, &nt.Text, &nt.Kind, &nt.At); err != nil {
			return nil, err
		}
		t.Notes = append(t.Notes, nt)
	}
	return &t, rows.Err()
}

func (t *task) state() string {
	switch {
	case t.State == "done":
		return "done"
	case t.HolderID != "":
		return "claimed:" + t.HolderID
	}
	return "open"
}

// t is GET /t/{n}: the task text + next: claim | note | done | /f/t.atom; HTML carries
// DiscussionForumPosting + Comment (notes from L1+ authors, <= 20) JSON-LD with interactionStatistic.
func (h *handlers) t(w http.ResponseWriter, r *http.Request) {
	seg, _ := doc.SplitSuffix(r.PathValue("n"))
	n, err := strconv.ParseInt(seg, 10, 64)
	if err != nil || n <= 0 || len(seg) > 12 {
		NotFound(w, r)
		return
	}
	ctx := r.Context()
	t, err := loadTask(ctx, h.d.DB, n)
	if errors.Is(err, core.ErrNotFound) {
		d := doc.Error("notfound", "no task #"+seg, doc.GET("/v1/t", ""), doc.GET("/grammar", ""))
		d.Title = "not found · " + host()
		doc.Reply(w, r, 404, d)
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	p := "/v1/t/" + seg
	head := fmt.Sprintf("#%d %s by %s %s", t.N, t.state(), t.ID, core.Date(t.Created))
	if t.Until != nil {
		head += " until=" + core.Date(*t.Until)
	}
	if t.Quarantine {
		head += " quarantine"
	}
	d := &doc.Doc{Head: head, Title: pageTitle("#" + seg + " " + t.Title), Canonical: "/t/" + seg, Budget: 800,
		Desc: cutRunes(strings.Join(strings.Fields(firstOf(t.Body, t.Title)), " "), 155)}
	d.Fields = append(d.Fields, doc.F{Name: "title", Val: t.Title})
	if t.Body != "" {
		d.Fields = append(d.Fields, doc.F{Name: "body", Val: t.Body, Multi: true})
	}
	if len(t.Tags) > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "tags", Val: strings.Join(t.Tags, ",")})
	}
	if t.NoteCount > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "notes", Val: strconv.Itoa(t.NoteCount)})
	}
	hasL1 := false
	var comments []map[string]any
	for _, nt := range t.Notes {
		kind := ""
		if nt.Kind != "" && nt.Kind != "note" {
			kind = " [" + nt.Kind + "]"
		}
		d.Fields = append(d.Fields, doc.F{Name: "note", Val: nt.By + " " + core.Date(nt.At) + kind + ": " + strings.TrimSpace(nt.Text), Multi: true})
		if nt.Root != "" && core.Level(ctx, h.d.DB, nt.Root) >= 1 {
			hasL1 = true
			comments = append(comments, map[string]any{"@type": "Comment", "text": cutRunes(doc.CleanMulti(nt.Text), 2000), "dateCreated": nt.At.UTC().Format(time.RFC3339),
				"author": map[string]any{"@type": "Person", "name": nt.By, "url": doc.Base() + "/a/" + nt.Root}})
		}
	}
	if t.Space != "" {
		d.Fields = append(d.Fields, doc.F{Name: "space", Val: t.Space})
	}
	if t.Ask != "" {
		d.Fields = append(d.Fields, doc.F{Name: "ask", Val: t.Ask, Multi: true})
	}
	if len(t.Hazard) > 0 {
		d.Fields = append(d.Fields, doc.F{Name: "hazard", Val: strings.Join(t.Hazard, ",")})
	}
	d.Fields = append(d.Fields, doc.F{Name: "url", Val: doc.Base() + "/t/" + seg})
	switch {
	case t.Quarantine:
		d.Next = []doc.Action{doc.POST(p+"/ok", "L2 confirm"), doc.POST(p+"/bad", ""), doc.GET("/quarantine", ""), doc.GET("/f/t.atom", "")}
	case t.State == "done":
		d.Next = []doc.Action{doc.GET("/v1/t?s=done", ""), doc.GET("/v1/t", ""), doc.GET("/f/t.atom", "")}
	default:
		d.Next = []doc.Action{doc.POST(p+"/claim", ""), doc.POST(p+"/note", ""), doc.POST(p+"/done", ""), doc.GET("/f/t.atom", "")}
	}
	st, _ := trust.Load(ctx, h.d.DB, t.Root)
	ix := trust.Indexable("task", trust.IndexInput{Author: st, Quarantine: t.Quarantine, Flags: t.Flags, Hazard: t.Hazard, Age: time.Since(t.Created)}) && (t.State == "done" || hasL1)
	d.NoIndex = !ix
	ld := map[string]any{"@context": ldSchema, "@type": "DiscussionForumPosting", "headline": doc.SafeLine(t.Title), "url": doc.Base() + "/t/" + seg,
		"datePublished": t.Created.UTC().Format(time.RFC3339), "commentCount": t.NoteCount, "isAccessibleForFree": true,
		"author":               map[string]any{"@type": "Person", "name": t.ID},
		"interactionStatistic": []map[string]any{{"@type": "InteractionCounter", "interactionType": ldSchema + "/CommentAction", "userInteractionCount": t.NoteCount}}}
	if t.Root != "" {
		ld["author"].(map[string]any)["url"] = doc.Base() + "/a/" + t.Root
	}
	if t.Body != "" {
		ld["text"] = cutRunes(doc.CleanMulti(t.Body), 4000)
	}
	if t.Closed != nil {
		ld["dateModified"] = t.Closed.UTC().Format(time.RFC3339)
	}
	if len(comments) > 0 {
		ld["comment"] = comments
	}
	d.LD = ld
	d.Links = []doc.Link{{Rel: "alternate", Type: "application/atom+xml", Href: "/f/t.atom"}}
	doc.Reply(w, r, 200, d)
}

func firstOf(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

// --- profiles ------------------------------------------------------------------------------------

// fmtK renders 12400 as 12.4k and 1200000 as 1.2M.
func fmtK(n int64) string {
	switch {
	case n >= 1_000_000:
		return strconv.FormatFloat(float64(n)/1_000_000, 'f', 1, 64) + "M"
	case n >= 1000:
		return strconv.FormatFloat(float64(n)/1000, 'f', 1, 64) + "k"
	}
	return strconv.FormatInt(n, 10)
}

// nameOK gates the chosen name (4.9, 8.3): valid, not reserved, lexicon-clean.
func nameOK(name string) bool {
	if !core.ValidName(name) || core.Reserved(name) {
		return false
	}
	score, _, _ := scrub.Flags(name)
	return score == 0
}

// a is GET /a/{id}: the public profile, aggregates only (never IPs or subkeys); the chosen name
// shows only when it passes core.Reserved and the lexicon; ProfileExtraFn lines are appended.
func (h *handlers) a(w http.ResponseWriter, r *http.Request) {
	id, _ := doc.SplitSuffix(r.PathValue("id"))
	if !core.ValidIDPrefix(id, 'a') {
		NotFound(w, r)
		return
	}
	ctx := r.Context()
	var name, family string
	var rep int
	var created time.Time
	var seed, isRoot bool
	var revoked *time.Time
	err := h.d.DB.QueryRow(ctx, `SELECT name, rep, created, family, seed, parent IS NULL, revoked_at FROM identities WHERE id = $1`, id).
		Scan(&name, &rep, &created, &family, &seed, &isRoot, &revoked)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !isRoot) {
		d := doc.Error("notfound", "no agent "+id, doc.GET("/grammar", ""))
		d.Title = "not found · " + host()
		doc.Reply(w, r, 404, d)
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if revoked != nil {
		doc.Reply(w, r, 410, doc.Error("gone", "agent "+id+" revoked", doc.GET("/grammar", "")))
		return
	}
	st, _ := trust.Load(ctx, h.d.DB, id)
	var fixes, confirmed, tasksDone int
	var saved int64
	if err := h.d.DB.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM kb WHERE author_root = $1 AND kind = 'fix' AND NOT hidden AND NOT quarantine AND superseded_by = '' AND expires_at > now()),
		(SELECT count(*) FROM kb_votes v JOIN kb k ON k.id = v.kb_id WHERE k.author_root = $1 AND v.up AND NOT v.seed),
		(SELECT coalesce(sum(v.saved), 0) FROM kb_votes v JOIN kb k ON k.id = v.kb_id WHERE k.author_root = $1 AND v.up),
		(SELECT count(*) FROM tasks t WHERE t.state = 'done' AND (t.root = $1 OR EXISTS (SELECT 1 FROM task_notes tn WHERE tn.n = t.n AND tn.kind = 'done' AND tn.root = $1)))`, id).
		Scan(&fixes, &confirmed, &saved, &tasksDone); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var b strings.Builder
	b.WriteString(id)
	shown := nameOK(name)
	if shown {
		b.WriteString(" " + name)
	}
	fmt.Fprintf(&b, " lvl=L%d rep=%d since=%s fixes=%d confirmed=%d tasks_done=%d saved=%s", st.Level(), rep, core.Date(created), fixes, confirmed, tasksDone, fmtK(saved))
	if family != "" && doc.OneLine(family) {
		b.WriteString(" family~" + cutRunes(family, 24))
	}
	if seed {
		b.WriteString(" seed")
	}
	title := id
	if shown {
		title = name + " (" + id + ")"
	}
	d := &doc.Doc{Head: b.String(), Title: title + " · " + host(), Canonical: "/a/" + id, Budget: 400,
		Desc: fmt.Sprintf("Agent %s on %s: level L%d, %d fixes, %d confirmations received.", id, host(), st.Level(), fixes, confirmed),
		Fields: []doc.F{{Name: "lvl", Val: "L" + strconv.Itoa(st.Level())}, {Name: "rep", Val: strconv.Itoa(rep)}, {Name: "since", Val: core.Date(created)},
			{Name: "fixes", Val: strconv.Itoa(fixes)}, {Name: "confirmed", Val: strconv.Itoa(confirmed)}, {Name: "tasks_done", Val: strconv.Itoa(tasksDone)}, {Name: "saved", Val: strconv.FormatInt(saved, 10)}}}
	for _, fn := range ProfileExtraFn {
		for _, l := range fn(ctx, h.d.DB, id) {
			if l = strings.TrimSpace(doc.SafeLine(l)); l != "" {
				d.Rows = append(d.Rows, []string{l})
			}
		}
	}
	d.Next = []doc.Action{doc.GET("/f/a/"+id+".atom", ""), doc.GET("/b/a/"+id+".svg", ""), doc.GET("/v1/rep/"+id, "")}
	d.NoIndex = !trust.Indexable("profile", trust.IndexInput{Author: st, Seed: st.Seed, Age: st.Age})
	person := map[string]any{"@type": "Person", "identifier": id, "url": doc.Base() + "/a/" + id}
	if shown {
		person["name"] = name
	}
	d.LD = map[string]any{"@context": ldSchema, "@type": "ProfilePage", "url": doc.Base() + "/a/" + id, "dateCreated": created.UTC().Format(time.RFC3339), "mainEntity": person}
	doc.Reply(w, r, 200, d)
}

// --- resolver ------------------------------------------------------------------------------------

// x is GET /x/{id}: the universal resolver through the registered prefix resolvers (8.3).
func (h *handlers) x(w http.ResponseWriter, r *http.Request) {
	id, _ := doc.SplitSuffix(r.PathValue("id"))
	if !core.ValidID(id) && !taskRe.MatchString(id) && !hashRe.MatchString(id) {
		doc.Fail(w, r, core.Bad("id must be a 7-char id, t:<n> or a 64-hex hash"))
		return
	}
	typ, title, u, ok := h.d.Resolve(r.Context(), id)
	if !ok || typ == "" || u == "" {
		d := doc.Error("notfound", "no object "+id, doc.GET("/grammar", ""), doc.GET("/q/"+esc(id), ""))
		d.Title = "not found · " + host()
		doc.Reply(w, r, 404, d)
		return
	}
	title = doc.SafeLine(title)
	d := &doc.Doc{Head: typ + " " + title + " " + u, Title: title + " · " + host(), NoIndex: true, MaxAge: 300,
		Fields: []doc.F{{Name: "type", Val: typ}, {Name: "title", Val: title}, {Name: "url", Val: u}},
		Next:   []doc.Action{doc.GET(relPath(u), "")}}
	doc.Reply(w, r, 200, d)
}

// --- tag hubs ------------------------------------------------------------------------------------

// tag is GET /tag/{t}: the latest 50 indexable entries of a tag (CollectionPage + feed link);
// aliases answer 301 to the canonical tag through TagCanonFn.
func (h *handlers) tag(w http.ResponseWriter, r *http.Request) {
	t, f := doc.SplitSuffix(r.PathValue("t"))
	t = strings.ToLower(t)
	if !tagRe.MatchString(t) {
		NotFound(w, r)
		return
	}
	if TagCanonFn != nil {
		if c, ok := TagCanonFn(t); ok && c != t && tagRe.MatchString(c) {
			h.redirect(w, r, "/tag/"+c, f)
			return
		}
	}
	f, done := canonFormat(w, r, f)
	if done {
		return
	}
	ctx := r.Context()
	es, _, err := kb.Latest(ctx, h.d.DB, kb.LatestOpts{Tag: t, N: 50, IndexableOnly: true})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if len(es) == 0 {
		d := doc.Error("notfound", "no entries tagged "+t, doc.GET("/q/"+esc(t), ""), doc.POST("/v1/kb", "tags="+t))
		d.Title = "not found · " + host()
		doc.ReplyAs(w, r, 404, d, f)
		return
	}
	d := &doc.Doc{Head: fmt.Sprintf("tag: %s n=%d", t, len(es)), Title: "tag: " + t + " · " + host(), Canonical: "/tag/" + t, Budget: 400,
		Desc: fmt.Sprintf("The %d latest confirmed fixes tagged %s, written and confirmed by AI agents.", len(es), t), Cols: []string{"id", "ok", "date", "title"}}
	var items []map[string]any
	var mod time.Time
	for i, e := range es {
		d.Rows = append(d.Rows, []string{e.ID, "ok" + strconv.FormatFloat(float64(e.OkW), 'g', -1, 32), core.Date(e.Created), e.Title})
		items = append(items, map[string]any{"@type": "ListItem", "position": i + 1, "url": doc.Base() + "/kb/" + e.ID, "name": doc.SafeLine(e.Title)})
		if m := modifiedAt(e); m.After(mod) {
			mod = m
		}
	}
	d.LD = map[string]any{"@context": ldSchema, "@type": "CollectionPage", "name": "tag: " + t, "url": doc.Base() + "/tag/" + t, "isAccessibleForFree": true,
		"dateModified": mod.UTC().Format(time.RFC3339), "mainEntity": map[string]any{"@type": "ItemList", "numberOfItems": len(es), "itemListElement": items}}
	d.Links = []doc.Link{{Rel: "alternate", Type: "application/atom+xml", Href: "/f/kb/" + t + ".atom"}}
	d.Next = []doc.Action{doc.GET("/f/kb/"+t+".atom", ""), doc.GET("/q/"+esc(t), ""), doc.POST("/v1/kb", "tags="+t)}
	w.Header().Set("Last-Modified", mod.UTC().Format(http.TimeFormat))
	doc.ReplyAs(w, r, 200, d, f)
}

// round is the JSON-LD upvoteCount of a weight.
func round(w float32) int { return int(math.Round(float64(w))) }
