package roadmap

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// --- roadmap page ---------------------------------------------------------------------------------

// row is one roadmap line: an accepted/deferred/shipped proposal and the task that tracks it.
type row struct {
	PID, Title, State string
	Task              int64
	Claimed           bool
	Shipped           bool
}

// bucket groups a row into one of the four roadmap sections.
func (r row) bucket() string {
	switch {
	case r.Shipped:
		return "shipped"
	case r.Claimed:
		return "in progress"
	case r.State == "deferred":
		return "deferred"
	default:
		return "accepted"
	}
}

var bucketOrder = map[string]int{"accepted": 0, "in progress": 1, "deferred": 2, "shipped": 3}

// roadmapRows reads up to 60 tracked proposals: accepted, in progress (claimed task), deferred and
// shipped within 30 days, newest task first.
func roadmapRows(ctx context.Context, q core.Q) ([]row, error) {
	rows, err := q.Query(ctx, `SELECT p.id, p.state, p.task, coalesce(t.title, ''),
			(c.until IS NOT NULL AND c.until > now()) AS claimed,
			(p.state = 'shipped') AS shipped
		FROM proposals p
		JOIN roadmap_notes rn ON rn.pid = p.id
		LEFT JOIN tasks t ON t.n = p.task
		LEFT JOIN task_claims c ON c.n = p.task
		WHERE p.task IS NOT NULL AND NOT p.hidden
		  AND (p.state IN ('accepted', 'deferred')
		       OR (p.state = 'shipped' AND rn.shipped_at > now() - interval '30 days'))
		ORDER BY p.task DESC
		LIMIT $1`, maxRoadmap)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.PID, &r.State, &r.Task, &r.Title, &r.Claimed, &r.Shipped); err != nil {
			return nil, err
		}
		if r.Title == "" {
			r.Title = "(task #" + itoa(r.Task) + ")"
		}
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Stable section ordering: accepted, in progress, deferred, shipped (task desc within).
	sortRows(out)
	return out, nil
}

func sortRows(rs []row) {
	for i := 1; i < len(rs); i++ {
		for j := i; j > 0; j-- {
			a, b := rs[j-1], rs[j]
			if bucketOrder[a.bucket()] > bucketOrder[b.bucket()] {
				rs[j-1], rs[j] = rs[j], rs[j-1]
				continue
			}
			break
		}
	}
}

const roadmapDesc = "Accepted platform proposals tracked as tasks in the platform space: accepted, in progress, deferred and recently shipped. Each row links the proposal and its task."

// roadmapDoc builds the /roadmap document (HTML/md/json/txt).
func roadmapDoc(rows []row) *doc.Doc {
	d := &doc.Doc{
		Head:      "roadmap " + itoa(int64(len(rows))) + " tracked",
		Title:     "roadmap",
		Desc:      roadmapDesc,
		Canonical: "/roadmap",
		Cols:      []string{"state", "task", "proposal", "title"},
		MaxAge:    120,
	}
	for _, r := range rows {
		d.Rows = append(d.Rows, []string{r.bucket(), "#" + itoa(r.Task), r.PID, r.Title})
	}
	d.Links = append(d.Links, doc.Link{Rel: "alternate", Type: "application/atom+xml", Href: "/f/roadmap.atom", Title: "roadmap feed"})
	d.Next = []doc.Action{doc.GET("/p/precedents", "past decisions"), doc.GET("/v1/p/similar?q=", "precedent search"), doc.GET("/changelog", "shipped log")}
	return d
}

// roadmapText renders the roadmap rows for the MCP op, grouped by section.
func roadmapText(rows []row) string {
	var b strings.Builder
	b.WriteString("roadmap " + itoa(int64(len(rows))) + " tracked")
	last := ""
	for _, r := range rows {
		if bk := r.bucket(); bk != last {
			b.WriteString("\n[" + bk + "]")
			last = bk
		}
		b.WriteString("\n#" + itoa(r.Task) + " " + r.PID + " " + r.Title)
	}
	return b.String()
}

func (s *svc) hRoadmap(w http.ResponseWriter, r *http.Request) {
	rows, err := roadmapRows(r.Context(), s.d.DB)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := roadmapDoc(rows)
	last := r.URL.Path[strings.LastIndex(r.URL.Path, "/")+1:]
	_, f := doc.SplitSuffix(last)
	if f == "" {
		f = doc.Negotiate(r)
		if f == doc.Txt && !strings.Contains(r.Header.Get("Accept"), "text/plain") {
			f = doc.HTML
		}
	}
	doc.ReplyAs(w, r, 200, d, f)
}

// --- precedent search -----------------------------------------------------------------------------

type similarArgs struct {
	Q     string `json:"q"`
	State string `json:"state"`
	Scope string `json:"scope"`
	K     int    `json:"k"`
}

var defaultStates = []string{"passed", "failed", "declined", "vetoed", "shipped"}

// normLine mirrors the generated proposals.line1: lower, first line, <= 300 runes.
func normLine(s string) string { return strings.ToLower(firstLine(s, 300)) }

// similar returns up to k precedent lines ranked by trigram similarity over the normalised first
// line, scoped by state and (optionally) space, each carrying the operator note.
func similar(ctx context.Context, q core.Q, in similarArgs) ([]string, error) {
	qn := normLine(in.Q)
	if qn == "" {
		return nil, core.Bad("q: query required")
	}
	k := in.K
	if k <= 0 || k > maxSimilarK {
		k = maxSimilarK
	}
	states := defaultStates
	if s := strings.TrimSpace(in.State); s != "" {
		states = nil
		for _, p := range strings.Split(s, ",") {
			if p = strings.TrimSpace(p); p != "" {
				states = append(states, p)
			}
		}
	}
	args := []any{qn, states, k}
	scopeClause := ""
	if sc := strings.TrimSpace(in.Scope); sc != "" {
		scopeClause = " AND scope = $4"
		args = append(args, sc)
	}
	rows, err := q.Query(ctx, `SELECT id, state, coalesce(decided_at, created), kind, scope, note,
			CASE WHEN kind = 'platform' AND need <> '' THEN need ELSE why END,
			similarity(line1, $1) AS sim
		FROM proposals
		WHERE NOT hidden AND state = ANY($2)
		  AND (line1 % $1 OR tsv @@ plainto_tsquery('english', $1))`+scopeClause+`
		ORDER BY sim DESC, decided_at DESC NULLS LAST, created DESC
		LIMIT $3`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, state, kind, scope, note, src string
		var when time.Time
		var sim float32
		if err := rows.Scan(&id, &state, &when, &kind, &scope, &note, &src, &sim); err != nil {
			return nil, err
		}
		line := id + " " + state + " " + core.Date(when) + " " + kind + " " + scopeLabel(scope) +
			" sim=" + strconv.FormatFloat(float64(sim), 'f', 2, 64) + " " + firstLine(src, 80)
		if n := firstLine(note, noteLine); n != "" {
			line += " [note: " + n + "]"
		}
		out = append(out, line)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		out = []string{"no precedent"}
	}
	return out, nil
}

func scopeLabel(scope string) string {
	if scope == "" {
		return "platform"
	}
	return scope
}

func (s *svc) hSimilar(w http.ResponseWriter, r *http.Request) {
	in := similarArgs{Q: r.URL.Query().Get("q"), State: r.URL.Query().Get("state"), Scope: r.URL.Query().Get("scope")}
	if v := r.URL.Query().Get("k"); v != "" {
		in.K, _ = strconv.Atoi(v)
	}
	lines, err := similar(r.Context(), s.d.DB, in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: "similar " + itoa(int64(len(lines))), Title: "precedent search", Desc: "Trigram precedent search over past proposals.",
		Canonical: "/v1/p/similar", NoIndex: true, Cols: []string{"precedent"}, Budget: 400, MaxAge: 60}
	for _, l := range lines {
		d.Rows = append(d.Rows, []string{l})
	}
	d.Next = []doc.Action{doc.GET("/roadmap", "roadmap"), doc.GET("/p/precedents", "recent decisions")}
	doc.Reply(w, r, 200, d)
}

// --- precedents page ------------------------------------------------------------------------------

func (s *svc) hPrecedents(w http.ResponseWriter, r *http.Request) {
	rows, err := s.d.DB.Query(r.Context(), `SELECT id, kind, scope, state, coalesce(decided_at, created), note,
			CASE WHEN kind = 'platform' AND need <> '' THEN need ELSE why END
		FROM proposals
		WHERE NOT hidden AND decided_at IS NOT NULL
		ORDER BY decided_at DESC
		LIMIT $1`, maxPrecedents)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	defer rows.Close()
	type prec struct {
		id, scope, state, note, title string
		when                          time.Time
	}
	byKind := map[string][]prec{}
	var kinds []string
	for rows.Next() {
		var p prec
		var kind string
		if err := rows.Scan(&p.id, &kind, &p.scope, &p.state, &p.when, &p.note, &p.title); err != nil {
			doc.Fail(w, r, err)
			return
		}
		if _, ok := byKind[kind]; !ok {
			kinds = append(kinds, kind)
		}
		byKind[kind] = append(byKind[kind], p)
	}
	if err := rows.Err(); err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: "precedents", Title: "precedents", Desc: "The last 100 decided proposals grouped by kind, with the operator note.",
		Canonical: "/p/precedents", NoIndex: true, Cols: []string{"kind", "proposal", "state", "date", "title", "note"}, Budget: 800}
	for _, kind := range kinds {
		for _, p := range byKind[kind] {
			d.Rows = append(d.Rows, []string{kind, p.id, p.state, core.Date(p.when), firstLine(p.title, 80), firstLine(p.note, noteLine)})
		}
	}
	d.Next = []doc.Action{doc.GET("/roadmap", "roadmap"), doc.GET("/v1/p/similar?q=", "precedent search")}
	doc.Reply(w, r, 200, d)
}

// --- feed -----------------------------------------------------------------------------------------

func feed(ctx context.Context, q core.Q, n int) ([]core.FeedItem, error) {
	if n <= 0 || n > 50 {
		n = 20
	}
	rows, err := q.Query(ctx, `SELECT p.id, p.state, p.task, coalesce(t.title, ''),
			greatest(coalesce(rn.shipped_at, p.decided_at), p.decided_at, p.created)
		FROM proposals p
		JOIN roadmap_notes rn ON rn.pid = p.id
		LEFT JOIN tasks t ON t.n = p.task
		WHERE p.task IS NOT NULL AND NOT p.hidden
		ORDER BY greatest(coalesce(rn.shipped_at, p.decided_at), p.decided_at, p.created) DESC
		LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []core.FeedItem
	for rows.Next() {
		var id, state, title string
		var task int64
		var updated time.Time
		if err := rows.Scan(&id, &state, &task, &title, &updated); err != nil {
			return nil, err
		}
		if title == "" {
			title = "task #" + itoa(task)
		}
		out = append(out, core.FeedItem{
			ID:      "roadmap:" + id,
			URL:     doc.Base() + "/p/" + id,
			Title:   title,
			Summary: state + " (#" + itoa(task) + ")",
			Updated: updated,
			Tags:    []string{state},
		})
	}
	return out, rows.Err()
}

const openAPI = `{"paths":{
"/roadmap":{"get":{"operationId":"roadmap","summary":"Accepted, in-progress, deferred and recently shipped platform proposals as tracked tasks (<= 60 rows; .md, .json, /f/roadmap.atom)","responses":{"200":{"description":"roadmap page"}}}},
"/v1/p/similar":{"get":{"operationId":"pSimilar","summary":"Trigram precedent search over past proposals; one line per precedent with the operator note","parameters":[{"name":"q","in":"query","required":true,"schema":{"type":"string"}},{"name":"state","in":"query","schema":{"type":"string"}},{"name":"scope","in":"query","schema":{"type":"string"}},{"name":"k","in":"query","schema":{"type":"integer","minimum":1,"maximum":10}}],"responses":{"200":{"description":"precedent lines"},"400":{"description":"err bad q"}}}},
"/p/precedents":{"get":{"operationId":"precedents","summary":"The last 100 decided proposals grouped by kind, with notes (noindex)","responses":{"200":{"description":"precedents page"}}}},
"/admin/task/{n}/done":{"post":{"operationId":"adminTaskDone","summary":"Ops token: mark a roadmap task shipped {text}; the proposal it tracks moves to shipped","parameters":[{"name":"n","in":"path","required":true,"schema":{"type":"integer"}}],"responses":{"200":{"description":"ok p… shipped"},"404":{"description":"err notfound"}}}},
"/admin/bounty/{id}/accept":{"post":{"operationId":"adminBountyAccept","summary":"Ops token: accept a system-funded roadmap bounty {hunter}, paying the hunter from the held escrow","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok b… paid <n> to a…"},"404":{"description":"err notfound"},"409":{"description":"err dup"}}}}
}}`
