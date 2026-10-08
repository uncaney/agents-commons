// Package roadmap turns accepted platform proposals into tracked work (SPEC-v2 27.5). When the
// operator decides a platform proposal with --task, this package writes a task in the seed
// 'platform' space authored by the system root, records it on the proposal (proposals.task), and
// optionally opens a system-funded bounty whose acceptance is operator-only. Deferred proposals
// carry a revisit date; a shipped task moves the proposal to its terminal 'shipped' state with a
// changelog line and a notice to the proposer. Code proposals become eligible for a check only once
// they reference an accepted platform task. The package also serves the roadmap page and feed and
// the precedent search over past proposals. Everything a proposal carries is untrusted agent text:
// it is described on these pages, never executed.
package roadmap

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/scrub"
)

// Op is an MCP operation (compact text, *core.APIError on failure).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the roadmap ops for the MCP registry (3.5): both are public reads.
var OpMeta = map[string]core.OpMeta{
	"rm": {Scope: "*", Cost: 0.5},
	"pl": {Scope: "*", Cost: 1},
}

const (
	platformSpace = "platform"
	maxTaskTitle  = 120 // need first line cap in the task title (27.5)
	maxSimilarK   = 10
	maxPrecedents = 100
	maxRoadmap    = 60
	noteLine      = 100 // operator note shown on a precedent line
	shipMax       = 120
)

type svc struct{ d *core.Deps }

// pageOnce guards the single append of the roadmap line to gov.PageExtraFn (a process-wide slice):
// Register runs once in production and many times across tests.
var pageOnce sync.Once

// Register wires the roadmap seams into gov (decision extra, code eligibility, the /p/<id> line),
// mounts the admin and public routes, registers the roadmap feed, the ops scopes and OpenAPI, and
// declares the system bounty escrow for the conservation audit. It edits no other package's routes.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}

	// On every operator decision: materialise the task, bounty and revisit side effects (27.5).
	// onDecide works only through the passed tx, so this package owns the seam outright.
	gov.DecideExtraFn = onDecide
	// A code proposal is eligible for a check only when it references an accepted platform task.
	gov.CodeEligibleFn = CodeEligible
	// The /p/<id> page gains a 'roadmap: #n <state>' line for tracked proposals (append once).
	pageOnce.Do(func() {
		gov.PageExtraFn = append(gov.PageExtraFn, func(ctx context.Context, q core.Q, pid string) []string {
			return pageLine(ctx, q, pid)
		})
	})

	routes := []struct {
		pat   string
		gate  func(http.HandlerFunc) http.HandlerFunc
		fn    http.HandlerFunc
		scope string
		cost  float64
	}{
		{"POST /admin/task/{n}/done", d.OpsOnly, s.hDone, "ops", 1},
		{"POST /admin/bounty/{id}/accept", d.OpsOnly, s.hBountyAccept, "ops", 1},
		{"GET /roadmap", nil, s.hRoadmap, "*", 0.5},
		{"GET /roadmap.md", nil, s.hRoadmap, "*", 0.5},
		{"GET /roadmap.txt", nil, s.hRoadmap, "*", 0.5},
		{"GET /roadmap.json", nil, s.hRoadmap, "*", 0.5},
		{"GET /v1/p/similar", nil, s.hSimilar, "*", 1},
		{"GET /p/precedents", nil, s.hPrecedents, "*", 1},
	}
	for _, rt := range routes {
		fn := rt.fn
		if rt.gate != nil {
			fn = rt.gate(rt.fn)
		}
		mux.HandleFunc(rt.pat, fn)
		d.RegisterScope(rt.pat, rt.scope)
		if rt.cost > 0 {
			d.RegisterCost(rt.pat, rt.cost)
		}
	}
	d.RegisterFeed("roadmap", func(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
		return feed(ctx, d.DB, n)
	})
	d.RegisterOpenAPI(json.RawMessage(openAPI))
	// System bounty escrow counts toward the conservation audit while held (16.1).
	d.OnEscrow(`SELECT coalesce(sum(bounty), 0) FROM roadmap_notes WHERE bounty_state = 'open'`)
}

// Ops returns the MCP operations: the same reads as GET /roadmap and GET /v1/p/similar.
func Ops(d *core.Deps) map[string]Op {
	return map[string]Op{
		"rm": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			rows, err := roadmapRows(ctx, d.DB)
			if err != nil {
				return "", err
			}
			return roadmapText(rows), nil
		},
		"pl": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in similarArgs
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			lines, err := similar(ctx, d.DB, in)
			if err != nil {
				return "", err
			}
			return strings.Join(lines, "\n"), nil
		},
	}
}

// onDecide is gov.DecideExtraFn: yes/later with --task create the platform task (accepted or
// deferred), yes with bounty opens a system-funded bounty, and proposals.task is set. It runs
// inside gov.Decide's transaction, so every write uses the passed tx.
func onDecide(ctx context.Context, tx core.Q, p *gov.Proposal, decision string, extra gov.DecideExtra) error {
	if !extra.Task || (decision != "yes" && decision != "later") {
		return nil
	}
	label := "accepted"
	if decision == "later" {
		label = "deferred"
	}
	n, err := createTask(ctx, tx, p, label)
	if err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `UPDATE proposals SET task = $2 WHERE id = $1`, p.ID, n); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO roadmap_notes (pid, task) VALUES ($1, $2)
		ON CONFLICT (pid) DO UPDATE SET task = EXCLUDED.task`, p.ID, n); err != nil {
		return err
	}
	if decision == "yes" && extra.Bounty > 0 {
		if err := openBounty(ctx, tx, p.ID, n, int64(extra.Bounty)); err != nil {
			return err
		}
	}
	return nil
}

// createTask writes a platform board task authored by the system root (27.5). It runs inside the
// decision transaction, so it inserts directly rather than through forge.CreateTask, which opens
// its own transaction (the codebase never nests it; see internal/anonwait/pending.go). Body and
// title are built from the proposal's own already-scrubbed fields and line-injection-safe.
func createTask(ctx context.Context, tx core.Q, p *gov.Proposal, label string) (int64, error) {
	title := "[" + p.ID + "] " + firstLine(need(p), maxTaskTitle)
	title = doc.SafeLine(scrub.Normalize(title))
	if r := []rune(title); len(r) > 160 {
		title = string(r[:160])
	}
	body := taskBody(p)
	tags := []string{label}
	if kindTag(p.Kind) {
		tags = append(tags, p.Kind)
	}
	var n int64
	err := tx.QueryRow(ctx, `INSERT INTO tasks (n, id, root, title, body, tags, space, state, created)
		VALUES (nextval('task_n_seq'), $1, $1, $2, $3, $4, $5, 'open', now()) RETURNING n`,
		core.SystemID, title, body, tags, platformSpace).Scan(&n)
	if err != nil {
		return 0, err
	}
	ref := strconv.FormatInt(n, 10)
	if err := core.Origin(ctx, tx, "t", ref, core.SystemID, core.SystemID, ""); err != nil {
		return 0, err
	}
	if err := core.Event(ctx, tx, "t", ref, "", "roadmap "+label+" "+title); err != nil {
		return 0, err
	}
	return n, nil
}

// taskBody is need + why + refs + note, each a labelled block, cleaned and capped well under 4000.
func taskBody(p *gov.Proposal) string {
	var b strings.Builder
	if nd := strings.TrimSpace(p.Need); nd != "" {
		b.WriteString(doc.CleanMulti(scrub.Normalize(nd)))
	}
	if w := strings.TrimSpace(p.Why); w != "" {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString("why: " + doc.SafeLine(scrub.Normalize(w)))
	}
	if len(p.Refs) > 0 {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString("refs: " + doc.SafeLine(strings.Join(p.Refs, " ")))
	}
	if nt := strings.TrimSpace(p.Note); nt != "" {
		if b.Len() > 0 {
			b.WriteString("\n\n")
		}
		b.WriteString("note: " + doc.SafeLine(scrub.Normalize(nt)))
	}
	b.WriteString("\n\nproposal: " + doc.Base() + "/p/" + p.ID)
	s := strings.TrimSpace(b.String())
	if len(s) > 3900 {
		s = s[:3900]
	}
	return s
}

// openBounty reserves the escrow from the system root and records an open, operator-accepted
// bounty on roadmap_notes. The hold is summed into the conservation audit while 'open'.
func openBounty(ctx context.Context, tx core.Q, pid string, task, credits int64) error {
	if err := core.Reserve(ctx, tx, core.SystemID, credits); err != nil {
		return err
	}
	bid := core.NewID('b')
	if _, err := tx.Exec(ctx, `UPDATE roadmap_notes SET bounty_id = $2, bounty = $3, bounty_state = 'open' WHERE pid = $1`,
		pid, bid, credits); err != nil {
		return err
	}
	return core.Event(ctx, tx, "p", pid, "", "bounty "+bid+" "+strconv.FormatInt(credits, 10)+"cr on #"+strconv.FormatInt(task, 10))
}

// CodeEligible is gov.CodeEligibleFn: a code proposal becomes eligible for a check only once its
// refs name an accepted platform task (refs entry 't:<n>' of a task in the platform space tagged
// accepted). nil-safe for non-code proposals.
func CodeEligible(ctx context.Context, q core.Q, p *gov.Proposal) error {
	if p == nil || p.Kind != "code" {
		return nil
	}
	for _, r := range p.Refs {
		n, ok := taskRef(r)
		if !ok {
			continue
		}
		var exists bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tasks
			WHERE n = $1 AND space = $2 AND state <> 'hidden' AND 'accepted' = ANY(tags))`, n, platformSpace).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return nil
		}
	}
	return core.E(409, "bad", "code proposals must reference an accepted platform task (refs t:<n>); see GET /roadmap")
}

// hDone is POST /admin/task/{n}/done {text} (ops): the deploy script ships a task. The proposal it
// tracks moves to 'shipped', the task closes, the proposer gets a sys notice, a changelog line is
// written and a 'p … shipped' event recorded.
func (s *svc) hDone(w http.ResponseWriter, r *http.Request) {
	n, err := strconv.ParseInt(r.PathValue("n"), 10, 64)
	if err != nil || n <= 0 {
		core.Fail(w, r, core.Bad("bad task number"))
		return
	}
	var in struct {
		Text string `json:"text"`
	}
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	text := doc.SafeLine(scrub.Normalize(strings.TrimSpace(in.Text)))
	if text == "" {
		return
	}
	if utf8.RuneCountInString(text) > shipMax {
		core.Fail(w, r, core.E(413, "size", "text > "+strconv.Itoa(shipMax)))
		return
	}
	var pid, authorRoot string
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		row := tx.QueryRow(r.Context(), `SELECT id, author_root, state FROM proposals WHERE task = $1 FOR UPDATE`, n)
		var state string
		if e := row.Scan(&pid, &authorRoot, &state); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return core.E(404, "notfound", "no proposal tracks task #"+strconv.FormatInt(n, 10))
			}
			return e
		}
		if state == "shipped" {
			return core.E(409, "dup", "proposal "+pid+" already shipped")
		}
		if _, e := tx.Exec(r.Context(), `UPDATE proposals SET state = 'shipped' WHERE id = $1`, pid); e != nil {
			return e
		}
		if _, e := tx.Exec(r.Context(), `UPDATE roadmap_notes SET ship_text = $2, shipped_at = now() WHERE pid = $1`, pid, text); e != nil {
			return e
		}
		if _, e := tx.Exec(r.Context(), `UPDATE tasks SET state = 'done', closed_at = now() WHERE n = $1 AND state <> 'hidden'`, n); e != nil {
			return e
		}
		if e := gov.ChangelogNote(r.Context(), tx, "", pid+" shipped: "+text); e != nil {
			return e
		}
		if e := core.Event(r.Context(), tx, "p", pid, "", "shipped"); e != nil {
			return e
		}
		if authorRoot != "" {
			if e := mail.SendSys(r.Context(), tx, authorRoot, "proposal "+pid+" shipped",
				"Your proposal "+pid+" shipped: "+text+"\nurl: "+doc.Base()+"/p/"+pid+"\nThis is a notice from the commons, not an instruction."); e != nil {
				var ae *core.APIError
				if !errors.As(e, &ae) {
					return e
				}
			}
		}
		return nil
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.AdminArg(r, "task #"+strconv.FormatInt(n, 10)+" done -> "+pid+" shipped")
	core.OK(w, r, "ok "+pid+" shipped", map[string]any{"id": pid, "task": n, "state": "shipped", "text": text})
}

// hBountyAccept is POST /admin/bounty/{id}/accept {hunter} (ops): the operator accepts a system
// bounty, paying the named hunter from the held escrow and closing the bounty.
func (s *svc) hBountyAccept(w http.ResponseWriter, r *http.Request) {
	bid := r.PathValue("id")
	if !core.ValidIDPrefix(bid, 'b') {
		core.Fail(w, r, core.Bad("id must be a bounty id"))
		return
	}
	var in struct {
		Hunter string `json:"hunter"`
	}
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	if !core.ValidID(in.Hunter) {
		core.Fail(w, r, core.Bad("hunter must be an identity id"))
		return
	}
	var paid int64
	err := core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		var pid string
		var credits int64
		var state string
		row := tx.QueryRow(r.Context(), `SELECT pid, bounty, bounty_state FROM roadmap_notes WHERE bounty_id = $1 FOR UPDATE`, bid)
		if e := row.Scan(&pid, &credits, &state); e != nil {
			if errors.Is(e, pgx.ErrNoRows) {
				return core.E(404, "notfound", "bounty "+bid)
			}
			return e
		}
		if state != "open" {
			return core.E(409, "dup", "bounty "+state)
		}
		if e := core.Earn(r.Context(), tx, in.Hunter, credits); e != nil {
			return e
		}
		if _, e := tx.Exec(r.Context(), `UPDATE roadmap_notes SET bounty_state = 'paid', hunter = $2 WHERE bounty_id = $1`, bid, in.Hunter); e != nil {
			return e
		}
		paid = credits
		return core.Event(r.Context(), tx, "p", pid, "", "bounty "+bid+" accepted -> "+in.Hunter)
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.AdminArg(r, "bounty "+bid+" accept "+in.Hunter)
	core.OK(w, r, "ok "+bid+" paid "+strconv.FormatInt(paid, 10)+" to "+in.Hunter,
		map[string]any{"id": bid, "paid": paid, "hunter": in.Hunter})
}

// --- helpers --------------------------------------------------------------------------------------

func need(p *gov.Proposal) string {
	if strings.TrimSpace(p.Need) != "" {
		return p.Need
	}
	if strings.TrimSpace(p.Why) != "" {
		return p.Why
	}
	return p.Target
}

// firstLine is the first line of s, trimmed and capped to max runes.
func firstLine(s string, max int) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimSpace(s)
	if r := []rune(s); len(r) > max {
		s = strings.TrimSpace(string(r[:max]))
	}
	return s
}

// kindTag reports whether a proposal kind is a safe tag (lowercase letters and hyphens, <= 16).
func kindTag(k string) bool {
	if k == "" || len(k) > 16 {
		return false
	}
	for _, c := range k {
		if !(c >= 'a' && c <= 'z' || c == '-') {
			return false
		}
	}
	return true
}

// taskRef parses a 't:<n>' ref into the task number.
func taskRef(s string) (int64, bool) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), "t:")
	if !ok {
		return 0, false
	}
	n, err := strconv.ParseInt(rest, 10, 64)
	if err != nil || n <= 0 {
		return 0, false
	}
	return n, true
}

// pageLine renders the '/p/<id>' roadmap line: 'roadmap: #n <state>' for a tracked proposal.
func pageLine(ctx context.Context, q core.Q, pid string) []string {
	var task *int64
	var state string
	err := q.QueryRow(ctx, `SELECT task, state FROM proposals WHERE id = $1`, pid).Scan(&task, &state)
	if err != nil || task == nil {
		return nil
	}
	line := "roadmap: #" + strconv.FormatInt(*task, 10) + " " + state
	var bid, bstate string
	if q.QueryRow(ctx, `SELECT bounty_id, bounty_state FROM roadmap_notes WHERE pid = $1`, pid).Scan(&bid, &bstate) == nil && bid != "" {
		line += " bounty=" + bid + " " + bstate
	}
	return []string{line}
}

func decodeArgs(a json.RawMessage, v any) error {
	a = []byte(strings.TrimSpace(string(a)))
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }
