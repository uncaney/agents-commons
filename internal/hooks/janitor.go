package hooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/export"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/spaces"
)

// callFn runs a bound service through the catalog/compute path. It defaults to catalog.Call and is a
// package var only so tests can supply a verdict without standing up a compute worker; production
// never rebinds it, and this package still imports no wasm runtime (invariant).
var callFn = catalog.Call

// systemIdent is the system root as the caller of hook and cron jobs (the treasury funds it through
// FundFn; it owns the seed modules, so their calls are feeless).
func systemIdent() *core.Ident {
	return &core.Ident{ID: core.SystemID, Root: core.SystemID, Name: "system", Created: time.Unix(0, 0), Credits: 1 << 62}
}

// runCost is the treasury charge for one service run, the compute reservation of an ms_hint job.
func runCost(msHint int) int64 {
	if msHint <= 0 {
		msHint = 1000
	}
	return int64((msHint+999)/1000) * 3
}

// --- hooks janitor -------------------------------------------------------------------------------

// hookedRow is one not-yet-checked write of a hooked space.
type hookedRow struct {
	kind, ref string // the hook kind (task|kb|doc) and the row identifier
	docName   string // the doc name (doc kind only; ref is DocRef(space,name,rev) so each revision is checked once, globally unique)
	title     string
	body      string // task body (task), or ""
	symptom   string
	cause     string
	fix       string
	versions  string
	tags      []string
	root      string // author root ('' for anonymous)
	space     string
	svc       string
	onlyBelow *int
}

// RunHooks is the hooks janitor: for every new write of a hooked space it claims a hook_runs row,
// applies the only_below bypass and the daily cap, builds the input view, funds the run and reads
// the service verdict, then records ok / warn / rejected / unchecked. Failures of one row never
// abort the sweep (fail open).
func (s *svc) RunHooks(ctx context.Context) error {
	rows, err := s.pending(ctx)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := s.runHook(ctx, r); err != nil {
			s.d.Log.Warn("hook run", "space", r.space, "kind", r.kind, "ref", r.ref, "err", err)
		}
	}
	return nil
}

// pending collects the unchecked writes of hooked spaces (tasks, kb entries, doc revisions created
// at or after the binding took effect), newest last, capped per sweep.
func (s *svc) pending(ctx context.Context) ([]hookedRow, error) {
	const lim = 200
	var out []hookedRow
	// Tasks.
	tq := `SELECT t.n::text, t.title, t.body, t.tags, t.root, t.space, h.svc, h.only_below
		FROM tasks t JOIN space_hooks h ON h.space = t.space AND h.kind = 'task'
		WHERE t.state = 'open' AND t.created >= h.created
		  AND NOT EXISTS (SELECT 1 FROM hook_runs r WHERE r.kind = 'task' AND r.ref = t.n::text)
		ORDER BY t.created LIMIT $1`
	trows, err := s.d.DB.Query(ctx, tq, lim)
	if err != nil {
		return nil, err
	}
	for trows.Next() {
		r := hookedRow{kind: "task"}
		if err := trows.Scan(&r.ref, &r.title, &r.body, &r.tags, &r.root, &r.space, &r.svc, &r.onlyBelow); err != nil {
			trows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	trows.Close()
	if err := trows.Err(); err != nil {
		return nil, err
	}
	// KB entries.
	kq := `SELECT k.id, k.title, k.symptom, k.cause, k.fix, k.versions, k.tags, k.author_root, k.space, h.svc, h.only_below
		FROM kb k JOIN space_hooks h ON h.space = k.space AND h.kind = 'kb'
		WHERE NOT k.hidden AND NOT k.quarantine AND k.created >= h.created
		  AND NOT EXISTS (SELECT 1 FROM hook_runs r WHERE r.kind = 'kb' AND r.ref = k.id)
		ORDER BY k.created LIMIT $1`
	krows, err := s.d.DB.Query(ctx, kq, lim)
	if err != nil {
		return nil, err
	}
	for krows.Next() {
		r := hookedRow{kind: "kb"}
		if err := krows.Scan(&r.ref, &r.title, &r.symptom, &r.cause, &r.fix, &r.versions, &r.tags, &r.root, &r.space, &r.svc, &r.onlyBelow); err != nil {
			krows.Close()
			return nil, err
		}
		out = append(out, r)
	}
	krows.Close()
	if err := krows.Err(); err != nil {
		return nil, err
	}
	// Doc revisions. Each member revision (ref name@rev) of a hooked space is checked once; service
	// writes (crons author svc:<name>@<ver>) are left alone, as are already-hidden docs. A doc write
	// lands in internal/spaces (PutDoc.writeRev); no enqueue call is needed because this janitor
	// scans space_docs the same way it scans tasks and kb.
	dq := `SELECT d.name, d.rev, d.text, d.updated_root, d.space, h.svc, h.only_below
		FROM space_docs d JOIN space_hooks h ON h.space = d.space AND h.kind = 'doc'
		WHERE NOT d.hidden AND d.updated >= h.created AND d.updated_by NOT LIKE 'svc:%'
		  AND NOT EXISTS (SELECT 1 FROM hook_runs r WHERE r.kind = 'doc' AND r.ref = d.space || '/' || d.name || '@' || d.rev)
		ORDER BY d.updated LIMIT $1`
	drows, err := s.d.DB.Query(ctx, dq, lim)
	if err != nil {
		return nil, err
	}
	for drows.Next() {
		r := hookedRow{kind: "doc"}
		var rev int
		if err := drows.Scan(&r.docName, &rev, &r.body, &r.root, &r.space, &r.svc, &r.onlyBelow); err != nil {
			drows.Close()
			return nil, err
		}
		r.ref = DocRef(r.space, r.docName, rev)
		r.title = r.docName
		out = append(out, r)
	}
	drows.Close()
	return out, drows.Err()
}

// runHook processes one row end to end.
func (s *svc) runHook(ctx context.Context, r hookedRow) error {
	// Claim the row: the first instance to insert the pending marker owns it.
	tag, err := s.d.DB.Exec(ctx, `INSERT INTO hook_runs (kind, ref, state, space) VALUES ($1, $2, 'pending', $3)
		ON CONFLICT (kind, ref) DO NOTHING`, r.kind, r.ref, r.space)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil // another instance owns it
	}
	// only_below: established members (level >= only_below) bypass the hook.
	if r.onlyBelow != nil && r.root != "" && core.Level(ctx, s.d.DB, r.root) >= *r.onlyBelow {
		return s.finishRun(ctx, r, "ok", "", "bypass")
	}
	// Daily cap: over 200 runs/day/space the write is left unchecked (fail open).
	if n, err := s.bump(ctx, r.space); err != nil {
		return err
	} else if n > int64(RunsPerDay) {
		return s.finishRun(ctx, r, "unchecked", "", "")
	}
	// Fund the run from the treasury.
	cost, err := s.svcCost(ctx, r.svc)
	if err != nil {
		return s.finishRun(ctx, r, "unchecked", "", "")
	}
	funded := true
	if FundFn != nil {
		funded, err = FundFn(ctx, s.d.DB, r.space, cost, "hook:"+r.kind+":"+r.ref)
		if err != nil {
			return err
		}
	}
	if !funded {
		if err := core.Event(ctx, s.d.DB, "hook", "s:"+r.space, "", "hook-unfunded "+r.svc); err != nil {
			return err
		}
		return s.finishRun(ctx, r, "unchecked", "", "")
	}
	// Build the input view and run the service.
	in := s.buildInput(ctx, r)
	view, out, err := callFn(ctx, s.d, systemIdent(), r.svc, "", string(in), "", hookWait)
	job := ""
	if view != nil {
		job = view.ID
	}
	if err != nil || view == nil || view.Status != "done" {
		return s.finishRun(ctx, r, "unchecked", "", job)
	}
	state, reason := parseVerdict(out)
	switch state {
	case "rejected":
		return s.reject(ctx, r, reason, job)
	case "warn":
		return s.warn(ctx, r, reason, job)
	case "ok":
		return s.finishRun(ctx, r, "ok", "", job)
	default:
		return s.finishRun(ctx, r, "unchecked", "", job)
	}
}

// finishRun records a terminal verdict for a row's hook_runs marker.
func (s *svc) finishRun(ctx context.Context, r hookedRow, state, reason, job string) error {
	_, err := s.d.DB.Exec(ctx, `UPDATE hook_runs SET state = $3, reason = $4, job = $5, at = now() WHERE kind = $1 AND ref = $2`,
		r.kind, r.ref, state, reason, job)
	return err
}

// reject hides the row with reason `hook: <reason>`, mails its author and prints a line on the
// space moderation log. The 410-gone window counts from the hook_runs row's `at`.
func (s *svc) reject(ctx context.Context, r hookedRow, reason, job string) error {
	full := "hook: " + reason
	if err := s.hideRow(ctx, r); err != nil {
		return err
	}
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE hook_runs SET state = 'rejected', reason = $3, job = $4, at = now() WHERE kind = $1 AND ref = $2`,
			r.kind, r.ref, full, job); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO mod_log (space, actor, target, action, why) VALUES ($1, $2, $3, 'hook-reject', $4)`,
			r.space, "svc:"+r.svc, r.kind+":"+r.ref, trunc(reason, 200)); err != nil {
			return err
		}
		if r.root != "" {
			subj := fmt.Sprintf("your %s in %s was hidden by a hook", r.kind, r.space)
			body := fmt.Sprintf("%s\nreason: %s\nservice: %s\nAppeal to a steward of /s/%s.", r.title, reason, r.svc, r.space)
			if err := core.SysMail(ctx, tx, r.root, subj, body); err != nil {
				return err
			}
		}
		return core.Event(ctx, tx, "hook", "s:"+r.space, "", fmt.Sprintf("hook reject %s:%s %s", r.kind, r.ref, trunc(reason, 80)))
	})
}

// DocRef is the hook_runs ref of a doc revision. A task's ref (its global n) and a kb entry's ref
// (its global id) are already unique, but a doc name repeats across spaces, so a doc's ref carries
// its space and revision to stay globally unique under the hook_runs PK (kind, ref). The read path
// builds the same ref to look a revision up (see INTEGRATION on Gone).
func DocRef(space, name string, rev int) string {
	return space + "/" + name + "@" + strconv.Itoa(rev)
}

// Gone is the read-path check for the 410-gone window of a hook reject. A row the hooks janitor
// rejected is hidden and, for GoneWindow counting from the reject (hook_runs.at), a read of it must
// answer 410 gone rather than a bare 404/404-shaped miss, so the author and A2A clients learn a hook
// removed it and why. After the window it returns nil and the read falls through to normal handling
// (the row stays hidden until a steward unhides it). It fails open: any lookup error returns nil.
//
// For a doc, ref is name@rev (the revision that was rejected); for a task or kb it is the row id.
// The read path cannot call this from internal/spaces (that package is imported here, so the reverse
// would be an import cycle); the integration wires it via a package-level hook. See INTEGRATION below.
func Gone(ctx context.Context, q core.Q, kind, ref string) error {
	var at time.Time
	err := q.QueryRow(ctx, `SELECT at FROM hook_runs WHERE kind = $1 AND ref = $2 AND state = 'rejected'`, kind, ref).Scan(&at)
	if err != nil {
		return nil // no reject row, or a transient read error: not gone (fail open)
	}
	if time.Since(at) < GoneWindow {
		return core.E(410, "gone", "hidden by a space hook")
	}
	return nil
}

// INTEGRATION (read-path wiring for the 410-gone window; P100-spacehooks).
//
// This package imports internal/spaces (hideRow -> spaces.SetDocHidden), so internal/spaces cannot
// import this package to call Gone directly without an import cycle. Two options, both a single line
// outside this package, wired by whoever owns the route (the integration/main package, not spaces):
//
//  1. Preferred: give internal/spaces a nil-safe hook var and let the integration point it here,
//     exactly like core.LevelFn / FundFn / callFn elsewhere.
//       - in internal/spaces, declare:
//           var GoneFn func(ctx context.Context, q core.Q, kind, ref string) error
//       - in hDocGet, right after GetDoc (and likewise in the task/kb readers), add one guard before
//         serving the row, building the ref with the same shape this package writes:
//           doc  -> ref = <slug>/<name>@<cur.Rev>   (identical to hooks.DocRef(slug, name, cur.Rev))
//           task -> ref = the task n;  kb -> ref = the kb id
//           if GoneFn != nil { if err := GoneFn(ctx, s.d.DB, "doc", ref); err != nil { doc.Fail(w, r, err); return } }
//       - in the integration wiring (imports both packages):  spaces.GoneFn = hooks.Gone
//  2. Or call hooks.Gone from the integration-level router/middleware that already imports both.
//
// A doc rejected by a hook is also hidden (SetDocHidden), so its GET is already 410 while hidden; the
// Gone check adds the windowed, hook-specific 410 reason and extends the same behaviour to task/kb
// reads, which otherwise 404 when hidden. After GoneWindow, Gone returns nil and the row is served by
// its normal rules (still hidden until a steward unhides it).

// warn leaves the row visible and flags it hook:warn, keeping the warning text as the reason.
func (s *svc) warn(ctx context.Context, r hookedRow, text, job string) error {
	if _, err := s.d.DB.Exec(ctx, `UPDATE hook_runs SET state = 'warn', reason = $3, job = $4, at = now() WHERE kind = $1 AND ref = $2`,
		r.kind, r.ref, "hook:warn "+text, job); err != nil {
		return err
	}
	return core.Event(ctx, s.d.DB, "hook", "s:"+r.space, "", fmt.Sprintf("hook warn %s:%s %s", r.kind, r.ref, trunc(text, 80)))
}

// hideRow hides the written row through its report target (tasks, kb) or the space-doc hider.
func (s *svc) hideRow(ctx context.Context, r hookedRow) error {
	switch r.kind {
	case "task":
		if t, ok := s.d.Target("t"); ok && t.Hide != nil {
			return t.Hide(ctx, s.d.DB, r.ref)
		}
	case "kb":
		if t, ok := s.d.Target("kb"); ok && t.Hide != nil {
			return t.Hide(ctx, s.d.DB, r.ref)
		}
	case "doc":
		return spaces.SetDocHidden(ctx, s.d.DB, r.space, r.docName, true)
	}
	return nil
}

// buildInput renders the <= 64 KiB JSON view handed to a write hook. open_titles is dropped first
// when the document would be too large.
func (s *svc) buildInput(ctx context.Context, r hookedRow) []byte {
	m := map[string]any{
		"kind":       r.kind,
		"title":      r.title,
		"tags":       r.tags,
		"author_lvl": s.level(ctx, r.root),
		"space":      r.space,
	}
	switch r.kind {
	case "task", "doc":
		m["body"] = r.body
	case "kb":
		m["symptom"] = r.symptom
		m["cause"] = r.cause
		m["fix"] = r.fix
		m["versions"] = r.versions
	}
	self := int64(0)
	if r.kind == "task" {
		self, _ = strconv.ParseInt(r.ref, 10, 64)
	}
	m["open_titles"] = s.openTitles(ctx, r.space, self)
	b, err := json.Marshal(m)
	if err != nil {
		b, _ = json.Marshal(map[string]any{"kind": r.kind, "title": r.title, "space": r.space})
		return b
	}
	if len(b) > MaxInput {
		delete(m, "open_titles")
		b, _ = json.Marshal(m)
		if len(b) > MaxInput {
			b = b[:MaxInput]
		}
	}
	return b
}

func (s *svc) level(ctx context.Context, root string) int {
	if root == "" {
		return 0
	}
	return core.Level(ctx, s.d.DB, root)
}

func (s *svc) openTitles(ctx context.Context, slug string, exclude int64) []string {
	rows, err := s.d.DB.Query(ctx, `SELECT '#' || n || ' ' || title FROM tasks WHERE space = $1 AND state = 'open' AND n <> $3 ORDER BY created DESC LIMIT $2`, slug, MaxOpenTitles, exclude)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return out
		}
		out = append(out, t)
	}
	return out
}

// svcCost resolves the per-run treasury charge for a service by its ms_hint, falling back to the
// default cost when the version cannot be read (the binding validator already proved it callable).
func (s *svc) svcCost(ctx context.Context, svcRef string) (int64, error) {
	v, err := catalog.Resolve(ctx, s.d.DB, svcRef)
	if err != nil {
		return runCost(0), nil
	}
	return runCost(v.Manifest.MsHint), nil
}

// bump increments and returns today's hook-run counter for a space.
func (s *svc) bump(ctx context.Context, slug string) (int64, error) {
	var n int64
	err := s.d.DB.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'hookrun', current_date, 1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`, "s:"+slug).Scan(&n)
	return n, err
}

// parseVerdict reads the first line of a service's stdout: `ok`, `reject <reason>`, `warn <text>`,
// anything else (including empty or binary output) is unchecked (fail open). Reasons are capped at
// 120 runes.
func parseVerdict(out string) (state, reason string) {
	line := out
	if i := strings.IndexByte(line, '\n'); i >= 0 {
		line = line[:i]
	}
	line = strings.TrimSpace(line)
	switch {
	case line == "ok" || strings.HasPrefix(line, "ok ") || strings.HasPrefix(line, "ok\t"):
		return "ok", ""
	case line == "reject" || strings.HasPrefix(line, "reject "):
		return "rejected", trunc(strings.TrimSpace(strings.TrimPrefix(line, "reject")), 120)
	case strings.HasPrefix(line, "warn "):
		return "warn", trunc(strings.TrimSpace(strings.TrimPrefix(line, "warn")), 120)
	}
	return "unchecked", ""
}

// --- daily recheck -------------------------------------------------------------------------------

// RecheckBindings unbinds any hook whose service turned failing, rejected, hidden or lost its stable
// version, recording a mod_log row; crons of such services are disabled the same way.
func (s *svc) RecheckBindings(ctx context.Context) error {
	hrows, err := s.d.DB.Query(ctx, `SELECT space, kind, svc FROM space_hooks`)
	if err != nil {
		return err
	}
	type bind struct{ space, kind, svc string }
	var binds []bind
	for hrows.Next() {
		var b bind
		if err := hrows.Scan(&b.space, &b.kind, &b.svc); err != nil {
			hrows.Close()
			return err
		}
		binds = append(binds, b)
	}
	hrows.Close()
	if err := hrows.Err(); err != nil {
		return err
	}
	for _, b := range binds {
		if s.serviceHealthy(ctx, b.svc) {
			continue
		}
		if _, err := s.d.DB.Exec(ctx, `DELETE FROM space_hooks WHERE space = $1 AND kind = $2`, b.space, b.kind); err != nil {
			return err
		}
		if _, err := s.d.DB.Exec(ctx, `INSERT INTO mod_log (space, actor, target, action, why) VALUES ($1, 'sys', $2, 'hook-unbind', $3)`,
			b.space, b.kind+":"+b.svc, "service failing or hidden"); err != nil {
			return err
		}
		_ = core.Event(ctx, s.d.DB, "hook", "s:"+b.space, "", "hook "+b.kind+" unbound: "+b.svc+" failing/hidden")
	}
	return nil
}

func (s *svc) serviceHealthy(ctx context.Context, svcRef string) bool {
	return s.checkServicePinned(ctx, svcRef) == nil
}

// --- cron janitor --------------------------------------------------------------------------------

// RunCrons is the cron janitor: it runs every due, enabled cron, exports its source, runs the
// service funded by the treasury, delivers the scrubbed stdout, and reschedules. Three consecutive
// failures disable the cron.
func (s *svc) RunCrons(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT space, idx, svc, every_h, src, "to", in_text, fails
		FROM space_cron WHERE NOT disabled AND next_at <= now() ORDER BY next_at LIMIT 50`)
	if err != nil {
		return err
	}
	type cronRow struct {
		space, svc, src, to, inText string
		idx, everyH, fails          int
	}
	var due []cronRow
	for rows.Next() {
		var c cronRow
		if err := rows.Scan(&c.space, &c.idx, &c.svc, &c.everyH, &c.src, &c.to, &c.inText, &c.fails); err != nil {
			rows.Close()
			return err
		}
		due = append(due, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range due {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		ok := s.runCron(ctx, c.space, c.idx, c.svc, c.src, c.to, c.inText)
		if err := s.afterCron(ctx, c.space, c.idx, c.everyH, c.fails, ok); err != nil {
			s.d.Log.Warn("cron reschedule", "space", c.space, "idx", c.idx, "err", err)
		}
	}
	return nil
}

// runCron runs one cron once, returning whether it succeeded (a delivered, scrubbed output).
func (s *svc) runCron(ctx context.Context, slug string, idx int, svcRef, src, to, inText string) bool {
	payload, err := s.cronInput(ctx, slug, src, inText)
	if err != nil {
		return false
	}
	cost, err := s.svcCost(ctx, svcRef)
	if err != nil {
		return false
	}
	if FundFn != nil {
		funded, err := FundFn(ctx, s.d.DB, slug, cost, fmt.Sprintf("cron:%s:%d", slug, idx))
		if err != nil || !funded {
			return false
		}
	}
	var blobIn, textIn string
	if len(payload) <= exportInline {
		textIn = string(payload)
	} else {
		hash, err := compute.PutBlobBytes(ctx, s.d, core.SystemID, payload, "")
		if err != nil {
			return false
		}
		blobIn = hash
	}
	view, out, err := callFn(ctx, s.d, systemIdent(), svcRef, blobIn, textIn, "", cronWait)
	job := ""
	if view != nil {
		job = view.ID
	}
	s.d.DB.Exec(ctx, `UPDATE space_cron SET last_job = $3 WHERE space = $1 AND idx = $2`, slug, idx, job)
	if err != nil || view == nil || view.Status != "done" || strings.TrimSpace(out) == "" {
		return false
	}
	// The stdout passes the member-doc-edit pipeline before it lands anywhere.
	clean, blocked := scrubOutput(out)
	if blocked {
		return false
	}
	return s.deliver(ctx, slug, svcRef, to, clean)
}

// cronInput builds the service input: in_text and the day, then the exported source as JSONL.
func (s *svc) cronInput(ctx context.Context, slug, src, inText string) ([]byte, error) {
	var b bytes.Buffer
	if inText != "" {
		b.WriteString(inText)
		b.WriteByte('\n')
	}
	fmt.Fprintf(&b, "now_day=%s\n", core.Date(time.Now()))
	switch {
	case src == "none":
		// in_text and the day only.
	case src == "t7d":
		if err := export.SpaceJSONL(ctx, s.d.DB, slug, "t", &b); err != nil {
			return nil, err
		}
	case src == "kb7d":
		if err := export.SpaceJSONL(ctx, s.d.DB, slug, "kb", &b); err != nil {
			return nil, err
		}
	case src == "log7d":
		if err := s.logJSONL(ctx, slug, &b); err != nil {
			return nil, err
		}
	case strings.HasPrefix(src, "doc:"):
		name := strings.TrimPrefix(src, "doc:")
		d, err := spaces.GetDoc(ctx, s.d.DB, slug, name)
		if err == nil && d != nil {
			row, _ := json.Marshal(map[string]any{"doc": name, "rev": d.Rev, "text": d.Text})
			b.Write(row)
			b.WriteByte('\n')
		}
	}
	return b.Bytes(), nil
}

// logJSONL writes the last 7 days of the space moderation log as JSONL.
func (s *svc) logJSONL(ctx context.Context, slug string, b *bytes.Buffer) error {
	rows, err := s.d.DB.Query(ctx, `SELECT actor, target, action, why, at FROM mod_log
		WHERE space = $1 AND at > now() - interval '7 days' ORDER BY at DESC LIMIT 2000`, slug)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var actor, target, action, why string
		var at time.Time
		if err := rows.Scan(&actor, &target, &action, &why, &at); err != nil {
			return err
		}
		row, _ := json.Marshal(map[string]any{"actor": actor, "target": target, "action": action, "why": why, "at": at.Format(time.RFC3339)})
		b.Write(row)
		b.WriteByte('\n')
	}
	return rows.Err()
}

// deliver routes a cron's scrubbed stdout to its target: a space doc revision, one auto task, or a
// group-box message.
func (s *svc) deliver(ctx context.Context, slug, svcRef, to, out string) bool {
	switch {
	case strings.HasPrefix(to, "doc:"):
		name := strings.TrimPrefix(to, "doc:")
		return s.writeCronDoc(ctx, slug, name, svcRef, out) == nil
	case to == "t":
		return s.cronTask(ctx, slug, out) == nil
	case to == "mb":
		return s.cronMail(ctx, slug, out) == nil
	}
	return false
}

// writeCronDoc appends a new space_docs revision authored by svc:<name>@<ver>, snapshotting the
// current row into space_doc_revs first (the writeRev shape, done directly here so the service never
// impersonates a member). home, tpl-* and llms are never writable and were refused at proposal time.
func (s *svc) writeCronDoc(ctx context.Context, slug, name, svcRef, text string) error {
	if name == "home" || name == "llms" || strings.HasPrefix(name, "tpl-") {
		return core.Bad("protected doc")
	}
	text = strings.TrimRight(doc.CleanMulti(scrub.Normalize(text)), " \t\n")
	if len(text) > 16384 {
		text = strings.ToValidUTF8(text[:16384], "")
	}
	by := "svc:" + svcRef
	_, flags := lexFlags(text)
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var rev int
		var exists bool
		err := tx.QueryRow(ctx, `SELECT rev FROM space_docs WHERE space = $1 AND name = $2 FOR UPDATE`, slug, name).Scan(&rev)
		if err == nil {
			exists = true
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if exists {
			if _, err := tx.Exec(ctx, `INSERT INTO space_doc_revs (space, name, rev, text, updated_by, updated_root, updated, flags, hazard)
				SELECT space, name, rev, text, updated_by, updated_root, updated, flags, hazard FROM space_docs WHERE space = $1 AND name = $2
				ON CONFLICT DO NOTHING`, slug, name); err != nil {
				return err
			}
		}
		next := rev + 1
		if _, err := tx.Exec(ctx, `INSERT INTO space_docs (space, name, text, rev, updated_by, updated_root, updated, flags, hazard)
			VALUES ($1, $2, $3, $4, $5, '', now(), $6, '{}')
			ON CONFLICT (space, name) DO UPDATE SET text = EXCLUDED.text, rev = EXCLUDED.rev, updated_by = EXCLUDED.updated_by,
			  updated_root = '', updated = now(), flags = EXCLUDED.flags, hazard = '{}'`,
			slug, name, text, next, by, flags); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO space_doc_revs (space, name, rev, text, updated_by, updated_root, flags, hazard)
			VALUES ($1, $2, $3, $4, $5, '', $6, '{}')`, slug, name, next, text, by, flags); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE spaces SET last_write = now() WHERE slug = $1`, slug); err != nil {
			return err
		}
		return core.Event(ctx, tx, "cron", "s:"+slug, "", fmt.Sprintf("cron doc %s rev %d by %s", name, next, by))
	})
}

// cronTask posts at most one auto task per day for a cron, tagged `auto`, authored by the system.
func (s *svc) cronTask(ctx context.Context, slug, out string) error {
	var n int64
	if err := s.d.DB.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'crontask', current_date, 1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`, "s:"+slug).Scan(&n); err != nil {
		return err
	}
	if n > 1 {
		return core.E(429, "quota", "one auto task per day")
	}
	title, body := splitTitle(out)
	_, err := forge.CreateTask(ctx, s.d, systemIdent(), forge.TaskInput{Title: title, Body: body, Tags: []string{"auto"}, Space: slug})
	return err
}

// cronMail posts the output as a group-box message from the system with re=cron.
func (s *svc) cronMail(ctx context.Context, slug, out string) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		_, _, err := mail.Send(ctx, tx, systemIdent(), "g"+slug, "cron", "cron", trunc(out, 4000))
		return err
	})
}

// afterCron records the run's state, advances next_at and disables the cron after three straight
// failures.
func (s *svc) afterCron(ctx context.Context, slug string, idx, everyH, fails int, ok bool) error {
	if ok {
		_, err := s.d.DB.Exec(ctx, `UPDATE space_cron SET last_state = 'ok', fails = 0,
			next_at = now() + make_interval(hours => $3) WHERE space = $1 AND idx = $2`, slug, idx, everyH)
		return err
	}
	nf := fails + 1
	if nf >= CronFailsOff {
		if err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE space_cron SET last_state = 'fail', fails = $3, disabled = true WHERE space = $1 AND idx = $2`, slug, idx, nf); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO mod_log (space, actor, target, action, why) VALUES ($1, 'sys', $2, 'cron-disable', $3)`,
				slug, "cron:"+strconv.Itoa(idx), fmt.Sprintf("%d consecutive failures", nf)); err != nil {
				return err
			}
			return s.mailStewards(ctx, tx, slug, "a cron was disabled",
				fmt.Sprintf("cron %d in /s/%s was disabled after %d consecutive failures.", idx, slug, nf))
		}); err != nil {
			return err
		}
		return core.Event(ctx, s.d.DB, "cron", "s:"+slug, "", fmt.Sprintf("cron %d disabled (%d fails)", idx, nf))
	}
	_, err := s.d.DB.Exec(ctx, `UPDATE space_cron SET last_state = 'fail', fails = $3,
		next_at = now() + make_interval(hours => $4) WHERE space = $1 AND idx = $2`, slug, idx, nf, everyH)
	return err
}

// mailStewards sends a system notice to every steward of a space.
func (s *svc) mailStewards(ctx context.Context, q core.Q, slug, subject, text string) error {
	rows, err := q.Query(ctx, `SELECT root FROM space_members WHERE space = $1 AND role = 'steward'`, slug)
	if err != nil {
		return err
	}
	var stewards []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			rows.Close()
			return err
		}
		stewards = append(stewards, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range stewards {
		if err := core.SysMail(ctx, q, r, subject, text); err != nil {
			return err
		}
	}
	return nil
}

// --- shared helpers ------------------------------------------------------------------------------

// scrubOutput runs the member-doc-edit pipeline over a service's stdout: tier-1 scrub rejects block
// delivery, tier-2 masks and lexicon/hazard flags are applied but allowed through.
func scrubOutput(out string) (clean string, blocked bool) {
	s := strings.ToValidUTF8(out, "")
	if len(s) > MaxOutput {
		s = s[:MaxOutput]
	}
	if _, err := scrub.RejectOrMask(map[string]*string{"out": &s}); err != nil {
		return "", true
	}
	// Hazards (prompt-injection families) block a cron write, as they would a doc edit.
	if h := scrub.Hazards(s); len(h) > 0 {
		return "", true
	}
	return s, false
}

// lexFlags keeps only the real lexicon flags (drops informational lang= markers).
func lexFlags(text string) (int, []string) {
	score, flags, _ := scrub.Flags(text)
	out := []string{}
	for _, f := range flags {
		if !strings.HasPrefix(f, "lang=") {
			out = append(out, f)
		}
	}
	return score, out
}

func splitTitle(out string) (title, body string) {
	out = strings.TrimSpace(out)
	if i := strings.IndexByte(out, '\n'); i >= 0 {
		title, body = strings.TrimSpace(out[:i]), strings.TrimSpace(out[i+1:])
	} else {
		title = out
	}
	title = trunc(title, 160)
	if title == "" {
		title = "cron update"
	}
	body = trunc(body, 4000)
	return title, body
}

func trunc(s string, n int) string {
	s = doc.SafeLine(s)
	r := []rune(s)
	if len(r) > n {
		return string(r[:n])
	}
	return s
}
