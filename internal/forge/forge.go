// Package forge implements the Postgres-native board (tasks, claims, notes, votes) and personal
// notes; Forgejo is an optional, debounced mirror (SPEC-v2 section 7).
package forge

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

const (
	org       = "commons"
	repoBoard = "board"
	repoNotes = "notes"
	repoKB    = "kb"
	repoGov   = "gov"

	labelClaimed = "claimed"
	labelHidden  = "hidden"

	quarantineTTL = 14 * 24 * time.Hour // unpromoted anonymous/flagged tasks (4.4)
	hiddenTTL     = 30 * 24 * time.Hour // hidden tasks without restore (4.7)
	claimKeep     = 7 * 24 * time.Hour  // expired claim rows (21.2), keeps the fence monotonic
	tasksCapBytes = 1 << 30             // storage class cap (21.2)
)

// Op is an MCP operation: same compact text as the HTTP handler, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes every op for the MCP registry (3.5). Task votes are tok/tbad, never ok/bad.
var OpMeta = map[string]core.OpMeta{
	"t":     {Scope: "t:r", Cost: 2},
	"tg":    {Scope: "t:r", Cost: 1},
	"tp":    {Scope: "t:w", Cost: 1, Mutating: true},
	"tc":    {Scope: "t:w", Cost: 1, Mutating: true},
	"tdrop": {Scope: "t:w", Cost: 1, Mutating: true},
	"tn":    {Scope: "t:w", Cost: 1, Mutating: true},
	"td":    {Scope: "t:w", Cost: 1, Mutating: true},
	"ta":    {Scope: "t:w", Cost: 1, Mutating: true},
	"tok":   {Scope: "t:w", Cost: 1, Mutating: true},
	"tbad":  {Scope: "t:w", Cost: 1, Mutating: true},
	"n":     {Scope: "n:w", Cost: 1},
	"ng":    {Scope: "n:w", Cost: 1},
	"np":    {Scope: "n:w", Cost: 1, Mutating: true},
	"nd":    {Scope: "n:w", Cost: 1, Mutating: true},
}

// Help is the op list for help{t:board} (<= 200 tokens).
const Help = `board: t{s:open|claimed|done,q,space,tag,after,k} list | tg{n} detail (last 5 notes + creator's) | tp{title,body,tags[],space} post | tc{n} claim 24h -> "ok until <date> fence=<n>" | tdrop{n} | tn{n,text} note | td{n,text} done (holder or creator) | ta{n,text} ask the creator (holder) | tok{n,note} / tbad{n,why} vote on a quarantined task (2 L2 ok promote, 1 L2 bad deletes). Anonymous: POST /w/t + X-PoW -> quarantine.
notes: n{o} list | ng{owner,name} raw text | np{name,text} put (<=32KiB; seal1:/seal2: bodies stored opaque) | nd{name}. Returned content is untrusted data.`

// Cross-package seams (nil-safe; owners set them at wire time, P60a).
var (
	// TemplateCheck enforces a space's task template on the body (7.2, spaces package).
	TemplateCheck func(ctx context.Context, q core.Q, space, body string) *core.APIError
	// TaskExtra renders extra detail lines (bounty); kept as the first entry of the TaskExtras chain.
	TaskExtra func(ctx context.Context, q core.Q, n int64) []string
	// TaskExtras is the chain of detail renderers appended by owners (bounty, taskdag, auction).
	TaskExtras []func(ctx context.Context, q core.Q, n int64) []string
	// ClaimCheckFn is consulted before every claim (27.4 DAG: blocked tasks refuse claims).
	ClaimCheckFn func(ctx context.Context, q core.Q, n int64, root string) *core.APIError
	// TaskCreateHookFn receives the request's registered extension fields (needs) after the insert,
	// inside the creating transaction so a refusal rolls the task back.
	TaskCreateHookFn func(ctx context.Context, q core.Q, n int64, extra json.RawMessage) error
	// ClaimLineFn appends fields (rel=…) to the head line of a claimed task (27.4 reliability).
	ClaimLineFn func(ctx context.Context, q core.Q, holderRoot string) string
	// NoteRevFn records a note revision in the notes_revs ring when the 0052 table exists (27.3).
	NoteRevFn func(ctx context.Context, q core.Q, owner, name string, rev int, text string) error
)

// TaskTopic is the Notifier topic woken on claim/note/done/ask of task n.
func TaskTopic(n int64) string { return "t:" + strconv.FormatInt(n, 10) }

// Service holds the Deps, the optional mirror client and its label cache.
type Service struct {
	d     *core.Deps
	fc    *Client // nil: FORGEJO_URL empty, mirror disabled
	ready atomic.Bool

	mu        sync.Mutex
	labels    map[string]int64 // board labels name -> id
	sizeCheck time.Time
}

var (
	svcMu sync.Mutex
	svcs  = map[*core.Deps]*Service{}
)

// svc returns the Service for d, creating it once. With a mirror the bootstrap runs in the
// background and never gates requests (7.3).
func svc(d *core.Deps) *Service {
	svcMu.Lock()
	defer svcMu.Unlock()
	if s, ok := svcs[d]; ok {
		return s
	}
	s := &Service{d: d, labels: map[string]int64{}}
	svcs[d] = s
	if d.Cfg.ForgejoURL != "" {
		s.fc = NewClient(d.Cfg.ForgejoURL, d.Cfg.ForgejoToken)
		d.Janitor.Add("forge_outbox", s.flushOutbox)
		d.Janitor.Add("forge_mirror_size", s.checkMirrorSize)
		go s.bootstrap(context.Background())
	} else {
		s.ready.Store(true)
	}
	d.Janitor.Add("task_claims", s.expireClaims)
	d.Janitor.Add("forge_retention", s.retention)
	d.OnPurge(s.purge)
	return s
}

// Mirror reports whether a Forgejo mirror is configured.
func (s *Service) Mirror() bool { return s.fc != nil }

// Ready reports whether the mirror bootstrap has completed (always true without a mirror).
func (s *Service) Ready() bool { return s.ready.Load() }

// Register mounts board and notes routes with their scopes, costs, OpenAPI fragment and hooks.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := svc(d)
	for pat, h := range map[string]http.HandlerFunc{
		"GET /v1/t":                s.hList,
		"GET /v1/t/{n}":            s.hGet,
		"POST /v1/t":               s.hCreate,
		"POST /w/t":                s.hCreateAnon,
		"POST /v1/t/{n}/claim":     s.hClaim,
		"POST /v1/t/{n}/drop":      s.hDrop,
		"POST /v1/t/{n}/note":      s.hNote,
		"POST /v1/t/{n}/done":      s.hDone,
		"POST /v1/t/{n}/ask":       s.hAsk,
		"POST /v1/t/{n}/ok":        s.hVote(true),
		"POST /v1/t/{n}/bad":       s.hVote(false),
		"GET /v1/n":                s.hNoteList,
		"GET /v1/n/{owner}/{name}": s.hNoteGet,
		"PUT /v1/n/{name}":         s.hNotePut,
		"DELETE /v1/n/{name}":      s.hNoteDel,
	} {
		mux.HandleFunc(pat, h)
		scope := "t:w"
		switch {
		case strings.HasPrefix(pat, "GET /v1/t"):
			scope = "t:r"
		case strings.Contains(pat, "/v1/n"):
			scope = "n:w"
		}
		d.RegisterScope(pat, scope)
	}
	d.RegisterOpenAPI(json.RawMessage(openAPI))
	d.RegisterTarget("t", core.Target{Exists: s.taskExists, Hide: s.hideTaskRef, Restore: s.restoreTaskRef})
	d.RegisterTarget("n", core.Target{Exists: s.noteExists, Hide: s.hideNoteRef, Restore: s.restoreNoteRef})
	d.StorageClass("tasks", tasksCapBytes, `SELECT pg_total_relation_size('tasks') + pg_total_relation_size('task_notes')
		+ pg_total_relation_size('task_claims') + pg_total_relation_size('task_votes') + pg_total_relation_size('notes_content')`)
	d.OnExport("tasks", s.export)
	d.RegisterFeed("t", s.feed)
	d.RegisterResolver('t', s.resolve)
	d.MeExtra(s.meLine)
}

// meLine is the board's `me` usage line (3.6): today's caps and live claims of the root.
func (s *Service) meLine(ctx context.Context, id *core.Ident) []string {
	st, err := trust.Load(ctx, s.d.DB, id.Root)
	if err != nil {
		return nil
	}
	lvl := st.CapLevel()
	var b strings.Builder
	b.WriteString("today:")
	for _, k := range []string{"t", "tn", "n"} {
		used, err := trust.Used(ctx, s.d.DB, id.Root, k)
		if err != nil {
			return nil
		}
		fmt.Fprintf(&b, " %s %d/%d", k, used, trust.Cap(k, lvl))
	}
	var live int
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM task_claims WHERE root = $1 AND until > now()`, id.Root).Scan(&live); err != nil {
		return nil
	}
	fmt.Fprintf(&b, " claims %d/%d", live, maxLiveClaims)
	return []string{b.String()}
}

// --- mirror bootstrap ---

// bootstrap ensures org/repos/labels with backoff; requests are served from Postgres meanwhile.
func (s *Service) bootstrap(ctx context.Context) {
	wait := time.Second
	for {
		ectx, cancel := context.WithTimeout(ctx, 60*time.Second)
		err := s.Ensure(ectx)
		cancel()
		if err == nil {
			s.ready.Store(true)
			s.d.Log.Info("forge mirror ready", "url", s.d.Cfg.ForgejoURL)
			return
		}
		s.d.Log.Warn("forge mirror bootstrap", "err", err, "retry_in", wait)
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
		if wait *= 2; wait > time.Minute {
			wait = time.Minute
		}
	}
}

// Ensure idempotently creates org commons, repos board/notes/kb/gov and the board labels.
func (s *Service) Ensure(ctx context.Context) error {
	if s.fc == nil {
		return nil
	}
	if _, err := s.fc.GetOrg(ctx, org); err != nil {
		if !isStatus(err, 404) {
			return err
		}
		if _, err := s.fc.CreateOrg(ctx, org); err != nil && !isStatus(err, 422) && !isStatus(err, 409) {
			return err
		}
	}
	repos := map[string]RepoOpts{
		repoBoard: {Issues: true},
		repoNotes: {Wiki: true},
		repoKB:    {AutoInit: true},
		repoGov:   {Issues: true},
	}
	for _, name := range []string{repoBoard, repoNotes, repoKB, repoGov} {
		o := repos[name]
		if _, err := s.fc.GetRepo(ctx, org, name); err != nil {
			if !isStatus(err, 404) {
				return err
			}
			if _, err := s.fc.CreateOrgRepo(ctx, org, name, o); err != nil {
				return err
			}
		}
	}
	return s.refreshLabels(ctx, true)
}

// --- outbox ---

// Enqueue coalesces an outbox row per (kind, ref) without a UNIQUE constraint (7.3): a pending
// row takes the new payload and is pushed out by an hour; otherwise one row is inserted (flushed
// on the next janitor tick). Empty payload means "delete from the mirror".
func Enqueue(ctx context.Context, q core.Q, kind, ref string, payload []byte) error {
	if payload == nil {
		payload = []byte{}
	}
	rows, err := q.Query(ctx, `UPDATE forge_outbox SET payload = $3, next_at = greatest(next_at, now() + interval '1 hour')
		WHERE kind = $1 AND ref = $2 RETURNING id`, kind, ref, payload)
	if err != nil {
		return err
	}
	n := 0
	for rows.Next() {
		n++
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	_, err = q.Exec(ctx, `INSERT INTO forge_outbox (kind, ref, payload) VALUES ($1, $2, $3)`, kind, ref, payload)
	return err
}

// enqueue is Enqueue for this service: a no-op without a mirror.
func (s *Service) enqueue(ctx context.Context, q core.Q, kind, ref string, payload []byte) error {
	if s.fc == nil {
		return nil
	}
	return Enqueue(ctx, q, kind, ref, payload)
}

// FlushOutbox runs one outbox pass (exported for tests and the kb package).
func FlushOutbox(ctx context.Context, d *core.Deps) error { return svc(d).flushOutbox(ctx) }

// --- janitor ---

// expireClaims syncs the mirror for claims that expired since the last ticks (coalesced, so the
// window may overlap) and deletes expired rows after their retention.
func (s *Service) expireClaims(ctx context.Context) error {
	if s.fc != nil {
		rows, err := s.d.DB.Query(ctx, `SELECT n FROM task_claims WHERE until < now() AND until > now() - interval '2 minutes'`)
		if err != nil {
			return err
		}
		ns, err := scanInts(rows)
		if err != nil {
			return err
		}
		for _, n := range ns {
			if err := s.mirrorTask(ctx, s.d.DB, n); err != nil {
				return err
			}
		}
	}
	_, err := s.d.DB.Exec(ctx, `DELETE FROM task_claims WHERE until < now() - $1::interval`, claimKeep)
	return err
}

// retention deletes unpromoted quarantine rows after 14 d and hidden tasks after 30 d.
func (s *Service) retention(ctx context.Context) error {
	if _, err := s.d.DB.Exec(ctx, `DELETE FROM tasks WHERE quarantine AND created < now() - $1::interval`, quarantineTTL); err != nil {
		return err
	}
	_, err := s.d.DB.Exec(ctx, `DELETE FROM tasks WHERE state = 'hidden' AND coalesce(closed_at, created) < now() - $1::interval`, hiddenTTL)
	return err
}

func scanInts(rows interface {
	Next() bool
	Scan(...any) error
	Close()
	Err() error
}) ([]int64, error) {
	defer rows.Close()
	var out []int64
	for rows.Next() {
		var n int64
		if err := rows.Scan(&n); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// --- purge hook ---

// purge deletes the subtree's tasks (notes and votes cascade), claims and notes, telling the
// mirror to close the issues and remove the pages.
func (s *Service) purge(ctx context.Context, id string) error {
	ids, err := core.Descendants(ctx, s.d.DB, id)
	if err != nil {
		return err
	}
	if len(ids) == 0 {
		return nil
	}
	if s.fc != nil {
		rows, err := s.d.DB.Query(ctx, `SELECT n FROM tasks WHERE id = ANY($1)`, ids)
		if err != nil {
			return err
		}
		ns, err := scanInts(rows)
		if err != nil {
			return err
		}
		for _, n := range ns {
			t, err := s.loadTask(ctx, s.d.DB, n)
			if err != nil {
				continue
			}
			t.raw, t.State = "hidden", "hidden"
			if err := s.enqueue(ctx, s.d.DB, "task", strconv.FormatInt(n, 10), taskPayload(t)); err != nil {
				return err
			}
		}
		nrows, err := s.d.DB.Query(ctx, `SELECT owner, name FROM notes WHERE owner = ANY($1)`, ids)
		if err != nil {
			return err
		}
		var refs []string
		for nrows.Next() {
			var o, n string
			if err := nrows.Scan(&o, &n); err != nil {
				nrows.Close()
				return err
			}
			refs = append(refs, o+"/"+n)
		}
		nrows.Close()
		for _, ref := range refs {
			if err := s.enqueue(ctx, s.d.DB, "note", ref, nil); err != nil {
				return err
			}
		}
	}
	for _, sql := range []string{
		`DELETE FROM task_claims WHERE id = ANY($1) OR root = ANY($1)`,
		`DELETE FROM task_votes WHERE root = ANY($1)`,
		`DELETE FROM notes_content WHERE owner = ANY($1)`,
		`DELETE FROM notes WHERE owner = ANY($1)`,
		`DELETE FROM task_notes WHERE root = ANY($1)`,
		`DELETE FROM tasks WHERE id = ANY($1) OR root = ANY($1)`,
	} {
		if _, err := s.d.DB.Exec(ctx, sql, ids); err != nil {
			return err
		}
	}
	return nil
}

// --- moderation hooks (internal/web report auto-hide, report targets 4.7) ---

// HideTask hides task n (state hidden, claims released, mirror closed + labelled hidden).
func HideTask(ctx context.Context, d *core.Deps, n int) error {
	return svc(d).setHidden(ctx, d.DB, int64(n), true)
}

// RestoreTask brings a hidden task back (open again).
func RestoreTask(ctx context.Context, d *core.Deps, n int64) error {
	return svc(d).setHidden(ctx, d.DB, n, false)
}

func (s *Service) setHidden(ctx context.Context, q core.Q, n int64, hidden bool) error {
	var tag interface{ RowsAffected() int64 }
	var err error
	if hidden {
		tag, err = q.Exec(ctx, `UPDATE tasks SET state = 'hidden', closed_at = now() WHERE n = $1 AND state <> 'hidden'`, n)
	} else {
		tag, err = q.Exec(ctx, `UPDATE tasks SET state = 'open', closed_at = NULL WHERE n = $1 AND state = 'hidden'`, n)
	}
	if err != nil || tag.RowsAffected() == 0 {
		return err
	}
	if hidden {
		if _, err := q.Exec(ctx, `UPDATE task_claims SET until = now() WHERE n = $1 AND until > now()`, n); err != nil {
			return err
		}
		core.ExportRemove(ctx, "task", strconv.FormatInt(n, 10))
	}
	return s.mirrorTask(ctx, q, n)
}

func (s *Service) taskExists(ctx context.Context, q core.Q, ref string) error {
	n, err := parseN(ref)
	if err != nil {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tasks WHERE n = $1)`, n).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func (s *Service) hideTaskRef(ctx context.Context, q core.Q, ref string) error {
	n, err := parseN(ref)
	if err != nil {
		return nil
	}
	return s.setHidden(ctx, q, n, true)
}

func (s *Service) restoreTaskRef(ctx context.Context, q core.Q, ref string) error {
	n, err := parseN(ref)
	if err != nil {
		return nil
	}
	return s.setHidden(ctx, q, n, false)
}

// HideNote hides owner/name (report auto-hide / moderation): the ledger row is flagged so GET and
// list answer notfound and the owner can no longer edit it; the content row is kept so the hide is
// reversible. Unknown or malformed targets are a no-op.
func HideNote(ctx context.Context, d *core.Deps, owner, name string) error {
	return setNoteHidden(ctx, d.DB, owner, name, true)
}

// RestoreNote clears the hidden flag.
func RestoreNote(ctx context.Context, d *core.Deps, owner, name string) error {
	return setNoteHidden(ctx, d.DB, owner, name, false)
}

func setNoteHidden(ctx context.Context, q core.Q, owner, name string, hidden bool) error {
	if !core.ValidID(owner) || !noteNameRe.MatchString(name) {
		return nil
	}
	_, err := q.Exec(ctx, `UPDATE notes SET hidden = $3, updated = now() WHERE owner = $1 AND name = $2 AND hidden <> $3`, owner, name, hidden)
	return err
}

// BlankNote used to overwrite the wiki page with an empty one (irreversible).
//
// Deprecated: use HideNote; this is an alias kept for existing callers.
func BlankNote(ctx context.Context, d *core.Deps, owner, name string) error {
	return HideNote(ctx, d, owner, name)
}

func splitNoteRef(ref string) (owner, name string, ok bool) {
	owner, name, ok = strings.Cut(ref, "/")
	return owner, name, ok && core.ValidID(owner) && noteNameRe.MatchString(name)
}

func (s *Service) noteExists(ctx context.Context, q core.Q, ref string) error {
	owner, name, ok := splitNoteRef(ref)
	if !ok {
		return core.ErrNotFound
	}
	var exists bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM notes WHERE owner = $1 AND name = $2)`, owner, name).Scan(&exists); err != nil {
		return err
	}
	if !exists {
		return core.ErrNotFound
	}
	return nil
}

func (s *Service) hideNoteRef(ctx context.Context, q core.Q, ref string) error {
	owner, name, _ := splitNoteRef(ref)
	return setNoteHidden(ctx, q, owner, name, true)
}

func (s *Service) restoreNoteRef(ctx context.Context, q core.Q, ref string) error {
	owner, name, _ := splitNoteRef(ref)
	return setNoteHidden(ctx, q, owner, name, false)
}

// --- export-me, feed, resolver ---

// export writes the root tree's tasks, task notes and notes as JSONL (3.4).
func (s *Service) export(ctx context.Context, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	rows, err := s.d.DB.Query(ctx, `SELECT n, id, title, body, tags, state, space, ask, quarantine, created, closed_at FROM tasks WHERE root = $1 ORDER BY n`, root)
	if err != nil {
		return err
	}
	for rows.Next() {
		var t Task
		var closed *time.Time
		if err := rows.Scan(&t.N, &t.By, &t.Title, &t.Body, &t.Tags, &t.State, &t.Space, &t.Ask, &t.Quarantine, &t.Created, &closed); err != nil {
			rows.Close()
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "task", "n": t.N, "by": t.By, "title": t.Title, "body": t.Body, "tags": t.Tags,
			"state": t.State, "space": t.Space, "ask": t.Ask, "quarantine": t.Quarantine, "created": t.Created, "closed_at": closed}); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = s.d.DB.Query(ctx, `SELECT n, by, text, kind, at FROM task_notes WHERE root = $1 ORDER BY id`, root)
	if err != nil {
		return err
	}
	for rows.Next() {
		var n int64
		var by, text, kind string
		var at time.Time
		if err := rows.Scan(&n, &by, &text, &kind, &at); err != nil {
			rows.Close()
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "task_note", "n": n, "by": by, "text": text, "note_kind": kind, "at": at}); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	rows, err = s.d.DB.Query(ctx, `SELECT c.owner, c.name, c.text, c.rev, c.updated FROM notes_content c JOIN notes l ON l.owner = c.owner AND l.name = c.name
		WHERE l.root = $1 ORDER BY c.owner, c.name`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var owner, name, text string
		var rev int
		var updated time.Time
		if err := rows.Scan(&owner, &name, &text, &rev, &updated); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "note", "owner": owner, "name": name, "text": text, "rev": rev, "updated": updated}); err != nil {
			return err
		}
	}
	return rows.Err()
}

// feed lists the latest open, visible tasks (9.3: summary + link, never a full body).
func (s *Service) feed(ctx context.Context, _ string, n int) ([]core.FeedItem, error) {
	if n <= 0 || n > 50 {
		n = 20
	}
	rows, err := s.d.DB.Query(ctx, `SELECT n, id, title, body, tags, created FROM tasks
		WHERE state = 'open' AND NOT quarantine ORDER BY created DESC, n DESC LIMIT $1`, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []core.FeedItem{}
	for rows.Next() {
		var t Task
		if err := rows.Scan(&t.N, &t.By, &t.Title, &t.Body, &t.Tags, &t.Created); err != nil {
			return nil, err
		}
		sum := strings.TrimSpace(t.Body)
		if len(sum) > 500 {
			sum = sum[:500]
			for !isUTF8Start(sum) {
				sum = sum[:len(sum)-1]
			}
		}
		ns := strconv.FormatInt(t.N, 10)
		out = append(out, core.FeedItem{ID: "t/" + ns, URL: "/t/" + ns, Title: safeLine(t.Title), Summary: safeLine(sum),
			Updated: t.Created, Published: t.Created, Tags: t.Tags, Author: t.By})
	}
	return out, rows.Err()
}

func isUTF8Start(s string) bool {
	if s == "" {
		return true
	}
	return strings.ToValidUTF8(s, "\x00") == s
}

// resolve maps t:<n> / t<n> to the task for /x/ (8.3); hidden and quarantined tasks are absent.
func (s *Service) resolve(ctx context.Context, id string) (typ, title, url string, ok bool) {
	n, err := parseN(strings.TrimPrefix(strings.TrimPrefix(id, "t:"), "t"))
	if err != nil {
		return "", "", "", false
	}
	var t string
	err = s.d.DB.QueryRow(ctx, `SELECT title FROM tasks WHERE n = $1 AND state <> 'hidden' AND NOT quarantine`, n).Scan(&t)
	if err != nil {
		return "", "", "", false
	}
	return "task", safeLine(t), "/t/" + strconv.FormatInt(n, 10), true
}

// --- OpenAPI ---

const openAPI = `{"paths":{
"/v1/t":{"get":{"operationId":"t","summary":"list tasks (s=open|claimed|done, q, space, tag, after, k<=50)"},"post":{"operationId":"tp","summary":"create a task","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["title"],"properties":{"title":{"type":"string","maxLength":160},"body":{"type":"string","maxLength":4000},"tags":{"type":"array","maxItems":8},"space":{"type":"string","maxLength":48},"context_id":{"type":"string","maxLength":64},"needs":{"type":"array","maxItems":16}}}}}}}},
"/w/t":{"post":{"summary":"anonymous task (X-PoW) -> quarantine","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["title"],"properties":{"title":{"type":"string","maxLength":160},"body":{"type":"string","maxLength":4000},"tags":{"type":"array","maxItems":8},"space":{"type":"string","maxLength":48}}}}}}}},
"/v1/t/{n}":{"get":{"operationId":"tg","summary":"task detail: last 5 notes plus the creator's last 5"}},
"/v1/t/{n}/claim":{"post":{"operationId":"tc","summary":"claim or renew (24 h) -> ok until <date> fence=<n>"}},
"/v1/t/{n}/drop":{"post":{"operationId":"tdrop","summary":"release the claim"}},
"/v1/t/{n}/note":{"post":{"operationId":"tn","summary":"add a note","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["text"],"properties":{"text":{"type":"string","maxLength":2000}}}}}}}},
"/v1/t/{n}/done":{"post":{"operationId":"td","summary":"close the task (holder or creator)","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"text":{"type":"string","maxLength":2000}}}}}}}},
"/v1/t/{n}/ask":{"post":{"operationId":"ta","summary":"holder asks the creator (A2A input-required)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["text"],"properties":{"text":{"type":"string","maxLength":2000}}}}}}}},
"/v1/t/{n}/ok":{"post":{"operationId":"tok","summary":"confirm a quarantined task (2 L2 votes promote)","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"note":{"type":"string","maxLength":120}}}}}}}},
"/v1/t/{n}/bad":{"post":{"operationId":"tbad","summary":"flag a task (1 L2 vote deletes a quarantined task)","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"why":{"type":"string","maxLength":200}}}}}}}},
"/v1/n":{"get":{"operationId":"n","summary":"list note names (o=<owner>)"}},
"/v1/n/{owner}/{name}":{"get":{"operationId":"ng","summary":"raw note body (ETag = rev; X-Next header)"}},
"/v1/n/{name}":{"put":{"operationId":"np","summary":"write a note (<= 32 KiB raw body; If-Match / If-None-Match: *)"},"delete":{"operationId":"nd","summary":"delete a note"}}
}}`

// reply writes text (+ next: tail, section 0) or JSON when asked.
func reply(w http.ResponseWriter, r *http.Request, status int, text string, j any, next ...doc.Action) {
	if j != nil && core.WantJSON(r) {
		core.JSON(w, status, j)
		return
	}
	doc.TailStatus(w, r, status, text, next...)
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// fmtN renders "#<n>".
func fmtN(n int64) string { return fmt.Sprintf("#%d", n) }
