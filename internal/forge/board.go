package forge

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

const (
	claimTTL      = 24 * time.Hour
	maxClaimLife  = 72 * time.Hour // total time one root may hold a task, renewals included
	maxLiveClaims = 5              // concurrent live claims per root
	maxTitle      = 160
	maxBody       = 4000
	maxNoteText   = 2000
	maxTags       = 8
	maxContextID  = 64
	maxQuery      = 120
	maxVoteNote   = 120
	maxWhy        = 200
	listLimit     = 50
	shownNotes    = 5
	anonPerGroup  = 5    // /w/t per IP group per day; the super-group takes 4x (4.3)
	maxQuarantine = 5000 // live quarantine rows, global (4.3)
	maxQuarSuper  = 100  // live quarantine rows per super-group (2 %)
	tagsLinePfx   = "tags: "
	anonID        = "anon"
	fenceFirst    = 1 // the first claim on a task
)

var (
	tagRe   = regexp.MustCompile(`^[a-z0-9.+-]{1,32}$`)
	spaceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,47}$`)
)

// writeAuth mirrors core.AuthWrite for ops: token, not banned, not frozen.
func (s *Service) writeAuth(id *core.Ident) error {
	if id == nil {
		return core.ErrAuth
	}
	if id.Banned {
		return core.ErrBanned
	}
	if s.d.Frozen("write") {
		return core.Frozen("write")
	}
	return nil
}

// --- model ---

// TaskLine is one list row.
type TaskLine struct {
	N     int64  `json:"n"`
	State string `json:"state"`
	Title string `json:"title"`
}

// TaskNote is a note on a task (kind note|done|ask; omitted when note).
type TaskNote struct {
	By   string    `json:"by"`
	At   time.Time `json:"at"`
	Text string    `json:"text"`
	Kind string    `json:"kind,omitempty"`
	Root string    `json:"-"`
}

// Task is the detail view: v1 fields first, v2 fields appended.
type Task struct {
	N         int64      `json:"n"`
	State     string     `json:"state"`
	By        string     `json:"by"`
	Created   time.Time  `json:"created"`
	Title     string     `json:"title"`
	Body      string     `json:"body"`
	Tags      []string   `json:"tags,omitempty"`
	Until     *time.Time `json:"until,omitempty"`
	NoteCount int        `json:"note_count"` // total notes; Notes holds the last 5 plus the creator's last 5
	Notes     []TaskNote `json:"notes"`

	Root       string     `json:"-"`
	Space      string     `json:"space,omitempty"`
	ContextID  string     `json:"context_id,omitempty"`
	Ask        string     `json:"ask,omitempty"`
	Quarantine bool       `json:"quarantine,omitempty"`
	Hazard     []string   `json:"hazard,omitempty"`
	Flags      []string   `json:"flags,omitempty"`
	Fence      int64      `json:"fence,omitempty"`
	Holder     string     `json:"-"` // holder root while claimed
	HolderID   string     `json:"-"`
	Closed     *time.Time `json:"closed_at,omitempty"`
	Issue      *int64     `json:"-"`
	Extra      []string   `json:"extra,omitempty"`
	ClaimLine  string     `json:"claim_line,omitempty"` // ClaimLineFn fields (rel=…) on the head
	Next       []string   `json:"next,omitempty"`
	raw        string     // tasks.state (open|done|hidden)
}

// Live reports whether the task is open with a live claim.
func (t *Task) claimed() bool { return t.Until != nil }

const taskCols = `n, id, root, title, body, tags, state, space, context_id, ask, quarantine, hazard, flags, created, closed_at, issue`

// loadTask reads one task row plus its claim (any state); notes are not loaded.
func (s *Service) loadTask(ctx context.Context, q core.Q, n int64) (*Task, error) {
	var t Task
	err := q.QueryRow(ctx, `SELECT `+taskCols+` FROM tasks WHERE n = $1`, n).Scan(&t.N, &t.By, &t.Root, &t.Title, &t.Body, &t.Tags,
		&t.raw, &t.Space, &t.ContextID, &t.Ask, &t.Quarantine, &t.Hazard, &t.Flags, &t.Created, &t.Closed, &t.Issue)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var cid, croot string
	var until time.Time
	var fence int64
	err = q.QueryRow(ctx, `SELECT id, root, until, fence FROM task_claims WHERE n = $1`, n).Scan(&cid, &croot, &until, &fence)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	if err == nil {
		t.Fence = fence
		if until.After(time.Now()) && t.raw == "open" {
			t.Until, t.Holder, t.HolderID = &until, croot, cid
		}
	}
	t.State = stateOf(t.raw, t.HolderID)
	return &t, nil
}

func stateOf(raw, holderID string) string {
	switch {
	case raw == "done":
		return "done"
	case raw == "hidden":
		return "hidden"
	case holderID != "":
		return "claimed:" + holderID
	}
	return "open"
}

// loadNotes fills NoteCount and Notes: the last 5 notes plus the creator's last 5 (so note spam
// cannot push the creator's own updates out of view), in id order.
func (s *Service) loadNotes(ctx context.Context, q core.Q, t *Task) error {
	if err := q.QueryRow(ctx, `SELECT count(*) FROM task_notes WHERE n = $1`, t.N).Scan(&t.NoteCount); err != nil {
		return err
	}
	t.Notes = []TaskNote{}
	if t.NoteCount == 0 {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT by, root, text, kind, at FROM (
		(SELECT id, by, root, text, kind, at FROM task_notes WHERE n = $1 ORDER BY id DESC LIMIT $3)
		UNION
		(SELECT id, by, root, text, kind, at FROM task_notes WHERE n = $1 AND (root = $2 OR by = $2) ORDER BY id DESC LIMIT $3)
		) x ORDER BY id`, t.N, creatorKey(t), shownNotes)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var nt TaskNote
		if err := rows.Scan(&nt.By, &nt.Root, &nt.Text, &nt.Kind, &nt.At); err != nil {
			return err
		}
		if nt.Kind == "note" {
			nt.Kind = ""
		}
		t.Notes = append(t.Notes, nt)
	}
	return rows.Err()
}

// creatorKey is the value notes of the creator match on (root; anonymous rows have none).
func creatorKey(t *Task) string {
	if t.Root != "" {
		return t.Root
	}
	return "\x00"
}

// GetTask returns task n with its notes and the extra lines of the TaskExtra chain. Hidden tasks
// read as absent; quarantined ones are visible at their permalink.
func (s *Service) GetTask(ctx context.Context, n int64) (*Task, error) {
	return s.getTask(ctx, s.d.DB, n)
}

func (s *Service) getTask(ctx context.Context, q core.Q, n int64) (*Task, error) {
	t, err := s.loadTask(ctx, q, n)
	if err != nil {
		return nil, err
	}
	if t.raw == "hidden" {
		return nil, core.ErrNotFound
	}
	if err := s.loadNotes(ctx, q, t); err != nil {
		return nil, err
	}
	t.Extra = extraLines(ctx, q, n)
	if t.claimed() && ClaimLineFn != nil {
		t.ClaimLine = strings.TrimSpace(safeLine(ClaimLineFn(ctx, q, t.Holder)))
	}
	return t, nil
}

// extraLines runs TaskExtra then every TaskExtras entry; each line is made single-line.
func extraLines(ctx context.Context, q core.Q, n int64) []string {
	var out []string
	fns := TaskExtras
	if TaskExtra != nil {
		fns = append([]func(context.Context, core.Q, int64) []string{TaskExtra}, fns...)
	}
	for _, fn := range fns {
		for _, l := range fn(ctx, q, n) {
			if l = strings.TrimSpace(safeLine(l)); l != "" {
				out = append(out, l)
			}
		}
	}
	return out
}

// ListOpts filters GET /v1/t (7.2).
type ListOpts struct {
	State, Q, Space, Tag, After string
	K                           int
	Quarantine                  bool
}

// ListTasks is the v1 entry point: state open|claimed|done (default open) matching q.
func (s *Service) ListTasks(ctx context.Context, state, q string) ([]TaskLine, error) {
	ls, _, err := s.List(ctx, ListOpts{State: state, Q: q})
	return ls, err
}

// tsquery builds an OR'ed tsquery from free text; each token is quoted so punctuation is safe.
func tsquery(s string) string {
	var toks []string
	for _, t := range strings.FieldsFunc(s, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune(`'"\|&!()<>:;,`, r)
	}) {
		if strings.IndexFunc(t, func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) }) < 0 {
			continue
		}
		toks = append(toks, "'"+t+"'")
		if len(toks) == 32 {
			break
		}
	}
	return strings.Join(toks, " | ")
}

// List returns up to k tasks (newest first) and the keyset cursor after the last row when the
// page was full.
func (s *Service) List(ctx context.Context, o ListOpts) ([]TaskLine, string, error) {
	if o.State == "" {
		o.State = "open"
	}
	if o.K <= 0 || o.K > listLimit {
		o.K = listLimit
	}
	var where []string
	var args []any
	arg := func(v any) string {
		args = append(args, v)
		return "$" + strconv.Itoa(len(args))
	}
	switch o.State {
	case "open":
		where = append(where, "t.state = 'open' AND c.n IS NULL")
	case "claimed":
		where = append(where, "t.state = 'open' AND c.n IS NOT NULL")
	case "done":
		where = append(where, "t.state = 'done'")
	case "all":
		where = append(where, "t.state <> 'hidden'")
	default:
		return nil, "", core.Bad("s must be open|claimed|done")
	}
	if o.Quarantine {
		where = append(where, "t.quarantine")
	} else {
		where = append(where, "NOT t.quarantine")
	}
	if o.Q != "" {
		if len(o.Q) > maxQuery || !oneLine(o.Q) {
			return nil, "", core.Bad("q must be one line <= 120")
		}
		tq := tsquery(o.Q)
		if tq == "" {
			return []TaskLine{}, "", nil
		}
		where = append(where, "t.tsv @@ to_tsquery('english', "+arg(tq)+")")
	}
	if o.Space != "" {
		if !spaceRe.MatchString(o.Space) {
			return nil, "", core.Bad("bad space")
		}
		where = append(where, "t.space = "+arg(o.Space))
	}
	if o.Tag != "" {
		if !tagRe.MatchString(o.Tag) {
			return nil, "", core.Bad("bad tag")
		}
		where = append(where, arg(o.Tag)+" = ANY(t.tags)")
	}
	if o.After != "" {
		ts, id, ok := doc.DecodeCursor(o.After)
		an, err := strconv.ParseInt(id, 10, 64)
		if !ok || err != nil {
			return nil, "", core.Bad("bad after cursor")
		}
		where = append(where, "(t.created, t.n) < ("+arg(ts)+", "+arg(an)+")")
	}
	sql := `SELECT t.n, t.title, t.state, t.created, t.quarantine, coalesce(c.id, '') FROM tasks t
		LEFT JOIN task_claims c ON c.n = t.n AND c.until > now()
		WHERE ` + strings.Join(where, " AND ") + ` ORDER BY t.created DESC, t.n DESC LIMIT ` + arg(o.K)
	rows, err := s.d.DB.Query(ctx, sql, args...)
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	out := []TaskLine{}
	var lastTS time.Time
	for rows.Next() {
		var l TaskLine
		var raw, cid string
		var quarantine bool
		if err := rows.Scan(&l.N, &l.Title, &raw, &lastTS, &quarantine, &cid); err != nil {
			return nil, "", err
		}
		l.State = stateOf(raw, cid)
		if quarantine {
			l.State += "?"
		}
		out = append(out, l)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	cursor := ""
	if len(out) == o.K {
		cursor = doc.Cursor(lastTS, itoa(out[len(out)-1].N))
	}
	return out, cursor, nil
}

func fmtList(ls []TaskLine) string {
	var b strings.Builder
	for _, l := range ls {
		fmt.Fprintf(&b, "#%d %s %s\n", l.N, l.State, safeLine(l.Title))
	}
	return b.String()
}

// fmtTask renders the compact text: the v1 lines (head, title, body, tags, notes, note rows) with
// appended head fields (until= fence= ask quarantine, ClaimLineFn), then the v2 lines (space:,
// ask:, hazard:, TaskExtra chain). Multi-line user text is indented so no user line can masquerade
// as a header, a field or a "- <id> <date>:" row.
func fmtTask(t *Task) string {
	var b strings.Builder
	fmt.Fprintf(&b, "#%d %s by %s %s", t.N, t.State, t.By, core.Date(t.Created))
	if t.Until != nil {
		fmt.Fprintf(&b, " until=%s fence=%d", core.Date(*t.Until), t.Fence)
	}
	if t.Ask != "" {
		b.WriteString(" ask")
	}
	if t.Quarantine {
		b.WriteString(" quarantine")
	}
	if t.ClaimLine != "" {
		b.WriteString(" " + t.ClaimLine)
	}
	b.WriteByte('\n')
	fmt.Fprintf(&b, "title: %s\n", safeLine(t.Title))
	if t.Body != "" {
		fmt.Fprintf(&b, "body: %s\n", indent(t.Body))
	}
	if len(t.Tags) > 0 {
		b.WriteString(tagsLinePfx + strings.Join(t.Tags, ",") + "\n")
	}
	if t.NoteCount > 0 {
		fmt.Fprintf(&b, "notes: %d\n", t.NoteCount)
	}
	for _, n := range t.Notes {
		fmt.Fprintf(&b, "- %s %s: %s\n", safeLine(n.By), core.Date(n.At), indent(strings.TrimSpace(n.Text)))
	}
	if t.Space != "" {
		fmt.Fprintf(&b, "space: %s\n", safeLine(t.Space))
	}
	if t.Ask != "" {
		fmt.Fprintf(&b, "ask: %s\n", indent(strings.TrimSpace(t.Ask)))
	}
	if len(t.Hazard) > 0 {
		b.WriteString("hazard: " + strings.Join(t.Hazard, ",") + "\n")
	}
	for _, l := range t.Extra {
		b.WriteString(l + "\n")
	}
	return b.String()
}

// taskNext is the next: tail of a task detail (<= 4 actions).
func taskNext(t *Task) []doc.Action {
	p := "/v1/t/" + itoa(t.N)
	switch {
	case t.Quarantine:
		return []doc.Action{doc.POST(p+"/ok", "L2 confirm"), doc.POST(p+"/bad", ""), doc.GET("/quarantine", "")}
	case t.raw == "done":
		return []doc.Action{doc.GET("/v1/t?s=done", ""), doc.GET("/v1/t", "")}
	case t.claimed():
		return []doc.Action{doc.POST(p+"/note", ""), doc.POST(p+"/done", ""), doc.POST(p+"/ask", "holder"), doc.POST(p+"/drop", "")}
	}
	return []doc.Action{doc.POST(p+"/claim", ""), doc.POST(p+"/note", ""), doc.GET("/t/"+itoa(t.N), "")}
}

func actionStrings(acts []doc.Action) []string {
	out := make([]string, 0, len(acts))
	for _, a := range acts {
		out = append(out, a.String())
	}
	return out
}

// --- create ---

// TaskInput is the create payload (v1 fields + space, context_id); the non-JSON fields carry the
// anonymous writer's network keys and the registered extension fields for TaskCreateHookFn.
type TaskInput struct {
	Title     string   `json:"title"`
	Body      string   `json:"body"`
	Tags      []string `json:"tags"`
	Space     string   `json:"space"`
	ContextID string   `json:"context_id"`

	Anon       bool            `json:"-"`
	Grp, Super string          `json:"-"`
	Extra      json.RawMessage `json:"-"`
}

// Created is the result of a task creation.
type Created struct {
	N          int64
	Quarantine bool
	Masked     []string
	Hazard     []string
}

func validateTask(in *TaskInput) error {
	in.Title = strings.TrimSpace(scrub.Normalize(in.Title))
	if in.Title == "" || len(in.Title) > maxTitle || !oneLine(in.Title) {
		return core.Bad("title required, one line without control characters, <=160")
	}
	in.Body = strings.TrimRight(cleanMulti(scrub.Normalize(in.Body)), " \t\n")
	if len(in.Body) > maxBody {
		return core.Bad("body <=4000")
	}
	if len(in.Tags) > maxTags {
		return core.Bad("tags <=8")
	}
	for _, t := range in.Tags {
		if !tagRe.MatchString(t) || t == labelClaimed || t == labelHidden {
			return core.Bad("bad tag " + safeLine(t))
		}
	}
	if in.Tags == nil {
		in.Tags = []string{}
	}
	if in.Space != "" && !spaceRe.MatchString(in.Space) {
		return core.Bad("bad space")
	}
	if in.ContextID != "" && (len(in.ContextID) > maxContextID || !oneLine(in.ContextID)) {
		return core.Bad("context_id one line <=64")
	}
	return nil
}

// CreateTask creates a task for id (nil only for anonymous input with in.Anon) and returns its
// number: scrub (tier 1 rejects, tier 2 masks), lexicon, hazards, trust caps, TemplateCheck,
// core.Origin/Event/Audit, TaskCreateHookFn, mirror. Anonymous and lexicon-flagged tasks land in
// quarantine (4.4).
func CreateTask(ctx context.Context, d *core.Deps, id *core.Ident, in TaskInput) (int64, error) {
	c, err := svc(d).create(ctx, id, in)
	return c.N, err
}

// CreateTask is the v1 method shape (title, body, tags).
func (s *Service) CreateTask(ctx context.Context, id *core.Ident, title, body string, tags []string) (int64, error) {
	c, err := s.create(ctx, id, TaskInput{Title: title, Body: body, Tags: tags})
	return c.N, err
}

func (s *Service) create(ctx context.Context, id *core.Ident, in TaskInput) (Created, error) {
	var out Created
	if in.Anon {
		if in.Grp == "" {
			return out, core.E(400, "pow", "X-PoW required")
		}
		if s.d.Frozen("write") {
			return out, core.Frozen("write")
		}
		id = nil
	} else if err := s.writeAuth(id); err != nil {
		return out, err
	}
	if err := validateTask(&in); err != nil {
		return out, err
	}
	masked, aerr := scrub.RejectOrMask(map[string]*string{"title": &in.Title, "body": &in.Body})
	if aerr != nil {
		return out, aerr
	}
	score, flags, _ := scrub.Flags(in.Title + "\n" + in.Body)
	hazard := scrub.Hazards(in.Title + "\n" + in.Body)
	if hazard == nil {
		hazard = []string{}
	}
	if flags == nil {
		flags = []string{}
	}
	quarantine := in.Anon || score >= 2
	by, root := anonID, ""
	if id != nil {
		by, root = id.ID, id.Root
	}
	ip, _, _ := core.ClientFrom(ctx)
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if in.Anon {
			if err := core.UseNetQuota(ctx, tx, in.Grp, "wt", anonPerGroup); err != nil {
				return err
			}
			var total, bySuper int
			if err := tx.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE anon_super = $1) FROM tasks WHERE quarantine`, in.Super).Scan(&total, &bySuper); err != nil {
				return err
			}
			if total >= maxQuarantine || bySuper >= maxQuarSuper {
				return core.E(429, "quota", "quarantine full, retry later")
			}
		} else {
			st, err := trust.Load(ctx, tx, id.Root)
			if err != nil {
				return err
			}
			if err := trust.UseCap(ctx, tx, st, "t"); err != nil {
				return err
			}
		}
		if in.Space != "" && TemplateCheck != nil {
			if e := TemplateCheck(ctx, tx, in.Space, in.Body); e != nil {
				return e
			}
		}
		err := tx.QueryRow(ctx, `INSERT INTO tasks (n, id, root, title, body, tags, state, space, context_id, quarantine, anon_grp, anon_super, hazard, flags, scrub_v, created)
			VALUES (nextval('task_n_seq'), $1, $2, $3, $4, $5, 'open', $6, $7, $8, $9, $10, $11, $12, $13, now()) RETURNING n`,
			by, root, in.Title, in.Body, in.Tags, in.Space, in.ContextID, quarantine, in.Grp, in.Super, hazard, flags, scrub.RulesV).Scan(&out.N)
		if err != nil {
			return err
		}
		ref := itoa(out.N)
		if err := core.Origin(ctx, tx, "t", ref, root, by, ip); err != nil {
			return err
		}
		if !quarantine {
			if err := core.Event(ctx, tx, "t", ref, "", "task "+in.Title); err != nil {
				return err
			}
		}
		if id != nil {
			if err := core.Audit(ctx, tx, id.ID, "tp", ref, 0); err != nil {
				return err
			}
		}
		if TaskCreateHookFn != nil && len(in.Extra) > 0 {
			if err := TaskCreateHookFn(ctx, tx, out.N, in.Extra); err != nil {
				return err
			}
		}
		if quarantine {
			return nil
		}
		return s.mirrorTask(ctx, tx, out.N)
	})
	if err != nil {
		return Created{}, err
	}
	out.Quarantine, out.Masked, out.Hazard = quarantine, masked, hazard
	return out, nil
}

// createText is the create reply: "#<n>[ quarantine][ masked=a,b][ hazard=x,y]".
func createText(c Created) string {
	s := fmtN(c.N)
	if c.Quarantine {
		s += " quarantine"
	}
	if len(c.Masked) > 0 {
		s += " masked=" + strings.Join(c.Masked, ",")
	}
	if len(c.Hazard) > 0 {
		s += " hazard=" + strings.Join(c.Hazard, ",")
	}
	return s
}

// --- claims ---

// openState returns the task's raw state or notfound (hidden) / 409 bad closed (done).
func openState(ctx context.Context, q core.Q, n int64) (root string, err error) {
	var state string
	err = q.QueryRow(ctx, `SELECT state, root FROM tasks WHERE n = $1`, n).Scan(&state, &root)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && state == "hidden") {
		return "", core.ErrNotFound
	}
	if err != nil {
		return "", err
	}
	if state == "done" {
		return root, core.E(409, "bad", "task closed")
	}
	return root, nil
}

// Claim atomically takes or renews the claim on n for 24h (per root); v1 shape (until only).
func (s *Service) Claim(ctx context.Context, id *core.Ident, n int64) (time.Time, error) {
	until, _, err := s.ClaimFenced(ctx, id, n)
	return until, err
}

// ClaimFenced is Claim returning the fence too. 409 taken when held by another root; a root holds
// at most maxLiveClaims live claims (429 quota) and a renewal never extends a claim past
// maxClaimLife after it was first taken (429 quota). The fence increments when a different root
// takes the task; ClaimCheckFn is consulted first (27.4).
func (s *Service) ClaimFenced(ctx context.Context, id *core.Ident, n int64) (time.Time, int64, error) {
	if err := s.writeAuth(id); err != nil {
		return time.Time{}, 0, err
	}
	var until time.Time
	var fence int64
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		// Serialise this root's claims so the live-claim cap cannot be raced from parallel requests.
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('claim:' || $1))`, id.Root); err != nil {
			return err
		}
		if _, err := openState(ctx, tx, n); err != nil {
			return err
		}
		if ClaimCheckFn != nil {
			if e := ClaimCheckFn(ctx, tx, n, id.Root); e != nil {
				return e
			}
		}
		var cid, croot string
		var cuntil time.Time
		err := tx.QueryRow(ctx, `SELECT id, root, until FROM task_claims WHERE n = $1 FOR UPDATE`, n).Scan(&cid, &croot, &cuntil)
		live := err == nil && cuntil.After(time.Now())
		switch {
		case err != nil && !errors.Is(err, pgx.ErrNoRows):
			return err
		case live && croot != id.Root:
			return core.E(409, "taken", cid+" "+core.Date(cuntil))
		case live: // renewal by the holder, bounded by the lifetime since the first claim
			err = tx.QueryRow(ctx, `UPDATE task_claims SET id = $2, until = least(now() + $3, since + $4)
				WHERE n = $1 AND since + $4 > now() RETURNING until, fence`, n, id.ID, claimTTL, maxClaimLife).Scan(&until, &fence)
			if errors.Is(err, pgx.ErrNoRows) {
				return core.E(429, "quota", "claim lifetime 72h reached: drop it or let it expire")
			}
			return err
		}
		var count int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM task_claims WHERE root = $1 AND until > now() AND n <> $2`, id.Root, n).Scan(&count); err != nil {
			return err
		}
		if count >= maxLiveClaims {
			return core.E(429, "quota", fmt.Sprintf("max %d live claims per root", maxLiveClaims))
		}
		err = tx.QueryRow(ctx, `INSERT INTO task_claims (n, id, root, until, since, fence) VALUES ($1, $2, $3, now() + $4, now(), $5)
			ON CONFLICT (n) DO UPDATE SET id = EXCLUDED.id, root = EXCLUDED.root, until = EXCLUDED.until, since = EXCLUDED.since,
				fence = task_claims.fence + CASE WHEN task_claims.root <> EXCLUDED.root THEN 1 ELSE 0 END
			WHERE task_claims.until < now()
			RETURNING until, fence`, n, id.ID, id.Root, claimTTL, fenceFirst).Scan(&until, &fence)
		if errors.Is(err, pgx.ErrNoRows) { // lost the race to another root between our SELECT and INSERT
			var c claimRow
			if err := tx.QueryRow(ctx, `SELECT id, until FROM task_claims WHERE n = $1`, n).Scan(&c.ID, &c.Until); err != nil {
				return err
			}
			return core.E(409, "taken", c.ID+" "+core.Date(c.Until))
		}
		if err != nil {
			return err
		}
		if err := s.afterClaim(ctx, tx, n, id.ID, "claimed"); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "tc", itoa(n), 0)
	})
	if err != nil {
		return time.Time{}, 0, err
	}
	s.d.Notify.Wake(TaskTopic(n))
	return until, fence, nil
}

type claimRow struct {
	ID, Root string
	Until    time.Time
	Fence    int64
}

// afterClaim records the event and refreshes the mirror after a claim change.
func (s *Service) afterClaim(ctx context.Context, q core.Q, n int64, by, verb string) error {
	if err := core.Event(ctx, q, "t", itoa(n), "", verb+" by "+by); err != nil {
		return err
	}
	return s.mirrorTask(ctx, q, n)
}

// ClaimFence returns the task's current fence and the holder root ("" when no live claim).
func ClaimFence(ctx context.Context, q core.Q, n int64) (fence int64, holderRoot string, err error) {
	var until time.Time
	err = q.QueryRow(ctx, `SELECT fence, root, until FROM task_claims WHERE n = $1`, n).Scan(&fence, &holderRoot, &until)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, "", nil
	}
	if err != nil {
		return 0, "", err
	}
	if !until.After(time.Now()) {
		holderRoot = ""
	}
	return fence, holderRoot, nil
}

// ClaimAssign gives the claim on n to id (root) for ttl regardless of the current holder (auction
// awards, 27.4): fence + 1, since reset. The task must be open.
func ClaimAssign(ctx context.Context, q core.Q, n int64, id, root string, ttl time.Duration) (int64, error) {
	if ttl <= 0 || ttl > maxClaimLife {
		ttl = claimTTL
	}
	if _, err := openState(ctx, q, n); err != nil {
		return 0, err
	}
	var fence int64
	err := q.QueryRow(ctx, `INSERT INTO task_claims (n, id, root, until, since, fence) VALUES ($1, $2, $3, now() + $4, now(), $5)
		ON CONFLICT (n) DO UPDATE SET id = EXCLUDED.id, root = EXCLUDED.root, until = EXCLUDED.until, since = EXCLUDED.since, fence = task_claims.fence + 1
		RETURNING fence`, n, id, root, ttl, fenceFirst).Scan(&fence)
	if err != nil {
		return 0, err
	}
	if err := core.Event(ctx, q, "t", itoa(n), "", "assigned to "+id); err != nil {
		return 0, err
	}
	mirrorTaskAny(ctx, q, n)
	wakeAll(TaskTopic(n))
	return fence, nil
}

// ClaimHandover passes the live claim on n from the holder owning fence to toID/toRoot (fence + 1)
// and writes the task note "handover -> <id>" (+ note); a stale fence answers 409 fenced.
func ClaimHandover(ctx context.Context, q core.Q, n, fence int64, toID, toRoot, note string) (int64, error) {
	if !core.ValidID(toID) || !core.ValidID(toRoot) {
		return 0, core.Bad("bad to")
	}
	note = strings.TrimSpace(cleanMulti(scrub.Normalize(note)))
	if len(note) > 1<<10 {
		return 0, core.Bad("note <=1024")
	}
	var fromID, fromRoot string
	var newFence int64
	err := q.QueryRow(ctx, `UPDATE task_claims c SET id = $3, root = $4, fence = c.fence + 1,
			since = CASE WHEN c.root = $4 THEN c.since ELSE now() END
		FROM (SELECT id, root FROM task_claims WHERE n = $1 FOR UPDATE) o
		WHERE c.n = $1 AND c.fence = $2 AND c.until > now()
		RETURNING o.id, o.root, c.fence`, n, fence, toID, toRoot).Scan(&fromID, &fromRoot, &newFence)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, core.E(409, "fenced", "claim fence")
	}
	if err != nil {
		return 0, err
	}
	text := "handover -> " + toID
	if note != "" {
		text += "\n" + note
	}
	if _, err := q.Exec(ctx, `INSERT INTO task_notes (n, by, root, text, kind) VALUES ($1, $2, $3, $4, 'note')`, n, fromID, fromRoot, text); err != nil {
		return 0, err
	}
	if err := core.Event(ctx, q, "t", itoa(n), "", "handover to "+toID); err != nil {
		return 0, err
	}
	mirrorTaskAny(ctx, q, n)
	wakeAll(TaskTopic(n))
	return newFence, nil
}

// holder reports whether the caller's root holds the live claim on n.
func holder(ctx context.Context, q core.Q, root string, n int64) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM task_claims WHERE n = $1 AND root = $2 AND until > now())`, n, root).Scan(&ok)
	return ok, err
}

// Drop releases the caller's claim on n (v1 method).
func (s *Service) Drop(ctx context.Context, id *core.Ident, n int64) error {
	if err := s.writeAuth(id); err != nil {
		return err
	}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := dropClaim(ctx, tx, n, id.Root); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "tdrop", itoa(n), 0); err != nil {
			return err
		}
		return s.mirrorTask(ctx, tx, n)
	})
	if err != nil {
		return err
	}
	s.d.Notify.Wake(TaskTopic(n))
	return nil
}

// Drop releases root's live claim on n (sessions' dead-man plans, 27.3).
func Drop(ctx context.Context, q core.Q, n int64, root string) error {
	if err := dropClaim(ctx, q, n, root); err != nil {
		return err
	}
	mirrorTaskAny(ctx, q, n)
	wakeAll(TaskTopic(n))
	return nil
}

func dropClaim(ctx context.Context, q core.Q, n int64, root string) error {
	var state string
	err := q.QueryRow(ctx, `SELECT state FROM tasks WHERE n = $1`, n).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && state == "hidden") {
		return core.ErrNotFound
	}
	if err != nil {
		return err
	}
	tag, err := q.Exec(ctx, `UPDATE task_claims SET until = now() WHERE n = $1 AND root = $2 AND until > now()`, n, root)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.E(403, "auth", "not holder")
	}
	return core.Event(ctx, q, "t", itoa(n), "", "dropped")
}

// --- notes on tasks, done, ask ---

// noteText validates and scrubs a task note (tier 1 rejects, tier 2 masks).
func noteText(text string, required bool) (string, error) {
	text = strings.TrimSpace(cleanMulti(scrub.Normalize(text)))
	if text == "" {
		if required {
			return "", core.Bad("text required, <=2000")
		}
		return "", nil
	}
	if len(text) > maxNoteText {
		return "", core.Bad("text <=2000")
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"text": &text}); aerr != nil {
		return "", aerr
	}
	return text, nil
}

// addNote inserts a note of kind by (id, root) after the tn cap; a creator's note answers the
// open ask (19.2). The task must exist and not be hidden.
func addNote(ctx context.Context, q core.Q, n int64, by, root, text, kind string) error {
	var state, croot, ask string
	err := q.QueryRow(ctx, `SELECT state, root, ask FROM tasks WHERE n = $1 FOR UPDATE`, n).Scan(&state, &croot, &ask)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && state == "hidden") {
		return core.ErrNotFound
	}
	if err != nil {
		return err
	}
	if root != "" {
		st, err := trust.Load(ctx, q, root)
		if err != nil {
			return err
		}
		if err := trust.UseCap(ctx, q, st, "tn"); err != nil {
			return err
		}
	}
	if _, err := q.Exec(ctx, `INSERT INTO task_notes (n, by, root, text, kind) VALUES ($1, $2, $3, $4, $5)`, n, by, root, text, kind); err != nil {
		return err
	}
	if kind == "note" && ask != "" && root != "" && root == croot {
		if _, err := q.Exec(ctx, `UPDATE tasks SET ask = '' WHERE n = $1`, n); err != nil {
			return err
		}
	}
	if kind != "done" {
		if err := core.Audit(ctx, q, by, "t"+kind[:1], itoa(n), 0); err != nil {
			return err
		}
	}
	return core.Event(ctx, q, "t", itoa(n), "", kind+" by "+by)
}

// AddNote comments on task n.
func (s *Service) AddNote(ctx context.Context, id *core.Ident, n int64, text string) error {
	if err := s.writeAuth(id); err != nil {
		return err
	}
	text, err := noteText(text, true)
	if err != nil {
		return err
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := addNote(ctx, tx, n, id.ID, id.Root, text, "note"); err != nil {
			return err
		}
		return s.mirrorTask(ctx, tx, n)
	})
	if err != nil {
		return err
	}
	s.d.Notify.Wake(TaskTopic(n))
	return nil
}

// AddNoteAs writes a note on behalf of identity id/root (sessions' dead-man plans): quotas and
// scrub apply as for the owner's own request.
func AddNoteAs(ctx context.Context, q core.Q, n int64, id, root, text string) error {
	if !core.ValidID(id) || !core.ValidID(root) {
		return core.ErrAuth
	}
	text, err := noteText(text, true)
	if err != nil {
		return err
	}
	if err := addNote(ctx, q, n, id, root, text, "note"); err != nil {
		return err
	}
	mirrorTaskAny(ctx, q, n)
	wakeAll(TaskTopic(n))
	return nil
}

// Done closes task n (holder or creator), with an optional closing note.
func (s *Service) Done(ctx context.Context, id *core.Ident, n int64, text string) error {
	if err := s.writeAuth(id); err != nil {
		return err
	}
	text, err := noteText(text, false)
	if err != nil {
		return err
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		croot, err := openState(ctx, tx, n)
		if err != nil {
			return err
		}
		h, err := holder(ctx, tx, id.Root, n)
		if err != nil {
			return err
		}
		if !h && croot != id.Root {
			return core.E(403, "auth", "holder or creator only")
		}
		if text != "" {
			if err := addNote(ctx, tx, n, id.ID, id.Root, text, "done"); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE tasks SET state = 'done', closed_at = now(), ask = '' WHERE n = $1`, n); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE task_claims SET until = now() WHERE n = $1 AND until > now()`, n); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "td", itoa(n), 0); err != nil {
			return err
		}
		if err := core.Event(ctx, tx, "t", itoa(n), "", "done by "+id.ID); err != nil {
			return err
		}
		return s.mirrorTask(ctx, tx, n)
	})
	if err != nil {
		return err
	}
	s.d.Notify.Wake(TaskTopic(n))
	return nil
}

// Ask records the holder's question to the creator (note kind ask, tasks.ask set): the task shows
// `ask` in its head and maps to A2A input-required (19.2).
func (s *Service) Ask(ctx context.Context, id *core.Ident, n int64, text string) error {
	if err := s.writeAuth(id); err != nil {
		return err
	}
	text, err := noteText(text, true)
	if err != nil {
		return err
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := openState(ctx, tx, n); err != nil {
			return err
		}
		h, err := holder(ctx, tx, id.Root, n)
		if err != nil {
			return err
		}
		if !h {
			return core.E(403, "auth", "holder only")
		}
		if err := addNote(ctx, tx, n, id.ID, id.Root, text, "ask"); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE tasks SET ask = $2 WHERE n = $1`, n, text); err != nil {
			return err
		}
		return s.mirrorTask(ctx, tx, n)
	})
	if err != nil {
		return err
	}
	s.d.Notify.Wake(TaskTopic(n))
	return nil
}

// --- votes (tok / tbad) ---

// Vote records an ok/bad vote on task n (one per root, no self-vote, weight trust.Weight) and
// applies the quarantine rules (4.4): 2 ok from L2 roots in distinct super-groups promote, one L2
// bad deletes a quarantined task; otherwise collapsed bad_w >= ok_w + 2 hides it. Votes never
// mirror. Returns "ok", "ok promoted", "ok deleted" or "ok hidden".
func (s *Service) Vote(ctx context.Context, id *core.Ident, n int64, up bool, note string) (string, error) {
	if err := s.writeAuth(id); err != nil {
		return "", err
	}
	note = strings.TrimSpace(scrub.Normalize(note))
	max := maxWhy
	if up {
		max = maxVoteNote
	}
	if len(note) > max || !oneLine(note) {
		return "", core.Bad(fmt.Sprintf("note one line <=%d", max))
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"note": &note}); aerr != nil {
		return "", aerr
	}
	out := "ok"
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		t, err := s.loadTaskLocked(ctx, tx, n)
		if err != nil {
			return err
		}
		if t.Root != "" && t.Root == id.Root {
			return core.E(403, "auth", "no self vote")
		}
		st, err := trust.Load(ctx, tx, id.Root)
		if err != nil {
			return err
		}
		w, lvl := trust.Weight(st), st.Level()
		if _, err := tx.Exec(ctx, `INSERT INTO task_votes (n, root, up, w, note, ip_group, ip_super) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			n, id.Root, up, w, note, st.Group, st.Super); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "dup", "already voted")
			}
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, map[bool]string{true: "tok", false: "tbad"}[up], itoa(n), 0); err != nil {
			return err
		}
		if up {
			if _, err := tx.Exec(ctx, `UPDATE tasks SET ok_w = ok_w + $2 WHERE n = $1`, n, w); err != nil {
				return err
			}
			if t.Quarantine {
				promoted, err := s.promote(ctx, tx, t)
				if err != nil {
					return err
				}
				if promoted {
					out = "ok promoted"
				}
			}
			return nil
		}
		if t.Quarantine && lvl >= 2 {
			if _, err := tx.Exec(ctx, `DELETE FROM tasks WHERE n = $1`, n); err != nil {
				return err
			}
			out = "ok deleted"
			return nil
		}
		if _, err := tx.Exec(ctx, `UPDATE tasks SET bad_w = bad_w + $2 WHERE n = $1`, n, w); err != nil {
			return err
		}
		okSum, badSum, err := collapsed(ctx, tx, n)
		if err != nil {
			return err
		}
		if badSum >= okSum+2 && t.raw != "hidden" {
			if err := s.setHidden(ctx, tx, n, true); err != nil {
				return err
			}
			if t.Root != "" {
				if _, err := core.AddRep(ctx, tx, t.Root, -1, "", 0); err != nil {
					return err
				}
			}
			if err := penaliseConfirmers(ctx, tx, n); err != nil {
				return err
			}
			out = "ok hidden"
		}
		return nil
	})
	return out, err
}

func (s *Service) loadTaskLocked(ctx context.Context, tx pgx.Tx, n int64) (*Task, error) {
	if _, err := tx.Exec(ctx, `SELECT 1 FROM tasks WHERE n = $1 FOR UPDATE`, n); err != nil {
		return nil, err
	}
	t, err := s.loadTask(ctx, tx, n)
	if err != nil {
		return nil, err
	}
	if t.raw == "hidden" {
		return nil, core.ErrNotFound
	}
	return t, nil
}

// collapsed sums ok and bad weights with one voter per super-group (4.1).
func collapsed(ctx context.Context, q core.Q, n int64) (ok, bad float64, err error) {
	for side, dst := range map[string]*float64{"up": &ok, "down": &bad} {
		if err = q.QueryRow(ctx, `SELECT coalesce(sum(w), 0) FROM (`+trust.CollapseSQLWhere("task_votes", side, "n = $1")+`) c`, n).Scan(dst); err != nil {
			return 0, 0, err
		}
	}
	return ok, bad, nil
}

// promote clears the quarantine once two L2 ok-voters from pairwise distinct super-groups (none the
// author's) have confirmed; voters earn nothing.
func (s *Service) promote(ctx context.Context, tx pgx.Tx, t *Task) (bool, error) {
	rows, err := tx.Query(ctx, `SELECT root, ip_super FROM task_votes WHERE n = $1 AND up ORDER BY created`, t.N)
	if err != nil {
		return false, err
	}
	type voter struct{ root, super string }
	var vs []voter
	for rows.Next() {
		var v voter
		if err := rows.Scan(&v.root, &v.super); err != nil {
			rows.Close()
			return false, err
		}
		vs = append(vs, v)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, err
	}
	authorSuper := t.Quarantine && t.Root == ""
	aSuper := ""
	if authorSuper {
		var grp string
		if err := tx.QueryRow(ctx, `SELECT anon_grp, anon_super FROM tasks WHERE n = $1`, t.N).Scan(&grp, &aSuper); err != nil {
			return false, err
		}
	} else if t.Root != "" {
		if st, err := trust.Load(ctx, tx, t.Root); err == nil {
			aSuper = st.Super
		}
	}
	var l2 []string
	for _, v := range vs {
		if aSuper != "" && v.super == aSuper {
			continue
		}
		if trust.LevelOf(ctx, tx, v.root) >= 2 {
			l2 = append(l2, v.root)
		}
	}
	found := false
	for i := 0; i < len(l2) && !found; i++ {
		for j := i + 1; j < len(l2) && !found; j++ {
			ok, err := trust.Distinct(ctx, tx, l2[i], l2[j])
			if err != nil {
				return false, err
			}
			found = ok
		}
	}
	if !found {
		return false, nil
	}
	if _, err := tx.Exec(ctx, `UPDATE tasks SET quarantine = false, confirmed_at = now() WHERE n = $1`, t.N); err != nil {
		return false, err
	}
	if err := core.Event(ctx, tx, "t", itoa(t.N), "", "task "+t.Title); err != nil {
		return false, err
	}
	return true, s.mirrorTask(ctx, tx, t.N)
}

// penaliseConfirmers costs the L2 ok-voters of a promoted task 2 rep when it is later hidden by votes.
func penaliseConfirmers(ctx context.Context, q core.Q, n int64) error {
	var confirmed bool
	if err := q.QueryRow(ctx, `SELECT confirmed_at IS NOT NULL FROM tasks WHERE n = $1`, n).Scan(&confirmed); err != nil {
		return err
	}
	if !confirmed {
		return nil
	}
	rows, err := q.Query(ctx, `SELECT root FROM task_votes WHERE n = $1 AND up`, n)
	if err != nil {
		return err
	}
	var roots []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			rows.Close()
			return err
		}
		roots = append(roots, r)
	}
	rows.Close()
	for _, r := range roots {
		if trust.LevelOf(ctx, q, r) >= 2 {
			if _, err := core.AddRep(ctx, q, r, -2, "", 0); err != nil {
				return err
			}
		}
	}
	return nil
}

// --- HTTP ---

func parseN(s string) (int64, error) {
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil || n <= 0 {
		return 0, core.Bad("bad task number")
	}
	return n, nil
}

func (s *Service) hList(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	k, _ := strconv.Atoi(qv.Get("k"))
	o := ListOpts{State: qv.Get("s"), Q: qv.Get("q"), Space: qv.Get("space"), Tag: qv.Get("tag"), After: qv.Get("after"), K: k,
		Quarantine: qv.Get("quarantine") == "1"}
	ls, cursor, err := s.List(r.Context(), o)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if core.WantJSON(r) {
		core.JSON(w, 200, ls)
		return
	}
	next := []doc.Action{doc.POST("/v1/t", "")}
	if cursor != "" {
		v := r.URL.Query()
		v.Set("after", cursor)
		next = append([]doc.Action{doc.GET("/v1/t?"+v.Encode(), "more")}, next...)
	}
	for _, st := range []string{"claimed", "done"} {
		if o.State != st {
			next = append(next, doc.GET("/v1/t?s="+st, ""))
		}
	}
	doc.Tail(w, r, fmtList(ls), next...)
}

func (s *Service) hGet(w http.ResponseWriter, r *http.Request) {
	n, err := parseN(r.PathValue("n"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	t, err := s.GetTask(r.Context(), n)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	next := taskNext(t)
	t.Next = actionStrings(next)
	reply(w, r, 200, fmtTask(t), t, next...)
}

// createIn is the POST /v1/t body: v1 fields plus space, context_id and the registered extension
// field `needs` (27.4), forwarded to TaskCreateHookFn.
type createIn struct {
	Title     string          `json:"title"`
	Body      string          `json:"body"`
	Tags      []string        `json:"tags"`
	Space     string          `json:"space"`
	ContextID string          `json:"context_id"`
	Needs     json.RawMessage `json:"needs"`
}

func (in createIn) input() TaskInput {
	ti := TaskInput{Title: in.Title, Body: in.Body, Tags: in.Tags, Space: in.Space, ContextID: in.ContextID}
	if len(in.Needs) > 0 && string(in.Needs) != "null" {
		ti.Extra = json.RawMessage(`{"needs":` + string(in.Needs) + `}`)
	}
	return ti
}

func (s *Service) hCreate(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in createIn
	if err := core.Decode(w, r, 16<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	s.created(w, r, id, in.input())
}

func (s *Service) created(w http.ResponseWriter, r *http.Request, id *core.Ident, in TaskInput) {
	c, err := s.create(r.Context(), id, in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	p := "/v1/t/" + itoa(c.N)
	status := 201
	next := []doc.Action{doc.POST(p+"/claim", ""), doc.GET(p, "")}
	if c.Quarantine {
		next = []doc.Action{doc.GET(p, ""), doc.GET("/quarantine", ""), doc.POST(p+"/ok", "2 L2 agents")}
		if in.Anon {
			status = 202
		}
	}
	j := map[string]any{"n": c.N}
	if c.Quarantine {
		j["quarantine"] = true
	}
	if len(c.Masked) > 0 {
		j["masked"] = c.Masked
	}
	if len(c.Hazard) > 0 {
		j["hazard"] = c.Hazard
	}
	reply(w, r, status, createText(c), j, next...)
}

// hCreateAnon serves POST /w/t: a bearer creates normally, X-PoW creates in quarantine (4.4).
func (s *Service) hCreateAnon(w http.ResponseWriter, r *http.Request) {
	id, grp, super, err := s.d.AuthOrPoW(w, r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in createIn
	if err := core.Decode(w, r, 16<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	ti := in.input()
	if id == nil {
		ti.Anon, ti.Grp, ti.Super = true, grp, super
	}
	s.created(w, r, id, ti)
}

func (s *Service) hClaim(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	n, err := parseN(r.PathValue("n"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	until, fence, err := s.ClaimFenced(r.Context(), id, n)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	p := "/v1/t/" + itoa(n)
	reply(w, r, 200, claimText(until, fence), map[string]any{"ok": true, "until": until.UTC().Format(time.RFC3339), "fence": fence},
		doc.POST(p+"/note", ""), doc.POST(p+"/done", ""), doc.POST(p+"/ask", ""), doc.POST(p+"/drop", ""))
}

func claimText(until time.Time, fence int64) string {
	return fmt.Sprintf("ok until %s fence=%d", core.Date(until), fence)
}

type textIn struct {
	Text string `json:"text"`
}

// hTask is the shared shape of drop/note/done/ask: auth, n, optional {"text"}, "ok".
func (s *Service) hTask(max int64, fn func(ctx context.Context, id *core.Ident, n int64, text string) error, next func(n int64) []doc.Action) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.d.AuthWrite(r)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		n, err := parseN(r.PathValue("n"))
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		var in textIn
		if max > 0 {
			if err := core.Decode(w, r, max, &in); err != nil {
				core.Fail(w, r, err)
				return
			}
		}
		if err := fn(r.Context(), id, n, in.Text); err != nil {
			core.Fail(w, r, err)
			return
		}
		reply(w, r, 200, "ok", map[string]bool{"ok": true}, next(n)...)
	}
}

func getNext(n int64) []doc.Action { return []doc.Action{doc.GET("/v1/t/"+itoa(n), "")} }

func (s *Service) hDrop(w http.ResponseWriter, r *http.Request) {
	s.hTask(0, func(ctx context.Context, id *core.Ident, n int64, _ string) error { return s.Drop(ctx, id, n) }, func(n int64) []doc.Action {
		return []doc.Action{doc.POST("/v1/t/"+itoa(n)+"/claim", ""), doc.GET("/v1/t", "")}
	})(w, r)
}

func (s *Service) hNote(w http.ResponseWriter, r *http.Request) {
	s.hTask(8<<10, s.AddNote, getNext)(w, r)
}

func (s *Service) hDone(w http.ResponseWriter, r *http.Request) {
	s.hTask(8<<10, s.Done, func(n int64) []doc.Action { return []doc.Action{doc.GET("/v1/t/"+itoa(n), ""), doc.GET("/v1/t", "")} })(w, r)
}

func (s *Service) hAsk(w http.ResponseWriter, r *http.Request) {
	s.hTask(8<<10, s.Ask, getNext)(w, r)
}

type voteIn struct {
	Note string `json:"note"`
	Why  string `json:"why"`
}

func (s *Service) hVote(up bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := s.d.AuthWrite(r)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		n, err := parseN(r.PathValue("n"))
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		var in voteIn
		if err := core.Decode(w, r, 4<<10, &in); err != nil {
			core.Fail(w, r, err)
			return
		}
		note := in.Note
		if !up {
			note = in.Why
		}
		out, err := s.Vote(r.Context(), id, n, up, note)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		reply(w, r, 200, out, map[string]any{"ok": true, "result": out}, doc.GET("/v1/t/"+itoa(n), ""), doc.GET("/quarantine", ""))
	}
}

// --- MCP ops ---

func decodeArgs(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

type nArg struct {
	N json.RawMessage `json:"n"` // number or string, "#" prefix tolerated
}

func (a nArg) num() (int64, error) {
	s := strings.TrimPrefix(strings.Trim(strings.TrimSpace(string(a.N)), `"`), "#")
	if s == "" {
		return 0, core.Bad("n required")
	}
	return parseN(s)
}

// Ops returns the board + notes MCP operations.
func Ops(d *core.Deps) map[string]Op {
	s := svc(d)
	m := map[string]Op{
		"t": func(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				S, Q, Space, Tag, After string
				K                       int
				Quarantine              bool
			}
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			ls, _, err := s.List(ctx, ListOpts{State: in.S, Q: in.Q, Space: in.Space, Tag: in.Tag, After: in.After, K: in.K, Quarantine: in.Quarantine})
			if err != nil {
				return "", err
			}
			return fmtList(ls), nil
		},
		"tg": func(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			var in nArg
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			n, err := in.num()
			if err != nil {
				return "", err
			}
			t, err := s.GetTask(ctx, n)
			if err != nil {
				return "", err
			}
			return fmtTask(t), nil
		},
		"tp": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in createIn
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			c, err := s.create(ctx, id, in.input())
			if err != nil {
				return "", err
			}
			return createText(c), nil
		},
		"tc": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in nArg
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			n, err := in.num()
			if err != nil {
				return "", err
			}
			until, fence, err := s.ClaimFenced(ctx, id, n)
			if err != nil {
				return "", err
			}
			return claimText(until, fence), nil
		},
		"tdrop": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in nArg
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			n, err := in.num()
			if err != nil {
				return "", err
			}
			if err := s.Drop(ctx, id, n); err != nil {
				return "", err
			}
			return "ok", nil
		},
	}
	for name, fn := range map[string]func(context.Context, *core.Ident, int64, string) error{"tn": s.AddNote, "td": s.Done, "ta": s.Ask} {
		fn := fn
		m[name] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				nArg
				Text string `json:"text"`
			}
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			n, err := in.num()
			if err != nil {
				return "", err
			}
			if err := fn(ctx, id, n, in.Text); err != nil {
				return "", err
			}
			return "ok", nil
		}
	}
	for name, up := range map[string]bool{"tok": true, "tbad": false} {
		up := up
		m[name] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				nArg
				voteIn
			}
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			n, err := in.num()
			if err != nil {
				return "", err
			}
			note := in.Note
			if !up {
				note = in.Why
			}
			return s.Vote(ctx, id, n, up, note)
		}
	}
	s.noteOps(m)
	return m
}
