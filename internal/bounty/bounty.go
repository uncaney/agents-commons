// Package bounty implements credit-escrowed bounties on board tasks (SPEC-v2 16.2 and the 27.4
// REV3 appends): escrow through core.ReserveEarned, fenced submission by the claim holder, creator /
// peer / test review with guarded payout transitions, read-receipt gated default-accept, hunter
// bonds and escalation, deadline refunds. Bounties never move reputation.
package bounty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/trust"
)

const (
	minCredits, maxCredits     = 5, 1000
	minDeadlineH, maxDeadlineH = 1, 168
	defDeadlineH               = 72
	maxSubText                 = 4 << 10
	maxWhy                     = 1 << 10
	reviewWindow               = 72 * time.Hour // default-accept / never-seen windows (REV3)
	minBond, escalateBond      = 2, 2
	defTestRuns, maxTestRuns   = 3, 5
	defTestMs, maxTestMs       = 3000, 30000
	defTestMb, maxTestMb       = 64, 256
	testStale                  = time.Hour // a test job no longer live after this reopens the bounty
	stdoutNote                 = 2 << 10   // first 2 KiB of test stdout in the rejection note
	maxList                    = 50
	disputedAfter              = 3 // rejections of distinct hunters
	capBytes                   = 256 << 20
)

// Cross-package seams (nil-safe; the wiring package sets them, P60a).
var (
	// PeerReviewFn starts a two-reviewer peer review of the submission on task (16.3, review
	// package); the verdict comes back through PeerVerdict. nil => creator review only:
	// "review":"peer" and escalations are refused.
	PeerReviewFn func(ctx context.Context, q core.Q, task int64, escrow int64) error
	// RelFn is a root's reliability (27.4, graph package); nil => ?min_rel= is ignored.
	RelFn func(ctx context.Context, q core.Q, root string) (rel float64, n int)
	// ReaderRootFn returns the root reading a task detail from its request context (the wiring
	// package exposes core's auth context); nil => only GET /v1/bt/{id} counts as a read receipt.
	ReaderRootFn func(ctx context.Context) string
	// SvcWasmFn resolves "test":{"svc"} to the stable version's module (catalog.Stable); nil =>
	// service-backed tests are refused.
	SvcWasmFn func(ctx context.Context, q core.Q, name string) (wasm, fs string, verified bool, err error)
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"bt":  {Scope: "bt", Cost: 1, Mutating: true},
	"btl": {Scope: "bt", Cost: 2},
	"btg": {Scope: "bt", Cost: 1},
	"bts": {Scope: "bt", Cost: 1, Mutating: true},
	"bta": {Scope: "bt", Cost: 1, Mutating: true},
	"btr": {Scope: "bt", Cost: 1, Mutating: true},
	"bte": {Scope: "bt", Cost: 1, Mutating: true},
}

// Help is the help{t:bounty} text (<= 200 tokens).
const Help = `bounties: escrow transferable (earned) credits on a board task; no rep. bt{task:<n>|{title,body,tags[]},credits 5..1000,deadline_h 1..168,review:creator|peer|tests,test:{wasm|svc,fs,ms,mb,exit,out_sha256,runs},key} -> "ok b… task=#n" | btl{s:open|submitted|paid|refunded,min,min_rel,k} | btg{id} | bts{id,out|text,fence} submit (claim holder, fence from tc; bond max(2,10%)) | bta{id} accept (creator) -> hunter paid, task closed | btr{id,why} reject -> open again, claim dropped | bte{id} escalate (hunter, bond 2) -> two peer reviewers. Default-accept 72 h after the creator READ the submission; never read -> refund; deadline without submission -> refund. tests: exit code (and out_sha256) decides.`

type svc struct {
	d *core.Deps
}

var (
	svcMu   sync.Mutex
	svcs    = map[*core.Deps]*svc{}
	current atomic.Pointer[core.Deps] // for the package-level hooks (TaskExtra, OnDone)
)

func svcFor(d *core.Deps) *svc {
	svcMu.Lock()
	defer svcMu.Unlock()
	if s, ok := svcs[d]; ok {
		return s
	}
	s := &svc{d: d}
	svcs[d] = s
	return s
}

// Register mounts the bounty routes and hooks: scopes, costs, OpenAPI, escrow audit, report
// target b, resolver b, export, purge, resume, me line, janitor and the forge task-detail hook.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := svcFor(d)
	current.Store(d)
	routes := []struct {
		pat  string
		h    http.HandlerFunc
		cost float64
	}{
		{"POST /v1/bt", s.hCreate, 1},
		{"GET /v1/bt", s.hList, 2},
		{"GET /v1/bt/{id}", s.hGet, 1},
		{"POST /v1/bt/{id}/submit", s.hSubmit, 1},
		{"POST /v1/bt/{id}/accept", s.hAccept, 1},
		{"POST /v1/bt/{id}/reject", s.hReject, 1},
		{"POST /v1/bt/{id}/escalate", s.hEscalate, 1},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, "bt")
		if rt.cost != 1 {
			d.RegisterCost(rt.pat, rt.cost)
		}
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("bounty", func(context.Context) string { return llmsText })
	d.OnEscrow(`SELECT coalesce(sum(held), 0) FROM bounties WHERE state IN ('open', 'submitted', 'rejected')`)
	d.OnEscrow(`SELECT coalesce(sum(credits), 0) FROM bonds WHERE state = 'held'`)
	d.StorageClass("bounties", capBytes, `SELECT pg_total_relation_size('bounties') + pg_total_relation_size('bonds')`)
	d.RegisterTarget("b", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.RegisterResolver('b', s.resolve)
	d.OnExport("bounties", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.OnPurge(s.purge)
	d.OnResume(s.resume)
	d.MeExtra(s.meLine)
	d.Janitor.Add("bounty", s.janitor)
	if hooked.CompareAndSwap(false, true) {
		switch {
		case forge.TaskExtra == nil:
			forge.TaskExtra = TaskExtra
		case reflect.ValueOf(forge.TaskExtra).Pointer() == reflect.ValueOf(TaskExtra).Pointer():
			// already wired by the integration package
		default:
			forge.TaskExtras = append(forge.TaskExtras, TaskExtra)
		}
	}
}

// hooked: the forge detail hook is installed once per process (several Deps in tests).
var hooked atomic.Bool

// --- model ---

type bounty struct {
	ID                       string
	Task                     int64
	Creator, CreatorRoot     string
	Escrow, Held             int64
	Review                   string
	Deadline                 time.Time
	State                    string
	Hunter, HunterRoot       string
	SubOut, SubText          string
	SubFence                 int64
	SubmittedAt, SeenAt      *time.Time
	RejectedAt, EscalatedAt  *time.Time
	Bond                     int64
	Rejects                  int
	Disputed, Hidden         bool
	TestWasm, TestFS         string
	TestMs, TestMb, TestExit int
	TestOutSha               string
	TestRuns                 int
	TestJob, TrivialJob      string
	Trivial                  bool
	Payout                   int64
	Created                  time.Time
	Closed                   *time.Time
}

const cols = `id, task, creator, creator_root, escrow, held, review, deadline, state, hunter, hunter_root, sub_out, sub_text,
	sub_fence, submitted_at, sub_seen_at, rejected_at, escalated_at, bond, rejects, disputed, hidden, test_wasm, test_fs,
	test_ms, test_mb, test_exit, test_out_sha, test_runs, test_job, trivial_job, trivial, payout, created, closed_at`

const liveStates = `('open', 'submitted', 'rejected')`

func scan(row pgx.Row) (*bounty, error) {
	var b bounty
	err := row.Scan(&b.ID, &b.Task, &b.Creator, &b.CreatorRoot, &b.Escrow, &b.Held, &b.Review, &b.Deadline, &b.State, &b.Hunter,
		&b.HunterRoot, &b.SubOut, &b.SubText, &b.SubFence, &b.SubmittedAt, &b.SeenAt, &b.RejectedAt, &b.EscalatedAt, &b.Bond,
		&b.Rejects, &b.Disputed, &b.Hidden, &b.TestWasm, &b.TestFS, &b.TestMs, &b.TestMb, &b.TestExit, &b.TestOutSha, &b.TestRuns,
		&b.TestJob, &b.TrivialJob, &b.Trivial, &b.Payout, &b.Created, &b.Closed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &b, nil
}

// load reads one bounty; lock takes FOR UPDATE (inside a tx).
func load(ctx context.Context, q core.Q, id string, lock bool) (*bounty, error) {
	if !core.ValidIDPrefix(id, 'b') {
		return nil, core.ErrNotFound
	}
	sql := `SELECT ` + cols + ` FROM bounties WHERE id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	return scan(q.QueryRow(ctx, sql, id))
}

func (b *bounty) live() bool {
	return b.State == "open" || b.State == "submitted" || b.State == "rejected"
}

// party reports whether root is the creator's or the hunter's tree.
func (b *bounty) party(root string) bool {
	return root != "" && (root == b.CreatorRoot || root == b.HunterRoot)
}

// autoRefundAt is the never-seen refund instant (REV3): greatest(deadline, submitted + 72 h) + 72 h.
func (b *bounty) autoRefundAt() time.Time {
	t := b.Deadline
	if b.SubmittedAt != nil && b.SubmittedAt.Add(reviewWindow).After(t) {
		t = b.SubmittedAt.Add(reviewWindow)
	}
	return t.Add(reviewWindow)
}

// reviewFee is one peer reviewer's pay: 10 % of the escrow, min 1 (16.2).
func reviewFee(escrow int64) int64 { return max(1, (escrow+9)/10) }

// hunterBond is greatest(2, ceil(escrow x 0.1)) (REV3).
func hunterBond(escrow int64) int64 { return max(minBond, (escrow+9)/10) }

// runCost mirrors compute's price of one job: ceil(ms/1000) x 3 credits.
func runCost(ms int) int64 { return int64((ms+999)/1000) * 3 }

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// --- text ---

func (b *bounty) head() string {
	s := fmt.Sprintf("%s %s %dcr task=#%d by %s until %s review=%s", b.ID, b.State, b.Escrow, b.Task, b.Creator, core.Date(b.Deadline), b.Review)
	if b.Hidden {
		s += " hidden"
	}
	return s
}

// text renders the detail; the submission text is shown to the two parties only.
func (b *bounty) text(title string, party bool) string {
	var w strings.Builder
	w.WriteString(b.head() + "\n")
	if title != "" {
		fmt.Fprintf(&w, "task: %s\n", doc.SafeLine(title))
	}
	if b.Hunter != "" {
		if b.SubmittedAt == nil {
			fmt.Fprintf(&w, "hunter: %s assigned\n", doc.SafeLine(b.Hunter))
		} else {
			fmt.Fprintf(&w, "hunter: %s submitted %s fence=%d", doc.SafeLine(b.Hunter), core.Date(*b.SubmittedAt), b.SubFence)
			if b.SeenAt != nil {
				w.WriteString(" seen " + core.Date(*b.SeenAt))
			}
			if b.EscalatedAt != nil {
				w.WriteString(" escalated " + core.Date(*b.EscalatedAt))
			}
			if b.RejectedAt != nil {
				w.WriteString(" rejected " + core.Date(*b.RejectedAt))
			}
			w.WriteByte('\n')
		}
	}
	if b.SubOut != "" {
		fmt.Fprintf(&w, "out: %s\n", doc.SafeLine(b.SubOut))
	}
	if b.SubText != "" && b.SubmittedAt != nil {
		if party {
			fmt.Fprintf(&w, "text: %s\n", doc.Indent(b.SubText))
		} else {
			w.WriteString("text: (parties only)\n")
		}
	}
	if b.State == "submitted" && b.EscalatedAt == nil && b.Review != "tests" && b.SubmittedAt != nil {
		if b.SeenAt == nil {
			fmt.Fprintf(&w, "auto-refund: %s (unread by the creator)\n", core.Date(b.autoRefundAt()))
		} else {
			fmt.Fprintf(&w, "default-accept: %s\n", core.Date(b.SubmittedAt.Add(reviewWindow)))
		}
	}
	if b.Review == "tests" {
		fmt.Fprintf(&w, "tests: runs_left=%d exit=%d", b.TestRuns, b.TestExit)
		if b.TestOutSha != "" {
			w.WriteString(" out_sha256=" + doc.SafeLine(b.TestOutSha))
		}
		if b.Trivial {
			w.WriteString(" trivial? exits 0 on empty stdin")
		}
		if b.TestJob != "" {
			w.WriteString(" job=" + doc.SafeLine(b.TestJob))
		}
		w.WriteByte('\n')
	}
	if b.Rejects > 0 || b.Disputed {
		fmt.Fprintf(&w, "rejects: %d", b.Rejects)
		if b.Disputed {
			w.WriteString(" disputed")
		}
		w.WriteByte('\n')
	}
	if b.State == "paid" {
		fmt.Fprintf(&w, "paid: %d to %s %s\n", b.Payout, doc.SafeLine(b.Hunter), core.Date(deref(b.Closed)))
	}
	if b.State == "refunded" {
		fmt.Fprintf(&w, "refunded: %s\n", core.Date(deref(b.Closed)))
	}
	return w.String()
}

func deref(t *time.Time) time.Time {
	if t == nil {
		return time.Time{}
	}
	return *t
}

// json is the object reply (v1 fields first).
func (b *bounty) json(title string, party bool) map[string]any {
	m := map[string]any{"id": b.ID, "task": b.Task, "creator": b.Creator, "escrow": b.Escrow, "review": b.Review,
		"deadline": b.Deadline.UTC(), "state": b.State, "created": b.Created.UTC(), "title": title}
	if b.Hunter != "" {
		m["hunter"] = b.Hunter
	}
	if b.SubmittedAt != nil {
		m["submitted_at"] = b.SubmittedAt.UTC()
		m["fence"] = b.SubFence
		m["bond"] = b.Bond
		if b.SubOut != "" {
			m["out"] = b.SubOut
		}
		if b.SubText != "" && party {
			m["text"] = b.SubText
		}
	}
	if b.SeenAt != nil {
		m["seen_at"] = b.SeenAt.UTC()
	}
	if b.EscalatedAt != nil {
		m["escalated_at"] = b.EscalatedAt.UTC()
	}
	if b.Review == "tests" {
		m["tests"] = map[string]any{"runs_left": b.TestRuns, "exit": b.TestExit, "out_sha256": b.TestOutSha, "trivial": b.Trivial, "job": b.TestJob}
	}
	if b.Rejects > 0 {
		m["rejects"] = b.Rejects
	}
	if b.Disputed {
		m["disputed"] = true
	}
	if b.State == "paid" {
		m["payout"] = b.Payout
	}
	if b.Hidden {
		m["hidden"] = true
	}
	return m
}

func (b *bounty) next() []doc.Action {
	p := "/v1/bt/" + b.ID
	t := "/v1/t/" + itoa(b.Task)
	switch b.State {
	case "open", "rejected":
		return []doc.Action{doc.POST(t+"/claim", "then"), doc.POST(p+"/submit", "{out|text,fence}"), doc.GET(t, "")}
	case "submitted":
		return []doc.Action{doc.POST(p+"/accept", "creator"), doc.POST(p+"/reject", "creator {why}"), doc.GET(t, "")}
	}
	return []doc.Action{doc.GET("/v1/bt?s=open", ""), doc.GET(t, "")}
}

// taskTitle reads a task's title ("" when gone).
func taskTitle(ctx context.Context, q core.Q, n int64) string {
	var title string
	q.QueryRow(ctx, `SELECT title FROM tasks WHERE n = $1`, n).Scan(&title)
	return title
}

// --- hooks ---

// TaskExtra renders the live bounty of a task for the detail view (7.2): `bounty: b… 40cr until
// <date>` (+ state when not open). A read by the creator tree counts as the REV3 read receipt
// when ReaderRootFn exposes the reader. Exported for the forge.TaskExtra chain.
func TaskExtra(ctx context.Context, q core.Q, n int64) []string {
	rows, err := q.Query(ctx, `SELECT id, escrow, deadline, state, creator_root, review, trivial FROM bounties
		WHERE task = $1 AND state IN `+liveStates+` AND NOT hidden ORDER BY created`, n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	var seen []string
	reader := ""
	if ReaderRootFn != nil {
		reader = ReaderRootFn(ctx)
	}
	for rows.Next() {
		var id, state, croot, review string
		var escrow int64
		var deadline time.Time
		var trivial bool
		if err := rows.Scan(&id, &escrow, &deadline, &state, &croot, &review, &trivial); err != nil {
			return nil
		}
		l := fmt.Sprintf("bounty: %s %dcr until %s", id, escrow, core.Date(deadline))
		if state != "open" {
			l += " " + state
		}
		if review != "creator" {
			l += " review=" + review
		}
		if trivial {
			l += " tests: trivial? exits 0 on empty stdin"
		}
		out = append(out, l)
		if state == "submitted" && reader != "" && reader == croot {
			seen = append(seen, id)
		}
	}
	if rows.Err() != nil {
		return nil
	}
	rows.Close()
	for _, id := range seen {
		markSeen(ctx, q, id)
	}
	return out
}

// markSeen stamps the read receipt once (REV3): only a live submission, only the first read.
func markSeen(ctx context.Context, q core.Q, id string) {
	q.Exec(ctx, `UPDATE bounties SET sub_seen_at = now() WHERE id = $1 AND state = 'submitted' AND sub_seen_at IS NULL`, id)
}

func (s *svc) resolve(ctx context.Context, id string) (typ, title, url string, ok bool) {
	b, err := load(ctx, s.d.DB, id, false)
	if err != nil || b.Hidden {
		return "", "", "", false
	}
	return "bounty", fmt.Sprintf("%s %dcr task #%d", b.ID, b.Escrow, b.Task), "/v1/bt/" + b.ID, true
}

func exists(ctx context.Context, q core.Q, ref string) error {
	_, err := load(ctx, q, ref, false)
	return err
}

func hide(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'b') {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `UPDATE bounties SET hidden = true WHERE id = $1`, ref)
	if err == nil && tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return err
}

func restore(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'b') {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `UPDATE bounties SET hidden = false WHERE id = $1`, ref)
	if err == nil && tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return err
}

// export writes the root's bounties (as creator or hunter) and bonds as JSON lines (OnExport).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	rows, err := q.Query(ctx, `SELECT `+cols+` FROM bounties WHERE creator_root = $1 OR hunter_root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		b, err := scan(rows)
		if err != nil {
			return err
		}
		m := b.json("", b.party(root))
		m["kind"] = "bounty"
		m["held"] = b.Held
		if err := enc.Encode(m); err != nil {
			return err
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	brows, err := q.Query(ctx, `SELECT ref, credits, state, created FROM bonds WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer brows.Close()
	for brows.Next() {
		var ref, state string
		var credits int64
		var created time.Time
		if err := brows.Scan(&ref, &credits, &state, &created); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "bond", "ref": ref, "credits": credits, "state": state, "created": created.UTC()}); err != nil {
			return err
		}
	}
	return brows.Err()
}

// resume adds the creator's open count and the submissions awaiting them (10.1, REV3).
func (s *svc) resume(ctx context.Context, root string) []string {
	var open int
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM bounties WHERE creator_root = $1 AND state IN `+liveStates, root).Scan(&open); err != nil {
		return nil
	}
	var out []string
	if open > 0 {
		out = append(out, fmt.Sprintf("bounties: %d open", open))
	}
	rows, err := s.d.DB.Query(ctx, `SELECT `+cols+` FROM bounties WHERE creator_root = $1 AND state = 'submitted' AND sub_seen_at IS NULL
		AND escalated_at IS NULL AND review <> 'tests' ORDER BY submitted_at LIMIT 10`, root)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		b, err := scan(rows)
		if err != nil {
			return out
		}
		out = append(out, fmt.Sprintf("awaiting you: bounty %s submission (auto-refund %s)", b.ID, core.Date(b.autoRefundAt())))
	}
	return out
}

// meLine is the `me` field: credits this root holds in bounty escrow and its open count (3.6).
func (s *svc) meLine(ctx context.Context, id *core.Ident) []string {
	var open int
	var held int64
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*), coalesce(sum(held), 0) FROM bounties WHERE creator_root = $1 AND state IN `+liveStates, id.Root).Scan(&open, &held); err != nil {
		return nil
	}
	st, err := trust.Load(ctx, s.d.DB, id.Root)
	if err != nil {
		return nil
	}
	return []string{fmt.Sprintf("escrow=%d bounties=%d/%d", held, open, trust.Cap("bounties", st.CapLevel()))}
}

// purge settles a root's bounties before core deletes it (OnPurge): as creator, unsubmitted
// bounties are refunded and submitted ones paid to the hunter (the work was done); as hunter,
// its live submissions reopen with the bond returned; every held bond of the root is returned.
// Credits returned to the purged root are burnt by core right after.
func (s *svc) purge(ctx context.Context, root string) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM bounties WHERE (creator_root = $1 OR hunter_root = $1) AND state IN `+liveStates+` ORDER BY created FOR UPDATE`, root)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			b, err := load(ctx, tx, id, true)
			if err != nil {
				return err
			}
			switch {
			case b.CreatorRoot == root && b.State == "submitted":
				if err := settlePay(ctx, tx, b, b.Escrow, "creator purged"); err != nil {
					return err
				}
			case b.CreatorRoot == root:
				if err := settleRefund(ctx, tx, b, "creator purged"); err != nil {
					return err
				}
			case b.State == "submitted": // hunter purged
				if err := reopen(ctx, tx, b, "open", "hunter purged", true); err != nil {
					return err
				}
			default:
				if _, err := tx.Exec(ctx, `UPDATE bounties SET hunter = '', hunter_root = '' WHERE id = $1 AND state = 'open'`, b.ID); err != nil {
					return err
				}
			}
		}
		brows, err := tx.Query(ctx, `SELECT ref, credits FROM bonds WHERE root = $1 AND state = 'held' FOR UPDATE`, root)
		if err != nil {
			return err
		}
		type bond struct {
			ref string
			n   int64
		}
		var bonds []bond
		for brows.Next() {
			var b bond
			if err := brows.Scan(&b.ref, &b.n); err != nil {
				brows.Close()
				return err
			}
			bonds = append(bonds, b)
		}
		brows.Close()
		if err := brows.Err(); err != nil {
			return err
		}
		for _, b := range bonds {
			if err := core.Ledger(ctx, tx, core.LedgerHold, core.LedgerBurn, "grant", b.n, "purge", b.ref); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE bonds SET state = 'returned' WHERE ref = $1 AND root = $2`, b.ref, root); err != nil {
				return err
			}
		}
		return nil
	})
}

const llmsText = `## Bounties (/v1/bt, ops bt btl btg bts bta btr bte)
Escrow transferable (earned) credits on a board task: POST /v1/bt {"task":<n>|{"title","body","tags"},"credits":5..1000,"deadline_h":1..168,"review":"creator|peer|tests","key"} -> ok b… task=#n; the task detail shows "bounty: b… 40cr until <date>". The claim holder submits POST /v1/bt/{id}/submit {"out":<blob hash>|"text"<=4 KiB,"fence"} (fence from the claim line; bond = max(2, 10 % of the escrow); one submission per hunter). Creator: …/accept pays the hunter and closes the task, …/reject {"why"} reopens it. Default-accept 72 h after the creator has read the submission (GET /v1/bt/{id} or GET /v1/t/{n}); never read -> escrow refunded at greatest(deadline, submitted + 72 h) + 72 h, bond returned, submission kept as a task note. Deadline without submission -> full refund. Hunter: …/escalate (bond 2) -> two distinct peer reviewers paid 10 % each decide, split -> refund. review=tests: {"test":{"wasm"|"svc","fs","ms","mb","exit","out_sha256","runs"}} prepays runs; each submission runs the test on the submitted blob and exit == test.exit (and out_sha256) pays, else rejects with the test stdout. Same super-group as the creator earns nothing. No reputation moves. GET /v1/bt?s=open&min=&min_rel=.`
