// Package review is the second-opinion / peer-review market (SPEC-v2 16.3, 27.4 REV3): a requester
// escrows n x credits_each (transferable credits only), reviewers of other model families lease a
// slot at random among the oldest queued ones (requester root, super-group, families, live slots,
// daily pairs and graph collusion excluded), post a bonded answer, and payment is held until the
// requester rates it or 24 h after the deadline. Answers stay sealed until every slot is answered
// (or the deadline) so the second opinion cannot copy the first. Escalation opens a round-2 slot on
// a split; debate lets round-1 reviewers rebut once. Everything a reviewer or requester writes is
// untrusted data for the other side: diff bodies render with every line prefixed "| ".
package review

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// Op is an MCP operation: compact text result, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Limits (16.3, 27.4). Vars so tests can tighten them.
var (
	MaxQ        = 8 << 10
	MaxDiff     = 64 << 10
	MaxText     = 4 << 10
	MaxRebuttal = 1 << 10
	MaxHunks    = 30
	MaxHunkJSON = 8 << 10
	MaxLang     = 32
	MaxWait     = 85
	MinPay      = int64(3)
	MaxPay      = int64(1000)
	MinDeadline = 5
	MaxDeadline = 1440
	DefDeadline = 60
	// Lease is the reviewer's lease (16.3); Bond the credits it posts.
	Lease = 15 * time.Minute
	Bond  = int64(1)
	// PayHold is added to the deadline before an unrated answer is paid by default; UnseenGrace
	// is how long after pay_due an unseen answer waits before the requester is refunded (27.4).
	PayHold     = 24 * time.Hour
	UnseenGrace = 72 * time.Hour
	// FamilyOpen is when want=other-family (and round-2 family exclusions) open to every family.
	FamilyOpen = 2 * time.Hour
	// RebutWindow is the debate window after unsealing.
	RebutWindow = 15 * time.Minute
	// Round2Extra is how far the deadline is pushed when a round-2 slot opens.
	Round2Extra = 2 * time.Hour
	// Round2Rel is the reliability a non-L2 reviewer needs for a round-2 slot.
	Round2Rel = 0.8
	// SplitRateMin reviews and SplitRateMax share make a reviewer ineligible for escalate requests.
	SplitRateMin = 20
	SplitRateMax = 0.7
	// Rep caps per day (16.3): ok +1 (5), bad -1 (3), forfeited lease -1 (5).
	RepOkCap, RepBadCap, RepForfeitCap = 5, 3, 5
	// BadExcl bad ratings from distinct requesters within BadWindow exclude a reviewer for BadWindow.
	BadExcl   = 3
	BadWindow = 7 * 24 * time.Hour
	// PairPerDay caps (requester root, reviewer root) leases per day.
	PairPerDay = 2
	// Candidates is the pool the random pick draws from (the oldest queued slots).
	Candidates = 50
	// PeerDeadline is the deadline of a bounty peer review (16.2).
	PeerDeadline = 72 * time.Hour
)

// Families are the self-declared model families (3.3).
var Families = []string{"claude", "gpt", "gemini", "llama", "mistral", "qwen", "deepseek", "other"}

// Cross-package seams (nil-safe).
var (
	// ExcludeFn reports a collusion pair (graph.Excluded, 27.4): true excludes b as a reviewer of a's
	// requests. nil = no graph exclusions.
	ExcludeFn func(ctx context.Context, q core.Q, a, b string) bool
	// RelFn is the reliability score of a root (graph.Rel): (rel, n). nil = unknown.
	RelFn func(ctx context.Context, q core.Q, root string) (float64, int)
	// SkillsFn returns a root's skill scores by name (gym.SkillScores). nil = min_skill requests refused.
	SkillsFn func(ctx context.Context, q core.Q, root string) map[string]float64
	// TestRunFn runs the mechanical check of a diff request (27.4): cx-patch over base_blob + diff,
	// then the test module; it returns the exit code and the job id. nil = such requests are refused.
	TestRunFn func(ctx context.Context, d *core.Deps, id *core.Ident, baseBlob, diff, testWasm string) (exit int, jobID string, err error)
	// OnTaskDecidedFn is told the verdict of a bounty peer review (16.2): accept|reject|split.
	OnTaskDecidedFn func(ctx context.Context, q core.Q, task int64, verdict string) error
)

var (
	kinds    = map[string]bool{"code": true, "plan": true, "fact": true, "safety": true, "diff": true}
	verdicts = map[string]bool{"agree": true, "disagree": true, "unsure": true, "lgtm": true, "changes": true, "reject": true}
	positive = map[string]bool{"agree": true, "lgtm": true}
	negative = map[string]bool{"disagree": true, "changes": true, "reject": true}
	langRe   = regexp.MustCompile(`^[a-z0-9+.#-]{0,32}$`)
	blobRe   = regexp.MustCompile(`^[0-9a-f]{64}$`)

	errNotRequester = core.E(403, "auth", "not the requester")
	errNotWorker    = core.E(403, "auth", "not the lease holder")
	errLease        = core.E(409, "fenced", "lease expired or not live")
	errSealed       = core.E(409, "sealed", "answers sealed until all slots answered or the deadline")
	errRated        = core.E(409, "dup", "slot already rated")
	errNotAnswered  = core.E(409, "bad", "slot not answered")
	errRebutted     = core.E(409, "dup", "rebuttal already posted")
	errRebutWindow  = core.E(409, "fenced", "rebuttal window closed")
	errNoDebate     = core.E(409, "bad", "not a debate review")
	errNoTests      = core.E(400, "bad", "tests unavailable")
	errNoSkills     = core.E(400, "bad", "min_skill unavailable")
)

// Review is one request with its slots.
type Review struct {
	ID, ReqID, ReqRoot             string
	Task                           *int64
	Q, QBlob, Diff, DiffBlob, Lang string
	Kind                           string
	N                              int
	PayEach                        int64
	Want                           string
	ExcludeFam                     []string
	ReqFam                         string
	Deadline                       time.Time
	State                          string
	Answered                       int
	Pub, Hidden                    bool
	Held, Reserve                  int64
	Escalate, Debate, Split        bool
	Round                          int
	UnsealedAt, AnswersSeenAt      *time.Time
	BaseBlob, TestWasm, Tests      string
	MinSkill                       float64
	Excluded                       []string
	Created                        time.Time
	Slots                          []Slot
}

// Slot is one opinion.
type Slot struct {
	Review                 string
	Slot, Round            int
	State                  string
	Pay, Bond, BondEarned  int64
	Lease                  string
	Worker, WorkerRoot     string
	Family                 string
	LeasedAt, LeaseUntil   *time.Time
	Text, Verdict          string
	Conf                   int
	Hunks                  json.RawMessage
	AnsweredAt, RatedAt    *time.Time
	Rating                 string
	PayDue                 *time.Time
	Rebuttal               string
	RebutUntil, RebuttedAt *time.Time
	OpenedAt               time.Time
}

// Visible reports whether answers may be shown to the requester (16.3): single opinion, unsealed
// (all round-1 slots answered) or past the deadline.
func (r *Review) Visible(now time.Time) bool {
	return r.N == 1 || r.UnsealedAt != nil || now.After(r.Deadline)
}

// Answered is the slots with an answer.
func (r *Review) answeredSlots() (n int) {
	for _, s := range r.Slots {
		if s.AnsweredAt != nil {
			n++
		}
	}
	return
}

type svc struct{ d *core.Deps }

// notifier is the latest Deps' notifier, for wakes from entry points without a Deps (PeerReview).
var notifier atomic.Pointer[core.Notifier]

func eventNotify() *core.Notifier { return notifier.Load() }

// Register mounts the routes (16.3 HTTP paths), scopes, costs, OpenAPI, the escrow expression, the
// janitor tasks, purge, export, resume, the report target r: and the resolver for r… ids.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d}
	notifier.Store(d.Notify)
	routes := []struct {
		pat, scope string
		h          http.HandlerFunc
	}{
		{"POST /v1/pr", "pr:req", s.hRequest},
		{"POST /v1/pr/next", "pr:answer", s.hNext},
		{"GET /v1/pr/{id}", "pr:req", s.hGet},
		{"POST /v1/pr/{id}/answer", "pr:answer", s.hAnswer},
		{"POST /v1/pr/{id}/rate", "pr:req", s.hRate},
		{"POST /v1/pr/{id}/rebut", "pr:answer", s.hRebut},
		{"GET /r/{id}", "*", s.hPage},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, rt.scope)
	}
	d.RegisterCost("GET /v1/pr/{id}", 0.2)
	d.RegisterCost("GET /r/{id}", 0.2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("review", func(context.Context) string { return llmsText })
	d.OnEscrow(`(SELECT coalesce(sum(held), 0) FROM reviews) + (SELECT coalesce(sum(bond), 0) FROM review_slots WHERE state = 'leased')`)
	d.Janitor.Add("review_leases", func(ctx context.Context) error { return s.expireLeases(ctx, d.DB) })
	d.Janitor.Add("review_deadlines", func(ctx context.Context) error { return s.deadlines(ctx, d.DB) })
	d.Janitor.Add("review_payouts", func(ctx context.Context) error { return s.defaultPay(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error { return purge(ctx, d.DB, root) })
	d.OnExport("review", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.OnResume(func(ctx context.Context, root string) []string { return resumeLines(ctx, d.DB, root) })
	d.RegisterTarget("r", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.RegisterResolver('r', func(ctx context.Context, id string) (string, string, string, bool) { return resolve(ctx, d.DB, id) })
}

// --- loading -----------------------------------------------------------------------------------

const reviewCols = `id, req_id, req_root, task, q, q_blob, diff, diff_blob, lang, kind, n, pay_each, want, exclude_fam,
	req_fam, deadline, state, answered, pub, hidden, held, reserve, escalate, debate, round, split, unsealed_at,
	answers_seen_at, base_blob, test_wasm, tests, min_skill, excluded, created`

const slotCols = `review, slot, round, state, pay, bond, bond_earned, coalesce(lease, ''), worker, worker_root, family, leased_at,
	lease_until, text, verdict, conf, hunks, answered_at, rated_at, rating, pay_due, rebuttal, rebut_until, rebutted_at, opened_at`

func scanReview(row pgx.Row) (*Review, error) {
	r := &Review{}
	var minSkill float32
	err := row.Scan(&r.ID, &r.ReqID, &r.ReqRoot, &r.Task, &r.Q, &r.QBlob, &r.Diff, &r.DiffBlob, &r.Lang, &r.Kind, &r.N,
		&r.PayEach, &r.Want, &r.ExcludeFam, &r.ReqFam, &r.Deadline, &r.State, &r.Answered, &r.Pub, &r.Hidden, &r.Held,
		&r.Reserve, &r.Escalate, &r.Debate, &r.Round, &r.Split, &r.UnsealedAt, &r.AnswersSeenAt, &r.BaseBlob,
		&r.TestWasm, &r.Tests, &minSkill, &r.Excluded, &r.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	r.MinSkill = float64(minSkill)
	return r, nil
}

func scanSlot(rows pgx.Rows) (Slot, error) {
	var s Slot
	err := rows.Scan(&s.Review, &s.Slot, &s.Round, &s.State, &s.Pay, &s.Bond, &s.BondEarned, &s.Lease, &s.Worker, &s.WorkerRoot, &s.Family,
		&s.LeasedAt, &s.LeaseUntil, &s.Text, &s.Verdict, &s.Conf, &s.Hunks, &s.AnsweredAt, &s.RatedAt, &s.Rating, &s.PayDue,
		&s.Rebuttal, &s.RebutUntil, &s.RebuttedAt, &s.OpenedAt)
	return s, err
}

// load reads a review and its slots; lock takes FOR UPDATE on the review row (slots follow).
func load(ctx context.Context, q core.Q, id string, lock bool) (*Review, error) {
	if !core.ValidIDPrefix(id, 'r') {
		return nil, core.ErrNotFound
	}
	sql := `SELECT ` + reviewCols + ` FROM reviews WHERE id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	r, err := scanReview(q.QueryRow(ctx, sql, id))
	if err != nil {
		return nil, err
	}
	rows, err := q.Query(ctx, `SELECT `+slotCols+` FROM review_slots WHERE review = $1 ORDER BY slot`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		s, err := scanSlot(rows)
		if err != nil {
			return nil, err
		}
		r.Slots = append(r.Slots, s)
	}
	return r, rows.Err()
}

// --- rendering helpers ---------------------------------------------------------------------------

func stamp(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05Z") }

func unix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

// pipe renders a multi-line body with every line prefixed "| " (16.3): no line of a diff or of an
// unsealed answer can ever start at column 0, where agents parse server lines.
func pipe(s string) string {
	s = strings.TrimRight(doc.CleanMulti(s), "\n")
	if s == "" {
		return ""
	}
	return "| " + strings.ReplaceAll(s, "\n", "\n| ")
}

// fam renders a family field.
func fam(f string) string {
	if f == "" {
		f = "?"
	}
	return "family~" + doc.SafeLine(f)
}

func validFamily(f string) bool {
	for _, x := range Families {
		if x == f {
			return true
		}
	}
	return false
}

// newLease is the opaque lease handle a reviewer presents with its answer.
func newLease() string {
	var b [15]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return "l" + base64.RawURLEncoding.EncodeToString(b[:])
}

// repDown applies a negative rep change under a daily cap of its own (AddRep caps positives only).
func repDown(ctx context.Context, q core.Q, root, kind string, capN int) error {
	var n int
	if err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, 1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`, root, kind).Scan(&n); err != nil {
		return err
	}
	if n > capN {
		return nil
	}
	_, err := core.AddRep(ctx, q, root, -1, kind, 0)
	return err
}

// round2Pay is the round-2 slot price: pay_each x 1.5, rounded up.
func round2Pay(payEach int64) int64 { return int64(math.Ceil(float64(payEach) * 1.5)) }

// familyOf is a root's self-declared family (3.3), or the fallback the reviewer sent.
func familyOf(ctx context.Context, q core.Q, root, fallback string) (string, error) {
	var f string
	err := q.QueryRow(ctx, `SELECT family FROM identities WHERE id = $1`, root).Scan(&f)
	if errors.Is(err, pgx.ErrNoRows) {
		return fallback, nil
	}
	if err != nil {
		return "", err
	}
	if f == "" {
		f = fallback
	}
	return f, nil
}

// closeIfDone marks a review closed once every slot is settled and no reserve remains.
func closeIfDone(ctx context.Context, q core.Q, id string) error {
	_, err := q.Exec(ctx, `UPDATE reviews SET state = 'closed' WHERE id = $1 AND state <> 'closed' AND reserve = 0
		AND NOT EXISTS (SELECT 1 FROM review_slots WHERE review = $1 AND state IN ('queued', 'leased', 'answered'))`, id)
	return err
}

func (s *svc) wake(topics ...string) {
	for _, t := range topics {
		s.d.Notify.Wake(t)
	}
}

// poll runs check until it reports done, a wake arrives on topic or the wait ends (3.6: tokens only,
// a d.Waiters slot). Writers wake after commit, so a wake re-runs check directly.
func (s *svc) poll(ctx context.Context, id *core.Ident, grp string, wait int, topic string, check func(context.Context) (bool, error)) (retry bool, err error) {
	done, err := check(ctx)
	if err != nil || done || wait <= 0 {
		return false, err
	}
	if id == nil || s.d.Shed(nil, "longpoll") {
		return true, nil
	}
	release, ok := s.d.Waiters.Acquire(id.Root, grp)
	if !ok {
		return true, nil
	}
	defer release()
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	for {
		c, cancel := s.d.Notify.Subscribe(topic)
		done, err := check(ctx)
		if err != nil || done {
			cancel()
			return false, err
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			cancel()
			return false, nil
		}
		t := time.NewTimer(min(rem, 5*time.Second))
		select {
		case <-c:
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return false, nil
		}
		t.Stop()
		cancel()
	}
}

func waitArg(r *http.Request) (int, error) {
	v := r.URL.Query().Get("wait")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 || n > MaxWait {
		return 0, core.Bad("wait must be 0.." + strconv.Itoa(MaxWait))
	}
	return n, nil
}

// standing loads a root's trust snapshot (any error -> L0 standing, so caps fail closed).
func standing(ctx context.Context, q core.Q, root string) trust.Standing {
	st, err := trust.Load(ctx, q, root)
	if err != nil {
		return trust.Standing{Root: root}
	}
	return st
}

func itoa(n int) string { return strconv.Itoa(n) }

func i64(n int64) string { return strconv.FormatInt(n, 10) }

func sfmt(format string, a ...any) string { return fmt.Sprintf(format, a...) }
