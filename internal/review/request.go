package review

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// requestIn is POST /v1/pr / op rq (16.3, 27.4).
type requestIn struct {
	Q          string   `json:"q"`
	QBlob      string   `json:"q_blob"`
	Diff       string   `json:"diff"`
	DiffBlob   string   `json:"diff_blob"`
	Lang       string   `json:"lang"`
	Kind       string   `json:"kind"`
	N          int      `json:"n"`
	Credits    int64    `json:"credits_each"`
	Want       string   `json:"want"`
	ExcludeFam []string `json:"exclude_fam"`
	DeadlineM  int      `json:"deadline_m"`
	Pub        bool     `json:"pub"`
	Escalate   bool     `json:"escalate"`
	Debate     bool     `json:"debate"`
	MinSkill   float64  `json:"min_skill"`
	BaseBlob   string   `json:"base_blob"`
	TestWasm   string   `json:"test_wasm"`
	Key        string   `json:"key"`
}

// requestOut is the created review.
type requestOut struct {
	ID       string
	N        int
	Each     int64
	Escrow   int64
	Deadline time.Time
	Tests    string
	Masked   []string
}

// Line is `ok r… n=<n> each=<credits> escrow=<total> until=<date>[ tests: …][ masked=…]`.
func (o *requestOut) Line() string {
	s := sfmt("ok %s n=%d each=%d escrow=%d until=%s", o.ID, o.N, o.Each, o.Escrow, stamp(o.Deadline))
	if o.Tests != "" {
		s += " " + o.Tests
	}
	if len(o.Masked) > 0 {
		s += " masked=" + strings.Join(o.Masked, ",")
	}
	return s
}

func (o *requestOut) JSON() map[string]any {
	m := map[string]any{"id": o.ID, "n": o.N, "credits_each": o.Each, "escrow": o.Escrow, "deadline": o.Deadline.UTC()}
	if o.Tests != "" {
		m["tests"] = o.Tests
	}
	return m
}

// hash is the idempotency request hash of a request body.
func (in *requestIn) hash() []byte {
	cp := *in
	cp.Key = ""
	b, _ := json.Marshal(cp)
	h := sha256.Sum256(b)
	return h[:]
}

// validate normalises and checks a request (sizes, grammar, blob shapes); scrub runs in create.
func (in *requestIn) validate() error {
	in.Kind = strings.ToLower(strings.TrimSpace(in.Kind))
	in.Lang = strings.ToLower(strings.TrimSpace(in.Lang))
	in.Want = strings.ToLower(strings.TrimSpace(in.Want))
	if in.Want == "" {
		in.Want = "any"
	}
	if in.N == 0 {
		in.N = 1
	}
	if in.DeadlineM == 0 {
		in.DeadlineM = DefDeadline
	}
	in.Q = strings.TrimRight(doc.CleanMulti(in.Q), "\n")
	in.Diff = strings.TrimRight(doc.CleanMulti(in.Diff), "\n")
	switch {
	case !kinds[in.Kind]:
		return core.Bad("kind must be code|plan|fact|safety|diff")
	case in.N < 1 || in.N > 3:
		return core.Bad("n must be 1..3")
	case in.Credits < MinPay || in.Credits > MaxPay:
		return core.Bad(sfmt("credits_each must be %d..%d", MinPay, MaxPay))
	case in.Want != "any" && in.Want != "other-family":
		return core.Bad("want must be any|other-family")
	case in.DeadlineM < MinDeadline || in.DeadlineM > MaxDeadline:
		return core.Bad(sfmt("deadline_m must be %d..%d", MinDeadline, MaxDeadline))
	case !langRe.MatchString(in.Lang) || len(in.Lang) > MaxLang:
		return core.Bad("lang must match [a-z0-9+.#-]{0,32}")
	case len(in.Q) > MaxQ:
		return core.E(413, "size", sfmt("q must be <= %d bytes", MaxQ))
	case len(in.Diff) > MaxDiff:
		return core.E(413, "size", sfmt("diff must be <= %d bytes", MaxDiff))
	case in.Q == "" && in.QBlob == "" && in.Diff == "" && in.DiffBlob == "":
		return core.Bad("q or diff required")
	case in.Kind == "diff" && in.Diff == "" && in.DiffBlob == "":
		return core.Bad("kind diff needs diff or diff_blob")
	case len(in.ExcludeFam) > len(Families):
		return core.Bad("exclude_fam: too many")
	case in.Escalate && in.N < 2:
		return core.Bad("escalate needs n >= 2")
	case in.Debate && in.N != 2:
		return core.Bad("debate needs n = 2")
	case in.MinSkill < 0 || in.MinSkill > 1:
		return core.Bad("min_skill must be 0..1")
	case in.MinSkill > 0 && SkillsFn == nil:
		return errNoSkills
	case (in.BaseBlob != "" || in.TestWasm != "") && (in.BaseBlob == "" || in.TestWasm == ""):
		return core.Bad("base_blob and test_wasm go together")
	case in.BaseBlob != "" && in.Kind != "diff":
		return core.Bad("tests need kind diff")
	case in.BaseBlob != "" && TestRunFn == nil:
		return errNoTests
	}
	for _, b := range []string{in.QBlob, in.DiffBlob, in.BaseBlob, in.TestWasm} {
		if b != "" && !blobRe.MatchString(b) {
			return core.Bad("blob refs must be sha256 hex")
		}
	}
	seen := map[string]bool{}
	for i, f := range in.ExcludeFam {
		f = strings.ToLower(strings.TrimSpace(f))
		if !validFamily(f) {
			return core.Bad("exclude_fam: unknown family " + doc.SafeLine(f))
		}
		if seen[f] {
			return core.Bad("exclude_fam: duplicate")
		}
		seen[f] = true
		in.ExcludeFam[i] = f
	}
	if in.ExcludeFam == nil {
		in.ExcludeFam = []string{}
	}
	return nil
}

// ownsBlob checks that the requester's tree uploaded (or may read) a referenced blob.
func ownsBlob(ctx context.Context, q core.Q, root, hash string) error {
	if hash == "" {
		return nil
	}
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM blobs WHERE hash = $1 AND (owner_root = $2 OR public))`, hash, root).Scan(&ok)
	if err != nil {
		return err
	}
	if !ok {
		return core.E(404, "notfound", "blob "+hash[:12]+"… not yours")
	}
	return nil
}

// create runs the request pipeline (16.3): caps, scrub, the optional mechanical test, then one
// transaction that escrows n x credits_each (+ 1.5 x for escalate) and opens the slots.
func (s *svc) create(ctx context.Context, id *core.Ident, in *requestIn) (*requestOut, error) {
	if err := in.validate(); err != nil {
		return nil, err
	}
	if s.d.Frozen("bounties") {
		return nil, core.Frozen("bounties")
	}
	masked, aerr := scrub.RejectOrMask(map[string]*string{"q": &in.Q, "diff": &in.Diff})
	if aerr != nil {
		return nil, aerr
	}
	for _, b := range []string{in.QBlob, in.DiffBlob, in.BaseBlob, in.TestWasm} {
		if err := ownsBlob(ctx, s.d.DB, id.Root, b); err != nil {
			return nil, err
		}
	}
	st := standing(ctx, s.d.DB, id.Root)
	tests := ""
	if in.BaseBlob != "" {
		exit, jid, err := TestRunFn(ctx, s.d, id, in.BaseBlob, in.Diff, in.TestWasm)
		if err != nil {
			return nil, err
		}
		verdict := "fail"
		if exit == 0 {
			verdict = "pass"
		}
		tests = sfmt("tests: %s %d j=%s", verdict, exit, doc.SafeLine(jid))
	}
	reqFam, err := familyOf(ctx, s.d.DB, id.Root, "")
	if err != nil {
		return nil, err
	}
	out := &requestOut{ID: core.NewID('r'), N: in.N, Each: in.Credits, Tests: tests, Masked: masked}
	out.Escrow = int64(in.N) * in.Credits
	reserve := int64(0)
	if in.Escalate {
		reserve = round2Pay(in.Credits)
		out.Escrow += reserve
	}
	out.Deadline = time.Now().Add(time.Duration(in.DeadlineM) * time.Minute)
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := trust.UseCap(ctx, tx, st, "reviews"); err != nil {
			return err
		}
		if err := core.ReserveEarned(ctx, tx, id.ID, out.Escrow); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO reviews (id, req_id, req_root, q, q_blob, diff, diff_blob, lang, kind, n, pay_each, want,
			exclude_fam, req_fam, deadline, pub, held, reserve, escalate, debate, base_blob, test_wasm, tests, min_skill)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, $23, $24)`,
			out.ID, id.ID, id.Root, in.Q, in.QBlob, in.Diff, in.DiffBlob, in.Lang, in.Kind, in.N, in.Credits, in.Want,
			in.ExcludeFam, reqFam, out.Deadline, in.Pub, out.Escrow, reserve, in.Escalate, in.Debate, in.BaseBlob, in.TestWasm,
			tests, float32(in.MinSkill)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO review_slots (review, slot, pay) SELECT $1, g, $2 FROM generate_series(1, $3) g`,
			out.ID, in.Credits, in.N); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "rq", out.ID, int(out.Escrow)); err != nil {
			return err
		}
		return core.Event(ctx, tx, "review", out.ID, id.Root, "review requested "+in.Kind)
	})
	if err != nil {
		return nil, err
	}
	s.wake("pr")
	return out, nil
}

// PeerReview opens the two-reviewer peer review of a bounty on task (16.2): each reviewer is paid
// 10 % of escrow (min 1), the requester is the task creator, kind code, 72 h deadline. The 2 x fee
// credits must already sit in hold (the caller moves them out of its own escrow accounting); this
// review's `held` then carries them until each slot is paid or refunded to the creator. The verdict
// reaches the caller through OnTaskDecidedFn and TaskOutcome.
func PeerReview(ctx context.Context, q core.Q, task int64, escrow int64) error {
	if task <= 0 || escrow <= 0 {
		return core.Bad("task and escrow required")
	}
	var creator, root string
	err := q.QueryRow(ctx, `SELECT id, root FROM tasks WHERE n = $1`, task).Scan(&creator, &root)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ErrNotFound
	}
	if err != nil {
		return err
	}
	fee := max(escrow/10, 1)
	id := core.NewID('r')
	qtext := sfmt("bounty peer review of task #%d: read GET /v1/t/%d (task, submission note and out blob). verdict agree = accept the submission, disagree = reject, unsure = cannot tell.", task, task)
	if _, err := q.Exec(ctx, `INSERT INTO reviews (id, req_id, req_root, task, q, kind, n, pay_each, deadline, held)
		VALUES ($1, $2, $3, $4, $5, 'code', 2, $6, now() + $7::interval, $8)`,
		id, creator, root, task, qtext, fee, PeerDeadline.String(), 2*fee); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `INSERT INTO review_slots (review, slot, pay) VALUES ($1, 1, $2), ($1, 2, $2)`, id, fee); err != nil {
		return err
	}
	if err := core.Event(ctx, q, "review", id, root, sfmt("peer review of task #%d", task)); err != nil {
		return err
	}
	if n := eventNotify(); n != nil {
		n.Wake("pr")
	}
	return nil
}

// TaskOutcome is the verdict of the latest peer review of task: accept|reject|split and whether it
// is decided (all slots answered or past the deadline).
func TaskOutcome(ctx context.Context, q core.Q, task int64) (verdict string, decided bool, err error) {
	var id string
	err = q.QueryRow(ctx, `SELECT id FROM reviews WHERE task = $1 ORDER BY created DESC LIMIT 1`, task).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, core.ErrNotFound
	}
	if err != nil {
		return "", false, err
	}
	r, err := load(ctx, q, id, false)
	if err != nil {
		return "", false, err
	}
	if r.answeredSlots() < len(r.Slots) && time.Now().Before(r.Deadline) {
		return "", false, nil
	}
	return taskVerdict(r), true, nil
}

// taskVerdict folds the round-1 verdicts: accept when every answer is positive, reject when every
// answer is negative, split otherwise (unsure, missing or disagreeing answers).
func taskVerdict(r *Review) string {
	pos, neg, n := 0, 0, 0
	for _, s := range r.Slots {
		if s.Round != 1 {
			continue
		}
		n++
		switch {
		case positive[s.Verdict]:
			pos++
		case negative[s.Verdict]:
			neg++
		}
	}
	switch {
	case n > 0 && pos == n:
		return "accept"
	case n > 0 && neg == n:
		return "reject"
	}
	return "split"
}
