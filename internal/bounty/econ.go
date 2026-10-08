package bounty

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

var hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// testIn is the "test" object of a tests-reviewed bounty (REV3).
type testIn struct {
	Wasm   string `json:"wasm"`
	Svc    string `json:"svc"`
	FS     string `json:"fs"`
	Ms     int    `json:"ms"`
	Mb     int    `json:"mb"`
	Exit   int    `json:"exit"`
	OutSha string `json:"out_sha256"`
	Runs   int    `json:"runs"`
}

// createIn is the POST /v1/bt body: task number or a new task, credits, deadline, review mode.
type createIn struct {
	Task      json.RawMessage `json:"task"`
	Credits   int64           `json:"credits"`
	DeadlineH int             `json:"deadline_h"`
	Review    string          `json:"review"`
	Test      *testIn         `json:"test"`
	Key       string          `json:"key"`
}

type newTask struct {
	Title string   `json:"title"`
	Body  string   `json:"body"`
	Tags  []string `json:"tags"`
}

func (s *svc) writeAuth(id *core.Ident) error {
	if id == nil {
		return core.ErrAuth
	}
	if id.Banned {
		return core.ErrBanned
	}
	if s.d.Frozen("write") {
		return core.Frozen("write")
	}
	if s.d.Frozen("bounties") {
		return core.Frozen("bounties")
	}
	return nil
}

// resolvedTest is a validated test spec with the prepaid run price.
type resolvedTest struct {
	wasm, fs string
	ms, mb   int
	exit     int
	outSha   string
	runs     int
}

func (t *resolvedTest) cost() int64 { return runCost(t.ms) * int64(t.runs) }

func resolveTest(ctx context.Context, q core.Q, root string, in *testIn) (*resolvedTest, error) {
	if in == nil {
		return nil, core.Bad(`review=tests needs "test":{"wasm"|"svc",…}`)
	}
	t := &resolvedTest{ms: in.Ms, mb: in.Mb, exit: in.Exit, outSha: in.OutSha, runs: in.Runs}
	if t.ms == 0 {
		t.ms = defTestMs
	}
	if t.mb == 0 {
		t.mb = defTestMb
	}
	if t.runs == 0 {
		t.runs = defTestRuns
	}
	if t.ms < 1 || t.ms > maxTestMs || t.mb < 1 || t.mb > maxTestMb {
		return nil, core.Bad(fmt.Sprintf("test.ms 1..%d, test.mb 1..%d", maxTestMs, maxTestMb))
	}
	if t.runs < 1 || t.runs > maxTestRuns {
		return nil, core.Bad(fmt.Sprintf("test.runs 1..%d", maxTestRuns))
	}
	if t.outSha != "" && !hashRe.MatchString(t.outSha) {
		return nil, core.Bad("test.out_sha256 must be a sha256 hex")
	}
	switch {
	case in.Svc != "" && in.Wasm != "":
		return nil, core.Bad("give test.wasm or test.svc, not both")
	case in.Svc != "":
		if SvcWasmFn == nil {
			return nil, core.Bad("test.svc unavailable")
		}
		wasm, fs, verified, err := SvcWasmFn(ctx, q, in.Svc)
		if err != nil {
			return nil, err
		}
		if !verified {
			return nil, core.Bad("test.svc must be a verified service")
		}
		t.wasm, t.fs = wasm, fs
		if in.FS != "" {
			t.fs = in.FS
		}
	case hashRe.MatchString(in.Wasm):
		var owner, kind string
		var private, public bool
		err := q.QueryRow(ctx, `SELECT owner_root, kind, private, public FROM blobs WHERE hash = $1`, in.Wasm).Scan(&owner, &kind, &private, &public)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, core.E(404, "notfound", "test.wasm blob "+in.Wasm[:12])
		}
		if err != nil {
			return nil, err
		}
		if kind != "wasm" {
			return nil, core.Bad("test.wasm is not a wasm module")
		}
		if owner != root && !public {
			return nil, core.E(403, "auth", "test.wasm blob is not yours")
		}
		t.wasm, t.fs = in.Wasm, in.FS
	default:
		return nil, core.Bad("test.wasm must be a sha256 hex (or test.svc)")
	}
	if t.fs != "" && !hashRe.MatchString(t.fs) {
		return nil, core.Bad("test.fs must be a sha256 hex")
	}
	return t, nil
}

// create escrows a bounty (16.2): ReserveEarned of the escrow (+ prepaid test runs + peer fees),
// caps 4.3 (open bounties and escrowed credits are live caps), one live bounty per task, task
// creation through forge.CreateTask when a title is given. A tests bounty then runs the test once
// on an empty blob (trivial-test detection, REV3).
func (s *svc) create(ctx context.Context, id *core.Ident, in createIn) (*bounty, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	if in.Credits < minCredits || in.Credits > maxCredits {
		return nil, core.Bad(fmt.Sprintf("credits %d..%d", minCredits, maxCredits))
	}
	if in.DeadlineH == 0 {
		in.DeadlineH = defDeadlineH
	}
	if in.DeadlineH < minDeadlineH || in.DeadlineH > maxDeadlineH {
		return nil, core.Bad(fmt.Sprintf("deadline_h %d..%d", minDeadlineH, maxDeadlineH))
	}
	if in.Review == "" {
		in.Review = "creator"
	}
	switch in.Review {
	case "creator", "tests":
	case "peer":
		if PeerReviewFn == nil {
			return nil, core.Bad("review=peer unavailable (no peer reviewers); use creator")
		}
	default:
		return nil, core.Bad("review must be creator, peer or tests")
	}
	if in.Review != "tests" && in.Test != nil {
		return nil, core.Bad(`"test" needs review=tests`)
	}
	if in.Review == "tests" && in.Test == nil {
		return nil, core.Bad(`review=tests needs "test":{"wasm"|"svc",…}`)
	}
	var task int64
	raw := strings.TrimSpace(string(in.Task))
	switch {
	case raw == "" || raw == "null":
		return nil, core.Bad(`task required: a number or {"title","body","tags"}`)
	case raw[0] == '{':
		var nt newTask
		dec := json.NewDecoder(strings.NewReader(raw))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&nt); err != nil {
			return nil, core.Bad("task: title, body, tags")
		}
		n, err := forge.CreateTask(ctx, s.d, id, forge.TaskInput{Title: nt.Title, Body: nt.Body, Tags: nt.Tags})
		if err != nil {
			return nil, err
		}
		task = n
	default:
		if _, err := fmt.Sscanf(raw, "%d", &task); err != nil || task <= 0 || itoa(task) != raw {
			return nil, core.Bad("task must be a task number")
		}
	}
	var test *resolvedTest
	b := &bounty{ID: core.NewID('b'), Task: task, Creator: id.ID, CreatorRoot: id.Root, Escrow: in.Credits, Review: in.Review,
		Deadline: time.Now().Add(time.Duration(in.DeadlineH) * time.Hour), State: "open"}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var state, troot string
		var quarantine bool
		err := tx.QueryRow(ctx, `SELECT state, root, quarantine FROM tasks WHERE n = $1 FOR UPDATE`, task).Scan(&state, &troot, &quarantine)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && state == "hidden") {
			return core.E(404, "notfound", "task #"+itoa(task))
		}
		if err != nil {
			return err
		}
		if state == "done" {
			return core.E(409, "bad", "task closed")
		}
		if troot != id.Root {
			return core.E(403, "auth", "task creator only")
		}
		if quarantine {
			return core.E(409, "quarantine", "task quarantined")
		}
		var liveID string
		if err := tx.QueryRow(ctx, `SELECT id FROM bounties WHERE task = $1 AND state IN `+liveStates+` LIMIT 1`, task).Scan(&liveID); err == nil {
			return core.E(409, "dup", "bounty "+liveID+" live on task #"+itoa(task))
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		hold := in.Credits
		if in.Review == "tests" {
			if test, err = resolveTest(ctx, tx, id.Root, in.Test); err != nil {
				return err
			}
			hold += test.cost()
			b.TestWasm, b.TestFS, b.TestMs, b.TestMb, b.TestExit, b.TestOutSha, b.TestRuns = test.wasm, test.fs, test.ms, test.mb, test.exit, test.outSha, test.runs
		}
		if in.Review == "peer" {
			hold += 2 * reviewFee(in.Credits)
		}
		b.Held = hold
		st, err := trust.Load(ctx, tx, id.Root)
		if err != nil {
			return err
		}
		lvl := st.CapLevel()
		capN, capEsc := trust.Cap("bounties", lvl), trust.Cap("bounty_escrow", lvl)
		var open int
		var held int64
		if err := tx.QueryRow(ctx, `SELECT count(*), coalesce(sum(held), 0) FROM bounties WHERE creator_root = $1 AND state IN `+liveStates, id.Root).Scan(&open, &held); err != nil {
			return err
		}
		if capN == 0 {
			return core.E(429, "quota", "bounties L1 required")
		}
		if open >= capN {
			return core.E(429, "quota", fmt.Sprintf("bounties open %d/%d", open, capN))
		}
		if held+hold > int64(capEsc) {
			return core.E(429, "quota", fmt.Sprintf("bounty_escrow %d/%d", held+hold, capEsc))
		}
		if err := core.ReserveEarned(ctx, tx, id.ID, hold); err != nil {
			if errors.Is(err, core.ErrEarned) {
				return core.E(402, "credits", fmt.Sprintf("earned required (earned=%d need=%d; bounties escrow transferable credits only)", id.Earned, hold))
			}
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO bounties (id, task, creator, creator_root, escrow, held, review, deadline, state,
				test_wasm, test_fs, test_ms, test_mb, test_exit, test_out_sha, test_runs)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'open', $9, $10, $11, $12, $13, $14, $15)`,
			b.ID, b.Task, b.Creator, b.CreatorRoot, b.Escrow, b.Held, b.Review, b.Deadline,
			b.TestWasm, b.TestFS, b.TestMs, b.TestMb, b.TestExit, b.TestOutSha, b.TestRuns); err != nil {
			return err
		}
		if err := core.Event(ctx, tx, "bt", b.ID, "", fmt.Sprintf("bounty %dcr on #%d", b.Escrow, b.Task)); err != nil {
			return err
		}
		return core.Audit(ctx, tx, id.ID, "bt", b.ID, int(b.Escrow))
	})
	if err != nil {
		return nil, err
	}
	if test != nil {
		s.probe(ctx, b)
	}
	s.d.Notify.Wake(forge.TaskTopic(task))
	return load(ctx, s.d.DB, b.ID, false)
}

// probe runs the test once on an empty blob (REV3 trivial-test detection); the run is charged to
// the creator's live balance and a failure to start only skips the detection.
func (s *svc) probe(ctx context.Context, b *bounty) {
	empty, err := compute.PutBlobBytes(ctx, s.d, b.CreatorRoot, []byte{}, "")
	if err != nil {
		s.d.Log.Warn("bounty probe blob", "bounty", b.ID, "err", err)
		return
	}
	jid, err := s.submitTest(ctx, b, empty)
	if err != nil {
		s.d.Log.Warn("bounty probe", "bounty", b.ID, "err", err)
		return
	}
	s.d.DB.Exec(ctx, `UPDATE bounties SET trivial_job = $2 WHERE id = $1`, b.ID, jid)
}

// submitTest queues the test module on blob in as the creator (jobs.bounty = id, fresh so the
// result cache never short-circuits OnDone). Kind btest is tried first; a compute build that does
// not accept it yet runs the job as a plain job, the bounty column still marking it.
func (s *svc) submitTest(ctx context.Context, b *bounty, in string) (string, error) {
	spec := compute.Spec{Wasm: b.TestWasm, In: in, FS: b.TestFS, Ms: b.TestMs, Mb: b.TestMb, Fresh: true, Lane: "public", Kind: "btest", Bounty: b.ID}
	ident := &core.Ident{ID: b.Creator, Root: b.CreatorRoot}
	ids, err := compute.Submit(ctx, s.d, ident, []compute.Spec{spec})
	var ae *core.APIError
	if errors.As(err, &ae) && ae.Status == 400 && strings.HasPrefix(ae.Msg, "kind must be") {
		spec.Kind = "job"
		ids, err = compute.Submit(ctx, s.d, ident, []compute.Spec{spec})
	}
	if err != nil {
		return "", err
	}
	if len(ids) == 0 {
		return "", core.E(500, "internal", "no job")
	}
	return ids[0], nil
}

// submitIn is the POST /v1/bt/{id}/submit body.
type submitIn struct {
	Out   string `json:"out"`
	Text  string `json:"text"`
	Fence int64  `json:"fence"`
	Key   string `json:"key"`
}

// submit records the claim holder's work (16.2): the caller's root holds the claim and fence
// matches forge.ClaimFence, a bond of greatest(2, 10 %) is reserved, one submission per hunter.
// A tests bounty then runs the test on the submitted blob, charged to the prepaid escrow.
func (s *svc) submit(ctx context.Context, id *core.Ident, bid string, in submitIn) (*bounty, []string, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, nil, err
	}
	in.Text = strings.TrimSpace(doc.CleanMulti(scrub.Normalize(in.Text)))
	switch {
	case in.Out != "" && in.Text != "":
		return nil, nil, core.Bad("give out or text, not both")
	case in.Out == "" && in.Text == "":
		return nil, nil, core.Bad("out (blob hash) or text required")
	case in.Out != "" && !hashRe.MatchString(in.Out):
		return nil, nil, core.Bad("out must be a sha256 hex")
	case len(in.Text) > maxSubText:
		return nil, nil, core.Bad("text <=4096")
	}
	if in.Text != "" {
		if _, aerr := scrub.RejectOrMask(map[string]*string{"text": &in.Text}); aerr != nil {
			return nil, nil, aerr
		}
	}
	var b *bounty
	var distinct bool
	var runPrice int64
	prevState := ""
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var err error
		if b, err = load(ctx, tx, bid, true); err != nil {
			return err
		}
		if b.Hidden && !b.party(id.Root) {
			return core.ErrNotFound
		}
		if b.State != "open" && b.State != "rejected" {
			return core.E(409, "bad", "not open ("+b.State+")")
		}
		if !b.Deadline.After(time.Now()) {
			return core.E(409, "bad", "deadline passed")
		}
		if id.Root == b.CreatorRoot {
			return core.E(403, "auth", "own bounty")
		}
		if b.SubmittedAt == nil && b.HunterRoot != "" && b.HunterRoot != id.Root {
			return core.E(403, "auth", "assigned to "+b.Hunter)
		}
		if b.Review == "tests" {
			if in.Out == "" {
				return core.Bad("out required: tests run on the submitted blob")
			}
			if b.TestRuns <= 0 {
				return core.E(409, "bad", "test runs exhausted")
			}
		}
		fence, holder, err := forge.ClaimFence(ctx, tx, b.Task)
		if err != nil {
			return err
		}
		if holder != id.Root {
			return core.E(409, "taken", "claim required: POST /v1/t/"+itoa(b.Task)+"/claim")
		}
		if fence != in.Fence {
			return core.E(409, "fenced", fmt.Sprintf("claim fence %d", fence))
		}
		if in.Out != "" {
			var private bool
			var owner string
			err := tx.QueryRow(ctx, `SELECT private, owner_root FROM blobs WHERE hash = $1`, in.Out).Scan(&private, &owner)
			if errors.Is(err, pgx.ErrNoRows) || (err == nil && private && owner != id.Root) {
				return core.E(404, "notfound", "out blob "+in.Out[:12])
			}
			if err != nil {
				return err
			}
		}
		bond := hunterBond(b.Escrow)
		if _, err := tx.Exec(ctx, `INSERT INTO bonds (ref, root, credits) VALUES ($1, $2, $3)`, b.ID, id.Root, bond); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "dup", "one submission per hunter per bounty")
			}
			return err
		}
		if err := core.Reserve(ctx, tx, id.ID, bond); err != nil {
			if errors.Is(err, core.ErrCredits) {
				return core.E(402, "credits", fmt.Sprintf("bond %d", bond))
			}
			return err
		}
		prevState = b.State
		runs := 0
		if b.Review == "tests" {
			runs = 1
		}
		if _, err := tx.Exec(ctx, `UPDATE bounties SET state = 'submitted', hunter = $2, hunter_root = $3, sub_out = $4, sub_text = $5, sub_fence = $6,
				submitted_at = now(), bond = $7, sub_seen_at = NULL, rejected_at = NULL, escalated_at = NULL, test_runs = test_runs - $8, test_job = ''
			WHERE id = $1`, b.ID, id.ID, id.Root, in.Out, in.Text, fence, bond, runs); err != nil {
			return err
		}
		if b.Review == "tests" {
			runPrice = runCost(b.TestMs)
			if err := core.RefundEarned(ctx, tx, b.Creator, runPrice); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `UPDATE bounties SET held = held - $2 WHERE id = $1`, b.ID, runPrice); err != nil {
				return err
			}
		}
		if b.Review == "peer" && PeerReviewFn != nil {
			if err := PeerReviewFn(ctx, tx, b.Task, b.Escrow); err != nil {
				return err
			}
		}
		if err := core.Event(ctx, tx, "bt", b.ID, "", "submission by "+id.ID); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "bts", b.ID, int(bond)); err != nil {
			return err
		}
		if b.Review != "tests" {
			if err := core.SysMail(ctx, tx, b.CreatorRoot, "bounty "+b.ID+" submission",
				fmt.Sprintf("%s submitted on #%d. Read it: GET /v1/bt/%s (default-accept 72 h after you read it); POST /v1/bt/%s/accept | reject {\"why\"}",
					id.ID, b.Task, b.ID, b.ID)); err != nil {
				return err
			}
		}
		distinct, err = trust.Distinct(ctx, tx, b.CreatorRoot, id.Root)
		return err
	})
	if err != nil {
		return nil, nil, err
	}
	if b.Review == "tests" {
		if jid, err := s.submitTest(ctx, b, in.Out); err != nil {
			s.undoSubmit(ctx, b.ID, id, prevState, runPrice)
			return nil, nil, err
		} else if _, err := s.d.DB.Exec(ctx, `UPDATE bounties SET test_job = $2 WHERE id = $1 AND state = 'submitted' AND hunter = $3`, b.ID, jid, id.ID); err != nil {
			return nil, nil, err
		}
	}
	s.wake(b)
	var notes []string
	if !distinct {
		notes = append(notes, "note: same super-group as the creator: the payout earns nothing")
	}
	b, err = load(ctx, s.d.DB, b.ID, false)
	return b, notes, err
}

// undoSubmit rolls a tests submission back when its job could not start: the run's price goes
// back into the hold, the bond is returned and the hunter may submit again.
func (s *svc) undoSubmit(ctx context.Context, bid string, id *core.Ident, prevState string, runPrice int64) {
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		b, err := load(ctx, tx, bid, true)
		if err != nil {
			return err
		}
		if b.State != "submitted" || b.Hunter != id.ID {
			return nil
		}
		if err := core.ReserveEarned(ctx, tx, b.Creator, runPrice); err == nil {
			if _, err := tx.Exec(ctx, `UPDATE bounties SET held = held + $2, test_runs = test_runs + 1 WHERE id = $1`, b.ID, runPrice); err != nil {
				return err
			}
		} else if !errors.Is(err, core.ErrEarned) {
			return err
		}
		return reopen(ctx, tx, b, prevState, "test run could not start", true)
	})
	if err != nil {
		s.d.Log.Warn("bounty undo submit", "bounty", bid, "err", err)
	}
}

func (s *svc) wake(b *bounty) {
	s.d.Notify.Wake("bt:" + b.ID)
	s.d.Notify.Wake(forge.TaskTopic(b.Task))
}

func wakeAll(b *bounty) {
	if d := current.Load(); d != nil {
		d.Notify.Wake("bt:" + b.ID)
		d.Notify.Wake(forge.TaskTopic(b.Task))
	}
}

// accept pays the hunter and closes the task (creator tree).
func (s *svc) accept(ctx context.Context, id *core.Ident, bid string) (*bounty, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		b, err := load(ctx, tx, bid, true)
		if err != nil {
			return err
		}
		if id.Root != b.CreatorRoot {
			return core.E(403, "auth", "creator only")
		}
		if b.State != "submitted" {
			return core.E(409, "bad", "not submitted ("+b.State+")")
		}
		if err := core.Audit(ctx, tx, id.ID, "bta", b.ID, int(b.Escrow)); err != nil {
			return err
		}
		return settlePay(ctx, tx, b, b.Escrow, "accepted by "+id.ID)
	})
	if err != nil {
		return nil, err
	}
	return load(ctx, s.d.DB, bid, false)
}

// rejectIn is the POST /v1/bt/{id}/reject body.
type rejectIn struct {
	Why string `json:"why"`
}

// reject reopens the bounty (creator review only): claim dropped, bond returned, the hunter may
// escalate. A rejection with reviewers pending (peer, tests, escalated) is refused.
func (s *svc) reject(ctx context.Context, id *core.Ident, bid string, in rejectIn) (*bounty, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	in.Why = strings.TrimSpace(doc.CleanMulti(scrub.Normalize(in.Why)))
	if len(in.Why) > maxWhy {
		return nil, core.Bad("why <=1024")
	}
	if in.Why != "" {
		if _, aerr := scrub.RejectOrMask(map[string]*string{"why": &in.Why}); aerr != nil {
			return nil, aerr
		}
	}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		b, err := load(ctx, tx, bid, true)
		if err != nil {
			return err
		}
		if id.Root != b.CreatorRoot {
			return core.E(403, "auth", "creator only")
		}
		if b.State != "submitted" {
			return core.E(409, "bad", "not submitted ("+b.State+")")
		}
		switch {
		case b.EscalatedAt != nil:
			return core.E(409, "bad", "escalated: peer reviewers decide")
		case b.Review == "tests":
			return core.E(409, "bad", "tests decide")
		case b.Review == "peer" && PeerReviewFn != nil:
			return core.E(409, "bad", "peer reviewers decide")
		}
		if _, err := tx.Exec(ctx, `UPDATE bounties SET state = 'open', rejected_at = now(), rejects = rejects + 1, test_job = '' WHERE id = $1 AND state = 'submitted'`, b.ID); err != nil {
			return err
		}
		if err := returnBond(ctx, tx, b.ID, b.Hunter, b.HunterRoot); err != nil {
			return err
		}
		if err := dropClaim(ctx, tx, b.Task, b.HunterRoot); err != nil {
			return err
		}
		note := "bounty " + b.ID + " rejected"
		if in.Why != "" {
			note += ": " + in.Why
		}
		if err := addNote(ctx, tx, b.Task, b.Creator, b.CreatorRoot, note); err != nil {
			return err
		}
		if err := core.Event(ctx, tx, "bt", b.ID, "", "rejected"); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "btr", b.ID, 0); err != nil {
			return err
		}
		return core.SysMail(ctx, tx, b.HunterRoot, "bounty "+b.ID+" rejected",
			fmt.Sprintf("%s\nbond returned; POST /v1/bt/%s/escalate asks two peer reviewers (bond 2)", in.Why, b.ID))
	})
	if err != nil {
		return nil, err
	}
	b, err := load(ctx, s.d.DB, bid, false)
	if err == nil {
		s.wake(b)
	}
	return b, err
}

// escalate (REV3): the hunter, after 72 h unread or after a reject, asks two Distinct peer
// reviewers (PeerReviewFn) for a decision; bond 2. Their fees come out of the escrow.
func (s *svc) escalate(ctx context.Context, id *core.Ident, bid string) (*bounty, error) {
	if err := s.writeAuth(id); err != nil {
		return nil, err
	}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		b, err := load(ctx, tx, bid, true)
		if err != nil {
			return err
		}
		if b.Hunter == "" || id.Root != b.HunterRoot || b.SubmittedAt == nil {
			return core.E(403, "auth", "hunter only")
		}
		if b.EscalatedAt != nil {
			return core.E(409, "dup", "escalated")
		}
		if !b.live() {
			return core.E(409, "bad", "closed ("+b.State+")")
		}
		if PeerReviewFn == nil {
			return core.E(409, "bad", "escalate unavailable (no peer reviewers)")
		}
		unread := b.State == "submitted" && b.SeenAt == nil && time.Since(*b.SubmittedAt) > reviewWindow
		rejected := b.RejectedAt != nil && b.State != "submitted"
		if !unread && !rejected {
			return core.E(409, "bad", "escalate after 72 h unread or after a reject")
		}
		if 2*reviewFee(b.Escrow) >= b.Escrow {
			return core.E(409, "bad", "escrow too small to pay reviewers")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO bonds (ref, root, credits) VALUES ($1, $2, $3)`, b.ID+"/esc", id.Root, escalateBond); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "dup", "escalated")
			}
			return err
		}
		if err := core.Reserve(ctx, tx, id.ID, escalateBond); err != nil {
			if errors.Is(err, core.ErrCredits) {
				return core.E(402, "credits", fmt.Sprintf("bond %d", escalateBond))
			}
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE bounties SET state = 'submitted', escalated_at = now() WHERE id = $1`, b.ID); err != nil {
			return err
		}
		if err := PeerReviewFn(ctx, tx, b.Task, b.Escrow); err != nil {
			return err
		}
		if err := core.Event(ctx, tx, "bt", b.ID, "", "escalated by "+id.ID); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "bte", b.ID, escalateBond); err != nil {
			return err
		}
		return core.SysMail(ctx, tx, b.CreatorRoot, "bounty "+b.ID+" escalated", "two peer reviewers decide; GET /v1/bt/"+b.ID)
	})
	if err != nil {
		return nil, err
	}
	b, err := load(ctx, s.d.DB, bid, false)
	if err == nil {
		s.wake(b)
	}
	return b, err
}

// PeerVerdict settles a peer review (16.2, REV3): verdicts maps the two reviewer identities to
// accept | reject | spam. Reviewers must be Distinct from each other, the creator and the hunter;
// each is paid 10 % of the escrow (min 1), prepaid for review=peer and taken from the escrow for
// an escalation. Two accepts pay; two rejects refund (two spam forfeit the hunter bond); a split
// default-accepts a peer-reviewed bounty and refunds an escalated one. Exported for the review
// package.
func PeerVerdict(ctx context.Context, q core.Q, id string, verdicts map[string]string) error {
	if len(verdicts) != 2 {
		return core.Bad("two verdicts")
	}
	b, err := load(ctx, q, id, true)
	if err != nil {
		return err
	}
	if b.State != "submitted" || b.Hunter == "" {
		return core.E(409, "bad", "not submitted ("+b.State+")")
	}
	var ids []string
	accepts, spams := 0, 0
	for rid, v := range verdicts {
		if !core.ValidID(rid) {
			return core.Bad("bad reviewer id")
		}
		switch v {
		case "accept":
			accepts++
		case "spam":
			spams++
		case "reject":
		default:
			return core.Bad("verdict must be accept, reject or spam")
		}
		ids = append(ids, rid)
	}
	rows, err := q.Query(ctx, `SELECT id, root FROM identities WHERE id = ANY($1) AND revoked_at IS NULL`, ids)
	if err != nil {
		return err
	}
	roots := map[string]string{}
	for rows.Next() {
		var rid, root string
		if err := rows.Scan(&rid, &root); err != nil {
			rows.Close()
			return err
		}
		roots[rid] = root
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if len(roots) != 2 {
		return core.Bad("unknown reviewer")
	}
	r1, r2 := roots[ids[0]], roots[ids[1]]
	for _, pair := range [][]string{{r1, r2}, {r1, b.CreatorRoot}, {r1, b.HunterRoot}, {r2, b.CreatorRoot}, {r2, b.HunterRoot}} {
		ok, err := trust.Distinct(ctx, q, pair...)
		if err != nil {
			return err
		}
		if !ok {
			return core.Bad("reviewers not distinct")
		}
	}
	fee := reviewFee(b.Escrow)
	if 2*fee > b.Held {
		return core.E(409, "bad", "hold too small for reviewer fees")
	}
	for _, rid := range ids {
		if err := core.Earn(ctx, q, rid, fee); err != nil {
			return err
		}
	}
	if err := q.QueryRow(ctx, `UPDATE bounties SET held = held - $2 WHERE id = $1 RETURNING held`, b.ID, 2*fee).Scan(&b.Held); err != nil {
		return err
	}
	escalated := b.EscalatedAt != nil
	payout := b.Escrow
	if escalated {
		payout -= 2 * fee
	}
	switch {
	case accepts == 2:
		err = settlePay(ctx, q, b, payout, "peer accepted")
	case accepts == 0:
		if spams == 2 {
			if err := forfeitBond(ctx, q, b.ID, b.HunterRoot); err != nil {
				return err
			}
		}
		if err := dropClaim(ctx, q, b.Task, b.HunterRoot); err != nil {
			return err
		}
		err = settleRefund(ctx, q, b, "peer rejected")
	case escalated:
		err = settleRefund(ctx, q, b, "peer split")
	default:
		err = settlePay(ctx, q, b, payout, "peer split -> default-accept")
	}
	if err != nil {
		return err
	}
	return returnBond(ctx, q, b.ID+"/esc", b.Hunter, b.HunterRoot)
}

// settlePay is the guarded payout (16.1): submitted -> paid once. The hunter earns payout unless
// it shares the creator's super-group (trust.Distinct), the remainder of the hold goes back to the
// creator, the bond is returned, the task is closed.
func settlePay(ctx context.Context, q core.Q, b *bounty, payout int64, how string) error {
	distinct, err := trust.Distinct(ctx, q, b.CreatorRoot, b.HunterRoot)
	if err != nil {
		return err
	}
	if !distinct {
		payout = 0
	}
	var held int64 // the hold before the transition (RETURNING alone would show the new 0)
	err = q.QueryRow(ctx, `WITH old AS (SELECT held FROM bounties WHERE id = $1 AND state = 'submitted' FOR UPDATE),
		u AS (UPDATE bounties t SET state = 'paid', payout = $2, held = 0, closed_at = now(), test_job = ''
		      FROM old WHERE t.id = $1 AND t.state = 'submitted' RETURNING old.held)
		SELECT held FROM u`, b.ID, payout).Scan(&held)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.E(409, "bad", "not submitted")
	}
	if err != nil {
		return err
	}
	if payout > held {
		payout = held
	}
	if payout > 0 {
		if err := core.Earn(ctx, q, b.Hunter, payout); err != nil {
			return err
		}
	}
	if rem := held - payout; rem > 0 {
		if err := core.RefundEarned(ctx, q, b.Creator, rem); err != nil {
			return err
		}
	}
	if err := returnBond(ctx, q, b.ID, b.Hunter, b.HunterRoot); err != nil {
		return err
	}
	note := fmt.Sprintf("bounty %s paid %dcr to %s (%s)", b.ID, payout, b.Hunter, how)
	if !distinct {
		note = fmt.Sprintf("bounty %s closed: %s shares the creator's super-group, payout withheld (%s)", b.ID, b.Hunter, how)
	}
	if err := closeTask(ctx, q, b, note); err != nil {
		return err
	}
	if err := core.Event(ctx, q, "bt", b.ID, "", fmt.Sprintf("paid %d", payout)); err != nil {
		return err
	}
	wakeAll(b)
	return core.SysMail(ctx, q, b.HunterRoot, fmt.Sprintf("bounty %s paid %d", b.ID, payout), note)
}

// settleRefund is the guarded refund: a live bounty -> refunded once; the hold returns to the
// creator (earned class), a submitted hunter's bond comes back. The task stays open.
func settleRefund(ctx context.Context, q core.Q, b *bounty, why string) error {
	var held int64
	err := q.QueryRow(ctx, `WITH old AS (SELECT held FROM bounties WHERE id = $1 AND state IN `+liveStates+` FOR UPDATE),
		u AS (UPDATE bounties t SET state = 'refunded', held = 0, closed_at = now(), test_job = ''
		      FROM old WHERE t.id = $1 AND t.state IN `+liveStates+` RETURNING old.held)
		SELECT held FROM u`, b.ID).Scan(&held)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.E(409, "bad", "closed")
	}
	if err != nil {
		return err
	}
	if held > 0 {
		if err := core.RefundEarned(ctx, q, b.Creator, held); err != nil {
			return err
		}
	}
	if b.Hunter != "" {
		if err := returnBond(ctx, q, b.ID, b.Hunter, b.HunterRoot); err != nil {
			return err
		}
	}
	if err := core.Event(ctx, q, "bt", b.ID, "", "refunded: "+why); err != nil {
		return err
	}
	if b.State == "submitted" && b.HunterRoot != "" {
		if err := core.SysMail(ctx, q, b.HunterRoot, "bounty "+b.ID+" refunded", why+"; bond returned"); err != nil {
			return err
		}
	}
	wakeAll(b)
	return core.SysMail(ctx, q, b.CreatorRoot, fmt.Sprintf("bounty %s refunded %d", b.ID, held), why)
}

// reopen puts a submitted bounty back to state (open|rejected) with the bond returned; retry
// deletes the bond row and the submission so the same hunter may submit again (the run never
// happened).
func reopen(ctx context.Context, q core.Q, b *bounty, state, why string, retry bool) error {
	if state != "open" && state != "rejected" {
		state = "open"
	}
	tag, err := q.Exec(ctx, `UPDATE bounties SET state = $2, test_job = '', rejected_at = CASE WHEN $2 = 'rejected' THEN now() ELSE rejected_at END
		WHERE id = $1 AND state = 'submitted'`, b.ID, state)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if err := returnBond(ctx, q, b.ID, b.Hunter, b.HunterRoot); err != nil {
		return err
	}
	if retry {
		if _, err := q.Exec(ctx, `DELETE FROM bonds WHERE ref = $1 AND root = $2`, b.ID, b.HunterRoot); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `UPDATE bounties SET hunter = '', hunter_root = '', sub_out = '', sub_text = '', sub_fence = 0, submitted_at = NULL, bond = 0 WHERE id = $1`, b.ID); err != nil {
			return err
		}
	}
	if err := core.Event(ctx, q, "bt", b.ID, "", "reopened: "+why); err != nil {
		return err
	}
	wakeAll(b)
	return core.SysMail(ctx, q, b.HunterRoot, "bounty "+b.ID+" reopened", why+"; bond returned")
}

// returnBond gives a held bond back to the identity that paid it.
func returnBond(ctx context.Context, q core.Q, ref, payee, root string) error {
	var n int64
	err := q.QueryRow(ctx, `UPDATE bonds SET state = 'returned' WHERE ref = $1 AND root = $2 AND state = 'held' RETURNING credits`, ref, root).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return core.Refund(ctx, q, payee, n)
}

// forfeitBond burns a held bond (two spam verdicts).
func forfeitBond(ctx context.Context, q core.Q, ref, root string) error {
	var n int64
	err := q.QueryRow(ctx, `UPDATE bonds SET state = 'forfeited' WHERE ref = $1 AND root = $2 AND state = 'held' RETURNING credits`, ref, root).Scan(&n)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	return core.BurnHeld(ctx, q, n, "bond", ref)
}

// closeTask marks the task done (claims released) with a closing note by the creator.
func closeTask(ctx context.Context, q core.Q, b *bounty, note string) error {
	if err := addNote(ctx, q, b.Task, b.Creator, b.CreatorRoot, note); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE tasks SET state = 'done', closed_at = now(), ask = '' WHERE n = $1 AND state = 'open'`, b.Task); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE task_claims SET until = now() WHERE n = $1 AND until > now()`, b.Task); err != nil {
		return err
	}
	return core.Event(ctx, q, "t", itoa(b.Task), "", "done by bounty "+b.ID)
}

// addNote writes a task note on behalf of id (quota and scrub as the owner's own request); a
// refusal (cap, closed task) never fails the settlement.
func addNote(ctx context.Context, q core.Q, n int64, id, root, text string) error {
	err := forge.AddNoteAs(ctx, q, n, id, root, text)
	var ae *core.APIError
	if errors.As(err, &ae) {
		return nil
	}
	return err
}

// dropClaim releases root's claim on the task when it still holds one.
func dropClaim(ctx context.Context, q core.Q, n int64, root string) error {
	if root == "" {
		return nil
	}
	err := forge.Drop(ctx, q, n, root)
	var ae *core.APIError
	if errors.As(err, &ae) {
		return nil
	}
	return err
}

// CreateFromEscrow opens a bounty whose escrow the caller already holds (auction awards, 27.4):
// the hold moves under this row in the caller's transaction, the winner is the only root allowed
// to submit, creator review applies, then 16.2 runs unchanged. Returns the bounty id.
func CreateFromEscrow(ctx context.Context, q core.Q, task int64, escrow int64, creator, creatorRoot, hunter, hunterRoot string, deadline time.Time) (string, error) {
	if escrow < 1 || escrow > maxCredits {
		return "", core.Bad(fmt.Sprintf("escrow 1..%d", maxCredits))
	}
	if !core.ValidID(creator) || !core.ValidID(creatorRoot) || !core.ValidID(hunter) || !core.ValidID(hunterRoot) {
		return "", core.Bad("bad identity")
	}
	if !deadline.After(time.Now()) {
		return "", core.Bad("deadline in the past")
	}
	var state string
	err := q.QueryRow(ctx, `SELECT state FROM tasks WHERE n = $1`, task).Scan(&state)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && state == "hidden") {
		return "", core.E(404, "notfound", "task #"+itoa(task))
	}
	if err != nil {
		return "", err
	}
	if state == "done" {
		return "", core.E(409, "bad", "task closed")
	}
	var liveID string
	if err := q.QueryRow(ctx, `SELECT id FROM bounties WHERE task = $1 AND state IN `+liveStates+` LIMIT 1`, task).Scan(&liveID); err == nil {
		return "", core.E(409, "dup", "bounty "+liveID+" live on task #"+itoa(task))
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	id := core.NewID('b')
	if _, err := q.Exec(ctx, `INSERT INTO bounties (id, task, creator, creator_root, escrow, held, review, deadline, state, hunter, hunter_root)
		VALUES ($1, $2, $3, $4, $5, $5, 'creator', $6, 'open', $7, $8)`, id, task, creator, creatorRoot, escrow, deadline, hunter, hunterRoot); err != nil {
		return "", err
	}
	if err := core.Event(ctx, q, "bt", id, "", fmt.Sprintf("bounty %dcr on #%d (auction)", escrow, task)); err != nil {
		return "", err
	}
	return id, nil
}

// OnDone settles a test run (REV3), inside compute's finalize transaction: the creation probe sets
// trivial, a submission's run pays on exit == test.exit (and out_sha256 when set) or rejects with
// the first 2 KiB of the test's stdout as a task note. Exported for the compute.OnDone chain.
func OnDone(ctx context.Context, q core.Q, j *compute.Job) error {
	if j == nil || j.Bounty == "" {
		return nil
	}
	b, err := load(ctx, q, j.Bounty, true)
	if errors.Is(err, core.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	pass := j.Status == "done" && j.Code == b.TestExit && (b.TestOutSha == "" || j.Out == b.TestOutSha)
	if j.ID == b.TrivialJob {
		_, err := q.Exec(ctx, `UPDATE bounties SET trivial = $2, trivial_job = '' WHERE id = $1`, b.ID, pass)
		return err
	}
	if j.ID != b.TestJob || b.State != "submitted" {
		return nil
	}
	if j.Status != "done" {
		return reopen(ctx, q, b, "open", "test run failed: "+doc.SafeLine(j.Reason), false)
	}
	if pass {
		return settlePay(ctx, q, b, b.Escrow, "tests passed j="+j.ID)
	}
	tag, err := q.Exec(ctx, `UPDATE bounties SET state = 'rejected', rejected_at = now(), rejects = rejects + 1, test_job = '' WHERE id = $1 AND state = 'submitted'`, b.ID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	if err := returnBond(ctx, q, b.ID, b.Hunter, b.HunterRoot); err != nil {
		return err
	}
	if err := dropClaim(ctx, q, b.Task, b.HunterRoot); err != nil {
		return err
	}
	head := fmt.Sprintf("bounty %s rejected: test exit=%d want %d j=%s", b.ID, j.Code, b.TestExit, j.ID)
	if b.TestOutSha != "" && j.Out != b.TestOutSha {
		head += " out_sha256 mismatch"
	}
	note := head
	if out := stdoutHead(current.Load(), j.Out, 1900-len(head)); out != "" {
		note += "\nstdout: " + doc.Indent(out)
	}
	if err := addNote(ctx, q, b.Task, b.Creator, b.CreatorRoot, note); err != nil {
		return err
	}
	var distinctRejects int
	if err := q.QueryRow(ctx, `SELECT count(DISTINCT root) FROM bonds WHERE ref = $1 AND state <> 'held'`, b.ID).Scan(&distinctRejects); err != nil {
		return err
	}
	if distinctRejects >= disputedAfter {
		if _, err := q.Exec(ctx, `UPDATE bounties SET disputed = true WHERE id = $1`, b.ID); err != nil {
			return err
		}
	}
	if err := core.Event(ctx, q, "bt", b.ID, "", "test rejected"); err != nil {
		return err
	}
	wakeAll(b)
	return core.SysMail(ctx, q, b.HunterRoot, "bounty "+b.ID+" rejected by tests", note)
}

// stdoutHead reads up to max bytes of a job's output blob from the data dir ("" when unavailable).
func stdoutHead(d *core.Deps, hash string, max int) string {
	if d == nil || !hashRe.MatchString(hash) || max <= 0 {
		return ""
	}
	if max > stdoutNote {
		max = stdoutNote
	}
	f, err := os.Open(filepath.Join(d.Cfg.DataDir, "blobs", hash[:2], hash))
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, max)
	n, _ := f.Read(buf)
	return strings.TrimSpace(doc.CleanMulti(strings.ToValidUTF8(string(buf[:n]), "")))
}

// janitor runs the timed transitions (16.2, REV3): default-accept of read submissions after 72 h,
// refund of never-read ones at greatest(deadline, submitted + 72 h) + 72 h with the submission
// kept as a task note, deadline refunds, and reopening of tests submissions whose job died.
// Every transition is a guarded UPDATE inside its own transaction.
func (s *svc) janitor(ctx context.Context) error {
	each := func(sql string, fn func(tx pgx.Tx, b *bounty) error) error {
		rows, err := s.d.DB.Query(ctx, sql)
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
			err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
				b, err := load(ctx, tx, id, true)
				if err != nil {
					return err
				}
				return fn(tx, b)
			})
			if err != nil {
				s.d.Log.Warn("bounty janitor", "bounty", id, "err", err)
			}
		}
		return nil
	}
	if err := each(`SELECT id FROM bounties WHERE state = 'submitted' AND escalated_at IS NULL AND review <> 'tests' AND sub_seen_at IS NOT NULL
			AND submitted_at + interval '72 hours' < now() ORDER BY submitted_at LIMIT 100`, func(tx pgx.Tx, b *bounty) error {
		if b.State != "submitted" || b.SeenAt == nil || b.EscalatedAt != nil || b.Review == "tests" || time.Since(*b.SubmittedAt) < reviewWindow {
			return nil
		}
		return settlePay(ctx, tx, b, b.Escrow, "default-accept")
	}); err != nil {
		return err
	}
	if err := each(`SELECT id FROM bounties WHERE state = 'submitted' AND escalated_at IS NULL AND review <> 'tests' AND sub_seen_at IS NULL
			AND greatest(deadline, submitted_at + interval '72 hours') + interval '72 hours' < now() ORDER BY submitted_at LIMIT 100`, func(tx pgx.Tx, b *bounty) error {
		if b.State != "submitted" || b.SeenAt != nil || b.EscalatedAt != nil || b.Review == "tests" || time.Now().Before(b.autoRefundAt()) {
			return nil
		}
		note := fmt.Sprintf("bounty %s submission by %s (unread by the creator, escrow refunded, bond returned)", b.ID, b.Hunter)
		if b.SubOut != "" {
			note += "\nout: " + b.SubOut
		}
		if b.SubText != "" {
			note += "\n" + b.SubText
		}
		if err := addNote(ctx, tx, b.Task, b.Hunter, b.HunterRoot, note); err != nil {
			return err
		}
		return settleRefund(ctx, tx, b, "submission never read")
	}); err != nil {
		return err
	}
	if err := each(`SELECT id FROM bounties WHERE state IN ('open', 'rejected') AND deadline < now() ORDER BY deadline LIMIT 100`, func(tx pgx.Tx, b *bounty) error {
		if b.State == "submitted" || !b.live() || b.Deadline.After(time.Now()) {
			return nil
		}
		return settleRefund(ctx, tx, b, "deadline without submission")
	}); err != nil {
		return err
	}
	return each(`SELECT id FROM bounties WHERE state = 'submitted' AND review = 'tests' AND submitted_at < now() - interval '1 hour'
			AND (test_job = '' OR NOT EXISTS (SELECT 1 FROM jobs WHERE jobs.id = bounties.test_job AND jobs.status IN ('queued', 'running'))) LIMIT 100`,
		func(tx pgx.Tx, b *bounty) error {
			if b.State != "submitted" || b.Review != "tests" || time.Since(*b.SubmittedAt) < testStale {
				return nil
			}
			return reopen(ctx, tx, b, "open", "test run inconclusive", false)
		})
}
