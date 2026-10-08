package gov

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Limits (18.1).
const (
	MaxWhy      = 600
	MaxNeed     = 1500
	MaxVoteWhy  = 200
	MaxWhyDiff  = 300
	MaxWaitS    = 85
	proposeAge  = 7 * 24 * time.Hour
	seniorAge   = 14 * 24 * time.Hour
	seniorRep   = 10
	ledgerFlowD = 14
)

// seniorKinds need rep >= 10 and age >= 14 d to propose (doc, platform, code).
var seniorKinds = map[string]bool{"doc": true, "platform": true, "code": true}

// spaceKinds are the kinds whose space rules.vote overrides apply.
var spaceKinds = map[string]bool{"rule": true, "doc": true, "pin": true, "template": true, "member": true}

// Input is the body of POST /v1/p and pp (18.1, 27.5).
type Input struct {
	Scope        string          `json:"scope"`
	Kind         string          `json:"kind"`
	Target       string          `json:"target"`
	Patch        json.RawMessage `json:"patch"`
	Why          string          `json:"why"`
	Need         string          `json:"need"`
	Refs         []string        `json:"refs"`
	WhyDifferent string          `json:"why_different"`
	Key          string          `json:"key"`
}

// ReqHash is the idempotency hash of an input (key excluded).
func (in Input) ReqHash() []byte {
	cp := in
	cp.Key = ""
	b, _ := json.Marshal(cp)
	h := sha256.Sum256(b)
	return h[:]
}

// DupError is the 409 of a near-duplicate (18.1, 27.5): it names the earlier proposal, its state
// and decision so the caller can read it or supersede it with refs + why_different.
type DupError struct {
	*core.APIError
	ID, State, Note string
	Decided         time.Time
}

func (e *DupError) Unwrap() error { return e.APIError }

// Next are the recovery actions of a DupError: read the earlier proposal, or (decided ones)
// re-propose with refs=[id] and a why_different.
func (e *DupError) Next() []doc.Action {
	acts := []doc.Action{doc.GET("/p/"+e.ID, "")}
	if e.State != "open" && e.State != "contested" {
		acts = append([]doc.Action{doc.POST("/v1/p", "refs=["+e.ID+"]+why_different")}, acts...)
	}
	return acts
}

// VoteResult is what a vote recorded.
type VoteResult struct {
	W      float64
	Reason string // "" | ledger | cohort | standing
}

// Line is the reply head of a vote.
func (v VoteResult) Line() string {
	s := "ok vote recorded weight=" + fw(v.W)
	switch v.Reason {
	case "ledger":
		s += " (credit flow with proposer in 14 d)"
	case "cohort":
		s += " (shared cohort with proposer)"
	case "standing":
		s += " (below governance eligibility)"
	}
	return s
}

// --- rows ------------------------------------------------------------------------------------------

const cols = `id, scope, kind, target, patch, why, need, refs, why_different, supersedes, author, author_root, created, closes_at, state,
	yes_w, no_w, eligible_w, groups, coalesce(prev, 'null'::jsonb), result, applied_at, passed_at, timelock_at, contested_at, decided_at, note,
	check_status, check_log, escrow, escrow_state, window_h, threshold, quorum, flags, hazard, lexicon, zeroed_ledger, zeroed_cohort, hidden`

func scan(row interface{ Scan(dest ...any) error }) (*Proposal, error) {
	var p Proposal
	var patch, prev []byte
	var yes, no, elig float32
	var applied, passed, timelock, contested, decided *time.Time
	if err := row.Scan(&p.ID, &p.Scope, &p.Kind, &p.Target, &patch, &p.Why, &p.Need, &p.Refs, &p.WhyDifferent, &p.Supersedes, &p.Author, &p.AuthorRoot,
		&p.Created, &p.ClosesAt, &p.State, &yes, &no, &elig, &p.Groups, &prev, &p.Result, &applied, &passed, &timelock, &contested, &decided, &p.Note,
		&p.CheckStatus, &p.CheckLog, &p.Escrow, &p.EscrowState, &p.WindowH, &p.Threshold, &p.Quorum, &p.Flags, &p.Hazard, &p.Lexicon,
		&p.ZeroedLedger, &p.ZeroedCohort, &p.Hidden); err != nil {
		return nil, err
	}
	p.Patch = json.RawMessage(patch)
	if string(prev) != "null" && len(prev) > 0 {
		p.Prev = json.RawMessage(prev)
	}
	p.YesW, p.NoW, p.EligibleW = float64(yes), float64(no), float64(elig)
	for _, x := range []struct {
		src *time.Time
		dst *time.Time
	}{{applied, &p.AppliedAt}, {passed, &p.PassedAt}, {timelock, &p.TimelockAt}, {contested, &p.ContestedAt}, {decided, &p.DecidedAt}} {
		if x.src != nil {
			*x.dst = *x.src
		}
	}
	if p.Refs == nil {
		p.Refs = []string{}
	}
	return &p, nil
}

func load(ctx context.Context, q core.Q, id string) (*Proposal, error) {
	if !core.ValidIDPrefix(id, 'p') {
		return nil, core.ErrNotFound
	}
	p, err := scan(q.QueryRow(ctx, `SELECT `+cols+` FROM proposals WHERE id = $1`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return p, err
}

func lock(ctx context.Context, q core.Q, id string) (*Proposal, error) {
	p, err := scan(q.QueryRow(ctx, `SELECT `+cols+` FROM proposals WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	return p, err
}

// Get reads one proposal (core.ErrNotFound when absent).
func Get(ctx context.Context, q core.Q, id string) (*Proposal, error) { return load(ctx, q, id) }

// Awaiting lists the proposals waiting for an operator decision, oldest first (18.5 inbox).
func Awaiting(ctx context.Context, q core.Q) ([]Proposal, error) {
	rows, err := q.Query(ctx, `SELECT `+cols+` FROM proposals WHERE state = 'awaiting_operator' ORDER BY passed_at, id LIMIT 500`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Proposal
	for rows.Next() {
		p, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

// Open reports whether a state still takes votes.
func (p *Proposal) Open() bool { return p.State == "open" || p.State == "contested" }

// Terminal reports whether a state is final.
func (p *Proposal) Terminal() bool {
	switch p.State {
	case "open", "contested", "passed", "awaiting_operator", "check_requested", "deferred":
		return false
	}
	return true
}

// --- create ----------------------------------------------------------------------------------------

var proposalIDRe = regexp.MustCompile(`\bp[a-z2-7]{6}\b`)

// Create validates, checks eligibility, caps, capture, cooldown and duplicates, reserves the escrow
// and inserts the proposal (18.1, 27.5). ip is the client address for content_origin.
func Create(ctx context.Context, d *core.Deps, id *core.Ident, in Input, ip string) (*Proposal, error) {
	if d.Frozen("write") {
		return nil, core.Frozen("write")
	}
	if _, ok := kindFor(in.Kind, in.Scope); !ok {
		return nil, core.Bad("kind must be one of " + strings.Join(Kinds(), ","))
	}
	if in.Scope != "" && !slugRe.MatchString(in.Scope) {
		return nil, core.Bad("scope must be '' (platform) or a space slug")
	}
	if utf8.RuneCountInString(in.Why) > MaxWhy || utf8.RuneCountInString(in.Need) > MaxNeed || utf8.RuneCountInString(in.WhyDifferent) > MaxWhyDiff {
		return nil, core.E(413, "size", fmt.Sprintf("why <= %d, need <= %d, why_different <= %d", MaxWhy, MaxNeed, MaxWhyDiff))
	}
	if len(in.Patch) > MaxPatchBytes {
		return nil, core.E(413, "size", "patch > 16 KiB")
	}
	if in.Kind == "platform" && strings.TrimSpace(in.Need) == "" {
		return nil, core.Bad("need required for platform proposals")
	}
	if in.Kind != "platform" && strings.TrimSpace(in.Why) == "" {
		return nil, core.Bad("why required")
	}
	if len(in.Patch) == 0 {
		in.Patch = json.RawMessage("{}")
	}
	if err := checkRefs(in.Refs); err != nil {
		return nil, err
	}
	if in.Kind == "rule" && in.Target == "" {
		in.Target = deriveTarget(in.Patch)
	}
	if err := checkTarget(in.Kind, in.Scope, in.Target); err != nil {
		return nil, err
	}
	// scrub first (normalises in place), then the shape validator on exactly the stored text.
	fields := map[string]*string{"why": &in.Why, "need": &in.Need, "why_different": &in.WhyDifferent}
	if _, aerr := scrub.RejectOrMask(fields); aerr != nil {
		return nil, aerr
	}
	patch, aerr := maskPatch(in.Patch)
	if aerr != nil {
		return nil, aerr
	}
	in.Patch = patch
	if err := validateKind(in.Kind, in.Scope, in.Patch); err != nil {
		return nil, err
	}
	text := in.Why + "\n" + in.Need + "\n" + in.WhyDifferent + "\n" + strings.Join(patchStrings(in.Patch), "\n")
	score, flags, _ := scrub.Flags(text)
	if score >= 2 {
		return nil, core.E(400, "bad", "lexicon "+scrub.FlagsLine(flags))
	}
	hazard := scrub.Hazards(text)

	q := d.DB
	st, err := trust.Load(ctx, q, id.Root)
	if err != nil {
		return nil, err
	}
	lvl := st.Level()
	if lvl < 2 || st.Age < proposeAge {
		return nil, core.E(403, "auth", "proposals need L2 and a 7 d old root")
	}
	if seniorKinds[in.Kind] && (st.Rep < seniorRep || st.Age < seniorAge) {
		return nil, core.E(403, "auth", in.Kind+" proposals need rep >= 10 and a 14 d old root")
	}
	rule := ruleFor(in.Kind, in.Scope)
	var sp SpaceInfo
	if in.Scope != "" {
		if sp, err = spaceInfo(ctx, q, in.Scope, id.Root); err != nil {
			return nil, err
		}
		if !sp.Member {
			return nil, core.E(403, "scope", "members propose in a space")
		}
		if sp.Frozen {
			return nil, core.Frozen("space")
		}
		if spaceKinds[in.Kind] {
			if sp.VoteWindowH > 0 {
				rule.windowH = clampWindow(sp.VoteWindowH)
			}
			if sp.VoteThreshold > 0 {
				rule.threshold = clampThreshold(sp.VoteThreshold)
			}
		}
	}
	// open caps (4.3): 1 per root per space, 3 platform-wide.
	capKind, capScope := "proposals_platform", ""
	if in.Scope != "" {
		capKind, capScope = "proposals", in.Scope
	}
	var open int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM proposals WHERE author_root = $1 AND scope = $2 AND state IN ('open', 'contested')`, id.Root, capScope).Scan(&open); err != nil {
		return nil, err
	}
	if open >= trust.Cap(capKind, st.CapLevel()) {
		return nil, core.E(429, "quota", "open proposals "+itoa(open)+"/"+itoa(trust.Cap(capKind, st.CapLevel())))
	}
	// capture (18.3): rule/member changes in a concentrated space need 3/4 and +48 h; < 3 groups refused.
	extraH := 0
	if in.Scope != "" && (in.Kind == "rule" || in.Kind == "member") && SpaceStatsFn != nil {
		stats, err := SpaceStatsFn(ctx, q, in.Scope)
		if err != nil {
			return nil, err
		}
		if stats.Groups < 3 {
			return nil, core.E(429, "quota", "need 3 groups")
		}
		if stats.TopGroupShare > Constitution.CaptureShare {
			rule.threshold = Constitution.CaptureThreshold
			extraH = Constitution.CaptureExtraH
		}
	}
	// kb facts (18.6): entry visible, kbmerge ordering, quorum 5 past ok_w 3.
	if in.Kind == "kbfix" || in.Kind == "kbmerge" {
		ks, err := kbStats(ctx, q, in.Target)
		if err != nil {
			return nil, err
		}
		if ks.OkW >= 3 {
			rule.quorum = 5
		}
		if in.Kind == "kbmerge" {
			var mp kbmergePatch
			json.Unmarshal(in.Patch, &mp)
			if mp.Into == in.Target {
				return nil, core.Bad("merge needs two different entries")
			}
			into, err := kbStats(ctx, q, mp.Into)
			if err != nil {
				return nil, err
			}
			if !into.Visible || into.OkW < ks.OkW {
				return nil, core.Bad("merge target must be visible with ok_w >= the merged entry")
			}
		}
	}
	// dedupe first (18.1, 27.5 REV3): a near-duplicate answers 409 with the precedent and the
	// refs + why_different path; then the cooldown (7 d on the same scope, kind, target after a
	// fail), which an explicit supersede of that very precedent bypasses.
	line1 := firstLine(in.Kind, in.Why, in.Need)
	supersedes, err := dedupe(ctx, q, in, line1)
	if err != nil {
		return nil, err
	}
	var cdID string
	var cdAt time.Time
	err = q.QueryRow(ctx, `SELECT id, coalesce(decided_at, closes_at) FROM proposals WHERE scope = $1 AND kind = $2 AND target = $3 AND state = 'failed'
		AND coalesce(decided_at, closes_at) > now() - ($4::int * interval '1 day') ORDER BY coalesce(decided_at, closes_at) DESC LIMIT 1`,
		in.Scope, in.Kind, in.Target, Constitution.CooldownD).Scan(&cdID, &cdAt)
	if err == nil && cdID != supersedes {
		until := cdAt.Add(time.Duration(Constitution.CooldownD) * 24 * time.Hour)
		return nil, core.E(429, "quota", "cooldown until "+core.Date(until)+" ("+cdID+" failed)")
	} else if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}
	now := time.Now()
	p := &Proposal{ID: core.NewID('p'), Scope: in.Scope, Kind: in.Kind, Target: in.Target, Patch: in.Patch, Why: in.Why, Need: in.Need,
		Refs: in.Refs, WhyDifferent: in.WhyDifferent, Supersedes: supersedes, Author: id.ID, AuthorRoot: id.Root, Created: now,
		ClosesAt: now.Add(time.Duration(rule.windowH+extraH) * time.Hour), State: "open", WindowH: rule.windowH + extraH,
		Threshold: rule.threshold, Quorum: rule.quorum, Flags: flags, Hazard: hazard, Lexicon: score, Escrow: Constitution.Escrow, EscrowState: "held"}
	if p.Refs == nil {
		p.Refs = []string{}
	}
	if p.Flags == nil {
		p.Flags = []string{}
	}
	if p.Hazard == nil {
		p.Hazard = []string{}
	}
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if err := core.Reserve(ctx, tx, id.ID, p.Escrow); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO proposals (id, scope, kind, target, patch, why, need, refs, why_different, supersedes, author, author_root,
			created, closes_at, state, window_h, threshold, quorum, flags, hazard, lexicon, escrow, escrow_state)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, 'open', $15, $16, $17, $18, $19, $20, $21, 'held')`,
			p.ID, p.Scope, p.Kind, p.Target, []byte(p.Patch), p.Why, p.Need, p.Refs, p.WhyDifferent, p.Supersedes, p.Author, p.AuthorRoot,
			p.Created, p.ClosesAt, p.WindowH, p.Threshold, p.Quorum, p.Flags, p.Hazard, p.Lexicon, p.Escrow); err != nil {
			if core.IsUniqueViolation(err) {
				return core.E(409, "retry", "id collision, resend")
			}
			return err
		}
		if err := core.Origin(ctx, tx, "p", p.ID, id.Root, id.ID, ip); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "pp", p.ID, 0); err != nil {
			return err
		}
		if ProposeHookFn != nil {
			before := len(p.Flags)
			if err := ProposeHookFn(ctx, tx, p); err != nil {
				return err
			}
			if len(p.Flags) != before {
				if hasFlag(p.Flags, "drastic") {
					p.Threshold = Constitution.CaptureThreshold
					p.ClosesAt = p.ClosesAt.Add(time.Duration(Constitution.CaptureExtraH) * time.Hour)
					p.WindowH += Constitution.CaptureExtraH
				}
				if _, err := tx.Exec(ctx, `UPDATE proposals SET flags = $2, threshold = $3, closes_at = $4, window_h = $5 WHERE id = $1`,
					p.ID, p.Flags, p.Threshold, p.ClosesAt, p.WindowH); err != nil {
					return err
				}
			}
		}
		if err := core.Event(ctx, tx, "p", p.ID, "", "open "+p.Kind+" "+scopeName(p.Scope)); err != nil {
			return err
		}
		if err := flagBribery(ctx, tx, in.Why+"\n"+in.Need, p.ID); err != nil {
			return err
		}
		return mirror(ctx, tx, p)
	})
	if err != nil {
		return nil, err
	}
	notifier.Store(d.Notify)
	wake(p.ID)
	return p, nil
}

// deriveTarget names a rule patch's keys (quota.t,quota.kb) so cooldowns and dedupes work per key.
func deriveTarget(patch json.RawMessage) string {
	var m map[string]json.RawMessage
	if json.Unmarshal(patch, &m) != nil {
		return ""
	}
	var keys []string
	for k, v := range m {
		var sub map[string]json.RawMessage
		if (k == "quota" || k == "vote" || k == "templates") && json.Unmarshal(v, &sub) == nil && len(sub) > 0 {
			for sk := range sub {
				keys = append(keys, k+"."+sk)
			}
			continue
		}
		keys = append(keys, k)
	}
	sortStrings(keys)
	t := strings.Join(keys, ",")
	if len(t) > 120 {
		t = t[:120]
	}
	return t
}

// firstLine is the Go twin of the line1 generated column: platform requests dedupe on their need,
// every other kind on its why.
func firstLine(kind, why, need string) string {
	src := why
	if kind == "platform" && need != "" {
		src = need
	}
	l, _, _ := strings.Cut(src, "\n")
	return strings.ToLower(truncRunes(l, 300))
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

// dedupe applies the trigram rules on the normalised first line: open proposals of the same
// scope+kind (and target, except platform/code whose target is free text) above 0.6 -> dup;
// decided platform proposals (declined|vetoed, 90 d) and failed space proposals (cooldown) -> dup
// unless refs names them and why_different is set (then the new proposal supersedes). A
// why_different near-identical (> 0.8) to a prior one on the same precedent is refused.
func dedupe(ctx context.Context, q core.Q, in Input, line1 string) (supersedes string, err error) {
	if line1 == "" {
		return "", nil
	}
	rows, err := q.Query(ctx, `SELECT id, state, coalesce(decided_at, closes_at), note, similarity(line1, $3) AS sim FROM proposals
		WHERE scope = $1 AND kind = $2 AND NOT hidden AND similarity(line1, $3) > $4 AND (
			state IN ('open', 'contested')
			OR (scope = '' AND state IN ('declined', 'vetoed') AND coalesce(decided_at, closes_at) > now() - interval '90 days')
			OR (scope <> '' AND state = 'failed' AND coalesce(decided_at, closes_at) > now() - ($5::int * interval '1 day')))
		AND ($6 OR target = $7)
		ORDER BY (state IN ('open', 'contested')) DESC, sim DESC LIMIT 1`, in.Scope, in.Kind, line1, Constitution.DedupeSim, Constitution.CooldownD,
		in.Kind == "platform" || in.Kind == "code", in.Target)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", rows.Err()
	}
	var id, state, note string
	var at time.Time
	var sim float32
	if err := rows.Scan(&id, &state, &at, &note, &sim); err != nil {
		return "", err
	}
	rows.Close()
	if state == "open" || state == "contested" {
		return "", &DupError{APIError: core.E(409, "dup", id+" open"), ID: id, State: state}
	}
	if in.WhyDifferent == "" || !refHas(in.Refs, id) {
		msg := id + " " + state + " " + core.Date(at)
		if note != "" {
			msg += ": " + doc.SafeLine(truncRunes(note, 100))
		}
		return "", &DupError{APIError: core.E(409, "dup", msg), ID: id, State: state, Note: note, Decided: at}
	}
	var prior string
	err = q.QueryRow(ctx, `SELECT id FROM proposals WHERE supersedes = $1 AND why_different <> '' AND similarity(lower(why_different), lower($2)) > $3 LIMIT 1`,
		id, in.WhyDifferent, Constitution.WhyDiffSim).Scan(&prior)
	if err == nil {
		return "", &DupError{APIError: core.E(409, "dup", prior+" why_different near-identical"), ID: prior, State: "superseding"}
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return "", err
	}
	return id, nil
}

func refHas(refs []string, id string) bool {
	for _, r := range refs {
		if r == id || r == "p:"+id {
			return true
		}
	}
	return false
}

// maskPatch runs the scrub on every string leaf of the patch (tier 1 rejects, tier 2 masks) and
// re-encodes it compactly.
func maskPatch(patch json.RawMessage) (json.RawMessage, *core.APIError) {
	var v any
	if err := json.Unmarshal(patch, &v); err != nil {
		return nil, core.Bad("patch: invalid json")
	}
	var walk func(x any) (any, *core.APIError)
	walk = func(x any) (any, *core.APIError) {
		switch t := x.(type) {
		case string:
			s := t
			if _, err := scrub.RejectOrMask(map[string]*string{"patch": &s}); err != nil {
				return nil, err
			}
			return s, nil
		case []any:
			for i, e := range t {
				y, err := walk(e)
				if err != nil {
					return nil, err
				}
				t[i] = y
			}
			return t, nil
		case map[string]any:
			for k, e := range t {
				y, err := walk(e)
				if err != nil {
					return nil, err
				}
				t[k] = y
			}
			return t, nil
		}
		return x, nil
	}
	out, aerr := walk(v)
	if aerr != nil {
		return nil, aerr
	}
	b, err := json.Marshal(out)
	if err != nil {
		return nil, core.Bad("patch")
	}
	return b, nil
}

func spaceInfo(ctx context.Context, q core.Q, slug, root string) (SpaceInfo, error) {
	if slug == "" {
		return SpaceInfo{Exists: true, Member: true}, nil
	}
	if SpaceInfoFn == nil {
		return SpaceInfo{}, core.E(404, "notfound", "space "+slug)
	}
	sp, err := SpaceInfoFn(ctx, q, slug, root)
	if err != nil {
		return sp, err
	}
	if !sp.Exists {
		return sp, core.E(404, "notfound", "space "+slug)
	}
	if sp.Banned {
		return sp, core.E(403, "auth", "banned in "+slug)
	}
	return sp, nil
}

func kbStats(ctx context.Context, q core.Q, id string) (KBStats, error) {
	if KBStatsFn == nil {
		return KBStats{Exists: true, Visible: true}, nil
	}
	ks, err := KBStatsFn(ctx, q, id)
	if err != nil {
		return ks, err
	}
	if !ks.Exists {
		return ks, core.E(404, "notfound", "entry "+id)
	}
	if !ks.Visible {
		return ks, core.E(410, "gone", "entry "+id+" not visible")
	}
	return ks, nil
}

// --- bribery flag (27.5) ---------------------------------------------------------------------------

// FlagBribery scans a referencing write (task, note, mail subject, bounty text) for the gov-bribe
// lexicon class and, when it fires, marks every open proposal it names bribery-suspected with a
// 24 h window extension (once per proposal).
func FlagBribery(ctx context.Context, q core.Q, text string) error {
	return flagBribery(ctx, q, text, "")
}

func flagBribery(ctx context.Context, q core.Q, text, self string) error {
	_, flags, _ := scrub.Flags(text)
	if !hasFlag(flags, "gov-bribe") {
		return nil
	}
	seen := map[string]bool{}
	for _, id := range proposalIDRe.FindAllString(text, 20) {
		if id == self || seen[id] {
			continue
		}
		seen[id] = true
		tag, err := q.Exec(ctx, `UPDATE proposals SET flags = array_append(flags, 'bribery-suspected'), closes_at = closes_at + ($2::int * interval '1 hour')
			WHERE id = $1 AND state IN ('open', 'contested') AND NOT ('bribery-suspected' = ANY(flags))`, id, Constitution.BriberyExtraH)
		if err != nil {
			return err
		}
		if tag.RowsAffected() > 0 {
			if err := core.Event(ctx, q, "p", id, "", "flag bribery-suspected"); err != nil {
				return err
			}
			wake(id)
		}
	}
	return nil
}

// --- vote ------------------------------------------------------------------------------------------

// Vote records one vote per root (18.1, 27.5): weight trust.GovWeight for the scope, zero with a
// ledger flow or a shared cohort with the proposer, one row per (pid, root), collapse at tally.
func Vote(ctx context.Context, d *core.Deps, id *core.Ident, pid string, up bool, why, ip string) (VoteResult, error) {
	var res VoteResult
	if d.Frozen("write") {
		return res, core.Frozen("write")
	}
	if utf8.RuneCountInString(why) > MaxVoteWhy {
		return res, core.E(413, "size", "why > 200")
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"why": &why}); aerr != nil {
		return res, aerr
	}
	if score, flags, _ := scrub.Flags(why); score >= 2 && !hasFlag(flags, "gov-bribe") {
		return res, core.E(400, "bad", "lexicon "+scrub.FlagsLine(flags))
	}
	p, err := load(ctx, d.DB, pid)
	if err != nil {
		return res, err
	}
	if p.Hidden {
		return res, core.E(410, "gone", "proposal hidden")
	}
	if !p.Open() {
		return res, core.E(409, "dup", "proposal "+p.State)
	}
	if p.AuthorRoot == id.Root {
		return res, core.E(403, "auth", "no self vote")
	}
	st, err := trust.Load(ctx, d.DB, id.Root)
	if err != nil {
		return res, err
	}
	var since time.Time
	minH := 0
	if p.Scope != "" {
		sp, err := spaceInfo(ctx, d.DB, p.Scope, id.Root)
		if err != nil {
			return res, err
		}
		if !sp.Member {
			return res, core.E(403, "scope", "members vote in a space")
		}
		since, minH = sp.MemberSince, sp.MinMemberH
	}
	w := trust.GovWeight(st, since, minH)
	reason := ""
	if w == 0 {
		reason = "standing"
	}
	if w > 0 {
		flow, err := ledgerFlow(ctx, d.DB, p.AuthorRoot, id.Root, p.Created)
		if err != nil {
			return res, err
		}
		if flow {
			w, reason = 0, "ledger"
		}
	}
	if w > 0 {
		same, err := sameCohort(ctx, d.DB, p.AuthorRoot, id.Root)
		if err != nil {
			return res, err
		}
		if same {
			w, reason = 0, "cohort"
		}
	}
	group, super := st.Group, st.Super
	if super == "" {
		group, super = core.IPGroup(ip), core.IPSuper(ip)
	}
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `INSERT INTO proposal_votes (pid, root, up, w, w_reason, ip_group, ip_super, why) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
			ON CONFLICT (pid, root) DO NOTHING`, pid, id.Root, up, float32(w), reason, group, super, why)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return core.E(409, "dup", "already voted")
		}
		if _, err := tx.Exec(ctx, `UPDATE proposals SET zeroed_ledger = (SELECT count(*) FROM proposal_votes WHERE pid = $1 AND w_reason = 'ledger'),
			zeroed_cohort = (SELECT count(*) FROM proposal_votes WHERE pid = $1 AND w_reason = 'cohort') WHERE id = $1`, pid); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "pv", pid, 0); err != nil {
			return err
		}
		return flagBribery(ctx, tx, why, "")
	})
	if err != nil {
		return res, err
	}
	notifier.Store(d.Notify)
	wake(pid)
	res.W, res.Reason = w, reason
	return res, nil
}

// ledgerFlow reports a ledger row between the proposer tree and the voter tree in the 14 d before
// the proposal was created (27.5).
func ledgerFlow(ctx context.Context, q core.Q, proposer, voter string, created time.Time) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM ledger l JOIN identities a ON a.id = l.from_id JOIN identities b ON b.id = l.to_id
		WHERE l.ts > $3::timestamptz - ($4::int * interval '1 day') AND l.ts <= $3::timestamptz
		  AND ((a.root = $1 AND b.root = $2) OR (a.root = $2 AND b.root = $1)))`, proposer, voter, created, ledgerFlowD).Scan(&ok)
	return ok, err
}

func sameCohort(ctx context.Context, q core.Q, a, b string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM identities x JOIN identities y ON y.cohort = x.cohort WHERE x.id = $1 AND y.id = $2 AND x.cohort <> '')`, a, b).Scan(&ok)
	return ok, err
}

// --- withdraw / accept -----------------------------------------------------------------------------

// Withdraw closes the author's own open proposal; the escrow comes back.
func Withdraw(ctx context.Context, d *core.Deps, id *core.Ident, pid string) error {
	return core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		p, err := lock(ctx, tx, pid)
		if err != nil {
			return err
		}
		if p.AuthorRoot != id.Root {
			return core.ErrForbid
		}
		if !p.Open() {
			return core.E(409, "dup", "proposal "+p.State)
		}
		if err := finish(ctx, tx, pid, "withdrawn", "withdrawn by author", true); err != nil {
			return err
		}
		notifier.Store(d.Notify)
		return core.Audit(ctx, tx, id.ID, "pw", pid, 0)
	})
}

// Accept is the kbfix/kbmerge fast path (18.6): the entry's author applies the proposal at once;
// refused when the proposer root is the entry author root.
func Accept(ctx context.Context, d *core.Deps, id *core.Ident, pid string) (*Proposal, error) {
	var out *Proposal
	err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		p, err := lock(ctx, tx, pid)
		if err != nil {
			return err
		}
		if p.Kind != "kbfix" && p.Kind != "kbmerge" {
			return core.Bad("accept is the kbfix/kbmerge fast path")
		}
		if !p.Open() {
			return core.E(409, "dup", "proposal "+p.State)
		}
		if KBStatsFn == nil {
			return core.E(503, "busy", "entry facts unavailable")
		}
		ks, err := KBStatsFn(ctx, tx, p.Target)
		if err != nil {
			return err
		}
		if !ks.Exists || ks.AuthorRoot == "" || ks.AuthorRoot != id.Root {
			return core.E(403, "auth", "only the entry author accepts")
		}
		if p.AuthorRoot == ks.AuthorRoot {
			return core.E(403, "auth", "the proposer cannot accept their own fix")
		}
		if err := settleEscrow(ctx, tx, p, true); err != nil {
			return err
		}
		p.Result = "accepted by the entry author"
		if err := apply(ctx, tx, p); err != nil {
			return err
		}
		notifier.Store(d.Notify)
		out = p
		return core.Audit(ctx, tx, id.ID, "pa", pid, 0)
	})
	if err != nil {
		return nil, err
	}
	wake(pid)
	return out, nil
}

// --- tally -----------------------------------------------------------------------------------------

// Tally is the janitor task (18.1): early closes, closes, contested expiries, time-locked applies,
// awaiting_operator expiries. Exported so tests and the platform package can run one pass.
func Tally(ctx context.Context, d *core.Deps) error {
	notifier.Store(d.Notify)
	var pool *pgxpool.Pool = d.DB
	if d.Ops != nil {
		pool = d.Ops
	}
	rows, err := pool.Query(ctx, `SELECT id FROM proposals p WHERE (state IN ('open', 'contested') AND NOT hidden
			AND (closes_at <= now() OR EXISTS (SELECT 1 FROM proposal_votes v WHERE v.pid = p.id AND v.w > 0)))
		OR (state = 'passed' AND timelock_at IS NOT NULL AND timelock_at <= now())
		OR (state = 'awaiting_operator' AND passed_at < now() - ($1::int * interval '1 day'))
		ORDER BY closes_at LIMIT 500`, Constitution.AwaitingOperatorD)
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
	var first error
	for _, id := range ids {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := tallyOne(ctx, pool, id); err != nil && first == nil {
			first = fmt.Errorf("tally %s: %w", id, err)
			d.Log.Warn("gov tally", "id", id, "err", err)
		}
	}
	return first
}

// sums are the collapsed tally of one proposal.
type sums struct {
	yes, no, eligible float64
	groups, yesGroups int
}

func tallySums(ctx context.Context, q core.Q, p *Proposal) (sums, error) {
	var s sums
	var yes, no float32
	if err := q.QueryRow(ctx, `SELECT coalesce(sum(w), 0) FROM (`+trust.CollapseSQLWhere("proposal_votes", "up", "pid = $1 AND w > 0")+`) c`, p.ID).Scan(&yes); err != nil {
		return s, err
	}
	if err := q.QueryRow(ctx, `SELECT coalesce(sum(w), 0) FROM (`+trust.CollapseSQLWhere("proposal_votes", "down", "pid = $1 AND w > 0")+`) c`, p.ID).Scan(&no); err != nil {
		return s, err
	}
	if err := q.QueryRow(ctx, `SELECT count(DISTINCT `+trust.NetKeySQL("v")+`), count(DISTINCT `+trust.NetKeySQL("v")+`) FILTER (WHERE v.up)
		FROM proposal_votes v WHERE v.pid = $1 AND v.w > 0`, p.ID).Scan(&s.groups, &s.yesGroups); err != nil {
		return s, err
	}
	s.yes, s.no = float64(yes), float64(no)
	elig, err := eligibleWeight(ctx, q, p.Scope)
	if err != nil {
		return s, err
	}
	s.eligible = elig
	return s, nil
}

// DefaultEligibleWeight is the platform-wide eligible governance weight: the GovWeight of every
// L2 root that could vote right now (age >= 7 d, rep >= 5, verified in 60 d, not seed or revoked).
func DefaultEligibleWeight(ctx context.Context, q core.Q) (float64, error) {
	var w float64
	err := q.QueryRow(ctx, `SELECT coalesce(sum(1 + least(rep, 30) / 15.0), 0) FROM identities WHERE parent IS NULL AND revoked_at IS NULL AND NOT seed
		AND rep >= 5 AND created <= now() - interval '7 days' AND verified_noncompute >= 1 AND last_verified_at > now() - interval '60 days'`).Scan(&w)
	return w, err
}

func eligibleWeight(ctx context.Context, q core.Q, scope string) (float64, error) {
	if EligibleWeightFn != nil {
		return EligibleWeightFn(ctx, q, scope)
	}
	return DefaultEligibleWeight(ctx, q)
}

// ScopeCounts returns the number of concluded proposals in a scope that passed and that failed
// (18.3 space_stats). Passed = any positive terminal state (passed, applied, awaiting_operator,
// accepted, shipped); failed = the negative terminals (failed, declined, vetoed). Open, contested,
// held and deferred proposals are still in flight and counted in neither. It is the spaces
// ProposalCountsFn seam, so a space slug is the scope.
func ScopeCounts(ctx context.Context, q core.Q, scope string) (passed, failed int, err error) {
	err = q.QueryRow(ctx, `SELECT
		count(*) FILTER (WHERE state IN ('passed', 'applied', 'awaiting_operator', 'accepted', 'shipped')),
		count(*) FILTER (WHERE state IN ('failed', 'declined', 'vetoed'))
		FROM proposals WHERE scope = $1 AND NOT hidden`, scope).Scan(&passed, &failed)
	return passed, failed, err
}

// tallyOne runs the state machine for one proposal inside a transaction.
func tallyOne(ctx context.Context, pool *pgxpool.Pool, id string) error {
	return core.Tx(ctx, pool, func(tx pgx.Tx) error {
		p, err := lock(ctx, tx, id)
		if err != nil {
			if errors.Is(err, core.ErrNotFound) {
				return nil
			}
			return err
		}
		now := time.Now()
		switch p.State {
		case "passed":
			if !p.TimelockAt.IsZero() && !p.TimelockAt.After(now) {
				return apply(ctx, tx, p)
			}
			return nil
		case "awaiting_operator":
			if !p.PassedAt.IsZero() && now.Sub(p.PassedAt) >= time.Duration(Constitution.AwaitingOperatorD)*24*time.Hour {
				return finish(ctx, tx, p.ID, "declined", "no operator decision in "+itoa(Constitution.AwaitingOperatorD)+" d", false)
			}
			return nil
		case "open", "contested":
		default:
			return nil
		}
		s, err := tallySums(ctx, tx, p)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE proposals SET yes_w = $2, no_w = $3, groups = $4, eligible_w = $5 WHERE id = $1`,
			p.ID, float32(s.yes), float32(s.no), s.groups, float32(s.eligible)); err != nil {
			return err
		}
		p.YesW, p.NoW, p.Groups, p.EligibleW = s.yes, s.no, s.groups, s.eligible
		rule := ruleFor(p.Kind, p.Scope)
		thr := float64(p.Threshold) / 100
		closed := !p.ClosesAt.After(now)
		if p.State == "contested" {
			if !closed {
				return nil
			}
			return finish(ctx, tx, p.ID, "failed", "contested: status quo kept", true)
		}
		quorum := s.groups >= p.Quorum && s.yes+s.no >= Constitution.QuorumShare*s.eligible && s.yes+s.no > 0
		if !closed {
			// early close: the yes weight alone exceeds the threshold share of everyone eligible.
			if quorum && s.eligible > 0 && s.yes > thr*s.eligible && !rule.support {
				return pass(ctx, tx, p, rule, "early close")
			}
			return nil
		}
		if rule.support {
			if s.yesGroups >= p.Quorum {
				return pass(ctx, tx, p, rule, "supported by "+itoa(s.yesGroups)+" groups")
			}
			expire := p.Created.Add(time.Duration(Constitution.PlatformExpireD) * 24 * time.Hour)
			if now.Before(expire) {
				_, err := tx.Exec(ctx, `UPDATE proposals SET closes_at = $2 WHERE id = $1`, p.ID, expire)
				return err
			}
			return finish(ctx, tx, p.ID, "failed", "expired without "+itoa(p.Quorum)+" supporting groups", false)
		}
		if !quorum {
			return finish(ctx, tx, p.ID, "failed", fmt.Sprintf("no quorum: groups %d/%d weight %s/%s", s.groups, p.Quorum, fw(s.yes+s.no), fw(Constitution.QuorumShare*s.eligible)), false)
		}
		if err := settleEscrow(ctx, tx, p, true); err != nil {
			return err
		}
		ratio := s.yes / (s.yes + s.no)
		if math.Abs(ratio-thr) <= Constitution.ContestedBand+1e-9 {
			until := now.Add(time.Duration(Constitution.ContestedH) * time.Hour)
			if _, err := tx.Exec(ctx, `UPDATE proposals SET state = 'contested', contested_at = now(), closes_at = $2,
				result = $3 WHERE id = $1`, p.ID, until, fmt.Sprintf("contested: yes %d%% within %d%% of %d%%", int(ratio*100+0.5), int(Constitution.ContestedBand*100), p.Threshold)); err != nil {
				return err
			}
			if err := core.Event(ctx, tx, "p", p.ID, "", "contested "+p.Kind+" "+scopeName(p.Scope)); err != nil {
				return err
			}
			wake(p.ID)
			return nil
		}
		if ratio >= thr {
			return pass(ctx, tx, p, rule, fmt.Sprintf("passed yes %s no %s groups %d", fw(s.yes), fw(s.no), s.groups))
		}
		return finish(ctx, tx, p.ID, "failed", fmt.Sprintf("failed yes %s no %s groups %d", fw(s.yes), fw(s.no), s.groups), false)
	})
}

// pass moves a proposal past its vote: awaiting_operator (platform docs, svc-bless, platform
// requests), passed + time-lock (rules), passed advisory (code) or applied at once.
func pass(ctx context.Context, tx core.Q, p *Proposal, rule kindRule, result string) error {
	if err := settleEscrow(ctx, tx, p, true); err != nil {
		return err
	}
	if p.Groups >= 5 && p.AuthorRoot != "" {
		if _, err := core.AddRep(ctx, tx, p.AuthorRoot, 1, "rep:gov", 3); err != nil {
			return err
		}
	}
	p.Result = result
	switch {
	case rule.awaitOperator || rule.support:
		return setState(ctx, tx, p, "awaiting_operator", `passed_at = now()`)
	case rule.timelockH > 0:
		return setState(ctx, tx, p, "passed", fmt.Sprintf(`passed_at = now(), timelock_at = now() + interval '%d hours'`, rule.timelockH))
	case rule.advisory:
		p.Result = result + "; advisory: never auto-merged"
		return setState(ctx, tx, p, "passed", `passed_at = now()`)
	}
	if _, err := tx.Exec(ctx, `UPDATE proposals SET passed_at = now() WHERE id = $1`, p.ID); err != nil {
		return err
	}
	return apply(ctx, tx, p)
}

// setState writes a non-terminal transition with its result and extra assignments (server SQL only).
func setState(ctx context.Context, tx core.Q, p *Proposal, state, extra string) error {
	sql := `UPDATE proposals SET state = $2, result = $3`
	if extra != "" {
		sql += ", " + extra
	}
	if _, err := tx.Exec(ctx, sql+` WHERE id = $1`, p.ID, state, doc.SafeLine(truncRunes(p.Result, 300))); err != nil {
		return err
	}
	p.State = state
	if err := core.Event(ctx, tx, "p", p.ID, "", state+" "+p.Kind+" "+scopeName(p.Scope)); err != nil {
		return err
	}
	if err := mirror(ctx, tx, p); err != nil {
		return err
	}
	wake(p.ID)
	return nil
}

// Apply runs the kind's applier for a passed or operator-accepted proposal inside tx: one
// transaction, prev snapshot, applied_at (18.1). Without an applier the proposal stays passed.
func Apply(ctx context.Context, tx core.Q, p *Proposal) error { return apply(ctx, tx, p) }

func apply(ctx context.Context, tx core.Q, p *Proposal) error {
	kind, _ := kindFor(p.Kind, p.Scope)
	if kind.apply == nil {
		p.Result = strings.TrimSpace(p.Result + "; no applier registered")
		p.State = "passed"
		if _, err := tx.Exec(ctx, `UPDATE proposals SET state = 'passed', result = $2, timelock_at = NULL, passed_at = coalesce(passed_at, now()) WHERE id = $1`,
			p.ID, doc.SafeLine(truncRunes(p.Result, 300))); err != nil {
			return err
		}
		wake(p.ID)
		return nil
	}
	prev, err := kind.apply(ctx, tx, p)
	if err != nil {
		var ae *core.APIError
		msg := "apply failed"
		if errors.As(err, &ae) {
			msg = "apply failed: " + ae.Msg
		} else {
			return err
		}
		return finish(ctx, tx, p.ID, "failed", msg, true)
	}
	if len(prev) == 0 || !json.Valid(prev) {
		prev = json.RawMessage("null")
	}
	p.Prev = prev
	if _, err := tx.Exec(ctx, `UPDATE proposals SET state = 'applied', applied_at = now(), prev = $2, result = $3, timelock_at = NULL WHERE id = $1`,
		p.ID, []byte(prev), doc.SafeLine(truncRunes(p.Result, 300))); err != nil {
		return err
	}
	p.State = "applied"
	p.AppliedAt = time.Now()
	if AppliedHookFn != nil {
		if err := AppliedHookFn(ctx, tx, p); err != nil {
			return err
		}
	}
	if err := core.Event(ctx, tx, "p", p.ID, "", "applied "+p.Kind+" "+scopeName(p.Scope)); err != nil {
		return err
	}
	if err := mirror(ctx, tx, p); err != nil {
		return err
	}
	wake(p.ID)
	return nil
}

// Finish moves a proposal to a terminal state (failed, declined, vetoed, withdrawn, dup, accepted,
// deferred, shipped) with its result; refund says whether a still-held escrow comes back (it is
// burned otherwise, so the conservation audit stays exact).
func Finish(ctx context.Context, q core.Q, id, state, result string, refund bool) error {
	return finish(ctx, q, id, state, result, refund)
}

func finish(ctx context.Context, q core.Q, id, state, result string, refund bool) error {
	p, err := lock(ctx, q, id)
	if err != nil {
		return err
	}
	if err := settleEscrow(ctx, q, p, refund); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE proposals SET state = $2, result = $3, decided_at = now(), timelock_at = NULL WHERE id = $1`,
		id, state, doc.SafeLine(truncRunes(result, 300))); err != nil {
		return err
	}
	p.State, p.Result = state, result
	if err := core.Event(ctx, q, "p", id, "", state+" "+p.Kind+" "+scopeName(p.Scope)); err != nil {
		return err
	}
	if err := mirror(ctx, q, p); err != nil {
		return err
	}
	wake(id)
	return nil
}

// settleEscrow refunds or burns a held escrow exactly once.
func settleEscrow(ctx context.Context, q core.Q, p *Proposal, refund bool) error {
	if p.EscrowState != "held" || p.Escrow <= 0 {
		return nil
	}
	state := "burned"
	if refund {
		state = "refunded"
	}
	tag, err := q.Exec(ctx, `UPDATE proposals SET escrow_state = $2 WHERE id = $1 AND escrow_state = 'held'`, p.ID, state)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return nil
	}
	p.EscrowState = state
	if refund {
		return core.Refund(ctx, q, p.Author, p.Escrow)
	}
	return core.BurnHeld(ctx, q, p.Escrow, "escrow", p.ID)
}

// mirror enqueues the proposal's text for the Forgejo mirror (outbox kind gov, 18.1).
func mirror(ctx context.Context, q core.Q, p *Proposal) error {
	_, err := q.Exec(ctx, `INSERT INTO forge_outbox (kind, ref, payload) VALUES ('gov', $1, $2)`, p.ID, []byte(p.Text()))
	return err
}
