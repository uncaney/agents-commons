package web

// Reports v2 (SPEC-v2 4.7). A report names a target "<kind>:<ref>"; the kinds come from the
// registry every package fills with d.RegisterTarget (exists/hide/restore by ref). Reporters weigh
// by standing (L2 1.0, L1 0.5, L0 root 0.34, anonymous group 0.25), each multiplied by their
// report_trust score; anonymous reporters collapse to one per super-group and weigh at most 1.0
// in total; a hide needs total >= 3.0 AND one report from an L1+ root, so anonymous reports alone
// never hide. Every hide decided here lands in report_hides: a reversal (appeal, operator) halves
// the reporters' trust and immunises the target for 30 d, a hide standing 30 d adds 0.1. Notice
// hides (notices.go) share the bookkeeping and wait for the operator.

import (
	"context"
	"errors"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

const (
	reportIPQuota    = 20 // anonymous reports per IP group per day (4.3)
	reportSuperQuota = 4 * reportIPQuota
	maxWhy           = 200
	maxTarget        = 220
	reportHideWeight = 3.0
	weightL2         = 1.0
	weightL1         = 0.5
	weightL0         = 0.34 // registered root below L1
	weightAnon       = 0.25 // per anonymous IP group, collapsed per super-group
	anonCap          = 1.0  // anonymous weight per target in total
	trustReversed    = 0.5  // multiplier per reversed hide
	trustUpheld      = 0.1  // added per hide standing 30 d
	trustMax         = 2.0
	upheldAfter      = 30 * 24 * time.Hour
	immuneFor        = 30 * 24 * time.Hour
)

var (
	errTarget  = core.Bad("target must be <kind>:<ref> (kb:<id>, t:<n>, n:<owner>/<name>, d:<secret>, m:<id>, c:<key>, …)")
	kindRe     = regexp.MustCompile(`^[a-z]{1,4}$`)
	refRe      = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._~:/@+=-]{0,199}$`)
	noteNameRe = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
)

type target struct{ kind, ref string }

func (t target) key() string { return t.kind + ":" + t.ref }

// parseTarget splits "<kind>:<ref>" and checks the ref grammar: the v1 kinds keep their exact
// shapes (a malformed ref is 400, never 404), every other kind gets the generic grammar and its
// owner's Exists decides. The kind must be registered (or a v1 fallback, targetFor).
func (s *srv) parseTarget(raw string) (target, error) {
	if len(raw) > maxTarget {
		return target{}, errTarget
	}
	k, v, ok := strings.Cut(raw, ":")
	if !ok || !kindRe.MatchString(k) || v == "" {
		return target{}, errTarget
	}
	switch k {
	case "kb":
		if !core.ValidIDPrefix(v, 'k') {
			return target{}, core.Bad("bad kb id")
		}
	case "t":
		n, err := strconv.Atoi(strings.TrimPrefix(v, "#"))
		if err != nil || n <= 0 {
			return target{}, core.Bad("bad task number")
		}
		v = strconv.Itoa(n)
	case "n":
		o, name, ok := strings.Cut(v, "/")
		if !ok || !core.ValidIDPrefix(o, 'a') || !noteNameRe.MatchString(name) {
			return target{}, core.Bad("bad note ref")
		}
	default:
		if !refRe.MatchString(v) {
			return target{}, errTarget
		}
	}
	if _, ok := s.targetFor(k); !ok {
		return target{}, errTarget
	}
	return target{k, v}, nil
}

// targetFor is the registry lookup with the v1 fallback for tasks and notes: a gateway that
// mounts web without forge (v1 environments, tests) still resolves t: and n: through forge's
// exported helpers; forge's own registration takes over wherever it is mounted.
func (s *srv) targetFor(kind string) (core.Target, bool) {
	if t, ok := s.d.Target(kind); ok {
		return t, true
	}
	switch kind {
	case "t":
		n := func(ref string) int64 { x, _ := strconv.ParseInt(ref, 10, 64); return x }
		return core.Target{
			Exists: func(ctx context.Context, q core.Q, ref string) error {
				return rowExists(ctx, q, `SELECT EXISTS (SELECT 1 FROM tasks WHERE n = $1)`, n(ref))
			},
			Hide:    func(ctx context.Context, _ core.Q, ref string) error { return forge.HideTask(ctx, s.d, int(n(ref))) },
			Restore: func(ctx context.Context, _ core.Q, ref string) error { return forge.RestoreTask(ctx, s.d, n(ref)) },
		}, true
	case "n":
		split := func(ref string) (string, string) { o, name, _ := strings.Cut(ref, "/"); return o, name }
		return core.Target{
			Exists: func(ctx context.Context, q core.Q, ref string) error {
				o, name := split(ref)
				return rowExists(ctx, q, `SELECT EXISTS (SELECT 1 FROM notes WHERE owner = $1 AND name = $2)`, o, name)
			},
			Hide: func(ctx context.Context, _ core.Q, ref string) error {
				o, name := split(ref)
				return forge.HideNote(ctx, s.d, o, name)
			},
			Restore: func(ctx context.Context, _ core.Q, ref string) error {
				o, name := split(ref)
				return forge.RestoreNote(ctx, s.d, o, name)
			},
		}, true
	}
	return core.Target{}, false
}

func rowExists(ctx context.Context, q core.Q, sql string, args ...any) error {
	var ok bool
	if err := q.QueryRow(ctx, sql, args...).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

// bumpCounter adds one to today's counter of (scope, kind) and returns the new value: the
// super-group and global caps core.UseIPQuota does not cover read it (4.3).
func bumpCounter(ctx context.Context, q core.Q, scope, kind string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, 1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`, scope, kind).Scan(&n)
	return n, err
}

// reporter is who reports: a root id with its effective level, or "ip:<group>" when anonymous;
// group and super are the request's network keys, stored on the row for the collapse.
type reporter struct {
	id           string
	lvl          int
	group, super string
}

// levelOf is the effective standing of a reporting root: trust's level, or L2 for a root that is
// established in v1's sense (rep >= 5 and 72 h, SPEC-v2 0) without a verified contribution yet.
func levelOf(st trust.Standing) int {
	if st.Banned {
		return 0
	}
	if l := st.Level(); l >= 2 || !(st.Rep >= 5 && st.Age >= core.EstablishedAge) {
		return l
	}
	return 2
}

func rootWeight(lvl int) float64 {
	switch {
	case lvl >= 2:
		return weightL2
	case lvl == 1:
		return weightL1
	}
	return weightL0
}

type tally struct {
	total      float64
	identified bool // at least one report from an L1+ root
	reporters  []string
}

// tally sums the weights behind a target (4.7): every reporter (roots by level x trust, anonymous
// groups 0.25 x trust) collapses to the max weight per super-group, mirroring the spec's
// DISTINCT ON (ip_super) ORDER BY w DESC — a single network can contribute at most one weight, so
// Sybil roots on one /24 (or /48) cannot stack, and an identified root and an anonymous report on
// the same network no longer double-count. The anonymous portion (super-groups whose winning
// weight is anonymous) is still capped at anonCap in total; notices weigh 1.0 x trust each off to
// the side (operator channel, never a Sybil vector). Purged, banned and seed roots weigh nothing.
func (s *srv) tally(ctx context.Context, q core.Q, key string) (tally, error) {
	rows, err := q.Query(ctx, `SELECT r.reporter, r.ip_super, coalesce(t.score, 1) FROM reports r
		LEFT JOIN report_trust t ON t.reporter = r.reporter WHERE r.target = $1`, key)
	if err != nil {
		return tally{}, err
	}
	type row struct {
		rep, super string
		score      float64
	}
	var rs []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.rep, &x.super, &x.score); err != nil {
			rows.Close()
			return tally{}, err
		}
		rs = append(rs, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return tally{}, err
	}
	var out tally
	// One winner per super-group (max weight). anon records whether that winner is an anonymous
	// reporter (its weight falls under anonCap) rather than an identified root (uncapped); l1
	// records whether it is an L1+ root (what identifies the report set).
	type winner struct {
		w        float64
		anon, l1 bool
	}
	groups := map[string]*winner{}
	consider := func(super string, w float64, isAnon, isL1 bool) {
		g := groups[super]
		if g == nil {
			g = &winner{}
			groups[super] = g
		}
		if w > g.w {
			g.w, g.anon, g.l1 = w, isAnon, isL1
		}
	}
	for _, x := range rs {
		switch {
		case strings.HasPrefix(x.rep, "ip:"):
			super := x.super
			if super == "" { // v1 row: derive the super-group from the group key
				super = core.IPSuper(strings.TrimPrefix(x.rep, "ip:"))
			}
			consider(super, weightAnon*x.score, true, false)
		case strings.HasPrefix(x.rep, "notice:"):
			out.total += weightL2 * x.score
		default:
			st, err := trust.Load(ctx, q, x.rep)
			if errors.Is(err, core.ErrNotFound) {
				continue
			}
			if err != nil {
				return out, err
			}
			if st.Banned || st.Seed {
				continue
			}
			lvl := levelOf(st)
			super := x.super
			if super == "" { // legacy row without a super: keep the root independent
				super = x.rep
			}
			consider(super, rootWeight(lvl)*x.score, false, lvl >= 1)
		}
		out.reporters = append(out.reporters, x.rep)
	}
	var a float64
	for _, g := range groups {
		if g.anon {
			a += g.w // anonymous super-group: counts against anonCap
			continue
		}
		out.total += g.w
		out.identified = out.identified || g.l1
	}
	out.total += math.Min(a, anonCap)
	return out, nil
}

// hideState is the bookkeeping state of a target: "open" while a hide decided here stands,
// "immune" for 30 d after a reversal, "" otherwise.
func hideState(ctx context.Context, q core.Q, key string) (string, error) {
	var st string
	err := q.QueryRow(ctx, `SELECT CASE WHEN settled_at IS NULL THEN 'open'
		WHEN outcome = 'reversed' AND settled_at > now() - $2::interval THEN 'immune' ELSE '' END
		FROM report_hides WHERE target = $1`, key, immuneFor.String()).Scan(&st)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return st, err
}

// hide applies a hide decided here and records it. Report hides on kb keep the report grade
// (kb.HideNoPenalty: immunity honoured, purged after 30 d) because kb's registered Hide is the
// notice grade (never auto-purged), the one notices need; every other kind goes through its
// registration. An open row absorbs a later notice (its reason wins, hidden_at stays), a settled
// one starts a new cycle.
func (s *srv) hide(ctx context.Context, q core.Q, t core.Target, tg target, reason string, reporters []string) error {
	fn := t.Hide
	if tg.kind == "kb" && reason == "report" {
		fn = kb.HideNoPenalty
	}
	if err := fn(ctx, q, tg.ref); err != nil {
		return err
	}
	author, err := s.authorOf(ctx, q, tg)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO report_hides (target, kind, ref, reason, author, reporters) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (target) DO UPDATE SET
		  reason = CASE WHEN report_hides.settled_at IS NULL AND report_hides.reason = 'notice' THEN 'notice' ELSE EXCLUDED.reason END,
		  author = EXCLUDED.author,
		  reporters = CASE WHEN report_hides.settled_at IS NULL THEN report_hides.reporters || EXCLUDED.reporters ELSE EXCLUDED.reporters END,
		  hidden_at = CASE WHEN report_hides.settled_at IS NULL THEN report_hides.hidden_at ELSE now() END,
		  settled_at = NULL, outcome = ''`, tg.key(), tg.kind, tg.ref, reason, author, reporters)
	return err
}

// authorOf is the root behind a target: kb's author column, else the latest content_origin row
// of the kind (claims and digests are recorded under their long names); "" when unknown.
func (s *srv) authorOf(ctx context.Context, q core.Q, tg target) (string, error) {
	var root string
	var err error
	switch kind := tg.kind; kind {
	case "kb":
		err = q.QueryRow(ctx, `SELECT author_root FROM kb WHERE id = $1`, tg.ref).Scan(&root)
	default:
		switch kind {
		case "v":
			kind = "claim"
		case "dg":
			kind = "digest"
		}
		err = q.QueryRow(ctx, `SELECT root FROM content_origin WHERE kind = $1 AND ref = $2 ORDER BY at DESC LIMIT 1`, kind, tg.ref).Scan(&root)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	return root, err
}

// Report records one report (idempotent per reporter) and hides the target once the tally
// reaches reportHideWeight with an L1+ root among the reporters; `d:` deletes on one L2 report.
// Targets already hidden here or immune after a reversal only collect the row. ErrNotFound when
// the target does not exist (nothing recorded).
func (s *srv) Report(ctx context.Context, tg target, rep reporter, why string) error {
	t, ok := s.targetFor(tg.kind)
	if !ok {
		return errTarget
	}
	if err := t.Exists(ctx, s.d.DB, tg.ref); err != nil {
		return err
	}
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `INSERT INTO reports (target, reporter, why, ip_group, ip_super) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
			tg.key(), rep.id, why, rep.group, rep.super); err != nil {
			return err
		}
		state, err := hideState(ctx, tx, tg.key())
		if err != nil || state != "" {
			return err
		}
		ty, err := s.tally(ctx, tx, tg.key())
		if err != nil {
			return err
		}
		if tg.kind == "d" && rep.lvl >= 2 {
			ty.total, ty.identified = reportHideWeight, true
		}
		if ty.total < reportHideWeight || !ty.identified {
			return nil
		}
		return s.hide(ctx, tx, t, tg, "report", ty.reporters)
	})
}

// report is POST /v1/report {target, why} (anonymous ok): quota, one row per (target, reporter),
// then the tally. `m:` only by the recipient (mail.CanReport), `d:` only by L2 roots.
func (s *srv) report(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthOpt(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in struct{ Target, Why string }
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	tg, err := s.parseTarget(strings.TrimSpace(in.Target))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if len(in.Why) > maxWhy {
		core.Fail(w, r, core.Bad("why <=200"))
		return
	}
	why, _ := scrub.Mask(doc.SafeLine(scrub.Normalize(in.Why)))
	ctx := r.Context()
	ip := s.d.ClientIP(r)
	rep := reporter{id: "ip:" + core.IPGroup(ip), group: core.IPGroup(ip), super: core.IPSuper(ip)}
	if id != nil {
		st, err := trust.Load(ctx, s.d.DB, id.Root)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		rep.id, rep.lvl = id.Root, levelOf(st)
	}
	switch tg.kind {
	case "m":
		if id == nil {
			core.Fail(w, r, core.ErrAuth)
			return
		}
		if err := mail.CanReport(ctx, s.d.DB, tg.ref, id.Root); err != nil {
			core.Fail(w, r, err)
			return
		}
	case "d":
		if rep.lvl < 2 {
			core.Fail(w, r, core.E(403, "auth", "d: targets are reported by L2 roots"))
			return
		}
	}
	if err := core.UseIPQuota(ctx, s.d.DB, ip, "report", reportIPQuota); err != nil {
		core.Fail(w, r, err)
		return
	}
	if n, err := bumpCounter(ctx, s.d.DB, "ip:"+rep.super, "report"); err != nil {
		core.Fail(w, r, err)
		return
	} else if n > reportSuperQuota {
		core.Fail(w, r, core.ErrQuota)
		return
	}
	if err := s.Report(ctx, tg, rep, why); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, "ok", map[string]bool{"ok": true})
}

// --- bookkeeping (4.7 appeal/restore) ---

// Reversed records that a hide decided here was undone (appeal upheld, operator restore): the
// reporters behind it lose half their trust and the target is immune to report-hides for 30 d.
// Idempotent; owners that restore outside web call it with the target key (kb:<id>, …).
func Reversed(ctx context.Context, q core.Q, key string) error {
	return settle(ctx, q, key, "reversed")
}

// settle closes the open hide of a target with an outcome and moves the reporters' trust: x0.5
// each on a reversal, +0.1 (capped at trustMax) each when the hide stood.
func settle(ctx context.Context, q core.Q, key, outcome string) error {
	var reporters []string
	err := q.QueryRow(ctx, `UPDATE report_hides SET settled_at = now(), outcome = $2 WHERE target = $1 AND settled_at IS NULL RETURNING reporters`, key, outcome).Scan(&reporters)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	sql := `INSERT INTO report_trust (reporter, score, upheld) VALUES ($1, $2, 1)
		ON CONFLICT (reporter) DO UPDATE SET score = LEAST($3, report_trust.score + $4), upheld = report_trust.upheld + 1, updated = now()`
	args := []any{nil, math.Min(trustMax, 1+trustUpheld), trustMax, trustUpheld}
	if outcome == "reversed" {
		sql = `INSERT INTO report_trust (reporter, score, reversed) VALUES ($1, $2, 1)
			ON CONFLICT (reporter) DO UPDATE SET score = report_trust.score * $3, reversed = report_trust.reversed + 1, updated = now()`
		args = []any{nil, trustReversed, trustReversed}
	}
	for _, rep := range reporters {
		args[0] = rep
		if _, err := q.Exec(ctx, sql, args...); err != nil {
			return err
		}
	}
	return nil
}

// settleHides is the janitor task: report hides standing 30 d are upheld; kb targets the appeal
// path (kb votes, 4.7) restored meanwhile are reversed. Notice hides wait for the operator.
func (s *srv) settleHides(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT h.target, h.hidden_at < now() - $1::interval, k.hidden
		FROM report_hides h LEFT JOIN kb k ON h.kind = 'kb' AND k.id = h.ref
		WHERE h.settled_at IS NULL AND h.reason = 'report' ORDER BY h.hidden_at LIMIT 500`, upheldAfter.String())
	if err != nil {
		return err
	}
	type row struct {
		key     string
		old     bool
		visible bool
	}
	var rs []row
	for rows.Next() {
		var x row
		var hidden *bool
		if err := rows.Scan(&x.key, &x.old, &hidden); err != nil {
			rows.Close()
			return err
		}
		x.visible = hidden != nil && !*hidden
		rs = append(rs, x)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, x := range rs {
		outcome := ""
		switch {
		case x.visible:
			outcome = "reversed"
		case x.old:
			outcome = "upheld"
		default:
			continue
		}
		if err := settle(ctx, s.d.DB, x.key, outcome); err != nil {
			return err
		}
	}
	return nil
}

// upheldReports counts the hides of a root's content standing within 30 d (open or upheld) for
// the L3 rule (4.1); installed as trust.UpheldReportsFn when nothing set it.
func upheldReports(ctx context.Context, q core.Q, root string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT count(*) FROM report_hides WHERE author = $1 AND outcome <> 'reversed' AND hidden_at > now() - $2::interval`,
		root, upheldAfter.String()).Scan(&n)
	return n, err
}

// registerReports wires the reports bookkeeping (called by RegisterNotices, the registration of
// this file's wave): the settle janitor, the purge hook (a purged root's reports and trust row go)
// and the upheld-reports seam of trust.
func (s *srv) registerReports() {
	d := s.d
	d.Janitor.Add("report_hides", s.settleHides)
	d.OnPurge(func(ctx context.Context, root string) error {
		for _, sql := range []string{`DELETE FROM reports WHERE reporter = $1`, `DELETE FROM report_trust WHERE reporter = $1`} {
			if _, err := d.DB.Exec(ctx, sql, root); err != nil {
				return err
			}
		}
		return nil
	})
	if trust.UpheldReportsFn == nil {
		trust.UpheldReportsFn = upheldReports
	}
}
