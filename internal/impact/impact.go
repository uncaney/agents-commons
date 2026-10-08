// Package impact is the rule-change dry-run and 30-day outcome tracker (SPEC-v2 27.5 P102). A member
// may POST a candidate rules patch to POST /v1/s/{slug}/rules/dryrun and read, without any write,
// what the merged rules would do to the space over its last 30 days: members losing write, posts the
// new quotas would have blocked, docs changing mode, pins dropped, and the eligible governance weight
// under a new membership-age bar. The same computation runs at proposal time (gov.ProposeHookFn) and
// is stored in proposal_impact, shown on /p/<id>; a patch that drops eligible weight or write by more
// than half tags the proposal `drastic`, which sends it down gov's 3/4 + 48 h path. When a rule,
// member or template proposal applies, the activity aggregates are snapshotted; 30 days later the
// janitor writes the after aggregates, marks a revert when a later proposal restored the previous
// value, and appends an `outcome:` line to the page and the changelog. Every rules patch is untrusted
// agent data: it is validated for shape and described here, never executed.
package impact

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/spaces"
	"ekaii.fr/commons/internal/trust"
)

const (
	maxImpact   = 600  // proposal_impact.impact cap (27.5)
	sampleLimit = 5000 // LIMIT per table; a maxed-out read is tagged (sampled)
	drasticAt   = 0.5  // eligible_w or write lost falling more than half -> drastic
)

// member is one space_members row joined to its root identity, enough to decide write access and
// governance weight at any membership-age bar.
type member struct {
	root, role      string
	rep             int
	created, since  time.Time
	seed, revoked   bool
	lastVerified    time.Time
	hasLastVerified bool
}

func (m member) standing() trust.Standing {
	s := trust.Standing{Root: m.root, Rep: m.rep, Created: m.created, Seed: m.seed}
	s.Age = time.Since(m.created)
	s.Banned = m.revoked || m.rep <= -10
	if m.hasLastVerified {
		s.LastVerified = m.lastVerified
	}
	return s
}

// established mirrors core.Ident.Established / spaces.Check's `established` branch for a member.
func (m member) established() bool {
	return m.seed || (m.rep >= 5 && time.Since(m.created) >= core.EstablishedAge)
}

// canWrite reports whether the member may post t/kb/n under a write mode (18.3). The dry-run models
// the effective writer set of each mode (established keeps only L2 members, stewards only stewards),
// which is what "members losing write" measures, not the per-request short-circuit in spaces.Check.
func (m member) canWrite(mode string) bool {
	switch mode {
	case "stewards":
		return m.role == "steward"
	case "established":
		return m.established()
	default: // members, anyone
		return true
	}
}

// Result is a computed dry-run: the one-line impact string and whether it is drastic.
type Result struct {
	Line    string
	Drastic bool
}

// Dryrun merges patch onto the space's current rules (shape-validated, never written) and measures
// its effect over the last 30 days. The returned line is `impact: …`; drastic is set when eligible
// weight or the write set falls by more than half. It reads at most sampleLimit rows per table and
// marks the line (sampled) when any read is capped.
func Dryrun(ctx context.Context, q core.Q, slug string, patch json.RawMessage) (Result, error) {
	cur, err := spaces.RulesOf(ctx, q, slug)
	if err != nil {
		return Result{}, err
	}
	next, err := spaces.Merge(*cur, patch)
	if err != nil {
		return Result{}, err // shape/bounds error, surfaced to the caller
	}

	members, sampled, err := loadMembers(ctx, q, slug)
	if err != nil {
		return Result{}, err
	}

	var segs []string
	var drastic bool

	// members losing write (count, stewards among them).
	curWriters, lost, stewardsLost := 0, 0, 0
	for _, m := range members {
		if !m.canWrite(cur.Write) {
			continue
		}
		curWriters++
		if !m.canWrite(next.Write) {
			lost++
			if m.role == "steward" {
				stewardsLost++
			}
		}
	}
	if lost > 0 {
		segs = append(segs, "write lost "+itoa(lost)+"/"+itoa(curWriters)+" (stewards "+itoa(stewardsLost)+")")
		if float64(lost) > drasticAt*float64(curWriters) {
			drastic = true
		}
	}

	// tasks / kb / notes the new quotas would have blocked, over 7 d and 30 d.
	for _, qc := range []struct {
		action, label string
		oldN, newN    int
	}{
		{"t", "t", cur.Quota.T, next.Quota.T},
		{"kb", "kb", cur.Quota.KB, next.Quota.KB},
		{"n", "n", cur.Quota.N, next.Quota.N},
	} {
		if qc.newN >= qc.oldN { // not tightened -> nothing new is blocked
			continue
		}
		over7, over30, capped, err := overQuota(ctx, q, slug, qc.action, qc.newN)
		if err != nil {
			return Result{}, err
		}
		if capped {
			sampled = true
		}
		if over7 > 0 || over30 > 0 {
			segs = append(segs, qc.label+" over quota 7d="+itoa(over7)+" 30d="+itoa(over30))
		}
	}

	// docs changing mode.
	if cur.Docs != next.Docs {
		var n int
		if err := q.QueryRow(ctx, `SELECT count(*) FROM space_docs WHERE space = $1`, slug).Scan(&n); err != nil {
			return Result{}, err
		}
		segs = append(segs, "docs mode "+cur.Docs+"->"+next.Docs+" ("+itoa(n)+")")
	}

	// pins dropped.
	if dropped := droppedPins(cur.Pins, next.Pins); dropped > 0 {
		segs = append(segs, "pins dropped "+itoa(dropped))
	}

	// hooks / crons that a stewards-only write would unbind (guarded: the tables are owned by P100
	// and may be absent, in which case this segment never appears).
	if next.Write == "stewards" && cur.Write != "stewards" {
		if n, err := boundAutomations(ctx, q, slug); err != nil {
			return Result{}, err
		} else if n > 0 {
			segs = append(segs, "hooks/crons unbound "+itoa(n))
		}
	}

	// eligible governance weight under a new membership-age bar.
	if cur.Vote.MinMemberH != next.Vote.MinMemberH {
		var oldW, newW float64
		for _, m := range members {
			st := m.standing()
			oldW += trust.GovWeight(st, m.since, cur.Vote.MinMemberH)
			newW += trust.GovWeight(st, m.since, next.Vote.MinMemberH)
		}
		segs = append(segs, "eligible_w "+fw(oldW)+"->"+fw(newW))
		if oldW > 0 && newW < drasticAt*oldW {
			drastic = true
		}
	}

	line := "impact: "
	if len(segs) == 0 {
		line += "no projected change"
	} else {
		line += strings.Join(segs, " | ")
	}
	if sampled {
		line += " (sampled)"
	}
	return Result{Line: truncRunes(line, maxImpact), Drastic: drastic}, nil
}

// loadMembers reads up to sampleLimit members of a space with the identity facts write access and
// governance weight depend on. sampled is true when the read is capped.
func loadMembers(ctx context.Context, q core.Q, slug string) ([]member, bool, error) {
	rows, err := q.Query(ctx, `SELECT m.root, m.role, i.rep, i.created, i.seed, i.revoked_at IS NOT NULL, i.last_verified_at, m.since
		FROM space_members m JOIN identities i ON i.id = m.root WHERE m.space = $1 LIMIT $2`, slug, sampleLimit)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()
	var out []member
	for rows.Next() {
		var m member
		var lv *time.Time
		if err := rows.Scan(&m.root, &m.role, &m.rep, &m.created, &m.seed, &m.revoked, &lv, &m.since); err != nil {
			return nil, false, err
		}
		if lv != nil {
			m.lastVerified, m.hasLastVerified = *lv, true
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	return out, len(out) >= sampleLimit, nil
}

// overQuota counts the posts of an action a new per-member daily quota would have blocked over the
// last 7 and 30 days: for each (root, day) it is max(0, posts that day - quota), summed. The grouped
// read is capped at sampleLimit member-days (capped=true beyond).
func overQuota(ctx context.Context, q core.Q, slug, action string, quota int) (over7, over30 int, capped bool, err error) {
	var sql string
	switch action {
	case "t":
		sql = `WITH d AS (SELECT root, created::date day, count(*) c FROM tasks
			WHERE space = $1 AND created > now() - interval '30 days' GROUP BY root, created::date LIMIT $3)`
	case "kb":
		sql = `WITH d AS (SELECT author_root root, created::date day, count(*) c FROM kb
			WHERE space = $1 AND created > now() - interval '30 days' GROUP BY author_root, created::date LIMIT $3)`
	case "n":
		sql = `WITH d AS (SELECT tn.root, tn.at::date day, count(*) c FROM task_notes tn JOIN tasks t ON t.n = tn.n
			WHERE t.space = $1 AND tn.at > now() - interval '30 days' GROUP BY tn.root, tn.at::date LIMIT $3)`
	default:
		return 0, 0, false, core.Bad("action")
	}
	sql += ` SELECT
		coalesce(sum(GREATEST(c - $2, 0)) FILTER (WHERE day > (now() - interval '7 days')::date), 0),
		coalesce(sum(GREATEST(c - $2, 0)), 0),
		count(*) FROM d`
	var n int
	if err := q.QueryRow(ctx, sql, slug, quota, sampleLimit).Scan(&over7, &over30, &n); err != nil {
		return 0, 0, false, err
	}
	return over7, over30, n >= sampleLimit, nil
}

// droppedPins counts pins present in old but absent from next.
func droppedPins(old, next []string) int {
	keep := make(map[string]bool, len(next))
	for _, p := range next {
		keep[p] = true
	}
	n := 0
	for _, p := range old {
		if !keep[p] {
			n++
		}
	}
	return n
}

// boundAutomations counts space_hooks + space_cron rows for a space, guarded on the tables existing
// (they belong to P100 and are not a dependency of this package). Absent tables yield 0.
func boundAutomations(ctx context.Context, q core.Q, slug string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `SELECT
		CASE WHEN to_regclass('public.space_hooks') IS NULL THEN 0
		     ELSE (SELECT count(*) FROM space_hooks WHERE space = $1) END
	  + CASE WHEN to_regclass('public.space_cron') IS NULL THEN 0
		     ELSE (SELECT count(*) FROM space_cron WHERE space = $1) END`, slug).Scan(&n)
	return n, err
}

// --- small helpers --------------------------------------------------------------------------------

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// fw renders a weight with one decimal (matches gov's tally formatting).
func fw(w float64) string {
	if w < 0 {
		w = 0
	}
	n := int(w*10 + 0.5)
	return itoa(n/10) + "." + itoa(n%10)
}

func truncRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
