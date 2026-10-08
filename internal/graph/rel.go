package graph

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
)

// Rel is the reliability score of a root (27.4): (ok + 2) / (ok + bad + 4) over the trailing 3
// calendar months, with n = ok + bad. The Laplace prior makes an unknown root read 0.50. The
// score is hidden until a root has at least 10 interactions: below that n is reported as 0, so
// callers render `rel=0.50 n=0`. Display only: never feeds rep, caps or ranking.
func Rel(ctx context.Context, q core.Q, root string) (float64, int) {
	if root == "" {
		return 0.5, 0
	}
	var ok, bad int
	err := q.QueryRow(ctx, `SELECT coalesce(sum(ok), 0), coalesce(sum(bad), 0) FROM rel_counters
		WHERE root = $1 AND month >= $2`, root, monthKey(time.Now().AddDate(0, -2, 0))).Scan(&ok, &bad)
	if err != nil {
		return 0.5, 0
	}
	n := ok + bad
	score := float64(ok+2) / float64(ok+bad+4)
	if n < relMinInteractions {
		return 0.5, 0
	}
	return score, n
}

// monthKey is the YYYY-MM bucket of t in UTC.
func monthKey(t time.Time) string { return t.UTC().Format("2006-01") }

// RelLine is the signed statement served by GET /v1/rel/{root}: `rel1 root=<r> rel=0.93 n=57
// at=<unix> k=<kid>` followed by its sig= token (type rel1). A hidden score is `rel=0.50 n=0`.
func RelLine(ctx context.Context, q core.Q, root string) (line, sig string) {
	rel, n := Rel(ctx, q, root)
	line = fmt.Sprintf("rel1 root=%s rel=%s n=%d at=%d k=%d",
		root, relFmt(rel), n, time.Now().Unix(), sign.KID())
	return line, sign.Sign("rel1", line)
}

// relFmt renders a reliability value with two decimals (0.50, 0.93).
func relFmt(rel float64) string { return strconv.FormatFloat(rel, 'f', 2, 64) }

// ClaimLine is forge.ClaimLineFn: the rel= field appended to a claimed task's head line.
func ClaimLine(ctx context.Context, q core.Q, holderRoot string) string {
	rel, n := Rel(ctx, q, holderRoot)
	if n < relMinInteractions {
		return ""
	}
	return fmt.Sprintf("rel=%s n=%d", relFmt(rel), n)
}

// RelLines is a pages.ProfileExtraFn: the confirmers=/nets=/rel= lines on /a/<id>. confirmers is
// the number of distinct counterparty roots this root has confirmed (outbound vote edges); nets is
// how many distinct super-groups those counterparties span; rel is shown only past 10 interactions.
func RelLines(ctx context.Context, q core.Q, root string) []string {
	if root == "" {
		return nil
	}
	var confirmers, nets int
	q.QueryRow(ctx, `SELECT count(*), count(DISTINCT coalesce(nullif(i.reg_ip, ''), e.b_root))
		FROM vote_edges e LEFT JOIN identities i ON i.id = e.b_root
		WHERE e.a_root = $1`, root).Scan(&confirmers, &nets)
	out := []string{fmt.Sprintf("confirmers=%d nets=%d", confirmers, nets)}
	if rel, n := Rel(ctx, q, root); n >= relMinInteractions {
		out = append(out, fmt.Sprintf("rel=%s n=%d", relFmt(rel), n))
	}
	return out
}

// StatsExtra is a gov.StatsExtraFn: the graph lines on /gov/stats. Nil-safe against a database
// where the janitor has not run: counts default to zero.
func StatsExtra(ctx context.Context, q core.Q) []string {
	var reciprocal, cliques, damped int
	var topShare float64
	q.QueryRow(ctx, `SELECT count(*) FROM pair_damp WHERE damp = 0 AND reason = 'reciprocal'`).Scan(&reciprocal)
	q.QueryRow(ctx, `SELECT count(DISTINCT reason) FROM pair_damp WHERE reason LIKE 'clique:%'`).Scan(&cliques)
	q.QueryRow(ctx, `SELECT coalesce(sum(n), 0) FROM pair_log pl JOIN pair_damp pd ON pd.a = pl.a AND pd.b = pl.b
		WHERE NOT pl.super AND pd.damp < 1 AND pl.day >= current_date - 30`).Scan(&damped)
	q.QueryRow(ctx, `SELECT coalesce(max(share), 0) FROM (
		SELECT sum(n)::real / nullif(sum(sum(n)) OVER (), 0) AS share
		FROM vote_edges GROUP BY a_root) t`).Scan(&topShare)
	return []string{
		fmt.Sprintf("reciprocal_pairs=%d cliques=%d damped_votes_30d=%d top_pair_share=%s",
			reciprocal, cliques, damped, relFmt(topShare)),
	}
}

// relBreakdown is one kind's ok/bad tally for GET /v1/me/rel.
type relBreakdown struct {
	Kind    string
	Ok, Bad int
}

// breakdown reads the per-kind ok/bad tallies of a root over the trailing 3 months.
func breakdown(ctx context.Context, q core.Q, root string) ([]relBreakdown, error) {
	rows, err := q.Query(ctx, `SELECT kind, coalesce(sum(ok), 0), coalesce(sum(bad), 0) FROM rel_counters
		WHERE root = $1 AND month >= $2 GROUP BY kind ORDER BY kind`,
		root, monthKey(time.Now().AddDate(0, -2, 0)))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []relBreakdown
	for rows.Next() {
		var b relBreakdown
		if err := rows.Scan(&b.Kind, &b.Ok, &b.Bad); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, rows.Err()
}

// meRelText renders the per-kind breakdown for GET /v1/me/rel.
func meRelText(rel float64, n int, bs []relBreakdown) string {
	var b strings.Builder
	fmt.Fprintf(&b, "rel=%s n=%d", relFmt(rel), n)
	for _, r := range bs {
		fmt.Fprintf(&b, "\n%s ok=%d bad=%d", r.Kind, r.Ok, r.Bad)
	}
	b.WriteByte('\n')
	return b.String()
}
