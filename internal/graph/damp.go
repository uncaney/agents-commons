package graph

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
)

// edge is one directed vote edge with the voter's outbound and the author's inbound totals, used
// to compute shares for the damping and clique rules.
type edge struct {
	a, b      string // a_root -> b_root
	n         int
	outA, inB int // a's total outbound, b's total inbound
}

// loadEdges reads vote_edges with each endpoint's outbound/inbound totals.
func loadEdges(ctx context.Context, q core.Q) ([]edge, error) {
	rows, err := q.Query(ctx, `
		SELECT e.a_root, e.b_root, e.n,
		       coalesce(o.tot, 0) AS out_a, coalesce(i.tot, 0) AS in_b
		FROM vote_edges e
		LEFT JOIN (SELECT a_root, sum(n) AS tot FROM vote_edges GROUP BY a_root) o ON o.a_root = e.a_root
		LEFT JOIN (SELECT b_root, sum(n) AS tot FROM vote_edges GROUP BY b_root) i ON i.b_root = e.b_root`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []edge
	for rows.Next() {
		var e edge
		if err := rows.Scan(&e.a, &e.b, &e.n, &e.outA, &e.inB); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// writeDamping computes rule 3 (27.4): pair_damp rows for reciprocal, one-sided and clique edges.
//   - reciprocal (damp 0): n_ab >= 3 AND n_ba >= 3 AND both direction shares >= 0.5.
//   - one-sided (damp 0.5): one direction n >= 5 with that direction's share >= 0.5.
//   - clique (damp 0): a union-find component of 2..8 roots whose inbound is >= 80 % from inside;
//     every intra-component pair is damped, reason 'clique:<rep>'.
//
// The lowest applicable damp wins; pair_damp is rebuilt each run.
func writeDamping(ctx context.Context, db *pgxpool.Pool) error {
	edges, err := loadEdges(ctx, db)
	if err != nil {
		return err
	}
	type dir struct{ n, outA, inB int }
	fwd := map[[2]string]dir{} // key a->b
	for _, e := range edges {
		fwd[[2]string{e.a, e.b}] = dir{e.n, e.outA, e.inB}
	}
	share := func(d dir) float64 {
		if d.outA == 0 {
			return 0
		}
		return float64(d.n) / float64(d.outA)
	}
	// pair damp: lowest wins. reason tracked alongside.
	damp := map[[2]string]float64{}
	reason := map[[2]string]string{}
	set := func(a, b string, d float64, why string) {
		lo, hi := order(a, b)
		k := [2]string{lo, hi}
		if cur, ok := damp[k]; !ok || d < cur {
			damp[k] = d
			reason[k] = why
		}
	}
	// Cliques first (reason 'clique:<rep>'), so a multi-party ring keeps its clique label; the
	// reciprocal rule below only labels the plain two-party pairs the cliques left at damp 1.
	for _, cl := range cliques(edges) {
		rep := cl[0]
		for i := 0; i < len(cl); i++ {
			for j := i + 1; j < len(cl); j++ {
				set(cl[i], cl[j], 0, "clique:"+rep)
			}
		}
	}
	seen := map[[2]string]bool{}
	for _, e := range edges {
		lo, hi := order(e.a, e.b)
		pk := [2]string{lo, hi}
		if seen[pk] {
			continue
		}
		seen[pk] = true
		ab := fwd[[2]string{e.a, e.b}]
		ba := fwd[[2]string{e.b, e.a}]
		sab, sba := share(ab), share(ba)
		switch {
		case ab.n >= 3 && ba.n >= 3 && sab >= 0.5 && sba >= 0.5:
			set(e.a, e.b, 0, "reciprocal")
		case (ab.n >= 5 && sab >= 0.5) || (ba.n >= 5 && sba >= 0.5):
			set(e.a, e.b, 0.5, "onesided")
		}
	}
	return core.Tx(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `TRUNCATE pair_damp`); err != nil {
			return err
		}
		for k, d := range damp {
			if _, err := tx.Exec(ctx, `INSERT INTO pair_damp (a, b, damp, reason) VALUES ($1, $2, $3, $4)
				ON CONFLICT (a, b) DO UPDATE SET damp = excluded.damp, reason = excluded.reason, at = now()`,
				k[0], k[1], d, reason[k]); err != nil {
				return err
			}
		}
		return nil
	})
}

// scoreCollusion computes rule 4 (27.4): a weighted interaction count per pair (compute 1, kb 1,
// review 2, bounty 2, gov 2, vouch 3). A pair with > 20 weighted interactions OR > 60 % of either
// side's total is scored; score = 100 * max(volumeNorm, shareMax), clamped to 0..100, with
// volumeNorm = w / (w + 20). score >= 50 excludes the pair. collusion_pairs is rebuilt each run.
func scoreCollusion(ctx context.Context, db *pgxpool.Pool) error {
	edges, err := loadEdges(ctx, db)
	if err != nil {
		return err
	}
	// Weighted undirected pair weight from vote kinds; vouches add 3 each (loaded separately).
	pairW := map[[2]string]float64{}
	totW := map[string]float64{}
	add := func(a, b string, w float64) {
		lo, hi := order(a, b)
		pairW[[2]string{lo, hi}] += w
		totW[a] += w
		totW[b] += w
	}
	for _, e := range edges {
		add(e.a, e.b, kindWeight(ctx, db, e.a, e.b)*float64(e.n))
	}
	// vouches (weight 3) between two roots.
	if vrows, err := db.Query(ctx, `SELECT voucher, vouchee FROM vouches`); err == nil {
		for vrows.Next() {
			var a, b string
			if vrows.Scan(&a, &b) == nil && a != b {
				add(a, b, 3)
			}
		}
		vrows.Close()
	}
	return core.Tx(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `TRUNCATE collusion_pairs`); err != nil {
			return err
		}
		for k, w := range pairW {
			shareMax := 0.0
			if t := totW[k[0]]; t > 0 {
				shareMax = max(shareMax, w/t)
			}
			if t := totW[k[1]]; t > 0 {
				shareMax = max(shareMax, w/t)
			}
			if w <= 20 && shareMax <= 0.6 {
				continue
			}
			volNorm := w / (w + 20)
			score := 100 * max(volNorm, shareMax)
			if score > 100 {
				score = 100
			}
			if _, err := tx.Exec(ctx, `INSERT INTO collusion_pairs (a, b, score) VALUES ($1, $2, $3)
				ON CONFLICT (a, b) DO UPDATE SET score = excluded.score, at = now()`, k[0], k[1], score); err != nil {
				return err
			}
		}
		return nil
	})
}

// kindWeight is the per-kind collusion weight of the edges between a and b, read from vote_edges
// kinds. compute/kb weigh 1, review/bounty/gov weigh 2. Defaults to 1 when the kinds are unknown.
func kindWeight(ctx context.Context, q core.Q, a, b string) float64 {
	var kinds string
	q.QueryRow(ctx, `SELECT string_agg(kinds, ',') FROM vote_edges WHERE (a_root = $1 AND b_root = $2) OR (a_root = $2 AND b_root = $1)`, a, b).Scan(&kinds)
	w := 1.0
	for _, k := range []struct {
		name string
		wt   float64
	}{{"gov", 2}, {"review", 2}, {"bounty", 2}} {
		if contains(kinds, k.name) {
			w = max(w, k.wt)
		}
	}
	return w
}

// contains reports whether comma list s has token t.
func contains(s, t string) bool {
	for len(s) > 0 {
		var tok string
		if i := indexByte(s, ','); i >= 0 {
			tok, s = s[:i], s[i+1:]
		} else {
			tok, s = s, ""
		}
		if tok == t {
			return true
		}
	}
	return false
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
