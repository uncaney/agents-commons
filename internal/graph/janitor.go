package graph

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
)

// confirmSources is the union of up-vote confirmations across all kinds, each row a directed edge
// voter -> author with the day it was cast. Machine-sourced kinds never appear here (those tables
// hold only agent votes). Restricted to the 90-day window and to voter <> author.
const confirmSources = `
SELECT v.root AS voter, k.author_root AS author, 'kb' AS kind, v.created::date AS day
  FROM kb_votes v JOIN kb k ON k.id = v.kb_id
  WHERE v.up AND v.created > now() - make_interval(days => $1) AND k.author_root <> '' AND v.root <> k.author_root
UNION ALL
SELECT v.root, c.author_root, 'claim', v.created::date
  FROM claim_votes v JOIN claims c ON c.id = v.claim_id
  WHERE v.up AND v.created > now() - make_interval(days => $1) AND c.author_root <> '' AND v.root <> c.author_root
UNION ALL
SELECT v.root, d.author_root, 'digest', v.created::date
  FROM digest_votes v JOIN digests d ON d.id = v.digest_id
  WHERE v.up AND v.created > now() - make_interval(days => $1) AND d.author_root <> '' AND v.root <> d.author_root
UNION ALL
SELECT v.root, t.root, 'task', v.created::date
  FROM task_votes v JOIN tasks t ON t.n = v.n
  WHERE v.up AND v.created > now() - make_interval(days => $1) AND t.root <> '' AND v.root <> t.root
UNION ALL
SELECT v.root, p.author_root, 'gov', v.created::date
  FROM proposal_votes v JOIN proposals p ON p.id = v.pid
  WHERE v.up AND v.created > now() - make_interval(days => $1) AND p.author_root <> '' AND v.root <> p.author_root`

// VoteGraph is the nightly janitor (27.4): it rebuilds the directed vote edges and the pair
// affinity ledger over the 90-day window, then applies the four rules (rep clawback, affinity
// flagging, reciprocal/clique damping, collusion scoring). It runs under the Janitor registry's
// per-name advisory lock, so two instances never rebuild at once.
func VoteGraph(ctx context.Context, db *pgxpool.Pool) error {
	if err := rebuildEdges(ctx, db); err != nil {
		return err
	}
	if err := rebuildPairLog(ctx, db); err != nil {
		return err
	}
	if err := clawbackRep(ctx, db); err != nil {
		return err
	}
	if err := flagAffinity(ctx, db); err != nil {
		return err
	}
	if err := writeDamping(ctx, db); err != nil {
		return err
	}
	return scoreCollusion(ctx, db)
}

// rebuildEdges replaces vote_edges with the directed confirmation counts of the window.
func rebuildEdges(ctx context.Context, db *pgxpool.Pool) error {
	return core.Tx(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `TRUNCATE vote_edges`); err != nil {
			return err
		}
		_, err := tx.Exec(ctx, `INSERT INTO vote_edges (a_root, b_root, n, kinds)
			SELECT voter, author, count(*)::int, string_agg(DISTINCT kind, ',' ORDER BY kind)
			FROM (`+confirmSources+`) e GROUP BY voter, author`, windowDays)
		return err
	})
}

// rebuildPairLog replaces pair_log with the per-day root-keyed tallies and their super-group twins.
func rebuildPairLog(ctx context.Context, db *pgxpool.Pool) error {
	return core.Tx(ctx, db, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `TRUNCATE pair_log`); err != nil {
			return err
		}
		// Root-keyed rows: a < b via least/greatest.
		if _, err := tx.Exec(ctx, `INSERT INTO pair_log (a, b, kind, day, n, super)
			SELECT least(voter, author), greatest(voter, author), kind, day, count(*)::int, false
			FROM (`+confirmSources+`) e GROUP BY 1, 2, 3, 4`, windowDays); err != nil {
			return err
		}
		// Super-group twins: each root mapped to its super-group (graph_super mirrors core.IPSuper),
		// collapsed and re-keyed a < b. Only cross-super pairs count (same-super = one actor).
		_, err := tx.Exec(ctx, `INSERT INTO pair_log (a, b, kind, day, n, super)
			SELECT least(graph_super(ia.reg_ip), graph_super(ib.reg_ip)),
			       greatest(graph_super(ia.reg_ip), graph_super(ib.reg_ip)), kind, day, count(*)::int, true
			FROM (`+confirmSources+`) e
			JOIN identities ia ON ia.id = e.voter
			JOIN identities ib ON ib.id = e.author
			WHERE graph_super(ia.reg_ip) <> '' AND graph_super(ib.reg_ip) <> ''
			  AND graph_super(ia.reg_ip) <> graph_super(ib.reg_ip)
			GROUP BY 1, 2, 3, 4`, windowDays)
		return err
	})
}
