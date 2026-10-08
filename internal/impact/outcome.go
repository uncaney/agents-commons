package impact

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/spaces"
)

// agg is the space activity snapshot stored in proposal_outcomes.before / .after (27.5). tasks_d is
// the mean tasks per day over the trailing 30 days; reports counts reports filed against the space's
// tasks in that window.
type agg struct {
	Members int `json:"members"`
	TasksD  int `json:"tasks_d"`
	Reports int `json:"reports"`
}

// snapshot reads the current activity aggregates of a space.
func snapshot(ctx context.Context, q core.Q, slug string) (agg, error) {
	var a agg
	var tasks30 int
	err := q.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM space_members WHERE space = $1),
		(SELECT count(*) FROM tasks WHERE space = $1 AND created > now() - interval '30 days'),
		(SELECT count(*) FROM reports r JOIN tasks t ON r.target = 't:' || t.n::text
		   WHERE t.space = $1 AND r.created > now() - interval '30 days')`,
		slug).Scan(&a.Members, &tasks30, &a.Reports)
	a.TasksD = tasks30 / 30
	return a, err
}

// OnApplied is gov.AppliedHookFn: when a space rule, member or template proposal applies, snapshot
// the space's activity aggregates as the outcome baseline. Runs inside gov's apply transaction.
func OnApplied(ctx context.Context, q core.Q, p *gov.Proposal) error {
	if p == nil || p.Scope == "" || !tracked(p.Kind) {
		return nil
	}
	a, err := snapshot(ctx, q, p.Scope)
	if err != nil {
		return err
	}
	b, err := json.Marshal(a)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO proposal_outcomes (pid, applied_at, before) VALUES ($1, now(), $2)
		ON CONFLICT (pid) DO NOTHING`, p.ID, b)
	return err
}

// RunOutcomes is the +30 d janitor task: for every applied proposal whose 30-day window has elapsed
// and whose outcome is still unwritten, it writes the after aggregates, the revert verdict, the
// page/changelog line and an event. Bounded per run so a large instance spreads the work.
func RunOutcomes(ctx context.Context, d *core.Deps) error {
	rows, err := d.DB.Query(ctx, `SELECT pid FROM proposal_outcomes
		WHERE written_at IS NULL AND applied_at <= now() - interval '30 days' ORDER BY applied_at LIMIT 200`)
	if err != nil {
		return err
	}
	var pids []string
	for rows.Next() {
		var pid string
		if err := rows.Scan(&pid); err != nil {
			rows.Close()
			return err
		}
		pids = append(pids, pid)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, pid := range pids {
		if err := writeOutcome(ctx, d, pid); err != nil {
			return err
		}
	}
	return nil
}

// writeOutcome fills one outcome row in its own transaction.
func writeOutcome(ctx context.Context, d *core.Deps, pid string) error {
	return core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var scope, kind string
		var patch, prev []byte
		var appliedAt time.Time
		err := tx.QueryRow(ctx, `SELECT scope, kind, patch, prev, applied_at FROM proposals WHERE id = $1`, pid).
			Scan(&scope, &kind, &patch, &prev, &appliedAt)
		if errors.Is(err, pgx.ErrNoRows) {
			// the proposal is gone (purged); stop rescanning this row.
			_, e := tx.Exec(ctx, `UPDATE proposal_outcomes SET written_at = now() WHERE pid = $1`, pid)
			return e
		}
		if err != nil {
			return err
		}
		after, err := snapshot(ctx, tx, scope)
		if err != nil {
			return err
		}
		rev, err := revertedRule(ctx, tx, scope, kind, patch, prev, appliedAt)
		if err != nil {
			return err
		}
		ab, err := json.Marshal(after)
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE proposal_outcomes SET after = $2, reverted = $3, written_at = now() WHERE pid = $1`,
			pid, ab, rev); err != nil {
			return err
		}
		var beforeRaw []byte
		if err := tx.QueryRow(ctx, `SELECT before FROM proposal_outcomes WHERE pid = $1`, pid).Scan(&beforeRaw); err != nil {
			return err
		}
		var before agg
		_ = json.Unmarshal(beforeRaw, &before)
		line := outcomeLine(before, after, rev)
		if err := gov.ChangelogNote(ctx, tx, scope, pid+" "+line); err != nil {
			return err
		}
		return core.Event(ctx, tx, "p", pid, "", "outcome")
	})
}

// revertedRule reports whether a later applied rule proposal restored this rule proposal's previous
// value: the proposal changed the rules, the space's rules are now back to its `prev`, and at least
// one rule proposal applied after it. Non-rule proposals are never marked reverted here.
func revertedRule(ctx context.Context, q core.Q, scope, kind string, patch, prev []byte, appliedAt time.Time) (bool, error) {
	if kind != "rule" || len(prev) == 0 {
		return false, nil
	}
	prevRules, err := spaces.Parse(prev)
	if err != nil {
		return false, nil
	}
	prevJSON := string(prevRules.JSON())
	afterP, err := spaces.Merge(*prevRules, patch)
	if err != nil || string(afterP.JSON()) == prevJSON {
		return false, nil // shape error or a no-op change is not revertible
	}
	var curRaw []byte
	if err := q.QueryRow(ctx, `SELECT rules FROM spaces WHERE slug = $1`, scope).Scan(&curRaw); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	curRules, err := spaces.Parse(curRaw)
	if err != nil || string(curRules.JSON()) != prevJSON {
		return false, nil
	}
	var later bool
	err = q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM proposals
		WHERE scope = $1 AND kind = 'rule' AND state = 'applied' AND applied_at > $2)`, scope, appliedAt).Scan(&later)
	return later, err
}

// outcomeLine renders the /p/<id> and changelog line.
func outcomeLine(before, after agg, reverted bool) string {
	rev := "no"
	if reverted {
		rev = "yes"
	}
	return "outcome: tasks/d " + itoa(before.TasksD) + "->" + itoa(after.TasksD) +
		" members " + itoa(before.Members) + "->" + itoa(after.Members) +
		" reports " + itoa(before.Reports) + "->" + itoa(after.Reports) +
		" reverted:" + rev
}

// tracked reports whether a proposal kind carries an impact line and an outcome (27.5).
func tracked(kind string) bool {
	return kind == "rule" || kind == "member" || kind == "template"
}
