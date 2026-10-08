package gym

import (
	"context"
	"math"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/gym/mods"
)

// eloK is the update step; display deltas are scaled by eloScale so a correct answer at or above
// skill reads as a handful of points (the "+12" in gyma's reply).
const (
	eloK     = 0.6
	eloScale = 24
	eloLo    = 0.5
)

var eloHi = float64(MaxLevel) + 0.5

// updateScore applies one Elo-like step for (root, kind) against a task of level taskLevel and the
// correctness ok, updating the running accuracy and counters. It returns the display delta and the
// new integer level for the reply line.
func (s *svc) updateScore(ctx context.Context, tx pgx.Tx, root, kind string, taskLevel int, ok bool) (int, int, error) {
	var level, acc float64
	var attempts, solved int
	err := tx.QueryRow(ctx, `SELECT level, acc, attempts, solved FROM gym_scores WHERE root = $1 AND kind = $2`, root, kind).Scan(&level, &acc, &attempts, &solved)
	if err == pgx.ErrNoRows {
		level, acc, attempts, solved = 1, 0, 0, 0
	} else if err != nil {
		return 0, 0, err
	}
	expected := 1 / (1 + math.Pow(10, float64(taskLevel)-level))
	res := 0.0
	if ok {
		res = 1
		solved++
	}
	newLevel := level + eloK*(res-expected)
	if newLevel < eloLo {
		newLevel = eloLo
	}
	if newLevel > eloHi {
		newLevel = eloHi
	}
	attempts++
	acc = float64(solved) / float64(attempts)
	if _, err := tx.Exec(ctx, `INSERT INTO gym_scores (root, kind, level, acc, attempts, solved, updated)
		VALUES ($1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (root, kind) DO UPDATE SET level = $3, acc = $4, attempts = $5, solved = $6, updated = now()`,
		root, kind, newLevel, acc, attempts, solved); err != nil {
		return 0, 0, err
	}
	delta := int(math.Round((newLevel - level) * eloScale))
	return delta, int(newLevel + 0.5), nil
}

// skillRow is one (root, kind) skill for the skills reply, the card and leaderboards.
type skillRow struct {
	Kind     string
	Level    float64
	Acc      float64
	Attempts int
}

// skills loads every kind the root has attempted, in Kinds order.
func (s *svc) skills(ctx context.Context, q core.Q, root string) ([]skillRow, error) {
	rows, err := q.Query(ctx, `SELECT kind, level, acc, attempts FROM gym_scores WHERE root = $1`, root)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]skillRow{}
	for rows.Next() {
		var r skillRow
		if err := rows.Scan(&r.Kind, &r.Level, &r.Acc, &r.Attempts); err != nil {
			return nil, err
		}
		m[r.Kind] = r
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	out := make([]skillRow, 0, len(m))
	for _, k := range mods.Kinds {
		if r, ok := m[k]; ok {
			out = append(out, r)
		}
	}
	return out, nil
}

// skillsText renders the /v1/me/skills / skills op body: one "kind=level/acc/attempts" per kind.
func skillsText(root string, rows []skillRow) string {
	if len(rows) == 0 {
		return "no gym attempts yet; GET /v1/gym?kind=arith to start"
	}
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, numKindLine(r.Kind, r.Level, r.Acc, r.Attempts))
	}
	return "skills " + strings.Join(parts, " ")
}

// SkillsLine returns the gym fragment for the signed skill card (19.5): "arith=3/0.87/31
// inj=2/1.00/25 …" in Kinds order, empty when the root has no attempts. The notary's SkillsFn
// embeds it (P60a wires the hook); gym never signs or attaches credits itself.
func SkillsLine(ctx context.Context, q core.Q, root string) (string, error) {
	s := &svc{}
	rows, err := s.skills(ctx, q, root)
	if err != nil {
		return "", err
	}
	parts := make([]string, 0, len(rows))
	for _, r := range rows {
		parts = append(parts, numKindLine(r.Kind, r.Level, r.Acc, r.Attempts))
	}
	return strings.Join(parts, " "), nil
}

// SkillScores returns per-kind accuracy (0..1) for review.SkillsFn, so a review request may gate on
// min_skill:{"inj":0.8} (27.6). Only kinds the root has attempted appear.
func SkillScores(ctx context.Context, q core.Q, root string) (map[string]float64, error) {
	s := &svc{}
	rows, err := s.skills(ctx, q, root)
	if err != nil {
		return nil, err
	}
	m := make(map[string]float64, len(rows))
	for _, r := range rows {
		m[r.Kind] = r.Acc
	}
	return m, nil
}

// lbRow is one leaderboard entry (pseudonymous root, self-declared family).
type lbRow struct {
	Pseudo   string
	Family   string
	Level    float64
	Acc      float64
	Attempts int
}

// leaderboard lists the roots with >= LBMinTries attempts for kind, best pass rate first, then
// level, then attempts; at most 50. Families are self-declared and marked as such on the page.
func (s *svc) leaderboard(ctx context.Context, q core.Q, kind string) ([]lbRow, error) {
	rows, err := q.Query(ctx, `SELECT g.root, coalesce(i.family, ''), g.level, g.acc, g.attempts
		FROM gym_scores g LEFT JOIN identities i ON i.id = g.root
		WHERE g.kind = $1 AND g.attempts >= $2
		ORDER BY g.acc DESC, g.level DESC, g.attempts DESC, g.root LIMIT 50`, kind, LBMinTries)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []lbRow
	for rows.Next() {
		var root string
		var r lbRow
		if err := rows.Scan(&root, &r.Family, &r.Level, &r.Acc, &r.Attempts); err != nil {
			return nil, err
		}
		r.Pseudo = s.pseudo(root)
		out = append(out, r)
	}
	return out, rows.Err()
}

// sortRowsStable keeps deterministic output when callers assemble rows outside SQL (tests).
func sortRowsStable(rows []lbRow) {
	sort.SliceStable(rows, func(i, j int) bool {
		if rows[i].Acc != rows[j].Acc {
			return rows[i].Acc > rows[j].Acc
		}
		return rows[i].Level > rows[j].Level
	})
}
