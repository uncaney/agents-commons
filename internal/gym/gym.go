// Package gym is the self-evaluation arena (SPEC-v2 19.5, 27.6). Portable-Go modules under
// internal/gym/mods/<kind> generate and check tasks (arith, units, regex, json, dates, and the
// REV3 safety family inj, leak, cite). A janitor keeps 50 unserved instances per (kind, level) in
// gym_tasks, funded from the system faucet. GET /v1/gym serves one prompt (seed, answer and salt
// never leave the server); POST /v1/gym/{id} grades one attempt and updates an Elo-like skill in
// gym_scores; GET /v1/me/skills and GET /lb/{kind} read them back. No credits, no rep: nothing a
// gym attempt produces feeds reputation. Gym prompts carry untrusted text, are noindex and never
// appear in feeds or exports; the lexicon is not applied to them.
package gym

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/gym/mods"
)

// Tunables (vars so tests can lower them).
var (
	PoolTarget = 50                // unserved instances kept per (kind, level)
	DailyOpens = 50                // GET /v1/gym per root per day
	DailyTries = 50                // POST attempts per root per day
	OpenTTL    = 600 * time.Second // an open instance expires after this
	LBMinTries = 20                // attempts needed to appear on /lb/{kind}
	MaxLevel   = 4
	GenCost    = 1 // faucet credits reserved per generated instance (pool refill)
)

type svc struct{ d *core.Deps }

func newSvc(d *core.Deps) *svc { return &svc{d: d} }

// task is one gym_tasks row (grading fields included; never rendered to clients).
type task struct {
	ID, Kind       string
	Level          int
	Prompt         string
	Answer, Secret string
	Checker        string
	Attempts       int
	Solved         bool
}

// Register mounts the gym routes and MCP-shared hooks. It does not touch cmd/gateway/main.go or
// internal/mcp; a later integration package wires Ops and the notary/review skill functions.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	mux.HandleFunc("GET /v1/gym", s.serveHTTP)
	mux.HandleFunc("POST /v1/gym/{id}", s.answerHTTP)
	mux.HandleFunc("GET /v1/me/skills", s.skillsHTTP)
	mux.HandleFunc("GET /lb/{kind}", s.lbHTTP) // {kind} carries any .txt/.md/.json/.html suffix; SplitSuffix strips it
	d.RegisterCost("GET /v1/gym", 1)
	d.RegisterCost("GET /lb/{kind}", 2)
	d.Janitor.Add("gym", func(ctx context.Context) error { return s.Refill(ctx) })
	d.StorageClass("gym", 128<<20, `SELECT pg_total_relation_size('gym_tasks') + pg_total_relation_size('gym_scores') + pg_total_relation_size('gym_attempts')`)
	d.OnPurge(func(ctx context.Context, root string) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM gym_scores WHERE root = $1; DELETE FROM gym_attempts WHERE root = $1; UPDATE gym_tasks SET served_to = NULL, served_at = NULL WHERE served_to = $1 AND attempts = 0`, root)
		return err
	})
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// pseudo is the pseudonymous root label shown on leaderboards: an HMAC of the root under the server
// secret, so the same root is stable across rows without exposing its id (19.5 pseudonymous).
func (s *svc) pseudo(root string) string {
	m := hmac.New(sha256.New, s.d.Cfg.ServerSecret)
	m.Write([]byte("cx-gym-lb-v1\x00" + root))
	return "a" + hex.EncodeToString(m.Sum(nil))[:11]
}

// serve returns the root's open instance for kind (one open per root per kind), or draws a fresh
// unserved one, marking it served. level <= 0 picks near the root's current skill. The prompt is
// returned; the answer, seed and salt are not.
func (s *svc) serve(ctx context.Context, id *core.Ident, kind string, level int) (*task, error) {
	kind = strings.ToLower(strings.TrimSpace(kind))
	if !mods.Valid(kind) {
		return nil, core.Bad("kind must be one of " + strings.Join(mods.Kinds, " "))
	}
	if level < 0 || level > MaxLevel {
		return nil, core.Bad(fmt.Sprintf("level must be 0 (auto) or 1..%d", MaxLevel))
	}
	var t *task
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		// Reuse a still-open instance for this (root, kind): one open per root per kind.
		if row, err := scanTask(tx.QueryRow(ctx, `SELECT id, kind, level, prompt, '' , '' , checker, attempts, solved
			FROM gym_tasks WHERE served_to = $1 AND kind = $2 AND solved = false AND attempts = 0 AND served_at > now() - make_interval(secs => $3)
			ORDER BY served_at DESC LIMIT 1`, id.Root, kind, int(OpenTTL.Seconds()))); err == nil {
			t = row
			return nil
		} else if err != pgx.ErrNoRows {
			return err
		}
		// Daily open cap.
		var opened int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM gym_tasks WHERE served_to = $1 AND served_at >= date_trunc('day', now())`, id.Root).Scan(&opened); err != nil {
			return err
		}
		if opened >= DailyOpens {
			return core.E(429, "quota", fmt.Sprintf("gym: %d opens today", DailyOpens))
		}
		if level == 0 {
			level = s.pickLevel(ctx, tx, id.Root, kind)
		}
		row, err := s.draw(ctx, tx, id.Root, kind, level)
		if err != nil {
			return err
		}
		t = row
		return nil
	})
	return t, err
}

// draw marks the oldest unserved instance of (kind, level) as served_to the root; if that level is
// empty it falls back to any level, and reports an empty-pool error when nothing is left.
func (s *svc) draw(ctx context.Context, tx pgx.Tx, root, kind string, level int) (*task, error) {
	const q = `UPDATE gym_tasks SET served_to = $1, served_at = now()
		WHERE id = (SELECT id FROM gym_tasks WHERE served_to IS NULL AND kind = $2 AND ($3 = 0 OR level = $3)
			ORDER BY created LIMIT 1 FOR UPDATE SKIP LOCKED)
		RETURNING id, kind, level, prompt, '', '', checker, attempts, solved`
	t, err := scanTask(tx.QueryRow(ctx, q, root, kind, level))
	if err == pgx.ErrNoRows && level != 0 {
		t, err = scanTask(tx.QueryRow(ctx, q, root, kind, 0)) // any level
	}
	if err == pgx.ErrNoRows {
		return nil, core.E(503, "empty", "gym: no "+kind+" instances available yet; the pool refills shortly")
	}
	return t, err
}

// pickLevel chooses a level near the root's current skill (rounded, 1..MaxLevel; default 1).
func (s *svc) pickLevel(ctx context.Context, tx pgx.Tx, root, kind string) int {
	var lvl float64 = 1
	tx.QueryRow(ctx, `SELECT level FROM gym_scores WHERE root = $1 AND kind = $2`, root, kind).Scan(&lvl)
	l := int(lvl + 0.5)
	if l < 1 {
		l = 1
	}
	if l > MaxLevel {
		l = MaxLevel
	}
	return l
}

func scanTask(row pgx.Row) (*task, error) {
	var t task
	if err := row.Scan(&t.ID, &t.Kind, &t.Level, &t.Prompt, &t.Answer, &t.Secret, &t.Checker, &t.Attempts, &t.Solved); err != nil {
		return nil, err
	}
	return &t, nil
}

// answer grades one attempt: the instance must be the caller's open instance, unattempted, within
// the daily cap. It records the attempt, marks the instance solved/attempted and updates the
// Elo-like skill, returning the reply line.
func (s *svc) answer(ctx context.Context, id *core.Ident, taskID, candidate string) (string, error) {
	if !core.ValidIDPrefix(taskID, 'g') {
		return "", core.Bad("not a gym instance id")
	}
	if len(candidate) > 8<<10 {
		return "", core.Bad("answer too long (<= 8 KiB)")
	}
	var line string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var t task
		err := tx.QueryRow(ctx, `SELECT id, kind, level, prompt, answer, secret, checker, attempts, solved
			FROM gym_tasks WHERE id = $1 FOR UPDATE`, taskID).Scan(
			&t.ID, &t.Kind, &t.Level, &t.Prompt, &t.Answer, &t.Secret, &t.Checker, &t.Attempts, &t.Solved)
		if err == pgx.ErrNoRows {
			return core.E(404, "notfound", "no such gym instance")
		}
		if err != nil {
			return err
		}
		var served *string
		if err := tx.QueryRow(ctx, `SELECT served_to FROM gym_tasks WHERE id = $1`, taskID).Scan(&served); err != nil {
			return err
		}
		if served == nil || *served != id.Root {
			return core.E(403, "forbidden", "this instance was not served to you")
		}
		if t.Attempts > 0 {
			return core.E(409, "spent", "one attempt per instance; this instance is already answered")
		}
		var tries int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM gym_attempts WHERE root = $1 AND created >= date_trunc('day', now())`, id.Root).Scan(&tries); err != nil {
			return err
		}
		if tries >= DailyTries {
			return core.E(429, "quota", fmt.Sprintf("gym: %d attempts today", DailyTries))
		}
		ok := mods.Check(t.Kind, mods.Task{Answer: t.Answer, Secret: t.Secret, Check: t.Checker}, candidate)
		if _, err := tx.Exec(ctx, `UPDATE gym_tasks SET attempts = attempts + 1, solved = $2 WHERE id = $1`, taskID, ok); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `INSERT INTO gym_attempts (task, root, kind, correct) VALUES ($1, $2, $3, $4)`, taskID, id.Root, t.Kind, ok); err != nil {
			return err
		}
		delta, lvl, err := s.updateScore(ctx, tx, id.Root, t.Kind, t.Level, ok)
		if err != nil {
			return err
		}
		if ok {
			line = fmt.Sprintf("ok correct +%d %s L%d", delta, t.Kind, lvl)
		} else {
			line = fmt.Sprintf("no %s L%d", t.Kind, lvl)
		}
		return nil
	})
	return line, err
}

// numKindLine formats a per-kind skill fragment "arith=3/0.87/31" (level/accuracy/attempts).
func numKindLine(kind string, level, acc float64, attempts int) string {
	return fmt.Sprintf("%s=%d/%.2f/%d", kind, int(level+0.5), acc, attempts)
}

func atoiLevel(s string) (int, bool) {
	n, err := strconv.Atoi(strings.TrimSpace(s))
	if err != nil || n < 0 || n > MaxLevel {
		return 0, false
	}
	return n, true
}
