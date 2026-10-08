// Package taskdag adds a dependency DAG over the forge board (SPEC-v2 27.4): a task may declare the
// tasks it needs, a task is blocked while any need is not done, GET /v1/t/ready and /v1/t/blocked
// expose the two sets, claims on a blocked task are refused, an unblocking janitor wakes dependents
// of a task that became done, and a fan-out split creates children with a join rule. The tasks
// table is left untouched: the parent link and join rule live in task_dag (migration 0061).
package taskdag

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
)

const (
	maxNeeds   = 16  // needs added in one request / in the create field
	maxDeps    = 64  // total prerequisites a task may carry
	maxItems   = 32  // children per split
	maxDepth   = 8   // parent-chain depth of any task in the DAG
	maxPerDay  = 256 // descendants created per owner root per day
	cycleDepth = 32  // recursive-CTE bound of the cycle check
	listLimit  = 50
)

// Op is the MCP op shape shared with forge.
type Op = forge.Op

// OpMeta describes every taskdag op for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"tneeds": {Scope: "t:w", Cost: 1, Mutating: true},
	"tsplit": {Scope: "t:w", Cost: 1, Mutating: true},
	"tready": {Scope: "t:r", Cost: 1},
}

// Help is the op list for help{t:board} additions (<= 200 tokens).
const Help = `dag: tneeds{n,add[],del[]} declare/remove prerequisites (creator; cycle -> 409 bad cycle; hidden/quarantined need -> 409) | tready list ready tasks (open, not blocked, unclaimed) | tsplit{n,items[{title,body,tags}]<=32,join:all|any|k:<k>} fan out children (holder or creator), join evaluated on child done -> parent note "join met 3/5". A task is blocked while any need is not done; claims on a blocked task are refused.`

// Service holds the Deps; one per Deps.
type Service struct{ d *core.Deps }

var (
	svcMu sync.Mutex
	svcs  = map[*core.Deps]*Service{}
	// hooked installs the single-value forge seams once per process (several Deps in tests).
	hooked sync.Once
)

func svc(d *core.Deps) *Service {
	svcMu.Lock()
	defer svcMu.Unlock()
	if s, ok := svcs[d]; ok {
		return s
	}
	s := &Service{d: d}
	svcs[d] = s
	d.Janitor.Add("taskdag", s.janitor)
	d.OnPurge(s.purge)
	return s
}

// Register mounts the DAG routes, their scopes and OpenAPI, and wires the forge seams.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := svc(d)
	for pat, h := range map[string]http.HandlerFunc{
		"POST /v1/t/{n}/needs": s.hNeeds,
		"POST /v1/t/{n}/split": s.hSplit,
		"GET /v1/t/ready":      s.hReady,
		"GET /v1/t/blocked":    s.hBlocked,
	} {
		mux.HandleFunc(pat, h)
		scope := "t:w"
		if strings.HasPrefix(pat, "GET ") {
			scope = "t:r"
		}
		d.RegisterScope(pat, scope)
	}
	d.RegisterOpenAPI(json.RawMessage(openAPI))
	hooked.Do(func() {
		forge.ClaimCheckFn = ClaimCheck
		forge.TaskCreateHookFn = createHook
		forge.TaskExtras = append(forge.TaskExtras, TaskExtra)
	})
}

// --- helpers ---

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

func parseN(s string) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimPrefix(s, "#"), 10, 64)
	if err != nil || n <= 0 {
		return 0, core.Bad("bad task number")
	}
	return n, nil
}

// taskState returns the raw state (open|done|hidden), quarantine flag and existence of a task.
func taskState(ctx context.Context, q core.Q, n int64) (state string, quarantine bool, err error) {
	err = q.QueryRow(ctx, `SELECT state, quarantine FROM tasks WHERE n = $1`, n).Scan(&state, &quarantine)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, core.ErrNotFound
	}
	return state, quarantine, err
}

// --- dependencies: add / del / cycle check ---

// addDep records that task n needs task m, inside the caller's tx: existence, hidden/quarantined and
// cycle checks (recursive CTE, depth 32), the per-task cap, then an idempotent insert; the task_dag
// row of n is (re)created so the unblock janitor re-announces after a fresh prerequisite.
func addDep(ctx context.Context, q core.Q, n, m int64) error {
	if m == n {
		return core.E(409, "bad", fmt.Sprintf("cycle #%d->#%d", n, m))
	}
	state, quar, err := taskState(ctx, q, m)
	if err != nil {
		return err
	}
	if state == "hidden" || quar {
		return core.E(409, "bad", fmt.Sprintf("need #%d not available", m))
	}
	// A cycle appears when m already reaches n through the dependency edges (m -> ... -> n).
	var cycles bool
	if err := q.QueryRow(ctx, `WITH RECURSIVE reach(node, depth) AS (
			SELECT $1::bigint, 0
			UNION ALL
			SELECT d.needs, r.depth + 1 FROM task_deps d JOIN reach r ON d.n = r.node WHERE r.depth < $3
		)
		SELECT EXISTS (SELECT 1 FROM reach WHERE node = $2)`, m, n, cycleDepth).Scan(&cycles); err != nil {
		return err
	}
	if cycles {
		return core.E(409, "bad", fmt.Sprintf("cycle #%d->#%d", n, m))
	}
	var count int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM task_deps WHERE n = $1`, n).Scan(&count); err != nil {
		return err
	}
	if count >= maxDeps {
		return core.E(409, "quota", fmt.Sprintf("max %d prerequisites", maxDeps))
	}
	if _, err := q.Exec(ctx, `INSERT INTO task_deps (n, needs) VALUES ($1, $2) ON CONFLICT DO NOTHING`, n, m); err != nil {
		return err
	}
	_, err = q.Exec(ctx, `INSERT INTO task_dag (n) VALUES ($1) ON CONFLICT (n) DO UPDATE SET unblocked_at = NULL`, n)
	return err
}

func delDep(ctx context.Context, q core.Q, n, m int64) error {
	_, err := q.Exec(ctx, `DELETE FROM task_deps WHERE n = $1 AND needs = $2`, n, m)
	return err
}

// createHook is forge.TaskCreateHookFn: it reads the registered `needs` extension field of a fresh
// task and records each prerequisite inside the creating transaction (a refusal rolls the task back).
func createHook(ctx context.Context, q core.Q, n int64, extra json.RawMessage) error {
	var in struct {
		Needs []int64 `json:"needs"`
	}
	if err := json.Unmarshal(extra, &in); err != nil {
		return core.Bad("needs: " + err.Error())
	}
	if len(in.Needs) > maxNeeds {
		return core.Bad(fmt.Sprintf("needs <= %d", maxNeeds))
	}
	for _, m := range in.Needs {
		if m <= 0 {
			return core.Bad("bad need")
		}
		if err := addDep(ctx, q, n, m); err != nil {
			return err
		}
	}
	return nil
}

// creator returns the task's creator id and root; an error for a missing or anonymous-owned task.
func creator(ctx context.Context, q core.Q, n int64) (id, root, state string, err error) {
	err = q.QueryRow(ctx, `SELECT id, root, state FROM tasks WHERE n = $1`, n).Scan(&id, &root, &state)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", core.ErrNotFound
	}
	return id, root, state, err
}

// Needs applies add/del dependency edits to task n on behalf of its creator (root). Returns the
// current needs summary lines. Only the creator tree may edit the prerequisites.
func (s *Service) Needs(ctx context.Context, id *core.Ident, n int64, add, del []int64) error {
	if id == nil {
		return core.ErrAuth
	}
	if id.Banned {
		return core.ErrBanned
	}
	if s.d.Frozen("write") {
		return core.Frozen("write")
	}
	if len(add) > maxNeeds || len(del) > maxNeeds {
		return core.Bad(fmt.Sprintf("add/del <= %d", maxNeeds))
	}
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		cid, croot, state, err := creator(ctx, tx, n)
		_ = cid
		if err != nil {
			return err
		}
		if state == "hidden" {
			return core.ErrNotFound
		}
		if croot == "" || croot != id.Root {
			return core.E(403, "auth", "creator only")
		}
		for _, m := range del {
			if err := delDep(ctx, tx, n, m); err != nil {
				return err
			}
		}
		for _, m := range add {
			if m <= 0 {
				return core.Bad("bad need")
			}
			if err := addDep(ctx, tx, n, m); err != nil {
				return err
			}
		}
		return core.Audit(ctx, tx, id.ID, "tneeds", itoa(n), 0)
	})
}

// --- blocked / ready ---

// blockedExpr is the SQL predicate (alias t) for "task t is blocked": a prerequisite is not done.
const blockedExpr = `EXISTS (SELECT 1 FROM task_deps d JOIN tasks td ON td.n = d.needs WHERE d.n = t.n AND td.state <> 'done')`

// Blocked reports whether task n currently has a prerequisite that is not done.
func Blocked(ctx context.Context, q core.Q, n int64) (bool, error) {
	var b bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM task_deps d JOIN tasks td ON td.n = d.needs
		WHERE d.n = $1 AND td.state <> 'done')`, n).Scan(&b)
	return b, err
}

// TaskLine is one row of the ready/blocked lists.
type TaskLine struct {
	N     int64  `json:"n"`
	Title string `json:"title"`
}

func (s *Service) list(ctx context.Context, ready bool, k int) ([]TaskLine, error) {
	if k <= 0 || k > listLimit {
		k = listLimit
	}
	cond := blockedExpr
	join := ""
	if ready {
		cond = "NOT " + blockedExpr
		join = "LEFT JOIN task_claims c ON c.n = t.n AND c.until > now()"
	}
	where := "t.state = 'open' AND NOT t.quarantine AND " + cond
	if ready {
		where += " AND c.n IS NULL"
	}
	rows, err := s.d.DB.Query(ctx, `SELECT t.n, t.title FROM tasks t `+join+`
		WHERE `+where+` ORDER BY t.created DESC, t.n DESC LIMIT $1`, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []TaskLine{}
	for rows.Next() {
		var l TaskLine
		if err := rows.Scan(&l.N, &l.Title); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

func fmtList(ls []TaskLine) string {
	var b strings.Builder
	for _, l := range ls {
		fmt.Fprintf(&b, "#%d %s\n", l.N, doc.SafeLine(l.Title))
	}
	return b.String()
}

// --- claim refusal ---

// ClaimCheck is forge.ClaimCheckFn: it refuses a claim on a blocked task with 409 and names the
// first unmet prerequisite plus a next: hint.
func ClaimCheck(ctx context.Context, q core.Q, n int64, root string) *core.APIError {
	var m int64
	err := q.QueryRow(ctx, `SELECT d.needs FROM task_deps d JOIN tasks td ON td.n = d.needs
		WHERE d.n = $1 AND td.state <> 'done' ORDER BY d.needs LIMIT 1`, n).Scan(&m)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return core.E(500, "internal", "dep check")
	}
	e := core.E(409, "blocked", fmt.Sprintf("needs #%d", m))
	e.Extra = []string{"next: GET /v1/t/" + itoa(m)}
	return e
}

// --- detail lines (forge.TaskExtras chain) ---

// TaskExtra renders the DAG lines of a task detail: `needs: #12 done, #13 open` and, for a split
// parent, `children: 3/5 done`.
func TaskExtra(ctx context.Context, q core.Q, n int64) []string {
	var out []string
	rows, err := q.Query(ctx, `SELECT d.needs, td.state, td.quarantine, d.gone FROM task_deps d
		JOIN tasks td ON td.n = d.needs WHERE d.n = $1 ORDER BY d.needs`, n)
	if err == nil {
		var parts []string
		for rows.Next() {
			var m int64
			var st string
			var quar, gone bool
			if err := rows.Scan(&m, &st, &quar, &gone); err != nil {
				parts = nil
				break
			}
			parts = append(parts, fmt.Sprintf("#%d %s", m, depState(st, quar, gone)))
		}
		rows.Close()
		if len(parts) > 0 {
			out = append(out, "needs: "+strings.Join(parts, ", "))
		}
	}
	var total, done int
	if err := q.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE td.state = 'done')
		FROM task_dag g JOIN tasks td ON td.n = g.n WHERE g.parent = $1`, n).Scan(&total, &done); err == nil && total > 0 {
		out = append(out, fmt.Sprintf("children: %d/%d done", done, total))
	}
	return out
}

func depState(state string, quar, gone bool) string {
	switch {
	case gone, state == "hidden":
		return "gone"
	case state == "done":
		return "done"
	case quar:
		return "quarantined"
	default:
		return "open"
	}
}

// --- purge ---

// purge removes the DAG rows of a root's tasks before core deletes them (OnPurge); the FK cascade
// also covers this, so it is a defensive cleanup that keeps no dangling edges.
func (s *Service) purge(ctx context.Context, root string) error {
	ids, err := core.Descendants(ctx, s.d.DB, root)
	if err != nil || len(ids) == 0 {
		return err
	}
	for _, sql := range []string{
		`DELETE FROM task_deps WHERE n IN (SELECT n FROM tasks WHERE root = ANY($1))
			OR needs IN (SELECT n FROM tasks WHERE root = ANY($1))`,
		`DELETE FROM task_dag WHERE n IN (SELECT n FROM tasks WHERE root = ANY($1))`,
	} {
		if _, err := s.d.DB.Exec(ctx, sql, ids); err != nil {
			return err
		}
	}
	return nil
}
