// Package sem implements SPEC-v2 27.4: counting semaphores with fenced permits, atomic
// multi-lock acquisition (lkm) and lease handover for locks, permits and task claims. Semaphores
// are their own tables (0132); multi-lock and the handover paths reuse swarm.AcquireTx,
// swarm.Handover and forge.ClaimHandover over the existing locks and task_claims rows, so the
// fence discipline (10.3) and the live-locks cap (4.3) stay shared with 12. Every name follows the
// swarm grammar (g:/~/a:/s:/r:); every write path is capped, scrubbed and line-injection-safe.
package sem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/swarm"
)

const (
	bodyMax     = 16 << 10
	semTTLDef   = 60
	semTTLMax   = 3600
	noteMax     = 1 << 10
	foreignCap  = 10 // foreign (cross-root) handovers per day per root
	leaseRepCap = 5  // lease-expiry rep penalty: at most 5 per day (4.2)
	// Storage cap for the semaphore tables (21.2), sharing the swarm class budget.
	semCapBytes = 32 << 20
)

// RelFn is the 27.4 reliability score of a root (P95), nil-safe: an unset seam reads as 1.0, a set
// one gates g: handover eligibility at rel >= 0.5.
var RelFn func(ctx context.Context, q core.Q, root string) float64

func rel(ctx context.Context, q core.Q, root string) float64 {
	if RelFn == nil {
		return 1.0
	}
	return RelFn(ctx, q, root)
}

type svc struct{ d *core.Deps }

func newSvc(d *core.Deps) *svc { return &svc{d: d} }

// Register mounts the semaphore, multi-lock and handover routes, the janitor, the report target,
// the OnPurge permit release, the scope and OpenAPI fragment.
func Register(mux *http.ServeMux, d *core.Deps) { register(mux, d) }

func register(mux *http.ServeMux, d *core.Deps) *svc {
	s := newSvc(d)
	current.Store(s)
	routes := []struct {
		pat, scope string
		h          http.HandlerFunc
		cost       float64
	}{
		{"POST /v1/sm/{name}", "lk", s.smAcquire, 1},
		{"POST /v1/sm/{name}/renew", "lk", s.smRenew, 1},
		{"DELETE /v1/sm/{name}/{slot}", "lk", s.smRelease, 1},
		{"GET /v1/sm/{name}", "lk", s.smGet, 0.2},
		{"POST /v1/sm/{name}/{slot}/handover", "lk", s.smHandover, 1},
		{"POST /v1/lkm", "lk", s.lkmAcquire, 1},
		{"DELETE /v1/lkm", "lk", s.lkmRelease, 1},
		{"POST /v1/lk/{name}/handover", "lk", s.lkHandover, 1},
		{"POST /v1/t/{n}/handover", "t:w", s.tHandover, 1},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, rt.scope)
		if rt.cost != 1 {
			d.RegisterCost(rt.pat, rt.cost)
		}
	}
	d.StorageClass("sem", semCapBytes, `SELECT pg_total_relation_size('sems') + pg_total_relation_size('sem_permits')`)
	d.Janitor.Add("sem_permits", s.janPermits)
	d.OnPurge(s.purge)
	d.RegisterTarget("sm", core.Target{Exists: s.smExists, Hide: s.smHide, Restore: s.smRestore})
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("sem", func(context.Context) string { return llmsText })
	return s
}

// reply mirrors swarm.reply: head line, optional status and next: actions.
type reply struct {
	status int
	text   string
	next   []doc.Action
}

func (s *svc) send(w http.ResponseWriter, r *http.Request, rep reply) {
	if rep.status == 0 {
		rep.status = http.StatusOK
	}
	doc.TailStatus(w, r, rep.status, rep.text, rep.next...)
}

func unix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

func (s *svc) wake(topic string) { s.d.Notify.Wake(topic) }

func checkWait(wait int) error {
	if wait < 0 || wait > swarm.MaxWait {
		return core.Bad("wait must be 0.." + strconv.Itoa(swarm.MaxWait))
	}
	return nil
}

// checkRange validates an integer option: zero takes the default, otherwise lo..hi.
func checkRange(name string, v, def, lo, hi int) (int, error) {
	if v == 0 {
		v = def
	}
	if v < lo || v > hi {
		return 0, core.Bad(fmt.Sprintf("%s must be %d..%d", name, lo, hi))
	}
	return v, nil
}

func quotaErr(what string, capN int) *core.APIError {
	return core.E(429, "quota", what+" "+strconv.Itoa(capN))
}

func (s *svc) frozen() error {
	if s.d.Frozen("sem") || s.d.Frozen("swarm") || s.d.Frozen("write") {
		return core.Frozen("write")
	}
	return nil
}

// writeOK mirrors core.AuthWrite for ops: token, not banned, no write freeze.
func (s *svc) writeOK(id *core.Ident) error {
	switch {
	case id == nil:
		return core.ErrAuth
	case id.Banned:
		return core.ErrBanned
	case s.d.Frozen("write"):
		return core.Frozen("write")
	}
	return nil
}

// bump adds n to today's (scope, kind) counter and returns the new value.
func bump(ctx context.Context, q core.Q, scope, kind string, n int) (int, error) {
	var cur int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, n).Scan(&cur)
	return cur, err
}

// cleanNote scrubs and caps a handover note (<= 1 KiB), masking tier-2 findings.
func cleanNote(note string) (string, error) {
	note = strings.TrimRight(doc.CleanMulti(scrub.Normalize(note)), "\n ")
	if len(note) > noteMax {
		return "", core.E(413, "size", "note > "+strconv.Itoa(noteMax)+" bytes")
	}
	if note == "" {
		return "", nil
	}
	if _, err := scrub.RejectOrMask(map[string]*string{"note": &note}); err != nil {
		return "", err
	}
	return note, nil
}

// arg decodes an MCP op argument object (empty/null = zero value).
func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(a)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

func queryInt(r *http.Request, name string) (int, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, core.Bad(name + " must be an integer")
	}
	return n, nil
}

func (s *svc) grp(r *http.Request) string { return s.d.IPGroup(r) }

func grpCtx(ctx context.Context) string {
	_, g, _ := core.ClientFrom(ctx)
	return g
}

// eligibleTo reports whether to (id/root) may receive a handover of a name in namespace ns: a: the
// same root tree, s:/r: through the swarm membership seams, g: a live, reliable identity. Returns
// a 409 bad to not live otherwise (27.4 eligibility).
func (s *svc) eligibleTo(ctx context.Context, n swarm.Name, toID, toRoot string) error {
	if !core.ValidIDPrefix(toID, 'a') || !core.ValidIDPrefix(toRoot, 'a') {
		return core.Bad("to: identity id")
	}
	if err := swarm.Access(ctx, s.d.DB, &core.Ident{ID: toID, Root: toRoot}, n, true); err != nil {
		if n.NS == 'a' || n.NS == 's' || n.NS == 'r' {
			return core.E(409, "bad", "to not live")
		}
		return err
	}
	if n.NS == 'g' {
		var seen *time.Time
		if err := s.d.DB.QueryRow(ctx, `SELECT last_seen FROM identities WHERE id = $1 AND parent IS NULL`, toRoot).Scan(&seen); err != nil {
			return core.E(409, "bad", "to not live")
		}
		if seen == nil || time.Since(*seen) > 10*time.Minute || rel(ctx, s.d.DB, toRoot) < 0.5 {
			return core.E(409, "bad", "to not live")
		}
	}
	return nil
}

// foreignHandover charges the giver root one of its <= 10/day foreign-handover budget when the
// recipient belongs to a different root tree (27.4). Same-root handovers are free.
func (s *svc) foreignHandover(ctx context.Context, q core.Q, fromRoot, toRoot string) error {
	if fromRoot == toRoot {
		return nil
	}
	n, err := bump(ctx, q, fromRoot, "sem:foreign", 1)
	if err != nil {
		return err
	}
	if n > foreignCap {
		return quotaErr("foreign handovers", foreignCap)
	}
	return nil
}
