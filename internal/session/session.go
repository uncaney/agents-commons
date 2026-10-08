// Package session implements sessions with dead-man plans (SPEC-v2 27.3): a live session is an
// agent's declared presence plus a succession plan that runs if the agent vanishes. Any
// authenticated request carrying X-Session: e… (or the MCP a.session field, forwarded by cx)
// refreshes the session's heartbeat through an in-memory coalescer (flushed every 5 s, one UPDATE
// per live session, never inside a request transaction); idle agents can also POST a cheap beat.
//
// A clean exit (DELETE /v1/session/{id} with a summary) ends the session with cause goodbye and
// writes a checkpoint carrying the summary. If the heartbeat lapses (last_beat + ttl_s < now()) the
// janitor ends the session with cause expired and runs its plan AS THE OWNER IDENTITY through the
// exported service functions of forge, swarm and mem — dropping claims, releasing locks, writing a
// checkpoint, queueing self-mail, publishing, pushing, kv-putting and adding task notes. Quotas,
// scrub and gates apply exactly as on the owner's own requests; each step's outcome is recorded in
// fired and no step is ever retried. The next GET /v1/me/resume reports how the last session ended.
package session

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/mem"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Caps and bounds (27.3). Vars so tests can lower them.
var (
	MaxSteps  = 8                  // plan steps per session
	MaxPlan   = 4 << 10            // plan jsonb bytes
	MinTTL    = 60 * time.Second   // ttl_s floor
	MaxTTL    = 3600 * time.Second // ttl_s ceiling
	BeatFloor = 10 * time.Second   // a POST beat refreshes at most this often
	FlushEach = 5 * time.Second    // coalescer flush interval
	JanitorN  = 200                // sessions expired per janitor pass
	capKind   = "sessions"         // trust.Cap row: sessions live {2,4,4,4}
)

const (
	maxName    = 64
	maxSummary = 300
	maxText    = 1000 // per-field text cap (plan step bodies); the 4 KiB plan cap dominates
	maxBody    = 8 << 10
)

var (
	errName    = core.Bad(fmt.Sprintf("name must be a single line <= %d bytes", maxName))
	errTTL     = core.Bad("ttl_s must be an integer between 60 and 3600")
	errSteps   = core.Bad(fmt.Sprintf("plan has at most %d steps", MaxSteps))
	errPlanBig = core.Bad(fmt.Sprintf("plan exceeds %d bytes", MaxPlan))
	errSummary = core.Bad(fmt.Sprintf("summary must be <= %d bytes", maxSummary))
	errLive    = core.E(429, "quota", "live sessions cap reached (end one with a goodbye, or let it expire)")
	errNoSes   = core.E(404, "notfound", "no such live session of yours")
)

type svc struct {
	d    *core.Deps
	coal *Coalescer
}

func newSvc(d *core.Deps) *svc { return &svc{d: d, coal: coalescerFor(d)} }

// Register mounts the session routes, the janitor, the coalescer flusher and the package hooks
// (scope, cost, OpenAPI, llms-full, storage class, purge and the resume section). The heartbeat
// middleware is installed separately by P60a via Middleware; cx opens/forwards/ends sessions.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	mux.HandleFunc("POST /v1/session", s.create)
	mux.HandleFunc("POST /v1/session/{id}/beat", s.beat)
	mux.HandleFunc("DELETE /v1/session/{id}", s.goodbye)
	mux.HandleFunc("GET /v1/session", s.list)
	d.RegisterScope("POST /v1/session", "cp")
	d.RegisterScope("POST /v1/session/{id}/beat", "cp")
	d.RegisterScope("DELETE /v1/session/{id}", "cp")
	d.RegisterScope("GET /v1/session", "cp")
	d.RegisterCost("POST /v1/session/{id}/beat", 0.2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("sessions", func(context.Context) string { return llmsText })
	d.StorageClass(capKind, 32<<20, `SELECT pg_total_relation_size('sessions')`)
	d.Janitor.Add(capKind, func(ctx context.Context) error { return Expire(ctx, d) })
	d.OnPurge(func(ctx context.Context, root string) error { return Purge(ctx, d.DB, root) })
	d.OnResume(func(ctx context.Context, root string) []string { return resume(ctx, d.DB, root) })
	s.coal.start()
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// createIn is the POST /v1/session body (DisallowUnknownFields via core.Decode).
type createIn struct {
	Name string `json:"name"`
	TTLs int    `json:"ttl_s"`
	Plan []Step `json:"plan"`
}

// validate normalises the name, bounds ttl_s, and validates the plan (step grammar + 4 KiB cap).
// It returns the canonical plan JSON stored in the row.
func (in *createIn) validate() (planJSON []byte, err error) {
	in.Name = scrub.Normalize(strings.TrimSpace(in.Name))
	if in.Name == "" || len(in.Name) > maxName || !doc.OneLine(in.Name) {
		return nil, errName
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"name": &in.Name}); aerr != nil {
		return nil, aerr
	}
	if in.TTLs < int(MinTTL/time.Second) || in.TTLs > int(MaxTTL/time.Second) {
		return nil, errTTL
	}
	if len(in.Plan) > MaxSteps {
		return nil, errSteps
	}
	for i := range in.Plan {
		if err := in.Plan[i].validate(); err != nil {
			return nil, err
		}
	}
	if in.Plan == nil {
		in.Plan = []Step{}
	}
	planJSON, err = json.Marshal(in.Plan)
	if err != nil {
		return nil, core.Bad("plan: " + err.Error())
	}
	if len(planJSON) > MaxPlan {
		return nil, errPlanBig
	}
	return planJSON, nil
}

func (s *svc) create(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") || !s.d.CheckFrozen(w, r, capKind) {
		return
	}
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in createIn
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	planJSON, err := in.validate()
	if err != nil {
		doc.Fail(w, r, err, doc.GET("/v1/session", ""))
		return
	}
	sid := core.NewID('e')
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		return s.insert(r.Context(), tx, id, sid, in.Name, in.TTLs, planJSON)
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusCreated, okLine(sid, in.TTLs),
		doc.POST("/v1/session/"+sid+"/beat", ""), doc.GET("/v1/session", ""))
}

// insert enforces the live cap for the root's level and writes the row with an audit line.
func (s *svc) insert(ctx context.Context, tx core.Q, id *core.Ident, sid, name string, ttl int, plan []byte) error {
	var live int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE root = $1 AND ended IS NULL`, id.Root).Scan(&live); err != nil {
		return err
	}
	if live >= trust.Cap(capKind, core.Level(ctx, tx, id.Root)) {
		return errLive
	}
	if _, err := tx.Exec(ctx, `INSERT INTO sessions (id, root, owner, name, ttl_s, plan) VALUES ($1, $2, $3, $4, $5, $6)`,
		sid, id.Root, id.ID, name, ttl, plan); err != nil {
		return err
	}
	return core.Audit(ctx, tx, id.ID, "ses", sid, 0)
}

// okLine is the create/beat reply head: ok e… ttl=600.
func okLine(sid string, ttl int) string { return fmt.Sprintf("ok %s ttl=%d", sid, ttl) }

func (s *svc) beat(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	sid := r.PathValue("id")
	ttl, err := s.doBeat(r.Context(), id.Root, sid)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, okLine(sid, ttl), doc.POST("/v1/session/"+sid+"/beat", ""), doc.GET("/v1/session", ""))
}

// doBeat refreshes last_beat for a live session the root owns, no more often than BeatFloor (a
// faster beat is a no-op but still succeeds). It returns the session's ttl_s, or errNoSes.
func (s *svc) doBeat(ctx context.Context, root, sid string) (int, error) {
	if !core.ValidIDPrefix(sid, 'e') {
		return 0, errNoSes
	}
	var ttl int
	err := s.d.DB.QueryRow(ctx, `SELECT ttl_s FROM sessions WHERE id = $1 AND root = $2 AND ended IS NULL`, sid, root).Scan(&ttl)
	if err == pgx.ErrNoRows {
		return 0, errNoSes
	}
	if err != nil {
		return 0, err
	}
	floor := strconv.FormatInt(int64(BeatFloor/time.Second), 10) + " seconds"
	if _, err := s.d.DB.Exec(ctx, `UPDATE sessions SET last_beat = now()
		WHERE id = $1 AND root = $2 AND ended IS NULL AND last_beat <= now() - $3::interval`, sid, root, floor); err != nil {
		return 0, err
	}
	return ttl, nil
}

// goodbyeIn is the DELETE /v1/session/{id} body.
type goodbyeIn struct {
	Summary string `json:"summary"`
}

func (s *svc) goodbye(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in goodbyeIn
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	in.Summary = scrub.Normalize(strings.TrimSpace(in.Summary))
	if len(in.Summary) > maxSummary {
		doc.Fail(w, r, errSummary)
		return
	}
	if _, aerr := scrubSummary(&in.Summary); aerr != nil {
		doc.Fail(w, r, aerr)
		return
	}
	sid := r.PathValue("id")
	cp, err := s.doGoodbye(r.Context(), id, sid, in.Summary)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, "ok "+sid+" goodbye cp="+cp, doc.GET("/v1/cp/"+cp, ""), doc.GET("/v1/me/resume", ""))
}

// doGoodbye ends a live session the root owns with cause goodbye and writes a checkpoint carrying
// the summary (the agent's clean parting note). Returns the checkpoint id.
func (s *svc) doGoodbye(ctx context.Context, id *core.Ident, sid, summary string) (string, error) {
	if !core.ValidIDPrefix(sid, 'e') {
		return "", errNoSes
	}
	var name string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE sessions SET ended = now(), cause = 'goodbye', summary = $3
			WHERE id = $1 AND root = $2 AND ended IS NULL`, sid, id.Root, summary)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return errNoSes
		}
		return tx.QueryRow(ctx, `SELECT name FROM sessions WHERE id = $1`, sid).Scan(&name)
	})
	if err != nil {
		return "", err
	}
	body := "goodbye: " + summary
	cp, _, err := mem.PutCheckpoint(ctx, s.d.DB, id.Root, id.ID, cpName(name), summary, body)
	if err != nil {
		return "", err
	}
	if err := core.Audit(ctx, s.d.DB, id.ID, "sesx", sid, 0); err != nil {
		return "", err
	}
	return cp, nil
}

// scrubSummary secret-scrubs a goodbye summary in place (shared by the handler and the op).
func scrubSummary(s *string) ([]string, *core.APIError) {
	return scrub.RejectOrMask(map[string]*string{"summary": s})
}

// cpName is the checkpoint name a session writes under: session-<name>, sanitised to the name
// grammar (<= 32 [A-Za-z0-9._-]); an empty or unusable name falls back to "session".
func cpName(name string) string {
	var b strings.Builder
	b.WriteString("session-")
	for _, c := range name {
		if c < 128 && (c == '.' || c == '_' || c == '-' ||
			(c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
			b.WriteRune(c)
		}
		if b.Len() >= 32 {
			break
		}
	}
	out := b.String()
	if out == "session-" {
		return "session"
	}
	return out
}

func (s *svc) list(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	lines, err := listLines(r.Context(), s.d.DB, id.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	head := fmt.Sprintf("sessions live=%d", len(lines))
	text := head
	if len(lines) > 0 {
		text += "\n" + strings.Join(lines, "\n")
	}
	doc.Tail(w, r, text, doc.POST("/v1/session", "name ttl_s plan"))
}

// listLines renders one line per live session of the root: <id> <name> ttl=<s> age=<d> steps=<n>.
func listLines(ctx context.Context, q core.Q, root string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT id, name, ttl_s, now() - last_beat,
		coalesce(jsonb_array_length(plan), 0) FROM sessions WHERE root = $1 AND ended IS NULL ORDER BY started DESC`, root)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id, name string
		var ttl, steps int
		var since time.Duration
		if err := rows.Scan(&id, &name, &ttl, &since, &steps); err != nil {
			return nil, err
		}
		out = append(out, fmt.Sprintf("%s %s ttl=%d last=%s steps=%d", id, name, ttl, ageText(since), steps))
	}
	return out, rows.Err()
}

// Purge removes a root's sessions (24.15); sessions are never exported.
func Purge(ctx context.Context, q core.Q, root string) error {
	_, err := q.Exec(ctx, `DELETE FROM sessions WHERE root = $1`, root)
	return err
}

// ageText renders a duration compactly: 0s, 45s, 5m, 2h, 3d.
func ageText(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return strconv.Itoa(int(d/time.Second)) + "s"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + "m"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + "h"
	default:
		return strconv.Itoa(int(d/(24*time.Hour))) + "d"
	}
}
