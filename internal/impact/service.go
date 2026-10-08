package impact

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/spaces"
)

// Op is an MCP operation (compact text, *core.APIError on failure).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the impact ops for the MCP registry (3.5): sdr is a member-only mutating-cost
// dry run (it charges a 20/day counter) that writes nothing.
var OpMeta = map[string]core.OpMeta{
	"sdr": {Scope: "gov", Cost: 1, Mutating: true},
}

const (
	dryrunPerDay = 20 // POST .../rules/dryrun per member per day (27.5)
	maxPatch     = 16 << 10
)

var slugRe = regexp.MustCompile(`^[a-z0-9-]{3,32}$`)

type svc struct{ d *core.Deps }

// seams guards the one-time wiring of the gov hooks (process-wide); Register runs once in production
// and many times across tests.
var seams sync.Once

// Register wires the impact seams into gov (propose/applied hooks, the /p/<id> lines and the
// /gov/stats counters), mounts POST /v1/s/{slug}/rules/dryrun, registers its scope and OpenAPI, and
// schedules the +30 d outcome janitor. It edits no other package's routes.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}
	seams.Do(func() {
		// propose-time impact + drastic tagging (chained, nil-safe).
		prevPropose := gov.ProposeHookFn
		gov.ProposeHookFn = func(ctx context.Context, q core.Q, p *gov.Proposal) error {
			if prevPropose != nil {
				if err := prevPropose(ctx, q, p); err != nil {
					return err
				}
			}
			return OnPropose(ctx, q, p)
		}
		// apply-time outcome snapshot (chained, nil-safe).
		prevApplied := gov.AppliedHookFn
		gov.AppliedHookFn = func(ctx context.Context, q core.Q, p *gov.Proposal) error {
			if prevApplied != nil {
				if err := prevApplied(ctx, q, p); err != nil {
					return err
				}
			}
			return OnApplied(ctx, q, p)
		}
		gov.PageExtraFn = append(gov.PageExtraFn, pageLines)
		gov.StatsExtraFn = append(gov.StatsExtraFn, statsLines)
	})

	mux.HandleFunc("POST /v1/s/{slug}/rules/dryrun", s.hDryrun)
	d.RegisterScope("POST /v1/s/{slug}/rules/dryrun", "gov")
	d.RegisterOpenAPI(json.RawMessage(openAPI))
	d.Janitor.Add("impact_outcomes", func(ctx context.Context) error { return RunOutcomes(ctx, d) })
}

// Ops returns the MCP operations: sdr mirrors POST /v1/s/{slug}/rules/dryrun.
func Ops(d *core.Deps) map[string]Op {
	return map[string]Op{
		"sdr": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.E(401, "auth", "auth required")
			}
			var in dryrunArgs
			if err := json.Unmarshal(a, &in); err != nil {
				return "", core.Bad("a: " + err.Error())
			}
			res, err := runDryrun(ctx, d, id.Root, in.Slug, in.Patch)
			if err != nil {
				return "", err
			}
			return res.Line, nil
		},
	}
}

type dryrunArgs struct {
	Slug  string          `json:"slug"`
	Patch json.RawMessage `json:"patch"`
}

// runDryrun gates (member only, 20/day), validates the patch shape, and computes the impact without
// writing anything.
func runDryrun(ctx context.Context, d *core.Deps, root, slug string, patch json.RawMessage) (Result, error) {
	if !slugRe.MatchString(slug) {
		return Result{}, core.ErrNotFound
	}
	member, err := spaces.IsMember(ctx, d.DB, slug, root)
	if err != nil {
		return Result{}, err
	}
	if !member {
		return Result{}, core.E(403, "auth", "members only")
	}
	if err := useDaily(ctx, d.DB, "impact-sdr:"+root, "sdr", dryrunPerDay); err != nil {
		return Result{}, err
	}
	if len(strings.TrimSpace(string(patch))) == 0 {
		return Result{}, core.Bad("patch required")
	}
	if err := spaces.ValidateRules(slug, patch); err != nil {
		return Result{}, err
	}
	return Dryrun(ctx, d.DB, slug, patch)
}

// useDaily charges one unit of a flat daily counter and refuses once it exceeds limit.
func useDaily(ctx context.Context, q core.Q, scope, kind string, limit int) error {
	var n int
	if err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, 1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`, scope, kind).Scan(&n); err != nil {
		return err
	}
	if n > limit {
		return core.E(429, "quota", "dryrun "+itoa(limit)+"/day")
	}
	return nil
}

func (s *svc) hDryrun(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		Patch json.RawMessage `json:"patch"`
	}
	if err := core.Decode(w, r, maxPatch, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := runDryrun(r.Context(), s.d, id.Root, r.PathValue("slug"), in.Patch)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, res.Line, doc.POST("/v1/p", "propose this"), doc.GET("/v1/s/"+r.PathValue("slug"), "space"))
}

// OnPropose is gov.ProposeHookFn: for a space rule, member or template proposal it stores the impact
// line in proposal_impact and tags the proposal `drastic` when the dry run says so (gov then applies
// the 3/4 + 48 h path). It never fails proposal creation on a bad patch — validation already ran.
func OnPropose(ctx context.Context, q core.Q, p *gov.Proposal) error {
	if p == nil || p.Scope == "" || !tracked(p.Kind) {
		return nil
	}
	var res Result
	if p.Kind == "rule" {
		r, err := Dryrun(ctx, q, p.Scope, p.Patch)
		if err != nil {
			var ae *core.APIError
			if !errors.As(err, &ae) {
				return err // a genuine DB error inside the creation tx
			}
			res = Result{Line: "impact: unavailable"}
		} else {
			res = r
		}
	} else {
		// member and template proposals do not change the rules.
		res = Result{Line: "impact: no rule change"}
	}
	if _, err := q.Exec(ctx, `INSERT INTO proposal_impact (pid, impact) VALUES ($1, $2)
		ON CONFLICT (pid) DO UPDATE SET impact = EXCLUDED.impact, at = now()`, p.ID, res.Line); err != nil {
		return err
	}
	if res.Drastic && !hasFlag(p.Flags, "drastic") {
		p.Flags = append(p.Flags, "drastic")
	}
	return nil
}

// pageLines is a gov.PageExtraFn entry: the stored impact line and, once written, the outcome line.
func pageLines(ctx context.Context, q core.Q, pid string) []string {
	var out []string
	var impact string
	if err := q.QueryRow(ctx, `SELECT impact FROM proposal_impact WHERE pid = $1`, pid).Scan(&impact); err == nil && impact != "" {
		out = append(out, impact)
	}
	var beforeRaw, afterRaw []byte
	var reverted bool
	if err := q.QueryRow(ctx, `SELECT before, after, reverted FROM proposal_outcomes WHERE pid = $1 AND written_at IS NOT NULL`,
		pid).Scan(&beforeRaw, &afterRaw, &reverted); err == nil && afterRaw != nil {
		var before, after agg
		_ = json.Unmarshal(beforeRaw, &before)
		_ = json.Unmarshal(afterRaw, &after)
		out = append(out, outcomeLine(before, after, reverted))
	}
	return out
}

// statsLines is a gov.StatsExtraFn entry: reverted rules and drastic passes over 30 days.
func statsLines(ctx context.Context, q core.Q) []string {
	var reverted, drastic int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM proposal_outcomes WHERE reverted AND written_at > now() - interval '30 days'`).Scan(&reverted); err != nil {
		return nil
	}
	if err := q.QueryRow(ctx, `SELECT count(*) FROM proposals WHERE 'drastic' = ANY(flags)
		AND state = 'applied' AND coalesce(applied_at, passed_at) > now() - interval '30 days'`).Scan(&drastic); err != nil {
		return nil
	}
	return []string{"rules_reverted_30d=" + itoa(reverted), "drastic_passed_30d=" + itoa(drastic)}
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

const openAPI = `{"paths":{
"/v1/s/{slug}/rules/dryrun":{"post":{"operationId":"spaceRulesDryrun","summary":"Member only (20/day): dry-run a rules patch over the space's last 30 days and read the impact line (members losing write, posts over the new quotas, docs mode, pins dropped, eligible weight) without any write","parameters":[{"name":"slug","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","properties":{"patch":{"type":"object"}},"required":["patch"]}}}},"responses":{"200":{"description":"impact: … line"},"400":{"description":"err bad rule <detail>"},"403":{"description":"members only"},"429":{"description":"dryrun 20/day"}}}}
}}`
