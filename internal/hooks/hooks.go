// Package hooks binds catalog services to a space in two post-hoc shapes (SPEC-v2 27.5, P100), both
// funded by the space treasury (0182) and both run through the ordinary catalog/compute path: the
// gateway in this package never executes module code (invariant test: no wazero import here).
//
//   - A write hook (space_hooks, <= 3 per space, one per kind task|kb|doc) runs AFTER a member write
//     lands. The hooks janitor builds a small JSON view of the row, calls the service funded by
//     FundFn, and reads the first line of its stdout: `ok`, `reject <reason>`, or `warn <text>`.
//     A reject hides the row with reason `hook: <reason>` (a 410-gone window counting from the run),
//     mails the author and prints a line on /s/<slug>/log; a warn flags it; anything else leaves it
//     visible (fail open). Established members bypass through only_below. 200 runs/day/space.
//   - A cron (space_cron, <= 2 per space) exports the last 7 days of a source as JSONL, prepends the
//     operator's in_text and the day, runs the service funded by the treasury, and writes the stdout
//     back as a space doc revision, one auto task, or a group-box message. Three consecutive failures
//     disable it. The output passes the same scrub + lexicon + hazard pipeline as a member doc edit.
//
// Both are configured by the governance kinds `hook` and `cron` (space proposals, same window and
// threshold as `rule`), whose validators pin the service to the owner's verified stable version.
// Every string an agent supplies (in_text, a service's stdout, a reject reason) is data, never a
// command to the server.
package hooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
)

// Op is an MCP operation: compact text result, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Limits (27.5). Vars so tests can tighten them.
var (
	MaxHooks      = 3        // write hooks per space
	MaxCrons      = 2        // crons per space
	MaxMsHint     = 2000     // a hooked/cron service's ms_hint ceiling
	MaxMbHint     = 64       // ...mb_hint ceiling
	RunsPerDay    = 200      // hook runs per space per day
	CronFailsOff  = 3        // consecutive cron failures that disable it
	MaxInput      = 64 << 10 // the hook input JSON cap
	MaxOutput     = 16 << 10 // a service's inline stdout cap (compute enforces the same)
	MaxOpenTitles = 50
	GoneWindow    = 24 * time.Hour // a reject's 410-gone window
	hookWait      = 8              // seconds the janitor waits on a hook job
	cronWait      = 20             // ...on a cron job
	exportInline  = 60 << 10       // export small enough to pass as in_text rather than a blob
)

// FundFn charges the space treasury for one service run and reports whether it was covered; it is
// nil-safe (a nil FundFn runs for free) and an uncovered run is marked `unchecked` with a
// `hook-unfunded` event. The integration package points it at treasury.Debit.
var FundFn func(ctx context.Context, q core.Q, slug string, n int64, ref string) (bool, error)

type svc struct{ d *core.Deps }

// Register mounts the read routes (GET /v1/s/{slug}/hooks, /cron), their scopes and OpenAPI, the
// `hook` and `cron` governance kinds, and the two janitors (hooks every few seconds, cron every few
// minutes; the gateway sets the cadence).
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}
	mux.HandleFunc("GET /v1/s/{slug}/hooks", s.hHooks)
	mux.HandleFunc("GET /v1/s/{slug}/cron", s.hCron)
	d.RegisterScope("GET /v1/s/{slug}/hooks", "sp")
	d.RegisterScope("GET /v1/s/{slug}/cron", "sp")
	d.RegisterCost("GET /v1/s/{slug}/hooks", 1)
	d.RegisterCost("GET /v1/s/{slug}/cron", 1)
	d.RegisterOpenAPI(openAPI)

	gov.RegisterScopedKind("hook", "space", s.validateHook, s.applyHook)
	gov.RegisterScopedKind("cron", "space", s.validateCron, s.applyCron)

	d.Janitor.Add("hook_runs", func(ctx context.Context) error { return s.RunHooks(ctx) })
	d.Janitor.Add("hook_recheck", func(ctx context.Context) error { return s.RecheckBindings(ctx) })
	d.Janitor.Add("space_cron", func(ctx context.Context) error { return s.RunCrons(ctx) })
}

// --- the `hook` governance kind ------------------------------------------------------------------

type hookPatch struct {
	Kind      string `json:"kind"`
	Svc       string `json:"svc"`
	OnlyBelow *int   `json:"only_below,omitempty"`
}

var hookKinds = map[string]string{"task": "t", "kb": "kb", "doc": "d"}

func decodeHook(patch json.RawMessage) (hookPatch, error) {
	var in hookPatch
	dec := json.NewDecoder(strings.NewReader(string(patch)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, core.Bad("patch: {kind, svc, only_below}")
	}
	in.Kind = strings.TrimSpace(in.Kind)
	in.Svc = strings.TrimSpace(in.Svc)
	return in, nil
}

// validateHook is the space-scoped `hook` validator: a known kind, a service that is verified and is
// its owner's stable version with ms_hint <= 2000 and mb_hint <= 64, only_below in 0..3, and room
// under the three-hook ceiling (an existing binding of the same kind is a replace, not a new slot).
func (s *svc) validateHook(scope string, patch json.RawMessage) error {
	if scope == "" {
		return core.Bad("hook is a space proposal")
	}
	in, err := decodeHook(patch)
	if err != nil {
		return err
	}
	if _, ok := hookKinds[in.Kind]; !ok {
		return core.Bad("kind must be task, kb or doc")
	}
	if in.OnlyBelow != nil && (*in.OnlyBelow < 0 || *in.OnlyBelow > 3) {
		return core.Bad("only_below 0..3")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.checkServicePinned(ctx, in.Svc); err != nil {
		return err
	}
	var n int
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM space_hooks WHERE space = $1 AND kind <> $2`, scope, in.Kind).Scan(&n); err != nil {
		return err
	}
	if n >= MaxHooks {
		return core.E(409, "quota", fmt.Sprintf("a space has at most %d hooks", MaxHooks))
	}
	return nil
}

// applyHook upserts the binding for its kind, returning the previous binding (or an unbind marker)
// as the revert snapshot.
func (s *svc) applyHook(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
	in, err := decodeHook(p.Patch)
	if err != nil {
		return nil, err
	}
	prev := s.hookPrev(ctx, tx, p.Scope, in.Kind)
	if _, err := tx.Exec(ctx, `INSERT INTO space_hooks (space, kind, svc, only_below) VALUES ($1, $2, $3, $4)
		ON CONFLICT (space, kind) DO UPDATE SET svc = EXCLUDED.svc, only_below = EXCLUDED.only_below, created = now()`,
		p.Scope, in.Kind, in.Svc, in.OnlyBelow); err != nil {
		return nil, err
	}
	if err := gov.ChangelogNote(ctx, tx, p.Scope, fmt.Sprintf("%s hook %s -> %s", p.ID, in.Kind, in.Svc)); err != nil {
		return nil, err
	}
	if err := core.Event(ctx, tx, "hook", "s:"+p.Scope, "", "space "+p.Scope+" hook "+in.Kind+" = "+in.Svc); err != nil {
		return nil, err
	}
	return prev, nil
}

// hookPrev snapshots the current binding of a kind for revert (an empty svc means "unbind").
func (s *svc) hookPrev(ctx context.Context, q core.Q, slug, kind string) json.RawMessage {
	var svc string
	var ob *int
	err := q.QueryRow(ctx, `SELECT svc, only_below FROM space_hooks WHERE space = $1 AND kind = $2`, slug, kind).Scan(&svc, &ob)
	if errors.Is(err, pgx.ErrNoRows) {
		b, _ := json.Marshal(hookPatch{Kind: kind})
		return b
	}
	if err != nil {
		return nil
	}
	b, _ := json.Marshal(hookPatch{Kind: kind, Svc: svc, OnlyBelow: ob})
	return b
}

// --- the `cron` governance kind ------------------------------------------------------------------

type cronPatch struct {
	Idx    int    `json:"idx"`
	Svc    string `json:"svc"`
	EveryH int    `json:"every_h"`
	Src    string `json:"src"`
	To     string `json:"to"`
	InText string `json:"in_text,omitempty"`
}

func decodeCron(patch json.RawMessage) (cronPatch, error) {
	var in cronPatch
	dec := json.NewDecoder(strings.NewReader(string(patch)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, core.Bad("patch: {idx, svc, every_h, src, to, in_text}")
	}
	in.Svc = strings.TrimSpace(in.Svc)
	in.Src = strings.TrimSpace(in.Src)
	in.To = strings.TrimSpace(in.To)
	return in, nil
}

var cronDocRe = regexp.MustCompile(`^[a-z0-9._-]{1,32}$`)

// validateCron is the space-scoped `cron` validator: idx 0..1, every_h 24..168, a known src and to
// (doc:<name> never home/tpl-*/llms), in_text <= 1 KiB, and the pinned-service rule.
func (s *svc) validateCron(scope string, patch json.RawMessage) error {
	if scope == "" {
		return core.Bad("cron is a space proposal")
	}
	in, err := decodeCron(patch)
	if err != nil {
		return err
	}
	if in.Idx < 0 || in.Idx > 1 {
		return core.Bad("idx 0 or 1")
	}
	if in.EveryH < 24 || in.EveryH > 168 {
		return core.Bad("every_h 24..168")
	}
	if err := validSrc(in.Src); err != nil {
		return err
	}
	if err := validTo(in.To); err != nil {
		return err
	}
	if len(in.InText) > 1024 {
		return core.E(413, "size", "in_text <= 1 KiB")
	}
	if !utf8.ValidString(in.InText) || strings.ContainsFunc(in.InText, func(r rune) bool { return r != '\n' && r != '\t' && unicode.IsControl(r) }) {
		return core.Bad("in_text has control characters")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return s.checkServicePinned(ctx, in.Svc)
}

func validSrc(src string) error {
	switch src {
	case "t7d", "kb7d", "log7d", "none":
		return nil
	}
	if name, ok := strings.CutPrefix(src, "doc:"); ok && cronDocRe.MatchString(name) {
		return nil
	}
	return core.Bad("src must be t7d, kb7d, log7d, none or doc:<name>")
}

func validTo(to string) error {
	if to == "t" || to == "mb" {
		return nil
	}
	if name, ok := strings.CutPrefix(to, "doc:"); ok {
		if !cronDocRe.MatchString(name) {
			return core.Bad("to doc:<name>")
		}
		if name == "home" || name == "llms" || strings.HasPrefix(name, "tpl-") {
			return core.Bad("a cron never writes home, tpl-* or llms")
		}
		return nil
	}
	return core.Bad("to must be doc:<name>, t or mb")
}

// applyCron upserts the cron at its idx and schedules its first run, returning the previous row for
// revert.
func (s *svc) applyCron(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
	in, err := decodeCron(p.Patch)
	if err != nil {
		return nil, err
	}
	prev := s.cronPrev(ctx, tx, p.Scope, in.Idx)
	if _, err := tx.Exec(ctx, `INSERT INTO space_cron (space, idx, svc, every_h, src, "to", in_text, next_at, fails, disabled)
		VALUES ($1, $2, $3, $4, $5, $6, $7, now(), 0, false)
		ON CONFLICT (space, idx) DO UPDATE SET svc = EXCLUDED.svc, every_h = EXCLUDED.every_h, src = EXCLUDED.src,
		  "to" = EXCLUDED."to", in_text = EXCLUDED.in_text, next_at = now(), fails = 0, disabled = false, created = now()`,
		p.Scope, in.Idx, in.Svc, in.EveryH, in.Src, in.To, in.InText); err != nil {
		return nil, err
	}
	if err := gov.ChangelogNote(ctx, tx, p.Scope, fmt.Sprintf("%s cron %d %s every %dh -> %s", p.ID, in.Idx, in.Svc, in.EveryH, in.To)); err != nil {
		return nil, err
	}
	if err := core.Event(ctx, tx, "cron", "s:"+p.Scope, "", fmt.Sprintf("space %s cron %d = %s", p.Scope, in.Idx, in.Svc)); err != nil {
		return nil, err
	}
	return prev, nil
}

func (s *svc) cronPrev(ctx context.Context, q core.Q, slug string, idx int) json.RawMessage {
	var c cronPatch
	c.Idx = idx
	err := q.QueryRow(ctx, `SELECT svc, every_h, src, "to", in_text FROM space_cron WHERE space = $1 AND idx = $2`, slug, idx).
		Scan(&c.Svc, &c.EveryH, &c.Src, &c.To, &c.InText)
	if err != nil {
		b, _ := json.Marshal(cronPatch{Idx: idx})
		return b
	}
	b, _ := json.Marshal(c)
	return b
}

// checkServicePinned enforces the rule shared by hook and cron: svc must be "name@ver", that version
// must be the service's current stable version, verified and not failing, with ms_hint <= 2000 and
// mb_hint <= 64.
func (s *svc) checkServicePinned(ctx context.Context, svcRef string) error {
	name, verStr, ok := strings.Cut(svcRef, "@")
	if !ok || name == "" || verStr == "" {
		return core.Bad("svc must be name@ver (the owner's stable version)")
	}
	ver, err := strconv.Atoi(verStr)
	if err != nil || ver < 1 {
		return core.Bad("svc version")
	}
	v, err := catalog.Stable(ctx, s.d.DB, name)
	if err != nil {
		return err
	}
	if v.Ver != ver {
		return core.E(409, "bad", fmt.Sprintf("svc must pin the stable version %s@%d", name, v.Ver))
	}
	if v.VerifiedAt == nil || v.FailingSince != nil || v.State == "rejected" || v.Hidden {
		return core.E(409, "bad", "svc must be a verified service")
	}
	if v.Manifest.MsHint > MaxMsHint {
		return core.E(409, "bad", fmt.Sprintf("svc ms_hint over %d", MaxMsHint))
	}
	if v.Manifest.MbHint > MaxMbHint {
		return core.E(409, "bad", fmt.Sprintf("svc mb_hint over %d", MaxMbHint))
	}
	return nil
}

// --- HTTP ----------------------------------------------------------------------------------------

func (s *svc) hHooks(w http.ResponseWriter, r *http.Request) {
	if _, err := s.d.Auth(r); err != nil {
		core.Fail(w, r, err)
		return
	}
	slug := r.PathValue("slug")
	text, err := s.hooksText(r.Context(), slug)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, text, doc.GET("/v1/s/"+slug+"/cron", ""), doc.GET("/v1/s/"+slug, ""))
}

func (s *svc) hooksText(ctx context.Context, slug string) (string, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT kind, svc, only_below FROM space_hooks WHERE space = $1 ORDER BY kind`, slug)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var kind, svc string
		var ob *int
		if err := rows.Scan(&kind, &svc, &ob); err != nil {
			return "", err
		}
		l := kind + " " + svc
		if ob != nil {
			l += " only_below=" + strconv.Itoa(*ob)
		}
		lines = append(lines, l)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	head := fmt.Sprintf("hooks %s n=%d", slug, len(lines))
	if len(lines) == 0 {
		return head, nil
	}
	return head + "\n" + strings.Join(lines, "\n"), nil
}

func (s *svc) hCron(w http.ResponseWriter, r *http.Request) {
	if _, err := s.d.Auth(r); err != nil {
		core.Fail(w, r, err)
		return
	}
	slug := r.PathValue("slug")
	text, err := s.cronText(r.Context(), slug)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, text, doc.GET("/v1/s/"+slug+"/hooks", ""), doc.GET("/v1/s/"+slug, ""))
}

func (s *svc) cronText(ctx context.Context, slug string) (string, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT idx, svc, every_h, src, "to", next_at, last_state, fails, disabled
		FROM space_cron WHERE space = $1 ORDER BY idx`, slug)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var lines []string
	for rows.Next() {
		var idx, everyH, fails int
		var svc, src, to, last string
		var nextAt time.Time
		var disabled bool
		if err := rows.Scan(&idx, &svc, &everyH, &src, &to, &nextAt, &last, &fails, &disabled); err != nil {
			return "", err
		}
		l := fmt.Sprintf("%d %s every=%dh src=%s to=%s next=%s", idx, svc, everyH, src, to, core.Date(nextAt))
		if last != "" {
			l += " last=" + last
		}
		if fails > 0 {
			l += " fails=" + strconv.Itoa(fails)
		}
		if disabled {
			l += " disabled"
		}
		lines = append(lines, l)
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	head := fmt.Sprintf("cron %s n=%d", slug, len(lines))
	if len(lines) == 0 {
		return head, nil
	}
	return head + "\n" + strings.Join(lines, "\n"), nil
}

// --- MCP ops -------------------------------------------------------------------------------------

type slugArg struct {
	Slug string `json:"slug"`
}

// Ops are the MCP ops of this package (shk hooks, scron cron). The integration package merges them.
func Ops(d *core.Deps) map[string]Op {
	s := &svc{d: d}
	return map[string]Op{
		"shk": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in slugArg
			if err := arg(a, &in); err != nil {
				return "", err
			}
			return s.hooksText(ctx, in.Slug)
		},
		"scron": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in slugArg
			if err := arg(a, &in); err != nil {
				return "", err
			}
			return s.cronText(ctx, in.Slug)
		},
	}
}

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"shk":   {Scope: "sp", Cost: 1},
	"scron": {Scope: "sp", Cost: 1},
}

func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: bad args")
	}
	return nil
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/s/{slug}/hooks":{"get":{"operationId":"shk","summary":"The write hooks bound to a space (kind svc [only_below])","parameters":[{"name":"slug","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"hooks <slug> n=<k> then one line per hook"}}}},
"/v1/s/{slug}/cron":{"get":{"operationId":"scron","summary":"The scheduled automations of a space (idx svc every src to next)","parameters":[{"name":"slug","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"cron <slug> n=<k> then one line per cron"}}}}}}`)
