// Package dc implements the swarm quick decisions of SPEC-v2 27.4. A named decision fixes n,
// quorum and 2..8 options (the creator's values bind); identities post one sealed ballot each
// (the first is binding, replays are idempotent); at quorum the ballots are tallied by weight
// (1, or trust.Weight collapsed per super-group when distinct, L0 = 0), ties go to the lowest
// option index, and generations cycle on expiry. Names follow the 12 grammar (g:, ~ / a:<root>.,
// s:<slug>.); g: results are readable anonymously. Ballots are naturally idempotent (INSERT …
// ON CONFLICT DO NOTHING), so the op takes no idempotency key.
package dc

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

const (
	// MaxWait is the long-poll ceiling in seconds (3.6).
	MaxWait  = 85
	bodyMax  = 16 << 10
	ttlDef   = 600
	ttlMax   = 3600
	maxQ     = 200
	maxOpt   = 40
	minOpts  = 2
	maxOpts  = 8
	retryNoW = 5 // retry=<s> appended when a requested wait could not be honoured
	capBytes = 64 << 20
	tieRule  = "tie=lowest-index"
)

var settleSteps = []time.Duration{100 * time.Millisecond, 400 * time.Millisecond}

type svc struct{ d *core.Deps }

// Register mounts the decision routes and hooks (scope br, poll cost, storage class, janitor,
// purge, resume, export, OpenAPI and llms-full).
func Register(mux *http.ServeMux, d *core.Deps) { register(mux, d) }

func register(mux *http.ServeMux, d *core.Deps) *svc {
	s := &svc{d: d}
	mux.HandleFunc("POST /v1/dc/{name}", s.hCast)
	mux.HandleFunc("GET /v1/dc/{name}", s.hGet)
	d.RegisterScope("POST /v1/dc/{name}", "br")
	d.RegisterScope("GET /v1/dc/{name}", "br")
	d.RegisterCost("GET /v1/dc/{name}", 0.2)
	d.StorageClass("decisions", capBytes, `SELECT pg_total_relation_size('decisions') + pg_total_relation_size('decision_gens')
		+ pg_total_relation_size('ballots')`)
	d.Janitor.Add("dc_decisions", s.janitor)
	d.OnPurge(s.purge)
	d.OnResume(s.resume)
	d.OnExport("dc", s.export)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("dc", func(context.Context) string { return llmsText })
	return s
}

// reply is a rendered text document: head line + lines and next: actions.
type reply struct {
	text string
	next []doc.Action
}

func (s *svc) send(w http.ResponseWriter, r *http.Request, rep reply) {
	doc.Tail(w, r, rep.text, rep.next...)
}

func unix(t time.Time) string { return strconv.FormatInt(t.Unix(), 10) }

func itoa(n int) string { return strconv.Itoa(n) }

// fw renders a tallied weight: integers bare, fractions with at most two decimals.
func fw(v float64) string {
	s := strings.TrimRight(strings.TrimRight(strconv.FormatFloat(v, 'f', 2, 64), "0"), ".")
	if s == "" || s == "-0" {
		return "0"
	}
	return s
}

// tok renders an option inside a head line: bare when it is one plain word, quoted otherwise so
// `decided <option>` and `<option>=<n>` stay parseable.
func tok(opt string) string {
	if opt != "" && !strings.ContainsAny(opt, " \"=\\") {
		return opt
	}
	return strconv.Quote(opt)
}

func optionsLine(opts []string) string { return strings.Join(opts, " | ") }

func checkWait(wait int) error {
	if wait < 0 || wait > MaxWait {
		return core.Bad("wait must be 0.." + itoa(MaxWait))
	}
	return nil
}

// checkRange validates an integer option: zero takes the default, otherwise lo..hi.
func checkRange(field string, v, def, lo, hi int) (int, error) {
	if v == 0 {
		v = def
	}
	if v < lo || v > hi {
		return 0, core.Bad(fmt.Sprintf("%s must be %d..%d", field, lo, hi))
	}
	return v, nil
}

// frozen maps a storage-class freeze to its 503.
func (s *svc) frozen(class string) error {
	if s.d.Frozen(class) {
		return core.Frozen(class)
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

// liveCap refuses a new live decision when the root already holds Cap("barriers") of them: live
// decisions share the `live locks / barriers / rendezvous` row of 4.3.
func liveCap(ctx context.Context, q core.Q, root string) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "dc:"+root); err != nil {
		return err
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM decisions WHERE owner_root = $1 AND until > now()`, root).Scan(&n); err != nil {
		return err
	}
	if capN := trust.Cap("barriers", core.Level(ctx, q, root)); n >= capN {
		return core.E(429, "quota", "barriers live "+itoa(capN))
	}
	return nil
}

// cleanOpt makes an option or choice one trimmed line (normalised, control characters dropped,
// whitespace collapsed).
func cleanOpt(s string) string {
	return strings.Join(strings.Fields(doc.SafeLine(scrub.Normalize(s))), " ")
}

// cleanSpec is the write order for the creation payload (4.6, 5): normalise, drop control
// characters, cap sizes, reject tier-1 secrets, mask tier-2 findings, then the lexicon on exactly
// the stored text (score >= 2 refuses, lower scores are rendered as flags:). opts are 2..8 unique
// single-line options <= 40 bytes; q is multi-line <= 200 bytes. Both are rewritten in place.
func cleanSpec(q *string, opts []string) (masked, flags []string, err error) {
	if len(opts) < minOpts || len(opts) > maxOpts {
		return nil, nil, core.Bad("options: 2..8 entries")
	}
	*q = strings.TrimRight(doc.CleanMulti(scrub.Normalize(*q)), "\n ")
	fields := map[string]*string{"q": q}
	for i := range opts {
		opts[i] = cleanOpt(opts[i])
		if opts[i] == "" {
			return nil, nil, core.Bad("options: empty option")
		}
		fields["option"+itoa(i)] = &opts[i]
	}
	if err := specSizes(*q, opts); err != nil {
		return nil, nil, err
	}
	masked, aerr := scrub.RejectOrMask(fields)
	if aerr != nil {
		return nil, nil, aerr
	}
	if err := specSizes(*q, opts); err != nil {
		return nil, nil, err
	}
	score, flags, _ := scrub.Flags(*q + "\n" + strings.Join(opts, "\n"))
	if score >= 2 {
		return nil, nil, core.E(400, "bad", "lexicon "+scrub.FlagsLine(flags))
	}
	return masked, flags, nil
}

func specSizes(q string, opts []string) error {
	if len(q) > maxQ {
		return core.E(413, "size", "q > "+itoa(maxQ)+" bytes")
	}
	for i, o := range opts {
		if len(o) > maxOpt {
			return core.E(413, "size", "option > "+itoa(maxOpt)+" bytes")
		}
		for _, p := range opts[:i] {
			if p == o {
				return core.Bad("options: duplicate " + tok(o))
			}
		}
	}
	return nil
}

func maskedField(kinds []string) string {
	if len(kinds) == 0 {
		return ""
	}
	return " masked=" + strings.Join(kinds, ",")
}

// poll runs check until it reports done, a wake arrives on topic or the wait ends (3.6: tokens
// only, a d.Waiters slot, shed:longpoll); retry is 5 when a wait was asked but not honoured. A
// non-zero hint caps the sleep so a deadline is observed without a wake; writers wake after their
// commit, so an empty re-read after a wake settles briefly first.
func (s *svc) poll(ctx context.Context, id *core.Ident, grp string, wait int, topic string, check func(context.Context) (bool, time.Time, error)) (int, error) {
	done, _, err := check(ctx)
	if err != nil || done || wait == 0 {
		return 0, err
	}
	if id == nil || s.d.Shed(nil, "longpoll") {
		return retryNoW, nil
	}
	release, ok := s.d.Waiters.Acquire(id.Root, grp)
	if !ok {
		return retryNoW, nil
	}
	defer release()
	deadline := time.Now().Add(time.Duration(wait) * time.Second)
	settle := len(settleSteps)
	for {
		c, cancel := s.d.Notify.Subscribe(topic)
		done, hint, err := check(ctx)
		if err != nil || done {
			cancel()
			return 0, err
		}
		rem := time.Until(deadline)
		if rem <= 0 {
			cancel()
			return 0, nil
		}
		if settle < len(settleSteps) {
			rem = min(rem, settleSteps[settle])
			settle++
		}
		if !hint.IsZero() {
			rem = min(rem, max(time.Until(hint)+50*time.Millisecond, 20*time.Millisecond))
		}
		t := time.NewTimer(rem)
		select {
		case <-c:
			settle = 0
		case <-t.C:
		case <-ctx.Done():
			t.Stop()
			cancel()
			return 0, nil
		}
		t.Stop()
		cancel()
	}
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

func queryInt64(r *http.Request, field string) (int64, bool, error) {
	v := r.URL.Query().Get(field)
	if v == "" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false, core.Bad(field + " must be a non-negative integer")
	}
	return n, true, nil
}

func grpCtx(ctx context.Context) string {
	_, g, _ := core.ClientFrom(ctx)
	return g
}

// --- hooks -------------------------------------------------------------------------------------

// purge erases the root's ballots and the decisions it owns (OnPurge).
func (s *svc) purge(ctx context.Context, root string) error {
	for _, st := range []string{
		`DELETE FROM ballots WHERE root = $1`,
		`DELETE FROM ballots WHERE name IN (SELECT name FROM decisions WHERE owner_root = $1)`,
		`DELETE FROM decision_gens WHERE name IN (SELECT name FROM decisions WHERE owner_root = $1)`,
		`DELETE FROM decisions WHERE owner_root = $1`,
	} {
		if _, err := s.d.DB.Exec(ctx, st, root); err != nil {
			return err
		}
	}
	return nil
}

// resume lists the root's open decisions (OnResume).
func (s *svc) resume(ctx context.Context, root string) []string {
	rows, err := s.d.DB.Query(ctx, `SELECT name, gen, until FROM decisions WHERE owner_root = $1 AND decided IS NULL AND until > now()
		ORDER BY until LIMIT 10`, root)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		var gen int
		var until time.Time
		if rows.Scan(&n, &gen, &until) == nil {
			out = append(out, fmt.Sprintf("decision %s pending gen=%d until=%s", n, gen, unix(until)))
		}
	}
	return out
}

// export writes the root's decisions and ballots as JSON lines (OnExport "dc").
func (s *svc) export(ctx context.Context, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	rows, err := s.d.DB.Query(ctx, `SELECT name, n, quorum, q, options, by_super, gen, decided, created FROM decisions WHERE owner_root = $1 ORDER BY name`, root)
	if err != nil {
		return err
	}
	for rows.Next() {
		var name, q string
		var n, quorum, gen int
		var decided *int
		var opts []string
		var bySuper bool
		var created time.Time
		if err := rows.Scan(&name, &n, &quorum, &q, &opts, &bySuper, &gen, &decided, &created); err != nil {
			rows.Close()
			return err
		}
		m := map[string]any{"kind": "decision", "name": name, "n": n, "quorum": quorum, "q": q, "options": opts, "distinct": bySuper, "gen": gen, "created": created.UTC()}
		if decided != nil {
			m["decided"] = *decided
		}
		if err := enc.Encode(m); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	rows, err = s.d.DB.Query(ctx, `SELECT name, gen, id, choice, w, created FROM ballots WHERE root = $1 ORDER BY created LIMIT 5000`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, id string
		var gen, choice int
		var w float64
		var created time.Time
		if err := rows.Scan(&name, &gen, &id, &choice, &w, &created); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "ballot", "name": name, "gen": gen, "id": id, "choice": choice, "w": w, "created": created.UTC()}); err != nil {
			return err
		}
	}
	return rows.Err()
}
