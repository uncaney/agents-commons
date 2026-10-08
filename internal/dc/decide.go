package dc

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

var errNoDecision = errors.New("no decision")

type castIn struct {
	N        int      `json:"n"`
	Quorum   int      `json:"quorum"`
	Q        string   `json:"q"`
	Options  []string `json:"options"`
	Choice   string   `json:"choice"`
	TTL      int      `json:"ttl_s"`
	Distinct bool     `json:"distinct"`
	Wait     int      `json:"wait"`
}

type decision struct {
	name      string
	n, quorum int
	q         string
	options   []string
	ttl       int
	bySuper   bool
	owner     string
	flags     []string
	gen       int
	decided   *int
	until     time.Time
}

// outcome is the state of one generation: pending (open, k < quorum), decided (option index
// >= 0) or expired (closed without a decision).
type outcome struct {
	gen, k, n, quorum int
	closed            bool
	decided           int // option index; -1 while pending or when expired
	weights           []float64
	until             time.Time
	mine              int  // the caller's recorded choice, -1 when none
	changed           bool // this transaction closed a generation (wake the waiters)
}

func (s *svc) load(ctx context.Context, q core.Q, name string, lock bool) (decision, error) {
	d := decision{name: name}
	sql := `SELECT n, quorum, q, options, ttl_s, by_super, owner_root, flags, gen, decided, until FROM decisions WHERE name = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	err := q.QueryRow(ctx, sql, name).Scan(&d.n, &d.quorum, &d.q, &d.options, &d.ttl, &d.bySuper, &d.owner, &d.flags, &d.gen, &d.decided, &d.until)
	if errors.Is(err, pgx.ErrNoRows) {
		return d, errNoDecision
	}
	return d, err
}

// count is the participation of a generation: ballots, or distinct network keys of the weighted
// (L1+) ballots when the decision collapses per super-group.
func (s *svc) count(ctx context.Context, q core.Q, d decision, gen int) (int, error) {
	sql := `SELECT count(*) FROM ballots b WHERE b.name = $1 AND b.gen = $2`
	if d.bySuper {
		sql = `SELECT count(DISTINCT ` + trust.NetKeySQL("b") + `) FROM ballots b WHERE b.name = $1 AND b.gen = $2 AND b.w > 0`
	}
	var k int
	err := q.QueryRow(ctx, sql, d.name, gen).Scan(&k)
	return k, err
}

// tally sums the ballot weights per option index: every ballot of a plain decision (w = 1), or
// the heaviest ballot of each network key (DISTINCT ON the super-group, deterministic order) of a
// distinct one.
func (s *svc) tally(ctx context.Context, q core.Q, d decision, gen int) ([]float64, error) {
	sql := `SELECT choice, sum(w) FROM ballots WHERE name = $1 AND gen = $2 GROUP BY choice`
	if d.bySuper {
		sql = `SELECT choice, sum(w) FROM (SELECT DISTINCT ON (nk) choice, w FROM (SELECT b.choice, b.w, b.created, b.id, ` + trust.NetKeySQL("b") + ` AS nk
			FROM ballots b WHERE b.name = $1 AND b.gen = $2 AND b.w > 0) x ORDER BY nk, w DESC, created, id) c GROUP BY choice`
	}
	rows, err := q.Query(ctx, sql, d.name, gen)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	w := make([]float64, len(d.options))
	for rows.Next() {
		var c int
		var v float64
		if err := rows.Scan(&c, &v); err != nil {
			return nil, err
		}
		if c >= 0 && c < len(w) {
			w[c] = v
		}
	}
	return w, rows.Err()
}

// winner is the index of the heaviest option; ties keep the lowest index.
func winner(w []float64) int {
	best := 0
	for i := 1; i < len(w); i++ {
		if w[i] > w[best] {
			best = i
		}
	}
	return best
}

// weight is the ballot weight of root (1 for a plain decision, trust.Weight with L0 = 0 for a
// distinct one) and its super-group key: the root's registration network, or root:<id> when it
// is unknown so unknown roots never collapse together.
func (s *svc) weight(ctx context.Context, q core.Q, root string, bySuper bool) (float64, string, error) {
	st, err := trust.Load(ctx, q, root)
	if err != nil {
		return 0, "", err
	}
	super := st.Super
	if super == "" {
		super = "root:" + root
	}
	switch {
	case !bySuper:
		return 1, super, nil
	case st.Level() < 1:
		return 0, super, nil
	}
	return trust.Weight(st), super, nil
}

// closeGen records a generation (decided keeps its row from decide; expired writes one) and
// opens the next one.
func (s *svc) closeGen(ctx context.Context, q core.Q, d decision, k int) error {
	if _, err := q.Exec(ctx, `INSERT INTO decision_gens (name, gen, k) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, d.name, d.gen, k); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE decisions SET gen = gen + 1, decided = NULL, decided_at = NULL,
		until = now() + ttl_s * interval '1 second' WHERE name = $1`, d.name)
	return err
}

// decide tallies the open generation at quorum: the row keeps the winner until its deadline and
// the generation record makes the result stable afterwards.
func (s *svc) decide(ctx context.Context, q core.Q, d decision, k int) (outcome, error) {
	weights, err := s.tally(ctx, q, d, d.gen)
	if err != nil {
		return outcome{}, err
	}
	win := winner(weights)
	if _, err := q.Exec(ctx, `UPDATE decisions SET decided = $2, decided_at = now() WHERE name = $1`, d.name, win); err != nil {
		return outcome{}, err
	}
	if _, err := q.Exec(ctx, `INSERT INTO decision_gens (name, gen, k, decided, weights) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
		d.name, d.gen, k, win, weights); err != nil {
		return outcome{}, err
	}
	return outcome{gen: d.gen, k: k, n: d.n, quorum: d.quorum, closed: true, decided: win, weights: weights, until: d.until, mine: -1, changed: true}, nil
}

// outcomeOf reads generation gen: its record when closed, else the live count; the open
// generation past its deadline with ballots reads as expired before the janitor records it.
func (s *svc) outcomeOf(ctx context.Context, q core.Q, d decision, gen int) (outcome, error) {
	o := outcome{gen: gen, n: d.n, quorum: d.quorum, decided: -1, mine: -1, until: d.until}
	var dec *int
	err := q.QueryRow(ctx, `SELECT k, decided, weights FROM decision_gens WHERE name = $1 AND gen = $2`, d.name, gen).Scan(&o.k, &dec, &o.weights)
	if err == nil {
		o.closed = true
		if dec != nil {
			o.decided = *dec
		}
		return o, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return o, err
	}
	if o.k, err = s.count(ctx, q, d, gen); err != nil {
		return o, err
	}
	if gen != d.gen || (o.k > 0 && !d.until.After(time.Now())) {
		o.closed = true
	}
	return o, nil
}

func (s *svc) mine(ctx context.Context, q core.Q, name string, gen int, id string) (int, error) {
	var c int
	err := q.QueryRow(ctx, `SELECT choice FROM ballots WHERE name = $1 AND gen = $2 AND id = $3`, name, gen, id).Scan(&c)
	if errors.Is(err, pgx.ErrNoRows) {
		return -1, nil
	}
	return c, err
}

// head renders the first line: `pending k/n quorum=<q> until=<unix>` | `decided <option> votes
// a=2 b=1 gen=<g>` | `expired k/n quorum=<q> gen=<g>`, then the appended fields (gen, the tie
// rule printed on every open or decided reply, mine=, flags:).
func head(d decision, o outcome) string {
	var b strings.Builder
	switch {
	case o.closed && o.decided >= 0 && o.decided < len(d.options):
		fmt.Fprintf(&b, "decided %s votes", tok(d.options[o.decided]))
		for i, opt := range d.options {
			var w float64
			if i < len(o.weights) {
				w = o.weights[i]
			}
			fmt.Fprintf(&b, " %s=%s", tok(opt), fw(w))
		}
		fmt.Fprintf(&b, " gen=%d %s", o.gen, tieRule)
	case o.closed:
		fmt.Fprintf(&b, "expired %d/%d quorum=%d gen=%d", o.k, o.n, o.quorum, o.gen)
	default:
		fmt.Fprintf(&b, "pending %d/%d quorum=%d until=%s gen=%d %s", o.k, o.n, o.quorum, unix(o.until), o.gen, tieRule)
	}
	if o.mine >= 0 && o.mine < len(d.options) {
		b.WriteString(" mine=" + tok(d.options[o.mine]))
	}
	if len(d.flags) > 0 {
		b.WriteString(" flags:" + scrub.FlagsLine(d.flags))
	}
	return b.String()
}

// cast is POST /v1/dc/{name} and op dc: upsert, one sealed ballot (first binding), count, tally at
// quorum, optional long-poll until the generation closes.
func (s *svc) cast(ctx context.Context, id *core.Ident, raw string, in castIn, grp string) (reply, error) {
	n, err := parseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if in.N != 0 && (in.N < 2 || in.N > 64) {
		return reply{}, core.Bad("n must be 2..64")
	}
	if in.Quorum < 0 || in.Quorum > 64 || (in.N != 0 && in.Quorum > in.N) {
		return reply{}, core.Bad("quorum must be 1..n")
	}
	ttl, err := checkRange("ttl_s", in.TTL, ttlDef, 1, ttlMax)
	if err != nil {
		return reply{}, err
	}
	if err := checkWait(in.Wait); err != nil {
		return reply{}, err
	}
	var masked, flags []string
	if len(in.Options) > 0 {
		if masked, flags, err = cleanSpec(&in.Q, in.Options); err != nil {
			return reply{}, err
		}
	} else if len(in.Q) > maxQ {
		return reply{}, core.E(413, "size", "q > "+itoa(maxQ)+" bytes")
	}
	choice := cleanOpt(in.Choice)
	if len(choice) > maxOpt {
		return reply{}, core.Bad("choice: the text of one option (<= 40 bytes)")
	}
	if err := access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if err := s.frozen("decisions"); err != nil {
		return reply{}, err
	}
	d, out, err := s.castTx(ctx, id, n, in, ttl, choice, flags)
	if err != nil {
		return reply{}, err
	}
	if out.changed {
		s.d.Notify.Wake("dc:" + n.full)
	}
	retry := 0
	if !out.closed && in.Wait > 0 {
		mine := out.mine
		retry, err = s.poll(ctx, id, grp, in.Wait, "dc:"+n.full, func(ctx context.Context) (bool, time.Time, error) {
			cur, err := s.load(ctx, s.d.DB, n.full, false)
			if err != nil {
				return false, time.Time{}, err
			}
			o, err := s.outcomeOf(ctx, s.d.DB, cur, out.gen)
			if err != nil {
				return false, time.Time{}, err
			}
			o.mine = mine
			out = o
			var hint time.Time
			if cur.gen == out.gen {
				hint = cur.until
			}
			return o.closed, hint, nil
		})
		if err != nil {
			return reply{}, err
		}
	}
	text := head(d, out) + maskedField(masked)
	if retry > 0 {
		text += " retry=" + itoa(retry)
	}
	p := "/v1/dc/" + n.full
	return reply{text: text, next: []doc.Action{doc.GET(p+"?gen="+itoa(out.gen), "result"), doc.POST(p, "cast")}}, nil
}

// castTx is the ballot transaction: upsert + lock the decision (the creator fixes n, quorum and
// options), cycle a generation past its deadline, insert the ballot (first binding), count and
// decide at quorum. A decided generation answers its result without taking new ballots.
func (s *svc) castTx(ctx context.Context, id *core.Ident, n name, in castIn, ttl int, choice string, flags []string) (d decision, out outcome, err error) {
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		d, err = s.load(ctx, tx, n.full, true)
		if errors.Is(err, errNoDecision) {
			if in.N == 0 {
				return core.Bad("n required to create a decision (2..64)")
			}
			if len(in.Options) == 0 {
				return core.Bad("options required to create a decision (2..8 x <= 40 bytes)")
			}
			quorum := in.Quorum
			if quorum == 0 {
				quorum = in.N
			}
			if err := liveCap(ctx, tx, id.Root); err != nil {
				return err
			}
			if flags == nil {
				flags = []string{}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO decisions (name, n, quorum, q, options, ttl_s, by_super, owner_root, flags, until)
				VALUES ($1, $2, $3, $4, $5, $6::int, $7, $8, $9, now() + $6::int * interval '1 second') ON CONFLICT (name) DO NOTHING`,
				n.full, in.N, quorum, in.Q, in.Options, ttl, in.Distinct, id.Root, flags); err != nil {
				return err
			}
			d, err = s.load(ctx, tx, n.full, true)
		}
		if err != nil {
			return err
		}
		if in.N != 0 && in.N != d.n {
			return core.E(409, "bad", "n="+itoa(d.n))
		}
		if in.Quorum != 0 && in.Quorum != d.quorum {
			return core.E(409, "bad", "quorum="+itoa(d.quorum))
		}
		if len(in.Options) > 0 && !slices.Equal(in.Options, d.options) {
			return core.E(409, "bad", "options="+optionsLine(d.options))
		}
		if !d.until.After(time.Now()) {
			k, err := s.count(ctx, tx, d, d.gen)
			if err != nil {
				return err
			}
			if d.decided != nil || k > 0 {
				if err := s.closeGen(ctx, tx, d, k); err != nil {
					return err
				}
				d.gen++
				d.decided = nil
				out.changed = true
			} else if _, err := tx.Exec(ctx, `UPDATE decisions SET until = now() + ttl_s * interval '1 second' WHERE name = $1`, d.name); err != nil {
				return err
			}
			d.until = time.Now().Add(time.Duration(d.ttl) * time.Second)
		}
		if d.decided != nil {
			o, err := s.outcomeOf(ctx, tx, d, d.gen)
			if err != nil {
				return err
			}
			o.changed = out.changed
			out = o
			out.mine, err = s.mine(ctx, tx, d.name, d.gen, id.ID)
			return err
		}
		if choice != "" {
			idx := slices.Index(d.options, choice)
			if idx < 0 {
				return core.Bad("choice must be one of: " + optionsLine(d.options))
			}
			w, super, err := s.weight(ctx, tx, id.Root, d.bySuper)
			if err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `INSERT INTO ballots (name, gen, id, root, choice, w, ip_super) VALUES ($1, $2, $3, $4, $5, $6, $7)
				ON CONFLICT (name, gen, id) DO NOTHING`, d.name, d.gen, id.ID, id.Root, idx, w, super); err != nil {
				return err
			}
		}
		mine, err := s.mine(ctx, tx, d.name, d.gen, id.ID)
		if err != nil {
			return err
		}
		k, err := s.count(ctx, tx, d, d.gen)
		if err != nil {
			return err
		}
		changed := out.changed
		if k >= d.quorum {
			if out, err = s.decide(ctx, tx, d, k); err != nil {
				return err
			}
		} else {
			out = outcome{gen: d.gen, k: k, n: d.n, quorum: d.quorum, decided: -1, until: d.until}
		}
		out.mine, out.changed = mine, changed || out.changed
		return nil
	})
	return d, out, err
}

// get is GET /v1/dc/{name}?gen=<g> and op dcg: the generation's state, the question and the
// options; ballots are listed only once the generation is decided.
func (s *svc) get(ctx context.Context, id *core.Ident, raw string, gen int, hasGen bool) (reply, error) {
	n, err := parseName(raw, rootOf(id))
	if err != nil {
		return reply{}, err
	}
	if err := access(ctx, s.d.DB, id, n, false); err != nil {
		return reply{}, err
	}
	d, err := s.load(ctx, s.d.DB, n.full, false)
	if errors.Is(err, errNoDecision) {
		return reply{}, core.ErrNotFound
	}
	if err != nil {
		return reply{}, err
	}
	g := d.gen
	if hasGen {
		g = gen
	}
	if g < 0 || g > d.gen {
		return reply{}, core.ErrNotFound
	}
	o, err := s.outcomeOf(ctx, s.d.DB, d, g)
	if err != nil {
		return reply{}, err
	}
	if id != nil {
		if o.mine, err = s.mine(ctx, s.d.DB, d.name, g, id.ID); err != nil {
			return reply{}, err
		}
	}
	var sb strings.Builder
	sb.WriteString(head(d, o))
	if d.q != "" {
		sb.WriteString("\nq: " + doc.Indent(d.q))
	}
	sb.WriteString("\noptions: " + optionsLine(d.options))
	if o.closed && o.decided >= 0 {
		rows, err := s.d.DB.Query(ctx, `SELECT id, choice FROM ballots WHERE name = $1 AND gen = $2 ORDER BY created, id`, d.name, g)
		if err != nil {
			return reply{}, err
		}
		defer rows.Close()
		for rows.Next() {
			var bid string
			var c int
			if err := rows.Scan(&bid, &c); err != nil {
				return reply{}, err
			}
			opt := "?"
			if c >= 0 && c < len(d.options) {
				opt = d.options[c]
			}
			fmt.Fprintf(&sb, "\n- %s %s", bid, doc.SafeLine(opt))
		}
	}
	p := "/v1/dc/" + n.full
	return reply{text: sb.String(), next: []doc.Action{doc.POST(p, "cast"), doc.GET(p+"?gen="+itoa(d.gen), "current")}}, nil
}

// --- HTTP ---------------------------------------------------------------------------------------

func (s *svc) hCast(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in castIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.cast(r.Context(), id, r.PathValue("name"), in, s.d.IPGroup(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) hGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	gen, hasGen, err := queryInt64(r, "gen")
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.get(r.Context(), id, r.PathValue("name"), int(gen), hasGen)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

// --- janitor ------------------------------------------------------------------------------------

// janitor closes generations past their deadline (pending ones with ballots expire once, decided
// ones cycle), wakes their waiters and prunes rows idle for 7 days.
func (s *svc) janitor(ctx context.Context) error {
	q := s.d.DB
	rows, err := q.Query(ctx, `SELECT name FROM decisions d WHERE until <= now() AND (decided IS NOT NULL
		OR EXISTS (SELECT 1 FROM ballots b WHERE b.name = d.name AND b.gen = d.gen)) LIMIT 200`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	for _, name := range names {
		err := core.Tx(ctx, q, func(tx pgx.Tx) error {
			d, err := s.load(ctx, tx, name, true)
			if err != nil || d.until.After(time.Now()) {
				return err
			}
			k, err := s.count(ctx, tx, d, d.gen)
			if err != nil {
				return err
			}
			if d.decided == nil && k == 0 {
				return nil
			}
			return s.closeGen(ctx, tx, d, k)
		})
		if err != nil && !errors.Is(err, errNoDecision) {
			return err
		}
		s.d.Notify.Wake("dc:" + name)
	}
	for _, st := range []string{
		`DELETE FROM ballots WHERE created < now() - interval '7 days'`,
		`DELETE FROM decision_gens WHERE at < now() - interval '7 days'`,
		`DELETE FROM decisions WHERE until < now() - interval '7 days'`,
	} {
		if _, err := q.Exec(ctx, st); err != nil {
			return err
		}
	}
	return nil
}
