package swarm

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Barriers (12.2): cyclic, rank-giving, with gather. gen is the open generation; every closed
// generation (tripped or expired) has a barrier_gens row so gather replies stay stable.
const (
	brTTLDef   = 600
	brTTLMax   = 3600
	brMaxData  = 1024
	brMaxAllow = 64
)

var errNoBarrier = errors.New("no barrier")

type brIn struct {
	N        int      `json:"n"`
	TTL      int      `json:"ttl_s"`
	Data     string   `json:"data"`
	Distinct bool     `json:"distinct"`
	Allow    []string `json:"allow"`
	Wait     int      `json:"wait"`
}

type barrier struct {
	name    string
	n, gen  int
	ttl     int
	until   time.Time
	owner   string
	bySuper bool
	allow   []string
}

type brOutcome struct {
	gen, rank, k, n int
	closed, tripped bool
	until           time.Time
}

func (s *svc) brLoad(ctx context.Context, q core.Q, name string, lock bool) (barrier, error) {
	b := barrier{name: name}
	sql := `SELECT n, gen, ttl_s, until, owner_root, by_super, allow FROM barriers WHERE name = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	err := q.QueryRow(ctx, sql, name).Scan(&b.n, &b.gen, &b.ttl, &b.until, &b.owner, &b.bySuper, &b.allow)
	if errors.Is(err, pgx.ErrNoRows) {
		return b, errNoBarrier
	}
	return b, err
}

// brCount is the arrival count of the open generation: parties, or distinct super-groups of the
// L1+ parties when the barrier was created with distinct (L0 roots weigh 0).
func (s *svc) brCount(ctx context.Context, q core.Q, b barrier) (int, error) {
	if !b.bySuper {
		var k int
		err := q.QueryRow(ctx, `SELECT count(*) FROM barrier_parties WHERE name = $1 AND gen = $2`, b.name, b.gen).Scan(&k)
		return k, err
	}
	rows, err := q.Query(ctx, `SELECT p.root, coalesce(i.reg_ip, '') FROM barrier_parties p LEFT JOIN identities i ON i.id = p.root
		WHERE p.name = $1 AND p.gen = $2`, b.name, b.gen)
	if err != nil {
		return 0, err
	}
	type party struct{ root, ip string }
	var ps []party
	for rows.Next() {
		var p party
		if err := rows.Scan(&p.root, &p.ip); err != nil {
			rows.Close()
			return 0, err
		}
		ps = append(ps, p)
	}
	rows.Close()
	supers := map[string]struct{}{}
	for _, p := range ps {
		if core.Level(ctx, q, p.root) < 1 {
			continue
		}
		key := "root:" + p.root
		if p.ip != "" {
			key = core.IPSuper(p.ip)
		}
		supers[key] = struct{}{}
	}
	return len(supers), nil
}

// brClose records the outcome of the open generation and opens the next one.
func (s *svc) brClose(ctx context.Context, q core.Q, b barrier, k int, tripped bool) error {
	if _, err := q.Exec(ctx, `INSERT INTO barrier_gens (name, gen, n, k, tripped) VALUES ($1, $2, $3, $4, $5) ON CONFLICT DO NOTHING`,
		b.name, b.gen, b.n, k, tripped); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE barriers SET gen = gen + 1, until = now() + ttl_s * interval '1 second',
		tripped_at = CASE WHEN $2 THEN now() ELSE tripped_at END, expired_at = CASE WHEN $2 THEN expired_at ELSE now() END
		WHERE name = $1`, b.name, tripped)
	return err
}

// brOutcomeOf reads the state of generation gen: closed (tripped or expired, from barrier_gens) or
// the live count of the open generation.
func (s *svc) brOutcomeOf(ctx context.Context, q core.Q, name string, gen, n int) (brOutcome, error) {
	o := brOutcome{gen: gen, n: n}
	err := q.QueryRow(ctx, `SELECT k, tripped FROM barrier_gens WHERE name = $1 AND gen = $2`, name, gen).Scan(&o.k, &o.tripped)
	if err == nil {
		o.closed = true
		return o, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return o, err
	}
	b, err := s.brLoad(ctx, q, name, false)
	if err != nil {
		return o, err
	}
	o.until = b.until
	if b.gen != gen {
		return o, nil
	}
	o.k, err = s.brCount(ctx, q, b)
	return o, err
}

// arrive is POST /v1/br/{name} and op br.
func (s *svc) arrive(ctx context.Context, id *core.Ident, raw string, in brIn, grp string) (reply, error) {
	n, err := ParseName(raw, id.Root)
	if err != nil {
		return reply{}, err
	}
	if in.N != 0 && (in.N < 2 || in.N > 64) {
		return reply{}, core.Bad("n must be 2..64")
	}
	ttl, err := checkRange("ttl_s", in.TTL, brTTLDef, 1, brTTLMax)
	if err != nil {
		return reply{}, err
	}
	if err := checkWait(in.Wait); err != nil {
		return reply{}, err
	}
	if len(in.Allow) > brMaxAllow {
		return reply{}, core.Bad("allow: at most 64 roots")
	}
	for _, a := range in.Allow {
		if !core.ValidIDPrefix(a, 'a') {
			return reply{}, core.Bad("allow: root ids")
		}
	}
	masked, err := cleanText("data", &in.Data, brMaxData)
	if err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, true); err != nil {
		return reply{}, err
	}
	if err := s.frozen("swarm"); err != nil {
		return reply{}, err
	}
	out, err := s.brArriveTx(ctx, id, n, in, ttl)
	if err != nil {
		return reply{}, err
	}
	if out.tripped {
		wake("br:" + n.Full)
	}
	retry := 0
	if !out.closed && in.Wait > 0 {
		retry, err = s.poll(ctx, id, grp, in.Wait, "br:"+n.Full, func(ctx context.Context) (bool, error) {
			o, err := s.brOutcomeOf(ctx, s.d.DB, n.Full, out.gen, out.n)
			if err != nil {
				return false, err
			}
			out.k, out.closed, out.tripped = o.k, o.closed, o.tripped
			if !o.until.IsZero() {
				out.until = o.until
			}
			return o.closed, nil
		})
		if err != nil {
			return reply{}, err
		}
	}
	return brReply(n, out, masked, retry), nil
}

func brReply(n Name, out brOutcome, masked []string, retry int) reply {
	var text string
	switch {
	case out.closed && out.tripped:
		text = fmt.Sprintf("ok gen=%d rank=%d k=%d/%d", out.gen, out.rank, out.k, out.n)
	case out.closed:
		text = fmt.Sprintf("expired %d/%d gen=%d", out.k, out.n, out.gen)
	default:
		text = fmt.Sprintf("wait %d/%d until=%s gen=%d rank=%d", out.k, out.n, unix(out.until), out.gen, out.rank)
	}
	text += maskedField(masked)
	if retry > 0 {
		text += " retry=" + strconv.Itoa(retry)
	}
	p := "/v1/br/" + n.Full
	return reply{text: text, next: []doc.Action{doc.GET(p+"?gen="+strconv.Itoa(out.gen), "gather"), doc.POST(p, "arrive")}}
}

// brArriveTx is the arrival transaction: upsert + lock the barrier, allow list, close a stale
// generation, insert the party (rank = count before, idempotent), count, trip at n.
func (s *svc) brArriveTx(ctx context.Context, id *core.Ident, n Name, in brIn, ttl int) (out brOutcome, err error) {
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		b, err := s.brLoad(ctx, tx, n.Full, true)
		if errors.Is(err, errNoBarrier) {
			if in.N == 0 {
				return core.Bad("n required to create a barrier (2..64)")
			}
			if err := rootLock(ctx, tx, id.Root); err != nil {
				return err
			}
			if err := liveCap(ctx, tx, id.Root, "barriers", `SELECT count(*) FROM barriers WHERE owner_root = $1 AND until > now()`); err != nil {
				return err
			}
			allow := in.Allow
			if allow == nil {
				allow = []string{}
			}
			if _, err := tx.Exec(ctx, `INSERT INTO barriers (name, n, ttl_s, until, owner_root, by_super, allow)
				VALUES ($1, $2, $3::int, now() + $3::int * interval '1 second', $4, $5, $6) ON CONFLICT (name) DO NOTHING`,
				n.Full, in.N, ttl, id.Root, in.Distinct, allow); err != nil {
				return err
			}
			b, err = s.brLoad(ctx, tx, n.Full, true)
		}
		if err != nil {
			return err
		}
		if in.N != 0 && in.N != b.n {
			return core.E(409, "bad", "n="+strconv.Itoa(b.n))
		}
		if len(b.allow) > 0 && id.Root != b.owner && !slices.Contains(b.allow, id.Root) {
			return core.ErrForbid
		}
		if !b.until.After(time.Now()) {
			k, err := s.brCount(ctx, tx, b)
			if err != nil {
				return err
			}
			if k > 0 {
				if err := s.brClose(ctx, tx, b, k, false); err != nil {
					return err
				}
				b.gen++
			} else if _, err := tx.Exec(ctx, `UPDATE barriers SET until = now() + ttl_s * interval '1 second' WHERE name = $1`, b.name); err != nil {
				return err
			}
			b.until = time.Now().Add(time.Duration(b.ttl) * time.Second)
		}
		if _, err := tx.Exec(ctx, `INSERT INTO barrier_parties (name, gen, id, root, rank, data)
			VALUES ($1, $2, $3, $4, (SELECT count(*) FROM barrier_parties WHERE name = $1 AND gen = $2), $5)
			ON CONFLICT (name, gen, id) DO NOTHING`, b.name, b.gen, id.ID, id.Root, in.Data); err != nil {
			return err
		}
		var rank int
		if err := tx.QueryRow(ctx, `SELECT rank FROM barrier_parties WHERE name = $1 AND gen = $2 AND id = $3`, b.name, b.gen, id.ID).Scan(&rank); err != nil {
			return err
		}
		k, err := s.brCount(ctx, tx, b)
		if err != nil {
			return err
		}
		out = brOutcome{gen: b.gen, rank: rank, k: k, n: b.n, until: b.until}
		if k >= b.n {
			if err := s.brClose(ctx, tx, b, k, true); err != nil {
				return err
			}
			out.closed, out.tripped = true, true
		}
		return nil
	})
	return out, err
}

// gather is GET /v1/br/{name}?gen=<g> and op brg: the generation's outcome plus its parties.
func (s *svc) gather(ctx context.Context, id *core.Ident, raw string, gen int, hasGen bool) (reply, error) {
	n, err := ParseName(raw, rootOf(id))
	if err != nil {
		return reply{}, err
	}
	if err := Access(ctx, s.d.DB, id, n, false); err != nil {
		return reply{}, err
	}
	b, err := s.brLoad(ctx, s.d.DB, n.Full, false)
	if errors.Is(err, errNoBarrier) {
		return reply{}, core.ErrNotFound
	}
	if err != nil {
		return reply{}, err
	}
	g := b.gen
	if hasGen {
		g = gen
	}
	if g < 0 || g > b.gen {
		return reply{}, core.ErrNotFound
	}
	o, err := s.brOutcomeOf(ctx, s.d.DB, n.Full, g, b.n)
	if err != nil {
		return reply{}, err
	}
	var sb strings.Builder
	switch {
	case o.closed && o.tripped:
		fmt.Fprintf(&sb, "tripped gen=%d n=%d", g, b.n)
	case o.closed:
		fmt.Fprintf(&sb, "expired gen=%d k=%d/%d", g, o.k, b.n)
	default:
		fmt.Fprintf(&sb, "wait %d/%d gen=%d until=%s", o.k, b.n, g, unix(b.until))
	}
	rows, err := s.d.DB.Query(ctx, `SELECT id, rank, data FROM barrier_parties WHERE name = $1 AND gen = $2 ORDER BY rank, id`, n.Full, g)
	if err != nil {
		return reply{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var pid, data string
		var rank int
		if err := rows.Scan(&pid, &rank, &data); err != nil {
			return reply{}, err
		}
		fmt.Fprintf(&sb, "\n- %s rank=%d", pid, rank)
		if data != "" {
			sb.WriteString(" " + doc.Indent(data))
		}
	}
	p := "/v1/br/" + n.Full
	return reply{text: sb.String(), next: []doc.Action{doc.POST(p, "arrive"), doc.GET(p+"?gen="+strconv.Itoa(b.gen), "current")}}, nil
}

// --- HTTP ---------------------------------------------------------------------------------------

func (s *svc) brArrive(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in brIn
	if err := core.Decode(w, r, bodyMax, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rep, err := s.arrive(r.Context(), id, r.PathValue("name"), in, s.grp(r))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

func (s *svc) brGet(w http.ResponseWriter, r *http.Request) {
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
	rep, err := s.gather(r.Context(), id, r.PathValue("name"), int(gen), hasGen)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.send(w, r, rep)
}

// --- janitor ------------------------------------------------------------------------------------

// janBarriers closes generations past their deadline (stragglers read `expired k/n`), wakes their
// waiters and deletes rows idle for 7 days.
func (s *svc) janBarriers(ctx context.Context) error {
	q := s.d.DB
	rows, err := q.Query(ctx, `SELECT name FROM barriers b WHERE until <= now()
		AND EXISTS (SELECT 1 FROM barrier_parties p WHERE p.name = b.name AND p.gen = b.gen) LIMIT 200`)
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
			b, err := s.brLoad(ctx, tx, name, true)
			if err != nil || b.until.After(time.Now()) {
				return err
			}
			k, err := s.brCount(ctx, tx, b)
			if err != nil {
				return err
			}
			if k == 0 {
				return nil
			}
			return s.brClose(ctx, tx, b, k, false)
		})
		if err != nil && !errors.Is(err, errNoBarrier) {
			return err
		}
		wake("br:" + name)
	}
	for _, st := range []string{
		`DELETE FROM barrier_parties WHERE arrived < now() - interval '7 days'`,
		`DELETE FROM barrier_gens WHERE at < now() - interval '7 days'`,
		`DELETE FROM barriers WHERE until < now() - interval '7 days'`,
	} {
		if _, err := q.Exec(ctx, st); err != nil {
			return err
		}
	}
	return nil
}
