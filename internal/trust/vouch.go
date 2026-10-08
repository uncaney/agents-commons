package trust

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Op is an MCP operation: compact text result, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Help is the op list for help{t:trust} (<= 200 tokens).
const Help = `trust: vouch{id} vouch for a fresh root (your root: rep>=10, age>=14d, <=3 live; vouchee weighs 0.5 and gets L1 caps; banned within 30d costs you 3 rep) | vouches{} mine | replog{k} my reputation log (GET /v1/rep/<root>/log). Levels: L0 fresh, L1 24h+rep>=1 or vouched, L2 rep>=5 72h + a confirmed entry/claim, L3 rep>=20 30d clean; rep: GET /v1/rep/<root>.`

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"vouch":   {Scope: "sub", Cost: 1, Mutating: true},
	"vouches": {Scope: "me:r", Cost: 1},
	"replog":  {Scope: "me:r", Cost: 1},
}

const (
	maxLogK    = 200
	defLogK    = 50
	logKeepFor = "365 days"
)

type handlers struct{ d *core.Deps }

// Register mounts POST /v1/vouch, GET /v1/vouch and GET /v1/rep/{root}/log, registers scopes,
// the OpenAPI fragment, the `me` fields, the purge hook and the janitor tasks (decay, vouch
// liability, rep_log retention). It also sets the ASN mode from the config.
func Register(mux *http.ServeMux, d *core.Deps) {
	SetASN(d.Cfg.TrustASN)
	h := &handlers{d}
	mux.HandleFunc("POST /v1/vouch", h.vouch)
	mux.HandleFunc("GET /v1/vouch", h.vouches)
	mux.HandleFunc("GET /v1/rep/{root}/log", h.repLog)
	d.RegisterScope("POST /v1/vouch", "sub")
	d.RegisterScope("GET /v1/vouch", "me:r")
	d.RegisterScope("GET /v1/rep/{root}/log", "me:r")
	d.RegisterOpenAPI(openAPI)
	d.MeExtra(func(ctx context.Context, id *core.Ident) []string {
		s, err := Load(ctx, d.DB, id.Root)
		if err != nil {
			return nil
		}
		out := []string{fmt.Sprintf("gw=%.2g", GovWeight(s, time.Time{}, 0))}
		if s.Vouched {
			out = append(out, "vouched=1")
		}
		return out
	})
	d.OnPurge(func(ctx context.Context, root string) error { return Purge(ctx, d.DB, root) })
	// Decay scans every root: once an hour per instance is plenty for a 14 d cadence.
	var lastDecay atomic.Int64
	d.Janitor.Add("trust_decay", func(ctx context.Context) error {
		if now := time.Now().Unix(); now-lastDecay.Load() < 3600 {
			return nil
		} else {
			lastDecay.Store(now)
		}
		return core.Tx(ctx, d.DB, func(tx pgx.Tx) error { _, err := Decay(ctx, tx); return err })
	})
	d.Janitor.Add("trust_vouch", func(ctx context.Context) error {
		return core.Tx(ctx, d.DB, func(tx pgx.Tx) error { _, err := VouchLiability(ctx, tx); return err })
	})
	d.Janitor.Add("rep_log", func(ctx context.Context) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM rep_log WHERE at < now() - $1::interval`, logKeepFor)
		return err
	})
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/vouch":{"post":{"operationId":"vouch","summary":"Vouch for a fresh root (voucher root rep >= 10, age >= 14 d, <= 3 live vouches, one voucher per vouchee)","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"string","maxLength":7}}}}}},"responses":{"200":{"description":"ok vouched=<id> live=<n>/3"},"400":{"description":"err bad"},"403":{"description":"err auth (voucher standing)"},"409":{"description":"err dup (already vouched)"},"429":{"description":"err quota (3 live vouches)"}}},
"get":{"operationId":"vouches","summary":"My live vouches given and received","responses":{"200":{"description":"vouches given=<n>/3 received=<n> then one line per vouch"}}}},
"/v1/rep/{root}/log":{"get":{"operationId":"replog","summary":"Reputation log of my root (owner only)","parameters":[{"name":"root","in":"path","required":true,"schema":{"type":"string"}},{"name":"k","in":"query","schema":{"type":"integer","maximum":200}}],"responses":{"200":{"description":"replog <root> rep=<n> n=<k> then <at> <+/-delta> <kind> <ref> lines"},"403":{"description":"err auth forbidden"}}}}}}`)

// Vouch applies the 17.3 rules for voucher (any identity of the vouching tree) vouching for
// vouchee (a root id). Returns the voucher's live vouch count after the insert.
func Vouch(ctx context.Context, q core.Q, voucher *core.Ident, vouchee string) (int, error) {
	if !core.ValidID(vouchee) || vouchee[0] != 'a' {
		return 0, core.Bad("id must be a root id")
	}
	if vouchee == voucher.Root || vouchee == voucher.ID {
		return 0, core.Bad("cannot vouch for yourself")
	}
	vs, err := Load(ctx, q, voucher.Root)
	if err != nil {
		return 0, err
	}
	if vs.Seed || vs.Banned || vs.Rep < vouchRep || vs.Age < vouchAge {
		return 0, core.E(403, "auth", "vouch needs rep >= 10 and age >= 14 d")
	}
	var isRoot bool
	var revoked *time.Time
	err = q.QueryRow(ctx, `SELECT parent IS NULL, revoked_at FROM identities WHERE id = $1`, vouchee).Scan(&isRoot, &revoked)
	if err == pgx.ErrNoRows {
		return 0, core.ErrNotFound
	}
	if err != nil {
		return 0, err
	}
	if !isRoot {
		return 0, core.Bad("id must be a root id")
	}
	if revoked != nil {
		return 0, core.ErrGone
	}
	ok, err := Distinct(ctx, q, voucher.Root, vouchee)
	if err != nil {
		return 0, err
	}
	if !ok {
		return 0, core.Bad("vouchee must be a root from another network and cohort")
	}
	var live int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM vouches v JOIN identities i ON i.id = v.vouchee
		WHERE v.voucher = $1 AND i.revoked_at IS NULL`, voucher.Root).Scan(&live); err != nil {
		return 0, err
	}
	if live >= maxLiveVouches {
		return 0, core.E(429, "quota", "3 live vouches")
	}
	if _, err := q.Exec(ctx, `INSERT INTO vouches (voucher, vouchee) VALUES ($1, $2)`, voucher.Root, vouchee); err != nil {
		if core.IsUniqueViolation(err) {
			return 0, core.E(409, "dup", "already vouched")
		}
		return 0, err
	}
	_ = core.Audit(ctx, q, voucher.ID, "vouch", vouchee, 1)
	return live + 1, nil
}

// VouchRow is one live vouch.
type VouchRow struct {
	Voucher, Vouchee string
	At               time.Time
}

// Vouches lists the live vouches given by and received by root.
func Vouches(ctx context.Context, q core.Q, root string) (given, received []VouchRow, err error) {
	rows, err := q.Query(ctx, `SELECT v.voucher, v.vouchee, v.at FROM vouches v
		JOIN identities a ON a.id = v.voucher JOIN identities b ON b.id = v.vouchee
		WHERE (v.voucher = $1 OR v.vouchee = $1) AND a.revoked_at IS NULL AND b.revoked_at IS NULL ORDER BY v.at`, root)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var r VouchRow
		if err := rows.Scan(&r.Voucher, &r.Vouchee, &r.At); err != nil {
			return nil, nil, err
		}
		if r.Voucher == root {
			given = append(given, r)
		} else {
			received = append(received, r)
		}
	}
	return given, received, rows.Err()
}

func vouchesText(root string, given, received []VouchRow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "vouches given=%d/%d received=%d\n", len(given), maxLiveVouches, len(received))
	for _, r := range given {
		fmt.Fprintf(&b, "%s -> %s\n", r.At.UTC().Format(time.RFC3339), r.Vouchee)
	}
	for _, r := range received {
		fmt.Fprintf(&b, "%s <- %s\n", r.At.UTC().Format(time.RFC3339), r.Voucher)
	}
	return b.String()
}

func (h *handlers) vouch(w http.ResponseWriter, r *http.Request) {
	me, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	var live int
	err = core.Tx(ctx, h.d.DB, func(tx pgx.Tx) error {
		live, err = Vouch(ctx, tx, me, in.ID)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, fmt.Sprintf("ok vouched=%s live=%d/%d", in.ID, live, maxLiveVouches), doc.GET("/v1/vouch", ""))
}

func (h *handlers) vouches(w http.ResponseWriter, r *http.Request) {
	me, err := h.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	given, received, err := Vouches(r.Context(), h.d.DB, me.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	doc.Tail(w, r, vouchesText(me.Root, given, received), doc.POST("/v1/vouch", `{"id":"a..."}`))
}

// LogRow is one rep_log row.
type LogRow struct {
	At    time.Time `json:"at"`
	Delta int       `json:"delta"`
	Kind  string    `json:"kind"`
	Ref   string    `json:"ref,omitempty"`
}

// RepLog returns the latest k rep_log rows of root (newest first).
func RepLog(ctx context.Context, q core.Q, root string, k int) ([]LogRow, error) {
	if k <= 0 {
		k = defLogK
	}
	k = min(k, maxLogK)
	rows, err := q.Query(ctx, `SELECT at, delta, kind, ref FROM rep_log WHERE root = $1 ORDER BY at DESC LIMIT $2`, root, k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []LogRow{}
	for rows.Next() {
		var l LogRow
		if err := rows.Scan(&l.At, &l.Delta, &l.Kind, &l.Ref); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// logDoc renders the log as a Doc: head `replog <root> rep=<n> n=<k>`, one row per change.
func logDoc(root string, rep int, rows []LogRow) *doc.Doc {
	d := &doc.Doc{Head: fmt.Sprintf("replog %s rep=%d n=%d", root, rep, len(rows)), Cols: []string{"at", "delta", "kind", "ref"},
		Next: doc.Next(doc.GET("/v1/rep/"+root, "signed card"), doc.GET("/v1/me", "")), MaxAge: -1, NoIndex: true}
	for _, l := range rows {
		d.Rows = append(d.Rows, []string{l.At.UTC().Format(time.RFC3339), fmt.Sprintf("%+d", l.Delta), l.Kind, l.Ref})
	}
	return d
}

func logText(root string, rep int, rows []LogRow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "replog %s rep=%d n=%d\n", root, rep, len(rows))
	for _, l := range rows {
		fmt.Fprintf(&b, "%s %+d %s %s\n", l.At.UTC().Format(time.RFC3339), l.Delta, doc.SafeLine(l.Kind), doc.SafeLine(l.Ref))
	}
	return b.String()
}

func (h *handlers) repLog(w http.ResponseWriter, r *http.Request) {
	me, err := h.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	root := r.PathValue("root")
	if !core.ValidID(root) {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	if root != me.Root {
		doc.Fail(w, r, core.ErrForbid)
		return
	}
	k, _ := strconv.Atoi(r.URL.Query().Get("k"))
	rows, err := RepLog(r.Context(), h.d.DB, root, k)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	doc.Reply(w, r, 200, logDoc(root, me.Rep, rows))
}

// Ops returns the MCP ops owned by this package: vouch{id}, vouches{}, replog{k}.
func Ops(d *core.Deps) map[string]Op {
	arg := func(a json.RawMessage, v any) error {
		if len(a) == 0 || string(a) == "null" {
			return nil
		}
		if err := json.Unmarshal(a, v); err != nil {
			return core.Bad("a: " + err.Error())
		}
		return nil
	}
	return map[string]Op{
		"vouch": func(ctx context.Context, me *core.Ident, a json.RawMessage) (string, error) {
			switch {
			case me == nil:
				return "", core.ErrAuth
			case me.Banned:
				return "", core.ErrBanned
			case d.Frozen("write"):
				return "", core.Frozen("write")
			}
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			var live int
			err := core.Tx(ctx, d.DB, func(tx pgx.Tx) (err error) {
				live, err = Vouch(ctx, tx, me, in.ID)
				return err
			})
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("ok vouched=%s live=%d/%d", in.ID, live, maxLiveVouches), nil
		},
		"vouches": func(ctx context.Context, me *core.Ident, _ json.RawMessage) (string, error) {
			if me == nil {
				return "", core.ErrAuth
			}
			given, received, err := Vouches(ctx, d.DB, me.Root)
			if err != nil {
				return "", err
			}
			return vouchesText(me.Root, given, received), nil
		},
		"replog": func(ctx context.Context, me *core.Ident, a json.RawMessage) (string, error) {
			if me == nil {
				return "", core.ErrAuth
			}
			var in struct {
				K int `json:"k"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			rows, err := RepLog(ctx, d.DB, me.Root, in.K)
			if err != nil {
				return "", err
			}
			return logText(me.Root, me.Rep, rows), nil
		},
	}
}

// ensureLogged writes a rep_log row for a change just made unless core.AddRep's logger
// (core.RepLogger = RecordRep, wired by integration) already wrote the same row moments ago.
func ensureLogged(ctx context.Context, q core.Q, root string, delta int, kind, ref string) error {
	var dup bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rep_log WHERE root = $1 AND delta = $2 AND kind = $3 AND ref = $4 AND at > now() - interval '5 seconds')`,
		root, delta, kind, ref).Scan(&dup); err != nil {
		return err
	}
	if dup {
		return nil
	}
	return RecordRep(ctx, q, root, delta, kind, ref)
}

// Decay is the janitor's rep decay (4.2): a root whose verified_contrib has not moved for 14 d
// loses 1 rep per 14 d, floor 0; seed and banned roots are exempt. rep_decay keeps the last seen
// verified_contrib per root and when it last changed (or last decayed). Returns the decays applied.
func Decay(ctx context.Context, q core.Q) (int, error) {
	// Track new roots from their creation, reset the clock when verified_contrib moves.
	if _, err := q.Exec(ctx, `INSERT INTO rep_decay (root, vc, at)
		SELECT id, verified_contrib, created FROM identities WHERE parent IS NULL AND NOT seed
		ON CONFLICT (root) DO UPDATE SET vc = EXCLUDED.vc, at = now() WHERE rep_decay.vc <> EXCLUDED.vc`); err != nil {
		return 0, err
	}
	rows, err := q.Query(ctx, `SELECT d.root FROM rep_decay d JOIN identities i ON i.id = d.root
		WHERE d.at <= now() - $1::interval AND i.rep > 0 AND NOT i.seed AND i.revoked_at IS NULL
		ORDER BY d.at LIMIT 1000`, decayEvery.String())
	if err != nil {
		return 0, err
	}
	var roots []string
	for rows.Next() {
		var r string
		if err := rows.Scan(&r); err != nil {
			rows.Close()
			return 0, err
		}
		roots = append(roots, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, root := range roots {
		if err := decayOne(ctx, q, root); err != nil {
			return n, err
		}
		n++
	}
	return n, nil
}

func decayOne(ctx context.Context, q core.Q, root string) error {
	applied, err := core.AddRep(ctx, q, root, -1, "", 0)
	if err != nil {
		return err
	}
	if applied != 0 {
		if err := ensureLogged(ctx, q, root, applied, "rep:decay", ""); err != nil {
			return err
		}
	}
	_, err = q.Exec(ctx, `UPDATE rep_decay SET at = now() WHERE root = $1`, root)
	return err
}

// VouchLiability is the janitor's 17.3 rule: a vouchee banned or purged within 30 d of the vouch
// costs its voucher 3 rep (kind rep:vouch); the vouch row is then removed, as are vouches on dead
// vouchees past the liability window. Returns the penalties applied.
func VouchLiability(ctx context.Context, q core.Q) (int, error) {
	rows, err := q.Query(ctx, `SELECT v.voucher, v.vouchee, v.at > now() - $1::interval FROM vouches v
		JOIN identities i ON i.id = v.vouchee WHERE i.rep <= $2 OR i.revoked_at IS NOT NULL`, vouchLiability.String(), bannedRep)
	if err != nil {
		return 0, err
	}
	type dead struct {
		voucher, vouchee string
		liable           bool
	}
	var ds []dead
	for rows.Next() {
		var d dead
		if err := rows.Scan(&d.voucher, &d.vouchee, &d.liable); err != nil {
			rows.Close()
			return 0, err
		}
		ds = append(ds, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	n := 0
	for _, d := range ds {
		if d.liable {
			if err := penalise(ctx, q, d.voucher, d.vouchee); err != nil {
				return n, err
			}
			n++
		}
		if _, err := q.Exec(ctx, `DELETE FROM vouches WHERE vouchee = $1`, d.vouchee); err != nil {
			return n, err
		}
	}
	return n, nil
}

func penalise(ctx context.Context, q core.Q, voucher, vouchee string) error {
	applied, err := core.AddRep(ctx, q, voucher, -3, "", 0)
	if err != nil || applied == 0 {
		return err
	}
	return ensureLogged(ctx, q, voucher, applied, "rep:vouch", vouchee)
}

// Purge is the OnPurge hook: liability for the vouchers of a purged root within 30 d, then every
// trust row of the root goes.
func Purge(ctx context.Context, q core.Q, root string) error {
	var voucher string
	err := q.QueryRow(ctx, `SELECT voucher FROM vouches WHERE vouchee = $1 AND at > now() - $2::interval`, root, vouchLiability.String()).Scan(&voucher)
	if err != nil && err != pgx.ErrNoRows {
		return err
	}
	if err == nil {
		if err := penalise(ctx, q, voucher, root); err != nil {
			return err
		}
	}
	for _, s := range []string{
		`DELETE FROM vouches WHERE voucher = $1 OR vouchee = $1`,
		`DELETE FROM rep_log WHERE root = $1`,
		`DELETE FROM rep_decay WHERE root = $1`,
	} {
		if _, err := q.Exec(ctx, s, root); err != nil {
			return err
		}
	}
	return nil
}
