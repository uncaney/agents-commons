// Package pay implements metered agreements and tips (SPEC-v2 27.4 P97). A payer pre-authorises an
// earned-credit budget on a payee tree (an escrow registered through core.ReserveEarned); the payee
// then draws idempotent per-unit charges against it (each an `earned`/`ag` ledger row paid from the
// escrow) until the ceiling, the deadline or a close by either side, with the remainder refunded on
// close. Tips are a one-shot transferable transfer with daily caps. Everything is L1+, scope bt,
// moves no reputation, and keeps ledger conservation exact.
package pay

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

const (
	minMax, maxMax             = 1, 1000
	minPerCharge, maxPerCharge = 1, 100
	minTTLH, maxTTLH           = 1, 720
	maxRe                      = 80
	maxKey                     = 64
	maxChargeRef               = 80
	acceptWindow               = 24 * time.Hour
	openPerRoot                = 10 // open agreements (offered|open) a payer may hold
	minTip, maxTip             = 1, 50
	tipsPerDay                 = 20
	tipCreditsPerDay           = 200
	maxList                    = 50
	capBytes                   = 64 << 20
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5); every pay op is scope bt.
var OpMeta = map[string]core.OpMeta{
	"ag":  {Scope: "bt", Cost: 1, Mutating: true},
	"aga": {Scope: "bt", Cost: 1, Mutating: true},
	"agc": {Scope: "bt", Cost: 1, Mutating: true},
	"agx": {Scope: "bt", Cost: 1, Mutating: true},
	"agg": {Scope: "bt", Cost: 1},
	"tip": {Scope: "bt", Cost: 1, Mutating: true},
}

// Help is the help{t:pay} text (<= 200 tokens).
const Help = `metered agreements (pre-authorised earned-credit budgets with idempotent per-unit charges) and tips; L1+, no rep. ag{to,max 1..1000,per_charge 1..100,ttl_h 1..720,re,key} -> "ok y… offered" escrows the ceiling and mails the payee | aga{id} payee accepts within 24 h (else auto-close + refund; 1 pending offer per pair) | agc{id,amount,key,ref} (payee tree) charge once per key (replay -> idem=replay), guarded used+amount<=max and amount<=per_charge else 402, paid from the escrow | agx{id} close (either side, remainder refunded) | agg{id} statement (no id -> mine) | tip{to,credits 1..50,re,key} one-shot transfer, 20 tips & 200 credits/day. me/card show earned=N (p2p M) from ledger reasons ag|tip.`

type svc struct {
	d *core.Deps
}

var (
	svcMu sync.Mutex
	svcs  = map[*core.Deps]*svc{}
)

func svcFor(d *core.Deps) *svc {
	svcMu.Lock()
	defer svcMu.Unlock()
	if s, ok := svcs[d]; ok {
		return s
	}
	s := &svc{d: d}
	svcs[d] = s
	return s
}

// Register mounts the agreement and tip routes and the hooks: scopes, costs, OpenAPI, the escrow
// audit expression, storage class, report target ag, resolver y, export, purge, resume, me line and
// the auto-close janitor.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := svcFor(d)
	routes := []struct {
		pat  string
		h    http.HandlerFunc
		cost float64
	}{
		{"POST /v1/ag", s.hCreate, 1},
		{"GET /v1/ag", s.hList, 2},
		{"GET /v1/ag/{id}", s.hGet, 1},
		{"POST /v1/ag/{id}/accept", s.hAccept, 1},
		{"POST /v1/ag/{id}/charge", s.hCharge, 1},
		{"POST /v1/ag/{id}/close", s.hClose, 1},
		{"POST /v1/tip", s.hTip, 1},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, "bt")
		if rt.cost != 1 {
			d.RegisterCost(rt.pat, rt.cost)
		}
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("pay", func(context.Context) string { return llmsText })
	// Credits a live agreement still holds in escrow = its ceiling minus what has been drawn.
	d.OnEscrow(`SELECT coalesce(sum(max - used), 0) FROM agreements WHERE state IN ('offered', 'open')`)
	d.StorageClass("agreements", capBytes, `SELECT pg_total_relation_size('agreements') + pg_total_relation_size('charges')`)
	d.RegisterTarget("ag", core.Target{Exists: exists, Hide: s.hide, Restore: restore})
	d.RegisterResolver('y', s.resolve)
	d.OnExport("agreements", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.OnPurge(s.purge)
	d.OnResume(s.resume)
	d.MeExtra(s.meLine)
	d.Janitor.Add("pay", s.janitor)
}

// --- model ---

type agreement struct {
	ID                   string
	Payer, PayerRoot     string
	PayeeRoot            string
	Max, PerCharge, Used int64
	Until                time.Time
	State                string
	Re                   string
	Created              time.Time
}

const cols = `id, payer, payer_root, payee_root, max, per_charge, used, until, state, re, created`

const liveStates = `('offered', 'open')`

func scan(row pgx.Row) (*agreement, error) {
	var a agreement
	err := row.Scan(&a.ID, &a.Payer, &a.PayerRoot, &a.PayeeRoot, &a.Max, &a.PerCharge, &a.Used, &a.Until, &a.State, &a.Re, &a.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// load reads one agreement; lock takes FOR UPDATE (inside a tx).
func load(ctx context.Context, q core.Q, id string, lock bool) (*agreement, error) {
	if !core.ValidIDPrefix(id, 'y') {
		return nil, core.ErrNotFound
	}
	sql := `SELECT ` + cols + ` FROM agreements WHERE id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	return scan(q.QueryRow(ctx, sql, id))
}

func (a *agreement) live() bool { return a.State == "offered" || a.State == "open" }

// party reports whether root is the payer's or the payee's tree (either may close / read).
func (a *agreement) party(root string) bool {
	return root != "" && (root == a.PayerRoot || root == a.PayeeRoot)
}

func (a *agreement) remainder() int64 { return a.Max - a.Used }

// --- text ---

func (a *agreement) head() string {
	return fmt.Sprintf("%s %s payer=%s payee=%s used=%d/%d per_charge=%d until=%s", a.ID, a.State, a.Payer, a.PayeeRoot, a.Used, a.Max, a.PerCharge, core.Date(a.Until))
}

// text renders the statement: the head plus every charge, oldest first.
func (a *agreement) text(ctx context.Context, q core.Q) string {
	var w strings.Builder
	w.WriteString(a.head() + "\n")
	if a.Re != "" {
		fmt.Fprintf(&w, "re: %s\n", doc.SafeLine(a.Re))
	}
	cs, _ := loadCharges(ctx, q, a.ID)
	fmt.Fprintf(&w, "charges: %d\n", len(cs))
	for _, c := range cs {
		line := fmt.Sprintf("- %s %dcr %s", c.Key, c.Amount, core.Date(c.At))
		if c.Ref != "" {
			line += " ref=" + doc.SafeLine(c.Ref)
		}
		w.WriteString(line + "\n")
	}
	return strings.TrimRight(w.String(), "\n")
}

func (a *agreement) json(ctx context.Context, q core.Q) map[string]any {
	m := map[string]any{"id": a.ID, "payer": a.Payer, "payer_root": a.PayerRoot, "payee_root": a.PayeeRoot,
		"max": a.Max, "per_charge": a.PerCharge, "used": a.Used, "remaining": a.remainder(),
		"until": a.Until.UTC(), "state": a.State, "re": a.Re, "created": a.Created.UTC()}
	cs, _ := loadCharges(ctx, q, a.ID)
	js := make([]map[string]any, 0, len(cs))
	for _, c := range cs {
		js = append(js, map[string]any{"key": c.Key, "amount": c.Amount, "ref": c.Ref, "at": c.At.UTC()})
	}
	m["charges"] = js
	return m
}

func (a *agreement) next() []doc.Action {
	p := "/v1/ag/" + a.ID
	switch a.State {
	case "offered":
		return []doc.Action{doc.POST(p+"/accept", "payee"), doc.POST(p+"/close", "either side"), doc.GET(p, "")}
	case "open":
		return []doc.Action{doc.POST(p+"/charge", "{amount,key,ref}"), doc.POST(p+"/close", "either side"), doc.GET(p, "")}
	}
	return []doc.Action{doc.GET("/v1/ag", "mine")}
}

type charge struct {
	Key    string
	Amount int64
	Ref    string
	At     time.Time
}

func loadCharges(ctx context.Context, q core.Q, id string) ([]charge, error) {
	rows, err := q.Query(ctx, `SELECT key, amount, ref, at FROM charges WHERE agreement = $1 ORDER BY at, key`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []charge
	for rows.Next() {
		var c charge
		if err := rows.Scan(&c.Key, &c.Amount, &c.Ref, &c.At); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// --- hooks ---

func (s *svc) resolve(ctx context.Context, id string) (typ, title, url string, ok bool) {
	a, err := load(ctx, s.d.DB, id, false)
	if err != nil {
		return "", "", "", false
	}
	return "agreement", fmt.Sprintf("%s used=%d/%d payee %s", a.ID, a.Used, a.Max, a.PayeeRoot), "/v1/ag/" + a.ID, true
}

func exists(ctx context.Context, q core.Q, ref string) error {
	_, err := load(ctx, q, ref, false)
	return err
}

// hide closes a live agreement (refunding the remainder) on a moderator hide; a closed one is a
// no-op. The report path passes the pool, so the close runs in its own transaction.
func (s *svc) hide(ctx context.Context, _ core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'y') {
		return core.ErrNotFound
	}
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		a, err := load(ctx, tx, ref, true)
		if err != nil {
			return err
		}
		if !a.live() {
			return nil
		}
		return settleClose(ctx, tx, a, "hidden by moderation")
	})
}

func restore(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'y') {
		return core.ErrNotFound
	}
	_, err := load(ctx, q, ref, false)
	return err
}

// export writes the root's agreements (as payer and as payee) and their charges as JSON lines.
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	rows, err := q.Query(ctx, `SELECT `+cols+` FROM agreements WHERE payer_root = $1 OR payee_root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	var ags []*agreement
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return err
		}
		ags = append(ags, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, a := range ags {
		m := a.json(ctx, q)
		m["kind"] = "agreement"
		if err := enc.Encode(m); err != nil {
			return err
		}
	}
	return nil
}

// resume surfaces offers awaiting this root's acceptance and its open agreements (10.1).
func (s *svc) resume(ctx context.Context, root string) []string {
	var offers, open int
	if err := s.d.DB.QueryRow(ctx, `SELECT
		(SELECT count(*) FROM agreements WHERE payee_root = $1 AND state = 'offered' AND until > now()),
		(SELECT count(*) FROM agreements WHERE payer_root = $1 AND state = 'open')`, root).Scan(&offers, &open); err != nil {
		return nil
	}
	var out []string
	if offers > 0 {
		out = append(out, fmt.Sprintf("agreements: %d offer(s) to accept", offers))
	}
	if open > 0 {
		out = append(out, fmt.Sprintf("agreements: %d open", open))
	}
	return out
}

// meLine renders the escrow held, the open count and `earned=N (p2p M)` from ledger reasons ag|tip
// (3.6, 27.4). N is the root's transferable balance; M is its lifetime p2p income.
func (s *svc) meLine(ctx context.Context, id *core.Ident) []string {
	var p2p int64
	if err := s.d.DB.QueryRow(ctx, `SELECT coalesce(sum(amount), 0) FROM ledger WHERE to_id = $1 AND reason IN ('ag', 'tip')`, id.Root).Scan(&p2p); err != nil {
		return nil
	}
	var open int
	var held int64
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*), coalesce(sum(max - used), 0) FROM agreements WHERE payer_root = $1 AND state IN `+liveStates, id.Root).Scan(&open, &held); err != nil {
		return nil
	}
	out := []string{fmt.Sprintf("earned=%d (p2p %d)", id.Earned, p2p)}
	if open > 0 {
		out = append(out, fmt.Sprintf("ag_escrow=%d agreements=%d", held, open))
	}
	return out
}

// purge closes a root's live agreements (as payer, refunding the remainder) before core deletes it.
func (s *svc) purge(ctx context.Context, root string) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM agreements WHERE payer_root = $1 AND state IN `+liveStates+` ORDER BY created FOR UPDATE`, root)
		if err != nil {
			return err
		}
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			ids = append(ids, id)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		for _, id := range ids {
			a, err := load(ctx, tx, id, true)
			if err != nil {
				return err
			}
			if err := settleClose(ctx, tx, a, "payer purged"); err != nil {
				return err
			}
		}
		return nil
	})
}
