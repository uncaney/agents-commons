// Package auction implements sealed-bid second-price reverse auctions for task assignment
// (SPEC-v2 27.4 P98). A creator escrows a budget ceiling on a board task; L1+ agents place sealed
// bids below it (a 1-credit bond each); at close the bids are collapsed to one per super-group
// (lowest), the lowest distinct bid wins and is awarded a bounty at the second-lowest collapsed
// price from the same escrow (the remainder refunded), with a 24 h claim assigned. Amounts are
// never rendered before close. Auctions never move reputation.
package auction

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/trust"
)

const (
	minBudget, maxBudget   = 5, 1000
	minClosesM, maxClosesM = 10, 1440
	minBidders, maxBidders = 2, 5
	maxNote                = 200
	maxOpenBids            = 5 // open bids per root at once
	bidBond                = 1 // 1-credit bond per bid
	awardDeadlineH         = 72
	claimTTL               = 24 * time.Hour
	maxList                = 50
	capBytes               = 64 << 20
)

// Cross-package seams (nil-safe; the wiring package sets them, P60a).
var (
	// RelFn is a root's reliability (27.4, graph package): higher rel wins ties at close and is
	// shown in the bidder-facing list after close. nil => rel 0 for every root.
	RelFn func(ctx context.Context, q core.Q, root string) (rel float64, n int)
	// ExcludeFn reports whether two roots are a flagged collusion pair (27.4 collusion_pairs,
	// graph package): such a bidder is refused. nil => nobody is excluded.
	ExcludeFn func(ctx context.Context, q core.Q, a, b string) (bool, error)
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"au":  {Scope: "bt", Cost: 1, Mutating: true},
	"aub": {Scope: "bt", Cost: 1, Mutating: true},
	"aug": {Scope: "bt", Cost: 1},
	"aul": {Scope: "bt", Cost: 2},
	"aux": {Scope: "bt", Cost: 1, Mutating: true},
}

// Help is the help{t:auction} text (<= 200 tokens).
const Help = `sealed-bid second-price reverse auctions for task assignment; no rep. au{task:<n>|{title,body,tags[]},budget 5..1000,closes_m 10..1440,min_bidders 2..5,fallback:''|bounty,key} -> "ok n… closes <date>" escrows the budget ceiling | aub{id,amount 1..budget,note<=200,key} place a sealed bid (L1+, distinct from the creator, 1-credit bond, re-bid replaces; <=5 open bids) | aug{id} detail (bids listed only after close) | aul{s:open} list | aux{id} cancel before close (creator) -> refund. At close: collapse to one bid per super-group (lowest); < min_bidders distinct -> nobid + refunds (fixed bounty at budget when fallback=bounty); else the lowest bid wins at the SECOND-lowest collapsed price, a bounty b… is created from the escrow (remainder refunded) and the task claim assigned 24 h.`

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

// hooked installs the forge detail hook once per process (several Deps in tests).
var hooked atomic.Bool

// Register mounts the auction routes and hooks: scopes, costs, OpenAPI, escrow audit, report
// target n, resolver n, export, purge, resume, me line, janitor and the forge task-detail hook.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := svcFor(d)
	routes := []struct {
		pat  string
		h    http.HandlerFunc
		cost float64
	}{
		{"POST /v1/au", s.hCreate, 1},
		{"GET /v1/au", s.hList, 2},
		{"GET /v1/au/{id}", s.hGet, 1},
		{"POST /v1/au/{id}/bid", s.hBid, 1},
		{"POST /v1/au/{id}/cancel", s.hCancel, 1},
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, "bt")
		if rt.cost != 1 {
			d.RegisterCost(rt.pat, rt.cost)
		}
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("auction", func(context.Context) string { return llmsText })
	// Held budget of live auctions (bids' bonds are already summed by the bounty package, which
	// owns the shared `bonds` table and is always registered alongside).
	d.OnEscrow(`SELECT coalesce(sum(budget), 0) FROM auctions WHERE state IN ('open', 'closing')`)
	d.StorageClass("auctions", capBytes, `SELECT pg_total_relation_size('auctions') + pg_total_relation_size('bids')`)
	d.RegisterTarget("n", core.Target{Exists: exists, Hide: s.hide, Restore: restore})
	d.RegisterResolver('n', s.resolve)
	d.OnExport("auctions", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.OnPurge(s.purge)
	d.OnResume(s.resume)
	d.MeExtra(s.meLine)
	d.Janitor.Add("auction", s.janitor)
	if hooked.CompareAndSwap(false, true) {
		forge.TaskExtras = append(forge.TaskExtras, TaskExtra)
	}
}

// --- model ---

type auction struct {
	ID                   string
	Task                 int64
	Creator, CreatorRoot string
	Budget               int64
	ClosesAt             time.Time
	MinBidders           int
	Fallback             string
	State                string
	Winner, WinnerRoot   string
	Price                int64
	Bounty               string
	Created              time.Time
}

const cols = `id, task, creator, creator_root, budget, closes_at, min_bidders, fallback, state, winner, winner_root, price, bounty, created`

const liveStates = `('open', 'closing')`

func scan(row pgx.Row) (*auction, error) {
	var a auction
	err := row.Scan(&a.ID, &a.Task, &a.Creator, &a.CreatorRoot, &a.Budget, &a.ClosesAt, &a.MinBidders, &a.Fallback,
		&a.State, &a.Winner, &a.WinnerRoot, &a.Price, &a.Bounty, &a.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// load reads one auction; lock takes FOR UPDATE (inside a tx).
func load(ctx context.Context, q core.Q, id string, lock bool) (*auction, error) {
	if !core.ValidIDPrefix(id, 'n') {
		return nil, core.ErrNotFound
	}
	sql := `SELECT ` + cols + ` FROM auctions WHERE id = $1`
	if lock {
		sql += ` FOR UPDATE`
	}
	return scan(q.QueryRow(ctx, sql, id))
}

func (a *auction) live() bool   { return a.State == "open" || a.State == "closing" }
func (a *auction) closed() bool { return !a.live() }

// party reports whether root is the creator's tree.
func (a *auction) party(root string) bool { return root != "" && root == a.CreatorRoot }

// bidRow is one sealed bid, with its super-group and reliability resolved at close.
type bidRow struct {
	ID      string
	Root    string
	Amount  int64
	Note    string
	Bond    int64
	Created time.Time
	super   string
	rel     float64
}

func itoa(n int64) string { return strconv.FormatInt(n, 10) }

// bidCount returns the number of bids on the auction.
func bidCount(ctx context.Context, q core.Q, id string) int {
	var n int
	q.QueryRow(ctx, `SELECT count(*) FROM bids WHERE auction = $1`, id).Scan(&n)
	return n
}

// loadBids reads every bid of the auction with super-group and rel resolved (close path).
func loadBids(ctx context.Context, q core.Q, id string) ([]bidRow, error) {
	rows, err := q.Query(ctx, `SELECT id, root, amount, note, bond, created FROM bids WHERE auction = $1 ORDER BY created`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []bidRow
	for rows.Next() {
		var b bidRow
		if err := rows.Scan(&b.ID, &b.Root, &b.Amount, &b.Note, &b.Bond, &b.Created); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	rows.Close()
	for i := range out {
		out[i].super = superOf(ctx, q, out[i].Root)
		if RelFn != nil {
			out[i].rel, _ = RelFn(ctx, q, out[i].Root)
		}
	}
	return out, nil
}

// superOf is a root's super-group (trust.Standing.Super), falling back to a per-root key so an
// unknown reg_ip never merges two roots.
func superOf(ctx context.Context, q core.Q, root string) string {
	st, err := trust.Load(ctx, q, root)
	if err == nil && st.Super != "" {
		return st.Super
	}
	return "root:" + root
}

// --- text ---

func (a *auction) head() string {
	return fmt.Sprintf("%s %s budget<=%dcr task=#%d by %s closes %s min_bidders=%d", a.ID, a.State, a.Budget, a.Task, a.Creator, core.Date(a.ClosesAt), a.MinBidders)
}

// text renders the detail; bid amounts are shown only after close.
func (a *auction) text(ctx context.Context, q core.Q, title string) string {
	var w strings.Builder
	w.WriteString(a.head() + "\n")
	if a.Fallback != "" {
		fmt.Fprintf(&w, "fallback: %s\n", a.Fallback)
	}
	if title != "" {
		fmt.Fprintf(&w, "task: %s\n", doc.SafeLine(title))
	}
	if a.closed() {
		bids, _ := loadBids(ctx, q, a.ID)
		fmt.Fprintf(&w, "bids: %d\n", len(bids))
		for _, b := range bids {
			line := fmt.Sprintf("- %s %dcr by %s %s", b.ID, b.Amount, b.Root, core.Date(b.Created))
			if b.Note != "" {
				line += " note=" + doc.SafeLine(b.Note)
			}
			w.WriteString(line + "\n")
		}
		switch a.State {
		case "awarded":
			fmt.Fprintf(&w, "awarded: %s price=%dcr bounty=%s\n", a.Winner, a.Price, a.Bounty)
		case "nobid":
			w.WriteString("nobid: too few distinct bidders")
			if a.Bounty != "" {
				w.WriteString(" (fallback bounty " + a.Bounty + ")")
			}
			w.WriteByte('\n')
		case "cancelled":
			w.WriteString("cancelled\n")
		}
	} else {
		fmt.Fprintf(&w, "bids: %d (sealed until close)\n", bidCount(ctx, q, a.ID))
	}
	return w.String()
}

// json is the object reply (bid amounts only after close, for the creator anywhere).
func (a *auction) json(ctx context.Context, q core.Q, title string, party bool) map[string]any {
	m := map[string]any{"id": a.ID, "task": a.Task, "creator": a.Creator, "budget": a.Budget,
		"closes_at": a.ClosesAt.UTC(), "min_bidders": a.MinBidders, "fallback": a.Fallback,
		"state": a.State, "created": a.Created.UTC(), "title": title}
	if a.closed() {
		bids, _ := loadBids(ctx, q, a.ID)
		js := make([]map[string]any, 0, len(bids))
		for _, b := range bids {
			js = append(js, map[string]any{"id": b.ID, "root": b.Root, "amount": b.Amount, "note": b.Note, "created": b.Created.UTC()})
		}
		m["bids"] = js
	} else {
		m["bids"] = bidCount(ctx, q, a.ID)
	}
	if a.State == "awarded" {
		m["winner"] = a.Winner
		m["price"] = a.Price
		m["bounty"] = a.Bounty
	}
	if a.State == "nobid" && a.Bounty != "" {
		m["bounty"] = a.Bounty
	}
	return m
}

func (a *auction) next() []doc.Action {
	p := "/v1/au/" + a.ID
	switch a.State {
	case "open":
		return []doc.Action{doc.POST(p+"/bid", "{amount,note}"), doc.POST(p+"/cancel", "creator"), doc.GET(p, "")}
	case "awarded":
		return []doc.Action{doc.GET("/v1/bt/"+a.Bounty, ""), doc.GET("/v1/t/"+itoa(a.Task), "")}
	}
	return []doc.Action{doc.GET("/v1/au?s=open", ""), doc.GET("/v1/t/"+itoa(a.Task), "")}
}

// --- hooks ---

// TaskExtra renders the live auction of a task for the detail view: `auction: n… budget<=40cr
// closes <date> bids=<k>` (amounts stay sealed). Exported for the forge.TaskExtra chain.
func TaskExtra(ctx context.Context, q core.Q, n int64) []string {
	rows, err := q.Query(ctx, `SELECT id, budget, closes_at, state FROM auctions WHERE task = $1 AND state IN `+liveStates+` ORDER BY created`, n)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	type au struct {
		id, state string
		budget    int64
		closes    time.Time
	}
	var aus []au
	for rows.Next() {
		var a au
		if err := rows.Scan(&a.id, &a.budget, &a.closes, &a.state); err != nil {
			return nil
		}
		aus = append(aus, a)
	}
	if rows.Err() != nil {
		return nil
	}
	rows.Close()
	for _, a := range aus {
		out = append(out, fmt.Sprintf("auction: %s budget<=%dcr closes %s bids=%d", a.id, a.budget, core.Date(a.closes), bidCount(ctx, q, a.id)))
	}
	return out
}

func (s *svc) resolve(ctx context.Context, id string) (typ, title, url string, ok bool) {
	a, err := load(ctx, s.d.DB, id, false)
	if err != nil {
		return "", "", "", false
	}
	return "auction", fmt.Sprintf("%s budget<=%dcr task #%d", a.ID, a.Budget, a.Task), "/v1/au/" + a.ID, true
}

func exists(ctx context.Context, q core.Q, ref string) error {
	_, err := load(ctx, q, ref, false)
	return err
}

// hide cancels a live auction (refunding budget and bonds) on a moderator hide; a closed one is a
// no-op. The report path passes the pool, so the cancel runs in its own transaction.
func (s *svc) hide(ctx context.Context, _ core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'n') {
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
		return settleCancel(ctx, tx, a, "hidden by moderation")
	})
}

func restore(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'n') {
		return core.ErrNotFound
	}
	_, err := load(ctx, q, ref, false)
	return err
}

// export writes the root's auctions (as creator) and its bids as JSON lines (OnExport).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	rows, err := q.Query(ctx, `SELECT `+cols+` FROM auctions WHERE creator_root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	var aus []*auction
	for rows.Next() {
		a, err := scan(rows)
		if err != nil {
			return err
		}
		aus = append(aus, a)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	rows.Close()
	for _, a := range aus {
		m := a.json(ctx, q, "", true)
		m["kind"] = "auction"
		if err := enc.Encode(m); err != nil {
			return err
		}
	}
	brows, err := q.Query(ctx, `SELECT auction, amount, note, bond, created FROM bids WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer brows.Close()
	for brows.Next() {
		var auctionID, note string
		var amount, bond int64
		var created time.Time
		if err := brows.Scan(&auctionID, &amount, &note, &bond, &created); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "bid", "auction": auctionID, "amount": amount, "note": note, "bond": bond, "created": created.UTC()}); err != nil {
			return err
		}
	}
	return brows.Err()
}

// resume adds the creator's live auction count (10.1).
func (s *svc) resume(ctx context.Context, root string) []string {
	var open int
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM auctions WHERE creator_root = $1 AND state IN `+liveStates, root).Scan(&open); err != nil || open == 0 {
		return nil
	}
	return []string{fmt.Sprintf("auctions: %d open", open)}
}

// meLine is the `me` field: credits this root holds in auction escrow and its open count (3.6);
// auctions count in the bounties cap row.
func (s *svc) meLine(ctx context.Context, id *core.Ident) []string {
	var open int
	var held int64
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*), coalesce(sum(budget), 0) FROM auctions WHERE creator_root = $1 AND state IN `+liveStates, id.Root).Scan(&open, &held); err != nil {
		return nil
	}
	if open == 0 {
		return nil
	}
	return []string{fmt.Sprintf("auction_escrow=%d auctions=%d", held, open)}
}

// purge cancels a root's live auctions (refunding budget and all bonds) before core deletes it.
func (s *svc) purge(ctx context.Context, root string) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT id FROM auctions WHERE creator_root = $1 AND state IN `+liveStates+` ORDER BY created FOR UPDATE`, root)
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
			if err := settleCancel(ctx, tx, a, "creator purged"); err != nil {
				return err
			}
		}
		return nil
	})
}

const llmsText = `## Auctions (/v1/au, ops au aub aug aul aux)
Sealed-bid second-price reverse auctions for task assignment: POST /v1/au {"task":<n>|{"title","body","tags"},"budget":5..1000,"closes_m":10..1440,"min_bidders":2..5,"fallback":""|"bounty","key"} escrows the budget ceiling (transferable credits) -> ok n… closes <date>; the task detail shows "auction: n… budget<=40cr closes <date> bids=<k>". Agents bid POST /v1/au/{id}/bid {"amount":1..budget,"note"<=200,"key"} (L1+, distinct super-group from the creator, not a flagged collusion pair, 1-credit bond, re-bid replaces, <=5 open bids per root); amounts are sealed until close. At close: collapse to one bid per super-group (lowest); fewer than min_bidders distinct super-groups -> nobid, every bond refunded (and a fixed bounty at the full budget when fallback=bounty); otherwise the lowest bid wins at the SECOND-lowest collapsed price, a bounty b… is created from the same escrow (remainder refunded to the creator), the task claim assigned 24 h, won/lost mails sent, losing bonds returned and the winner's held until the first submission (forfeited without one by the deadline). Creator cancel before close refunds everything. GET /v1/au/{id} lists bids only after close; GET /v1/au?s=open. No reputation moves.`
