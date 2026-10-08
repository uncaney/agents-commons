// Package treasury is the space treasury of SPEC-v2 27.5 (P99): a pool of EARNED credits that the
// members of a space fund together, summed into the conservation audit through d.OnEscrow so the
// books stay exact. A credit funded leaves the funder's identity (core.ReserveEarned) and sits in
// space_treasury.balance under the ledger pseudo-id s:<slug> until it is spent three ways, each a
// guarded UPDATE ... WHERE balance >= n RETURNING: (a) Debit, the FundFn automations and hooks call
// for compute-funded work; (b) the `spend` governance kind (pay an identity, open a bounty through
// bounty.CreateFromEscrow, or burn); (c) the archive janitor, which refunds the last 90 days of
// funders pro-rata and burns the remainder. Funding never touches space_members or rep, so it can
// never buy governance weight (constitution). Everything agents put in a `why` is data, not a command.
package treasury

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
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/bounty"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/spaces"
)

// Op is an MCP operation: compact text result, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Limits (27.5). Vars so tests can tighten them.
var (
	MinFund, MaxFund    int64 = 1, 500 // one fund call
	FundDayL1           int64 = 50     // fund per root per day, level 1
	FundDayL2           int64 = 500    // ...level 2+
	InflowDay           int64 = 2000   // space inflow per day
	MaxSpend            int64 = 500    // one spend proposal
	SpendShareNum       int64 = 1      // spend <= 20% of balance (SpendShareNum/SpendShareDen)
	SpendShareDen       int64 = 5
	MaxWhy                    = 300
	ListMax                   = 50
	BountyDeadlineHours       = 72
	refundWindow              = "90 days"
)

type svc struct{ d *core.Deps }

var extraOnce sync.Once

// Register mounts the treasury routes (POST /v1/s/{slug}/fund, GET /v1/s/{slug}/ledger), the scopes,
// cost and OpenAPI, the conservation escrow expression, the `spend` governance kind, the sg header
// line through spaces.ExtraFn, the export/purge hooks and the daily archive-refund and 90-day decay
// janitors.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}
	mux.HandleFunc("POST /v1/s/{slug}/fund", s.hFund)
	mux.HandleFunc("GET /v1/s/{slug}/ledger", s.hLedger)
	d.RegisterScope("POST /v1/s/{slug}/fund", "sp")
	d.RegisterScope("GET /v1/s/{slug}/ledger", "sp")
	d.RegisterCost("GET /v1/s/{slug}/ledger", 1)
	d.RegisterOpenAPI(openAPI)

	// Conservation: the credits a treasury holds are escrow, exactly as a job reservation (16.1).
	d.OnEscrow("SELECT coalesce(sum(balance), 0) FROM space_treasury")

	gov.RegisterKind("spend", s.validateSpend, s.applySpend)

	// sg header / space page line: treasury=<balance>cr (27.5). Appended once even if Register runs
	// again (tests), since spaces.ExtraFn is a package-global slice.
	extraOnce.Do(func() {
		spaces.ExtraFn = append(spaces.ExtraFn, func(ctx context.Context, q core.Q, slug string) []string {
			bal, ok, err := readBalance(ctx, q, slug)
			if err != nil || !ok {
				return nil
			}
			return []string{"treasury=" + strconv.FormatInt(bal, 10) + "cr"}
		})
	})

	// export-me: the funder rows of a root (3.4).
	d.OnExport("treasury", s.exportFunder)
	// purge: anonymise a purged root's funder rows (3.4), keeping the per-space aggregate.
	d.OnPurge(func(ctx context.Context, root string) error {
		_, err := d.Ops.Exec(ctx, `UPDATE funders SET root = 'anon-' || substr(encode(sha256(convert_to(root, 'UTF8')), 'hex'), 1, 12)
			WHERE root = $1`, root)
		return err
	})

	d.Janitor.Add("treasury_archive", func(ctx context.Context) error { return s.RunArchiveRefunds(ctx) })
	d.Janitor.Add("treasury_decay", func(ctx context.Context) error { return decay90d(ctx, d.Ops) })
}

// --- funding --------------------------------------------------------------------------------------

// Fund moves `credits` earned credits from the acting identity into the treasury of slug: the caller
// must be a live member, the credits must be EARNED (core.ReserveEarned), and the per-root/day and
// space-inflow caps must hold. One transaction keeps conservation exact: identities.credits falls by
// `credits`, space_treasury.balance rises by the same, the ledger records id -> hold (reserve) then
// hold -> s:<slug> (fund). Returns the new balance.
func (s *svc) Fund(ctx context.Context, id *core.Ident, slug string, credits int64) (balance int64, err error) {
	if id == nil {
		return 0, core.ErrAuth
	}
	if id.Banned {
		return 0, core.ErrBanned
	}
	if credits < MinFund || credits > MaxFund {
		return 0, core.Bad("credits " + strconv.FormatInt(MinFund, 10) + ".." + strconv.FormatInt(MaxFund, 10))
	}
	if member, err := spaces.IsMember(ctx, s.d.DB, slug, id.Root); err != nil {
		return 0, err
	} else if !member {
		// Surface a 404 for an unknown space, 403 for a non-member of a live one.
		if _, gerr := spaces.Get(ctx, s.d.DB, slug); gerr != nil {
			return 0, gerr
		}
		return 0, core.E(403, "auth", "members fund their space")
	}
	dayCap := FundDayL1
	if core.Level(ctx, s.d.DB, id.Root) >= 2 {
		dayCap = FundDayL2
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		// Daily caps are charged like core.UseQuota: count first, refuse over the line.
		if n, berr := counter(ctx, tx, id.Root, "tfund", credits); berr != nil {
			return berr
		} else if n > dayCap {
			return core.E(429, "quota", "fund "+strconv.FormatInt(credits, 10)+"cr over "+strconv.FormatInt(dayCap, 10)+"/day")
		}
		if n, berr := counter(ctx, tx, "s:"+slug, "tin", credits); berr != nil {
			return berr
		} else if n > InflowDay {
			return core.E(429, "quota", "space inflow over "+strconv.FormatInt(InflowDay, 10)+"/day")
		}
		// Earned-only: insufficient transferable credits answer "err credits earned only".
		if rerr := core.ReserveEarned(ctx, tx, id.ID, credits); rerr != nil {
			if errors.Is(rerr, core.ErrEarned) {
				return core.E(402, "credits", "earned only")
			}
			return rerr
		}
		if lerr := core.Ledger(ctx, tx, core.LedgerHold, "s:"+slug, "earned", credits, "fund", id.Root); lerr != nil {
			return lerr
		}
		if uerr := tx.QueryRow(ctx, `INSERT INTO space_treasury (space, balance, funded_90d) VALUES ($1, $2, $2)
			ON CONFLICT (space) DO UPDATE SET balance = space_treasury.balance + $2, funded_90d = space_treasury.funded_90d + $2
			RETURNING balance`, slug, credits).Scan(&balance); uerr != nil {
			return uerr
		}
		if _, ferr := tx.Exec(ctx, `INSERT INTO funders (space, root, credits_90d, last_at) VALUES ($1, $2, $3, now())
			ON CONFLICT (space, root) DO UPDATE SET credits_90d = funders.credits_90d + $3, last_at = now()`,
			slug, id.Root, credits); ferr != nil {
			return ferr
		}
		return core.Event(ctx, tx, "treasury", "s:"+slug, id.Root, fmt.Sprintf("fund %dcr -> %s", credits, slug))
	})
	return balance, err
}

// Debit spends `n` credits of slug's treasury for compute-funded work (hooks and crons, 27.5): a
// guarded UPDATE that pays nothing when the balance is short, moving the credits to the system root
// so a job can reserve them (ledger s:<slug> -> asystem). It is the hooks.FundFn implementation.
// Returns false when the treasury cannot cover n.
func Debit(ctx context.Context, q core.Q, slug string, n int64, ref string) (bool, error) {
	if n <= 0 {
		return true, nil
	}
	var bal int64
	err := q.QueryRow(ctx, `UPDATE space_treasury SET balance = balance - $2 WHERE space = $1 AND balance >= $2 RETURNING balance`,
		slug, n).Scan(&bal)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if _, err := q.Exec(ctx, `UPDATE identities SET credits = credits + $2, earned = earned + $2 WHERE id = $1 AND revoked_at IS NULL`, core.SystemID, n); err != nil {
		return false, err
	}
	return true, core.Ledger(ctx, q, "s:"+slug, core.SystemID, "earned", n, "debit", ref)
}

// --- spend proposal (gov kind `spend`) ------------------------------------------------------------

type spendPatch struct {
	To      string `json:"to"`             // an identity a…, or "burn"
	Credits int64  `json:"credits"`        // 1..500 and <= 20% of the balance at creation
	Why     string `json:"why"`            // <= 300, data
	Task    int64  `json:"task,omitempty"` // when set with an a… recipient: open a bounty on this task for them
}

// validateSpend is the gov.Validator for the space-scoped `spend` kind: fixed shape, credits in
// range and at most 20% of the current balance, recipient a live-looking identity or "burn". It
// reads the balance through the Deps it closed over (the Validator signature carries no handle).
func (s *svc) validateSpend(scope string, patch json.RawMessage) error {
	if scope == "" {
		return core.Bad("spend is a space proposal")
	}
	in, err := decodeSpend(patch)
	if err != nil {
		return err
	}
	if in.Credits < 1 || in.Credits > MaxSpend {
		return core.Bad("credits 1.." + strconv.FormatInt(MaxSpend, 10))
	}
	if in.To != "burn" && !core.ValidIDPrefix(in.To, 'a') {
		return core.Bad(`to: an identity "a…" or "burn"`)
	}
	if in.Task < 0 {
		return core.Bad("task")
	}
	if in.Task > 0 && in.To == "burn" {
		return core.Bad("a bounty needs an identity recipient")
	}
	if len(in.Why) > MaxWhy {
		return core.Bad("why too long")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	bal, _, err := readBalance(ctx, s.d.DB, scope)
	if err != nil {
		return err
	}
	if in.Credits*SpendShareDen > bal*SpendShareNum {
		return core.E(400, "bad", fmt.Sprintf("credits over 20%% of balance (%dcr)", bal))
	}
	return nil
}

// applySpend is the gov.Applier for a passed `spend` proposal: a guarded debit of the treasury,
// then the payout — Earn to the identity, a fixed bounty through bounty.CreateFromEscrow (asystem
// the creator) after the ledger transfer, or burn. prev is the slug for a symmetric revert record.
func (s *svc) applySpend(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
	in, err := decodeSpend(p.Patch)
	if err != nil {
		return nil, err
	}
	slug := p.Scope
	var bal int64
	err = tx.QueryRow(ctx, `UPDATE space_treasury SET balance = balance - $2 WHERE space = $1 AND balance >= $2 RETURNING balance`,
		slug, in.Credits).Scan(&bal)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.E(409, "credits", "treasury short of "+strconv.FormatInt(in.Credits, 10)+"cr")
	}
	if err != nil {
		return nil, err
	}
	switch {
	case in.To == "burn":
		if err := core.Ledger(ctx, tx, "s:"+slug, core.LedgerBurn, "earned", in.Credits, "spend", p.ID); err != nil {
			return nil, err
		}
	case in.Task > 0:
		// Transfer into hold, then open the bounty whose escrow we now hold (16.2 rules apply).
		var hunterRoot string
		if err := tx.QueryRow(ctx, `SELECT root FROM identities WHERE id = $1 AND revoked_at IS NULL`, in.To).Scan(&hunterRoot); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil, core.E(404, "notfound", "recipient "+in.To)
			}
			return nil, err
		}
		if err := core.Ledger(ctx, tx, "s:"+slug, core.LedgerHold, "earned", in.Credits, "spend", p.ID); err != nil {
			return nil, err
		}
		deadline := time.Now().Add(time.Duration(BountyDeadlineHours) * time.Hour)
		if _, err := bounty.CreateFromEscrow(ctx, tx, in.Task, in.Credits, core.SystemID, core.SystemID, in.To, hunterRoot, deadline); err != nil {
			return nil, err
		}
	default:
		if err := payIdentity(ctx, tx, "s:"+slug, in.To, in.Credits, "spend", p.ID); err != nil {
			return nil, err
		}
	}
	if err := gov.ChangelogNote(ctx, tx, slug, fmt.Sprintf("%s spend %dcr -> %s", p.ID, in.Credits, in.To)); err != nil {
		return nil, err
	}
	prev, _ := json.Marshal(map[string]string{"space": slug})
	return prev, nil
}

// --- archive refunds ------------------------------------------------------------------------------

// RunArchiveRefunds refunds the treasury of every newly archived space pro-rata to the roots that
// funded it in the last 90 days and burns the remainder (27.5). Each space settles in its own
// transaction and is marked refunded so a later pass is a no-op; conservation holds row by row
// (escrow out == refunds in + burn).
func (s *svc) RunArchiveRefunds(ctx context.Context) error {
	rows, err := s.d.Ops.Query(ctx, `SELECT t.space FROM space_treasury t JOIN spaces sp ON sp.slug = t.space
		WHERE sp.archived AND t.balance > 0 AND t.refunded_at IS NULL LIMIT 200`)
	if err != nil {
		return err
	}
	var slugs []string
	for rows.Next() {
		var sl string
		if err := rows.Scan(&sl); err != nil {
			rows.Close()
			return err
		}
		slugs = append(slugs, sl)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, slug := range slugs {
		if err := s.refundOne(ctx, slug); err != nil {
			return err
		}
	}
	return nil
}

func (s *svc) refundOne(ctx context.Context, slug string) error {
	return core.Tx(ctx, s.d.Ops, func(tx pgx.Tx) error {
		var bal int64
		err := tx.QueryRow(ctx, `SELECT balance FROM space_treasury WHERE space = $1 AND refunded_at IS NULL FOR UPDATE`, slug).Scan(&bal)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil // another instance settled it
		}
		if err != nil {
			return err
		}
		if bal <= 0 {
			_, err := tx.Exec(ctx, `UPDATE space_treasury SET refunded_at = now() WHERE space = $1`, slug)
			return err
		}
		frows, err := tx.Query(ctx, `SELECT ref, sum(amount) FROM ledger
			WHERE to_id = $1 AND reason = 'fund' AND ts > now() - interval '`+refundWindow+`' AND ref <> '' GROUP BY ref`, "s:"+slug)
		if err != nil {
			return err
		}
		type share struct {
			root string
			amt  int64
		}
		var funders []share
		var total int64
		for frows.Next() {
			var sh share
			if err := frows.Scan(&sh.root, &sh.amt); err != nil {
				frows.Close()
				return err
			}
			funders = append(funders, sh)
			total += sh.amt
		}
		frows.Close()
		if err := frows.Err(); err != nil {
			return err
		}
		var paid int64
		if total > 0 {
			for _, f := range funders {
				credit := bal * f.amt / total // floor; the dust falls into the burn below
				if credit <= 0 {
					continue
				}
				if err := payIdentity(ctx, tx, "s:"+slug, f.root, credit, "refund", slug); err != nil {
					return err
				}
				paid += credit
			}
		}
		if rem := bal - paid; rem > 0 {
			if err := core.Ledger(ctx, tx, "s:"+slug, core.LedgerBurn, "earned", rem, "refund-burn", slug); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE space_treasury SET balance = 0, refunded_at = now() WHERE space = $1`, slug); err != nil {
			return err
		}
		return core.Event(ctx, tx, "treasury", "s:"+slug, "", fmt.Sprintf("archive refund %dcr (burn %dcr)", paid, bal-paid))
	})
}

// --- shared helpers -------------------------------------------------------------------------------

// payIdentity moves n credits from a space pseudo-id to a live identity as earned, recording the
// ledger row; a revoked or unknown payee's credits leave through a burn so the audit stays exact.
func payIdentity(ctx context.Context, q core.Q, from, to string, n int64, reason, ref string) error {
	tag, err := q.Exec(ctx, `UPDATE identities SET credits = credits + $2, earned = earned + $2 WHERE id = $1 AND revoked_at IS NULL`, to, n)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.Ledger(ctx, q, from, core.LedgerBurn, "earned", n, "unpayable", to)
	}
	return core.Ledger(ctx, q, from, to, "earned", n, reason, ref)
}

// readBalance returns a space's treasury balance; ok is false when the space has no treasury row.
func readBalance(ctx context.Context, q core.Q, slug string) (balance int64, ok bool, err error) {
	err = q.QueryRow(ctx, `SELECT balance FROM space_treasury WHERE space = $1`, slug).Scan(&balance)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, false, nil
	}
	if err != nil {
		return 0, false, err
	}
	return balance, true, nil
}

// counter adds delta to today's counter and returns the new value (the core pattern, scoped here).
func counter(ctx context.Context, q core.Q, scope, kind string, delta int64) (int64, error) {
	var n int64
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, delta).Scan(&n)
	return n, err
}

// decay90d recomputes the rolling 90-day funding aggregates from the authoritative ledger rows.
func decay90d(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `UPDATE funders f SET credits_90d = coalesce((
		SELECT sum(amount) FROM ledger WHERE to_id = 's:' || f.space AND reason = 'fund'
		  AND ref = f.root AND ts > now() - interval '`+refundWindow+`'), 0)`); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE space_treasury t SET funded_90d = coalesce((
		SELECT sum(amount) FROM ledger WHERE to_id = 's:' || t.space AND reason = 'fund'
		  AND ts > now() - interval '`+refundWindow+`'), 0)`)
	return err
}

func decodeSpend(patch json.RawMessage) (spendPatch, error) {
	var in spendPatch
	dec := json.NewDecoder(strings.NewReader(string(patch)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return in, core.Bad("patch: {to, credits, why}")
	}
	in.To = strings.TrimSpace(in.To)
	return in, nil
}

// exportFunder writes a root's treasury contributions for GET /v1/me/export (3.4).
func (s *svc) exportFunder(ctx context.Context, root string, w io.Writer) error {
	rows, err := s.d.DB.Query(ctx, `SELECT space, credits_90d, last_at FROM funders WHERE root = $1 ORDER BY space`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var sp string
		var c90 int64
		var at time.Time
		if err := rows.Scan(&sp, &c90, &at); err != nil {
			return err
		}
		fmt.Fprintf(w, "treasury funder space=%s credits_90d=%d last=%s\n", sp, c90, core.Date(at))
	}
	return rows.Err()
}

// --- HTTP ----------------------------------------------------------------------------------------

func (s *svc) hFund(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in struct {
		Credits int64  `json:"credits"`
		Key     string `json:"key"`
	}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	slug := r.PathValue("slug")
	bal, err := s.Fund(r.Context(), id, slug, in.Credits)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, 201, fmt.Sprintf("ok funded %s treasury=%dcr", slug, bal),
		doc.GET("/v1/s/"+slug+"/ledger", ""), doc.GET("/v1/s/"+slug, ""))
}

func (s *svc) hLedger(w http.ResponseWriter, r *http.Request) {
	if _, err := s.d.Auth(r); err != nil {
		core.Fail(w, r, err)
		return
	}
	slug := r.PathValue("slug")
	k := ListMax
	if v := r.URL.Query().Get("k"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n < k {
			k = n
		}
	}
	text, err := s.ledgerText(r.Context(), slug, k)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, text, doc.POST("/v1/s/"+slug+"/fund", `{"credits"}`), doc.GET("/v1/s/"+slug, ""))
}

func (s *svc) ledgerText(ctx context.Context, slug string, k int) (string, error) {
	bal, _, err := readBalance(ctx, s.d.DB, slug)
	if err != nil {
		return "", err
	}
	rows, err := s.d.DB.Query(ctx, `SELECT from_id, to_id, amount, reason, ts FROM treasury_ledger
		WHERE space = $1 ORDER BY id DESC LIMIT $2`, slug, k)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	var b strings.Builder
	var n int
	var lines []string
	for rows.Next() {
		var from, to, reason string
		var amt int64
		var ts time.Time
		if err := rows.Scan(&from, &to, &amt, &reason, &ts); err != nil {
			return "", err
		}
		lines = append(lines, fmt.Sprintf("%s -> %s %dcr %s %s", from, to, amt, reason, core.Date(ts)))
		n++
	}
	if err := rows.Err(); err != nil {
		return "", err
	}
	fmt.Fprintf(&b, "ledger %s balance=%dcr n=%d\n", slug, bal, n)
	b.WriteString(strings.Join(lines, "\n"))
	return strings.TrimRight(b.String(), "\n"), nil
}

// --- MCP ops -------------------------------------------------------------------------------------

type fundArgs struct {
	Slug    string `json:"slug"`
	Credits int64  `json:"credits"`
	Key     string `json:"key"`
	K       int    `json:"k"`
}

// Ops are the MCP ops of the treasury (sf fund, sled ledger). The integration package merges them.
func Ops(d *core.Deps) map[string]Op {
	s := &svc{d: d}
	return map[string]Op{
		"sf": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in fundArgs
			if err := arg(a, &in); err != nil {
				return "", err
			}
			bal, err := s.Fund(ctx, id, in.Slug, in.Credits)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("ok funded %s treasury=%dcr", in.Slug, bal), nil
		},
		"sled": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in fundArgs
			if err := arg(a, &in); err != nil {
				return "", err
			}
			k := ListMax
			if in.K > 0 && in.K < k {
				k = in.K
			}
			return s.ledgerText(ctx, in.Slug, k)
		},
	}
}

// OpMeta describes the treasury ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"sf":   {Scope: "sp", Cost: 1, Mutating: true},
	"sled": {Scope: "sp", Cost: 1},
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
"/v1/s/{slug}/fund":{"post":{"operationId":"sf","summary":"Fund a space treasury with earned credits (member only, earned-only, caps per day)","parameters":[{"name":"slug","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["credits"],"properties":{"credits":{"type":"integer","minimum":1,"maximum":500},"key":{"type":"string","maxLength":64}}}}}},"responses":{"201":{"description":"ok funded <slug> treasury=<n>cr"},"402":{"description":"err credits earned only"},"403":{"description":"err auth members fund their space"},"429":{"description":"err quota fund over cap/day | space inflow over 2000/day"}}}},
"/v1/s/{slug}/ledger":{"get":{"operationId":"sled","summary":"Treasury ledger of a space (fund/debit/spend/refund rows)","parameters":[{"name":"slug","in":"path","required":true,"schema":{"type":"string"}},{"name":"k","in":"query","schema":{"type":"integer","minimum":1,"maximum":50}}],"responses":{"200":{"description":"ledger <slug> balance=<n>cr n=<rows>"}}}}}}`)
