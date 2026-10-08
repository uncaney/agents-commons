package core

import (
	"context"
	"fmt"
	"strings"
)

// Ledger appends one row to the credit ledger in the caller's transaction (16.1): class grant or
// earned, amount > 0. Packages that move credits through their own pseudo-ids (a treasury
// s:<slug>) compose it with Reserve/Earn so the flow stays readable; mint rows are written only by
// registration (trigger, 0042) and the admin faucet.
func Ledger(ctx context.Context, q Q, from, to, class string, n int64, reason, ref string) error {
	if n <= 0 {
		return Bad("ledger amount")
	}
	if class != "grant" && class != "earned" {
		return Bad("ledger class")
	}
	_, err := q.Exec(ctx, `INSERT INTO ledger (from_id, to_id, class, amount, reason, ref) VALUES ($1, $2, $3, $4, $5, $6)`,
		cleanLine(from, 64), cleanLine(to, 64), class, n, cleanLine(reason, 32), cleanLine(ref, 200))
	return err
}

// mint creates n grant credits for a live identity (the admin faucet, 16.1).
func mint(ctx context.Context, q Q, id string, n int64, reason string) (balance int64, err error) {
	err = q.QueryRow(ctx, `UPDATE identities SET credits = credits + $2 WHERE id = $1 AND revoked_at IS NULL RETURNING credits`, id, n).Scan(&balance)
	if err != nil {
		return 0, err
	}
	return balance, Ledger(ctx, q, LedgerMint, id, "grant", n, reason, "")
}

// AuditReport is one conservation check (16.1): credits held by identities, credits reserved by
// active jobs and credits in registered escrows against everything ever minted minus burnt.
type AuditReport struct {
	Credits, Reserved, Escrow, Mint, Burn int64
}

// Delta is zero when the books balance.
func (a AuditReport) Delta() int64 { return a.Credits + a.Reserved + a.Escrow - (a.Mint - a.Burn) }

// OK reports conservation.
func (a AuditReport) OK() bool { return a.Delta() == 0 }

// Line is the text reply of GET /admin/audit.
func (a AuditReport) Line() string {
	if a.OK() {
		return fmt.Sprintf("ok conserved mint=%d burn=%d", a.Mint, a.Burn)
	}
	return fmt.Sprintf("MISMATCH delta=%d credits=%d reserved=%d escrow=%d mint=%d burn=%d",
		a.Delta(), a.Credits, a.Reserved, a.Escrow, a.Mint, a.Burn)
}

// JSON is the object reply of GET /admin/audit.
func (a AuditReport) JSON() map[string]any {
	return map[string]any{"ok": a.OK(), "delta": a.Delta(), "credits": a.Credits, "reserved": a.Reserved,
		"escrow": a.Escrow, "mint": a.Mint, "burn": a.Burn}
}

// LedgerAudit sums the books in ONE statement (one snapshot, so a reservation committed between
// two sums can never look like a leak): sum(credits) + active job reservations + the registered
// escrow queries (d.EscrowSQL(): each returns one bigint) == mint - burn.
func LedgerAudit(ctx context.Context, q Q, escrowSQL []string) (AuditReport, error) {
	esc := "0::bigint"
	if len(escrowSQL) > 0 {
		parts := make([]string, len(escrowSQL))
		for i, s := range escrowSQL {
			parts[i] = "coalesce((" + s + "), 0)"
		}
		esc = strings.Join(parts, " + ")
	}
	var a AuditReport
	err := q.QueryRow(ctx, `SELECT (SELECT coalesce(sum(credits), 0) FROM identities),
		(SELECT coalesce(sum(reserved), 0) FROM jobs WHERE status IN ('queued', 'running')),
		(SELECT coalesce(sum(amount), 0) FROM ledger WHERE from_id = 'mint'),
		(SELECT coalesce(sum(amount), 0) FROM ledger WHERE to_id = 'burn'),
		(`+esc+`)::bigint`).Scan(&a.Credits, &a.Reserved, &a.Mint, &a.Burn, &a.Escrow)
	return a, err
}

// RunLedgerAudit is the shared body of the daily janitor task and GET /admin/audit: on a mismatch
// it freezes compute and bounties, records audit_fail and raises the ops event the operator inbox
// shows. Freezes are never lifted automatically.
func (d *Deps) RunLedgerAudit(ctx context.Context) (AuditReport, error) {
	q := Q(d.DB)
	if d.Ops != nil {
		q = d.Ops
	}
	a, err := LedgerAudit(ctx, q, d.EscrowSQL())
	if err != nil || a.OK() {
		return a, err
	}
	line := a.Line()
	d.Log.Error("ledger audit", "detail", line)
	for _, k := range []string{"freeze:compute", "freeze:bounties"} {
		if err := d.SetFreeze(ctx, k, true); err != nil {
			return a, err
		}
	}
	if _, err := d.DB.Exec(ctx, `INSERT INTO audit_fail (detail) VALUES ($1)`, line); err != nil {
		return a, err
	}
	return a, Event(ctx, d.DB, "ops", "audit_fail", "", "ledger audit "+line)
}

// Audit marker: the daily task runs once per UTC day across instances (Janitor.Add holds the
// advisory lock; the counters row remembers the day and is swept by the counters janitor).
const auditMarkerScope = "sys:ledger"

func (d *Deps) dailyLedgerAudit(ctx context.Context) error {
	var done bool
	if err := d.Ops.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM counters WHERE scope = $1 AND kind = 'audit' AND day = current_date)`,
		auditMarkerScope).Scan(&done); err != nil {
		return err
	}
	if done {
		return nil
	}
	if _, err := d.RunLedgerAudit(ctx); err != nil {
		return err
	}
	_, err := d.Ops.Exec(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'audit', current_date, 1) ON CONFLICT DO NOTHING`, auditMarkerScope)
	return err
}

// ledgerRetention keeps 12 months of ledger rows (21.2). Mint and burn totals must stay exact
// forever, so the rows leaving the window are first rolled up into one mint->rollup and one
// rollup->burn row; admin_log, audit_fail and ident_retention follow the same 12-month window.
// Batches of 10k rows per tick.
func (d *Deps) ledgerRetention(ctx context.Context) error {
	q := d.Ops
	if _, err := q.Exec(ctx, `WITH old AS (SELECT id, from_id, to_id, amount FROM ledger
			WHERE ts < now() - interval '12 months' ORDER BY id LIMIT 10000 FOR UPDATE SKIP LOCKED),
		m AS (INSERT INTO ledger (from_id, to_id, class, amount, reason)
			SELECT 'mint', 'rollup', 'grant', sum(amount), 'rollup' FROM old WHERE from_id = 'mint' HAVING sum(amount) > 0),
		b AS (INSERT INTO ledger (from_id, to_id, class, amount, reason)
			SELECT 'rollup', 'burn', 'grant', sum(amount), 'rollup' FROM old WHERE to_id = 'burn' HAVING sum(amount) > 0)
		DELETE FROM ledger WHERE id IN (SELECT id FROM old)`); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM admin_log WHERE at < now() - interval '12 months';
		DELETE FROM audit_fail WHERE at < now() - interval '12 months';
		DELETE FROM ident_retention WHERE deleted_at < now() - interval '12 months'`)
	return err
}

// ledgerTotals reads the mint/burn totals for /admin/stats.
func ledgerTotals(ctx context.Context, q Q) (mint, burn int64, err error) {
	err = q.QueryRow(ctx, `SELECT (SELECT coalesce(sum(amount), 0) FROM ledger WHERE from_id = 'mint'),
		(SELECT coalesce(sum(amount), 0) FROM ledger WHERE to_id = 'burn')`).Scan(&mint, &burn)
	return
}
