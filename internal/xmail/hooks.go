package xmail

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// deleteEnvs runs a DELETE on x_env (sql with its own WHERE, no RETURNING) and settles every counter
// the rows held: inbox rows/bytes, the live byte budget and the epoch-share linger (4.9). Returns the
// number of rows deleted. Shared by ack, the janitor and the purge hook.
func deleteEnvs(ctx context.Context, q core.Q, sql string, args ...any) (int64, error) {
	rows, err := q.Query(ctx, `WITH d AS (`+sql+` RETURNING to_id, size, epoch) SELECT to_id, size, epoch FROM d`, args...)
	if err != nil {
		return 0, err
	}
	type key struct {
		to    string
		epoch int64
	}
	type agg struct {
		n     int64
		bytes int64
	}
	boxes := map[string]*agg{}
	epochs := map[key]bool{}
	var total, n int64
	for rows.Next() {
		var to string
		var size int
		var epoch int64
		if err := rows.Scan(&to, &size, &epoch); err != nil {
			rows.Close()
			return 0, err
		}
		a := boxes[to]
		if a == nil {
			a = &agg{}
			boxes[to] = a
		}
		a.n++
		a.bytes += int64(size)
		total += int64(size)
		n++
		if epoch != 0 {
			epochs[key{to, epoch}] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, err
	}
	for to, a := range boxes {
		if _, err := q.Exec(ctx, `UPDATE x_inbox SET rows = greatest(rows - $2, 0), bytes = greatest(bytes - $3, 0), updated = now() WHERE id = $1`, to, a.n, a.bytes); err != nil {
			return 0, err
		}
	}
	if total > 0 {
		if _, err := q.Exec(ctx, `UPDATE x_bytes SET n = greatest(n - $1, 0) WHERE k = 'live'`, total); err != nil {
			return 0, err
		}
	}
	for k := range epochs {
		// The last envelope of a finished epoch left the inbox: its share lingers ShareLinger, no more.
		if _, err := q.Exec(ctx, `UPDATE epoch_shares s SET exp = least(s.exp, now() + $3::interval)
			FROM identities i WHERE i.id = $1 AND s.root = i.root AND s.e = $2 AND to_timestamp(($2 + 1) * 604800) < now()
			AND NOT EXISTS (SELECT 1 FROM x_env x JOIN identities j ON j.id = x.to_id WHERE j.root = i.root AND x.epoch = $2)`,
			k.to, k.epoch, ShareLinger.String()); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// Janitor is the periodic task (9.3): x_expire (30 d TTL), ledger expiry, stamps (2 d), leases,
// shares; the request nonces are the keys package's.
func Janitor(ctx context.Context, q core.Q) error {
	if _, err := deleteEnvs(ctx, q, `DELETE FROM x_env WHERE exp <= now()`); err != nil {
		return err
	}
	for _, sql := range []string{
		`DELETE FROM x_ledger WHERE exp <= now()`,
		`DELETE FROM x_stamps WHERE day < current_date - 1`,
		`DELETE FROM x_lease WHERE until <= now() - interval '1 hour'`,
		`DELETE FROM epoch_shares WHERE exp <= now()`,
		`DELETE FROM x_frozen WHERE until <= now()`,
	} {
		if _, err := q.Exec(ctx, sql); err != nil {
			return err
		}
	}
	return nil
}

// purge deletes a root's sealed rows in both directions (envelopes received by its tree, envelopes it
// sent) and every row about it: inboxes, allow/block lists, state, leases, stamps, shares, freezes.
// The bundle tombstone is the keys package's hook; successions are log facts and stay.
func purge(ctx context.Context, q core.Q, root string) error {
	if _, err := deleteEnvs(ctx, q, `DELETE FROM x_env WHERE from_root = $1 OR to_id IN (SELECT id FROM identities WHERE root = $1)`, root); err != nil {
		return err
	}
	for _, sql := range []string{
		`DELETE FROM x_ledger WHERE from_root = $1 OR to_id IN (SELECT id FROM identities WHERE root = $1)`,
		`DELETE FROM x_allow WHERE root = $1 OR inbox IN (SELECT id FROM identities WHERE root = $1)`,
		`DELETE FROM x_block WHERE root = $1 OR inbox IN (SELECT id FROM identities WHERE root = $1)`,
		`DELETE FROM x_state WHERE id IN (SELECT id FROM identities WHERE root = $1)`,
		`DELETE FROM x_lease WHERE id IN (SELECT id FROM identities WHERE root = $1)`,
		`DELETE FROM x_stamps WHERE to_id IN (SELECT id FROM identities WHERE root = $1)`,
		`DELETE FROM epoch_shares WHERE root = $1`,
		`DELETE FROM x_frozen WHERE id = $1 OR id IN (SELECT id FROM identities WHERE root = $1)`,
		`DELETE FROM x_inbox WHERE root = $1 OR id IN (SELECT id FROM identities WHERE root = $1)`,
	} {
		if _, err := q.Exec(ctx, sql, root); err != nil {
			return err
		}
	}
	return nil
}

// Freeze writes a sender freeze (`err auth mail-frozen`) for an identity or root: the reports
// package's lever (8.3) and the revocation path's.
func Freeze(ctx context.Context, q core.Q, id string, until time.Time, basis string) error {
	_, err := q.Exec(ctx, `INSERT INTO x_frozen (id, until, basis) VALUES ($1, $2, $3)
		ON CONFLICT (id) DO UPDATE SET until = greatest(x_frozen.until, EXCLUDED.until), basis = EXCLUDED.basis`, id, until, basis)
	return err
}

// Report target x:<to>/<seq> (4.7, 8.5): hide deletes the ciphertext (the ledger row and the
// header stay for evidence and accounting), restore cannot bring it back.
func splitRef(ref string) (string, int64, bool) {
	to, s, ok := strings.Cut(ref, "/")
	if !ok || !core.ValidIDPrefix(to, 'a') {
		return "", 0, false
	}
	seq, err := strconv.ParseInt(s, 10, 64)
	if err != nil || seq <= 0 {
		return "", 0, false
	}
	return to, seq, true
}

func exists(ctx context.Context, q core.Q, ref string) error {
	to, seq, ok := splitRef(ref)
	if !ok {
		return core.ErrNotFound
	}
	var found bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM x_ledger WHERE to_id = $1 AND seq = $2 AND exp > now())`, to, seq).Scan(&found); err != nil {
		return err
	}
	if !found {
		return core.ErrNotFound
	}
	return nil
}

func hide(ctx context.Context, q core.Q, ref string) error {
	to, seq, ok := splitRef(ref)
	if !ok {
		return core.ErrNotFound
	}
	if err := exists(ctx, q, ref); err != nil {
		return err
	}
	var size int
	err := q.QueryRow(ctx, `UPDATE x_env SET body = ''::bytea, hidden = true WHERE to_id = $1 AND seq = $2 AND NOT hidden RETURNING size`, to, seq).Scan(&size)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil // acked, expired or already hidden: the ledger row is the record
	}
	if err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE x_inbox SET bytes = greatest(bytes - $2, 0) WHERE id = $1`, to, size); err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE x_bytes SET n = greatest(n - $1, 0) WHERE k = 'live'`, size)
	return err
}

func restore(ctx context.Context, q core.Q, ref string) error {
	if err := exists(ctx, q, ref); err != nil {
		return err
	}
	return core.E(410, "gone", "a hidden sealed envelope cannot be restored: its ciphertext was deleted")
}
