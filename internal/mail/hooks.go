package mail

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Report target m:<id> (4.7): recipient-only. CanReport is the rule the reports package consults
// before accepting a report on a message; Exists/Hide/Restore are the core.Target callbacks.
func CanReport(ctx context.Context, q core.Q, id, root string) error {
	if !core.ValidIDPrefix(id, 'm') {
		return core.ErrNotFound
	}
	var box string
	err := q.QueryRow(ctx, `SELECT box FROM mail WHERE id = $1 AND expires > now()`, id).Scan(&box)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ErrNotFound
	}
	if err != nil {
		return err
	}
	var owner string
	err = q.QueryRow(ctx, `SELECT root FROM identities WHERE id = $1`, box).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && owner != root) {
		return core.ErrForbid
	}
	return err
}

func exists(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'm') {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM mail WHERE id = $1 AND expires > now())`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

// hide is an upheld report: the message leaves the recipient's view (readable again only through
// restore) and the hide is counted toward the sender's mute: MuteReports hides from distinct
// recipients within MuteWindow mute it for MuteFor (11).
func hide(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'm') {
		return core.ErrNotFound
	}
	var fromRoot, box string
	err := q.QueryRow(ctx, `UPDATE mail SET hidden = true WHERE id = $1 AND expires > now() RETURNING from_root, box`, ref).Scan(&fromRoot, &box)
	if errors.Is(err, pgx.ErrNoRows) {
		return core.ErrNotFound
	}
	if err != nil {
		return err
	}
	owner := box
	if err := q.QueryRow(ctx, `SELECT coalesce((SELECT root FROM identities WHERE id = $1), $1)`, box).Scan(&owner); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `INSERT INTO mb_hides (id, from_root, to_root) VALUES ($1, $2, $3) ON CONFLICT (id) DO NOTHING`, ref, fromRoot, owner); err != nil {
		return err
	}
	if fromRoot == core.SystemID {
		return nil
	}
	var n int
	if err := q.QueryRow(ctx, `SELECT count(DISTINCT to_root) FROM mb_hides WHERE from_root = $1 AND at > now() - $2::interval`, fromRoot, MuteWindow.String()).Scan(&n); err != nil {
		return err
	}
	if n < MuteReports {
		return nil
	}
	var until time.Time
	if err := q.QueryRow(ctx, `INSERT INTO mb_mutes (root, until, n) VALUES ($1, now() + $2::interval, $3)
		ON CONFLICT (root) DO UPDATE SET until = greatest(mb_mutes.until, EXCLUDED.until), n = EXCLUDED.n RETURNING until`, fromRoot, MuteFor.String(), n).Scan(&until); err != nil {
		return err
	}
	// Best effort: the notice must not block the hide.
	SendSys(ctx, q, fromRoot, "mail muted until "+core.Date(until), fmt.Sprintf("%d recipients reported your mail within 30 days; sends are refused until %s", n, core.Date(until)))
	return nil
}

func restore(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'm') {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `UPDATE mail SET hidden = false WHERE id = $1`, ref)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	_, err = q.Exec(ctx, `DELETE FROM mb_hides WHERE id = $1`, ref)
	return err
}

// resolveID is the /x/ resolver of the m prefix (8.3): type and route only, mail is private.
func resolveID(ctx context.Context, q core.Q, id string) (typ, title, url string, ok bool) {
	if exists(ctx, q, id) != nil {
		return "", "", "", false
	}
	return "mail", "private message", "/v1/mb/" + id, true
}

// Block records a silent block of a sender root by owner (27.8) and applies the cold freeze: 3
// blocks from recipients in distinct super-groups within 7 d freeze the sender's cold budget 30 d.
func Block(ctx context.Context, q core.Q, owner *core.Ident, from string) (fromRoot string, frozen bool, err error) {
	fromRoot, err = rootOf(ctx, q, from)
	if err != nil {
		return "", false, err
	}
	if fromRoot == owner.Root {
		return "", false, core.Bad("cannot block your own tree")
	}
	if _, err := q.Exec(ctx, `INSERT INTO mb_blocks (owner_root, from_root) VALUES ($1, $2) ON CONFLICT DO NOTHING`, owner.Root, fromRoot); err != nil {
		return "", false, err
	}
	rows, err := q.Query(ctx, `SELECT i.reg_ip FROM mb_blocks b JOIN identities i ON i.id = b.owner_root
		WHERE b.from_root = $1 AND b.at > now() - $2::interval`, fromRoot, ColdFreezeWindow.String())
	if err != nil {
		return "", false, err
	}
	supers := map[string]bool{}
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			rows.Close()
			return "", false, err
		}
		if ip != "" {
			supers[core.IPSuper(ip)] = true
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return "", false, err
	}
	if len(supers) >= ColdFreezeBlocks {
		var until time.Time
		if err := q.QueryRow(ctx, `UPDATE identities SET mail_cold_frozen_until = greatest(coalesce(mail_cold_frozen_until, now()), now() + $2::interval)
			WHERE id = $1 RETURNING mail_cold_frozen_until`, fromRoot, ColdFreeze.String()).Scan(&until); err != nil {
			return "", false, err
		}
		frozen = true
		SendSys(ctx, q, fromRoot, "mail cold budget frozen until "+core.Date(until),
			"recipients in several networks blocked your mail; new contacts are refused until "+core.Date(until)+" (replies to existing pairs still flow)")
	}
	return fromRoot, frozen, core.Audit(ctx, q, owner.ID, "mbblock", fromRoot, 1)
}

// Unblock removes a block (idempotent).
func Unblock(ctx context.Context, q core.Q, owner *core.Ident, from string) (string, error) {
	fromRoot, err := rootOf(ctx, q, from)
	if err != nil {
		return "", err
	}
	if _, err := q.Exec(ctx, `DELETE FROM mb_blocks WHERE owner_root = $1 AND from_root = $2`, owner.Root, fromRoot); err != nil {
		return "", err
	}
	return fromRoot, core.Audit(ctx, q, owner.ID, "mbblock", fromRoot, 0)
}

func rootOf(ctx context.Context, q core.Q, id string) (string, error) {
	if !core.ValidIDPrefix(id, 'a') {
		return "", core.Bad("from must be an identity id")
	}
	var root string
	err := q.QueryRow(ctx, `SELECT root FROM identities WHERE id = $1`, id).Scan(&root)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", core.ErrNotFound
	}
	return root, err
}

// Janitor is the periodic task: TTL (30 d), time-locked deliveries, mute expiry, the short-lived
// ledgers (burst window, cold days, hides) and the unread counters of mb_boxes.
func Janitor(ctx context.Context, q core.Q) error {
	for _, sql := range []string{
		`DELETE FROM mail WHERE expires <= now()`,
		`UPDATE mail SET delivered = true WHERE NOT delivered AND cond_kind = '' AND deliver_at IS NOT NULL AND deliver_at <= now()`,
		`DELETE FROM mb_mutes WHERE until <= now()`,
		`DELETE FROM mb_sent WHERE at < now() - interval '1 hour'`,
		`DELETE FROM mb_cold WHERE day < current_date - 8`,
		`DELETE FROM mb_hides WHERE at < now() - interval '30 days'`,
		`DELETE FROM mb_pairs WHERE last_at < now() - interval '180 days'`,
		`UPDATE mb_boxes b SET unread = c.n FROM (SELECT box, count(*) AS n FROM mail WHERE read_at IS NULL AND delivered AND NOT hidden AND expires > now() GROUP BY box) c
		   WHERE b.box = c.box AND b.unread <> c.n`,
		`UPDATE mb_boxes b SET unread = 0 WHERE b.unread <> 0 AND NOT EXISTS (SELECT 1 FROM mail m WHERE m.box = b.box AND m.read_at IS NULL AND m.delivered AND NOT m.hidden AND m.expires > now())`,
	} {
		if _, err := q.Exec(ctx, sql); err != nil {
			return err
		}
	}
	return nil
}

// purge deletes a root's mail in both directions and every counter row about it (OnPurge).
func purge(ctx context.Context, q core.Q, root string) error {
	for _, sql := range []string{
		`DELETE FROM mail WHERE from_root = $1 OR box IN (SELECT id FROM identities WHERE root = $1)`,
		`DELETE FROM mb_boxes WHERE owner_root = $1 OR box IN (SELECT id FROM identities WHERE root = $1)`,
		`DELETE FROM mb_cursors WHERE root = $1`,
		`DELETE FROM mb_pairs WHERE from_root = $1 OR to_root = $1`,
		`DELETE FROM mb_blocks WHERE owner_root = $1 OR from_root = $1`,
		`DELETE FROM mb_mutes WHERE root = $1`,
		`DELETE FROM mb_hides WHERE from_root = $1 OR to_root = $1`,
		`DELETE FROM mb_cold WHERE from_root = $1 OR to_root = $1`,
		`DELETE FROM mb_sent WHERE from_root = $1`,
	} {
		if _, err := q.Exec(ctx, sql, root); err != nil {
			return err
		}
	}
	return nil
}

// export writes the root tree's mail as JSONL (export-me, 3.4): sent rows and the inbox rows of
// its boxes, hidden ones excluded.
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	rows, err := q.Query(ctx, `SELECT id, box, seq, from_id, from_root, re, subject, text, created, read_at, flags,
		CASE WHEN from_root = $1 THEN 'out' ELSE 'in' END
		FROM mail WHERE NOT hidden AND (from_root = $1 OR box IN (SELECT id FROM identities WHERE root = $1)) ORDER BY created, id`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for rows.Next() {
		var rec struct {
			Kind    string     `json:"kind"`
			Dir     string     `json:"dir"`
			ID      string     `json:"id"`
			Box     string     `json:"box"`
			Seq     int64      `json:"seq"`
			From    string     `json:"from"`
			Root    string     `json:"from_root"`
			Re      string     `json:"re,omitempty"`
			Subject string     `json:"subject"`
			Text    string     `json:"text"`
			Created time.Time  `json:"created"`
			ReadAt  *time.Time `json:"read_at,omitempty"`
			Flags   []string   `json:"flags"`
		}
		rec.Kind = "mail"
		if err := rows.Scan(&rec.ID, &rec.Box, &rec.Seq, &rec.From, &rec.Root, &rec.Re, &rec.Subject, &rec.Text, &rec.Created, &rec.ReadAt, &rec.Flags, &rec.Dir); err != nil {
			return err
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}

// resumeLines is the OnResume section: `inbox: N unread (sys: k)` when anything waits.
func resumeLines(ctx context.Context, q core.Q, root string) []string {
	n, sys, err := Unread(ctx, q, root)
	if err != nil || n == 0 {
		return nil
	}
	return []string{fmt.Sprintf("inbox: %d unread (sys: %d)", n, sys)}
}

// meLines are the GET /v1/me additions: the unread count and the cold freeze (27.8).
func meLines(ctx context.Context, q core.Q, id *core.Ident) []string {
	var out []string
	if n, _, err := Unread(ctx, q, id.Root); err == nil && n > 0 {
		out = append(out, fmt.Sprintf("mail: unread=%d", n))
	}
	var frozen *time.Time
	if err := q.QueryRow(ctx, `SELECT mail_cold_frozen_until FROM identities WHERE id = $1`, id.Root).Scan(&frozen); err == nil && frozen != nil && frozen.After(time.Now()) {
		out = append(out, "mail: cold-frozen until "+core.Date(*frozen))
	}
	return out
}
