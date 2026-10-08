package webhook

import (
	"context"
	"encoding/json"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/events"
)

// deliverBatch caps the events one hook consumes per pass (the cursor advances, so a backlog
// drains over successive ticks without one hook starving the others).
const deliverBatch = 1000

// deliverPass is the janitor task (registered under a per-task advisory lock): for every hook with
// unconsumed events it renders one signed envelope per matching event into hook_out, advances the
// hook cursor, and trims the hook to MaxOutLive rows. Reuses the 19.1 watch matcher (events.Match),
// including the hook root's own root-scoped events.
func (h *handlers) deliverPass(ctx context.Context) error {
	head, err := events.Head(ctx, h.d.DB)
	if err != nil {
		return err
	}
	rows, err := h.d.DB.Query(ctx, `SELECT `+hookCols+` FROM hooks WHERE last_seq < $1 ORDER BY id`, head)
	if err != nil {
		return err
	}
	var hooks []Hook
	for rows.Next() {
		hk, err := scanHook(rows)
		if err != nil {
			rows.Close()
			return err
		}
		hooks = append(hooks, *hk)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	base := doc.Base()
	now := time.Now()
	for i := range hooks {
		if err := h.deliverHook(ctx, &hooks[i], head, base, now); err != nil && ctx.Err() == nil {
			h.d.Log.Warn("webhook deliver", "hook", hooks[i].ID, "err", err)
		}
	}
	return nil
}

// deliverHook consumes a single hook's event backlog up to head.
func (h *handlers) deliverHook(ctx context.Context, hk *Hook, head int64, base string, now time.Time) error {
	cursor := hk.LastSeq
	fired := false
	for cursor < head {
		rows, err := h.d.DB.Query(ctx, `SELECT seq, at, kind, ref, title, root_scope IS NOT NULL
			FROM events WHERE seq > $1 AND (root_scope IS NULL OR root_scope = $2) ORDER BY seq LIMIT $3`,
			cursor, hk.Root, deliverBatch)
		if err != nil {
			return err
		}
		var batch []events.Row
		for rows.Next() {
			var r events.Row
			if err := rows.Scan(&r.Seq, &r.At, &r.Kind, &r.Ref, &r.Title, &r.Scoped); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil {
			return err
		}
		if len(batch) == 0 {
			cursor = head
			break
		}
		for _, row := range batch {
			cursor = row.Seq
			ok, err := h.render(ctx, hk, row, base, now)
			if err != nil {
				return err
			}
			if ok {
				fired = true
			}
		}
		if len(batch) < deliverBatch {
			cursor = head
		}
	}
	if _, err := h.d.DB.Exec(ctx, `UPDATE hooks SET last_seq = $2 WHERE id = $1 AND last_seq < $2`, hk.ID, cursor); err != nil {
		return err
	}
	if err := trimHook(ctx, h.d.DB, hk.ID); err != nil {
		return err
	}
	if fired {
		h.d.Notify.Wake(outTopic(hk.ID))
	}
	return nil
}

// render inserts one envelope for a matching event; a non-match or a duplicate (hook, ev_seq) is a
// no-op. Returns whether a new row was inserted.
func (h *handlers) render(ctx context.Context, hk *Hook, row events.Row, base string, now time.Time) (bool, error) {
	if !events.Match(hk.Kinds, hk.Tags, hk.Q, row) {
		return false, nil
	}
	env := renderEnvelope(hk.Fmt, hk.URL, hk.Secret, row, base, now)
	b, err := json.Marshal(env)
	if err != nil || len(b) > maxEnv {
		return false, nil // an oversized envelope is dropped rather than wedging the cursor
	}
	tag, err := h.d.DB.Exec(ctx, `INSERT INTO hook_out (hook, ev_seq, envelope) VALUES ($1,$2,$3)
		ON CONFLICT (hook, ev_seq) DO NOTHING`, hk.ID, row.Seq, b)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// trimHook keeps at most MaxOutLive rows for a hook: acked rows are dropped before unacked, oldest
// before newest.
func trimHook(ctx context.Context, q core.Q, hook string) error {
	_, err := q.Exec(ctx, `DELETE FROM hook_out WHERE id IN (
		SELECT id FROM (
			SELECT id, row_number() OVER (ORDER BY acked DESC, id ASC) AS rn, count(*) OVER () AS c
			FROM hook_out WHERE hook = $1
		) t WHERE t.rn <= t.c - $2)`, hook, MaxOutLive)
	return err
}
