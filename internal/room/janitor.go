package room

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
)

// cleanupRoom deletes every r:<id> row across the owners' tables and the room itself. This is the
// one cross-package write of 27.9 (SPEC 27.9 and the P118 brief name it the explicit exception), and
// it reaches other packages' tables by prefix only: the KV namespace is the exact r:<id>, the swarm
// primitives are r:<id>.<name>, the mailbox box is r<id>. The room id is base32 only, so it carries
// no LIKE metacharacter.
//
// Rendezvous (rv) rows are not reachable here: swarm stores only khash = HMAC(secret, key), so a
// room's rendezvous keys cannot be matched by prefix under the frozen swarm schema; they fall away on
// their own TTL (rv.until) and on their owner's purge.
func cleanupRoom(ctx context.Context, q core.Q, id string) error {
	pfx := ns(id) + ".%" // r:<id>. — swarm primitive names
	kvNS := ns(id)       // r:<id>   — kv namespace (keys hang off it)
	mbox := box(id)      // r<id>    — mailbox box
	stmts := []struct {
		sql  string
		args []any
	}{
		{`DELETE FROM locks WHERE name LIKE $1`, []any{pfx}},
		{`DELETE FROM barrier_parties WHERE name LIKE $1`, []any{pfx}},
		{`DELETE FROM barrier_gens WHERE name LIKE $1`, []any{pfx}},
		{`DELETE FROM barriers WHERE name LIKE $1`, []any{pfx}},
		{`DELETE FROM kv WHERE ns = $1`, []any{kvNS}},
		{`DELETE FROM topic_msgs WHERE topic LIKE $1`, []any{pfx}},
		{`DELETE FROM topic_cursors WHERE topic LIKE $1`, []any{pfx}},
		{`DELETE FROM topics WHERE name LIKE $1`, []any{pfx}},
		{`DELETE FROM q_items WHERE queue LIKE $1`, []any{pfx}},
		{`DELETE FROM queues WHERE name LIKE $1`, []any{pfx}},
		{`DELETE FROM mail WHERE box = $1`, []any{mbox}},
		{`DELETE FROM mb_cursors WHERE box = $1`, []any{mbox}},
		{`DELETE FROM mb_boxes WHERE box = $1`, []any{mbox}},
		{`DELETE FROM room_members WHERE room = $1`, []any{id}},
		{`DELETE FROM rooms WHERE id = $1`, []any{id}},
	}
	for _, s := range stmts {
		if _, err := q.Exec(ctx, s.sql, s.args...); err != nil {
			return err
		}
	}
	return nil
}

// Janitor runs the room maintenance: it closes live rooms that have exceeded a room-wide cap (to
// new writes; IsMember reports the flip) and, at until, deletes every r:<id> row and the room. Each
// expired room is torn down in its own transaction so one failure does not strand the rest.
func Janitor(ctx context.Context, pool *pgxpool.Pool) error {
	if err := enforceCaps(ctx, pool); err != nil {
		return err
	}
	rows, err := pool.Query(ctx, `SELECT id FROM rooms WHERE until < now()`)
	if err != nil {
		return err
	}
	var expired []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		expired = append(expired, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range expired {
		if err := core.Tx(ctx, pool, func(tx pgx.Tx) error { return cleanupRoom(ctx, tx, id) }); err != nil {
			return err
		}
	}
	return nil
}

// enforceCaps closes any live room whose primitive counts exceed a room-wide cap. It only ever
// closes (never reopens): an operator reopens an over-cap room with the o: report-target restore.
func enforceCaps(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT id FROM rooms WHERE NOT closed AND until > now()`)
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
		c, err := countRoom(ctx, q, id)
		if err != nil {
			return err
		}
		if c.overCap() {
			if _, err := q.Exec(ctx, `UPDATE rooms SET closed = true WHERE id = $1`, id); err != nil {
				return err
			}
		}
	}
	return nil
}

// purge is the OnPurge hook: a departing root's owned rooms are torn down like an expiry (every
// r:<id> row), and the root is dropped from the membership of any room it merely joined.
func purge(ctx context.Context, pool *pgxpool.Pool, root string) error {
	rows, err := pool.Query(ctx, `SELECT id FROM rooms WHERE owner_root = $1`, root)
	if err != nil {
		return err
	}
	var owned []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		owned = append(owned, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range owned {
		if err := cleanupRoom(ctx, pool, id); err != nil {
			return err
		}
	}
	if _, err := pool.Exec(ctx, `DELETE FROM room_members WHERE root = $1`, root); err != nil {
		return err
	}
	return nil
}

// Report target o:<id> (4.7): a room exists while its row lives; hide closes it (IsMember then
// refuses, as for an over-cap room); restore reopens it.
func exists(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'o') {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM rooms WHERE id = $1)`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func hide(ctx context.Context, q core.Q, ref string) error { return setClosed(ctx, q, ref, true) }

func restore(ctx context.Context, q core.Q, ref string) error { return setClosed(ctx, q, ref, false) }

func setClosed(ctx context.Context, q core.Q, ref string, on bool) error {
	if !core.ValidIDPrefix(ref, 'o') {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `UPDATE rooms SET closed = $2 WHERE id = $1`, ref, on)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return nil
}
