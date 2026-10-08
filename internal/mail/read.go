package mail

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// Env is one envelope: everything a list shows, never the body.
type Env struct {
	ID, Box, From, FromRoot string
	Re, Subject             string
	Seq                     int64
	Size                    int
	At                      time.Time
	Flags                   []string
	Lvl                     int
	Age                     time.Duration
	Sys                     bool
}

const envCols = `id, box, seq, from_id, from_root, re, subject, size, created, flags`

// Line renders `m… <seq> from <id> lvl=L1 age=3d <date> re=<id> <size> <subject>`; sealed rows
// (flag enc) show `enc=1 bucket=<k>` in place of the exact size (26.4). The sender id, re and
// subject are the only user-influenced parts and never start the line.
func (e Env) Line() string {
	re := doc.SafeLine(e.Re)
	if re == "" {
		re = "-"
	}
	subj := doc.SafeLine(e.Subject)
	if subj == "" {
		subj = "-"
	}
	lvl, age := "L"+strconv.Itoa(e.Lvl), ageText(e.Age)
	if e.Sys {
		lvl, age = "-", "-"
	}
	size := strconv.Itoa(e.Size)
	if hasFlag(e.Flags, "enc") {
		size = "enc=1 bucket=" + bucket(e.Size)
	}
	return fmt.Sprintf("%s %d from %s lvl=%s age=%s %s re=%s %s %s", e.ID, e.Seq, doc.SafeLine(e.From), lvl, age, core.Date(e.At), re, size, subj)
}

// bucket is the E2EE 2.5 size bucket of a sealed body.
func bucket(size int) string {
	switch {
	case size <= 1024:
		return "1k"
	case size <= 2048:
		return "2k"
	}
	return "4k"
}

func ageText(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < 24*time.Hour {
		return strconv.Itoa(int(d/time.Hour)) + "h"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d"
}

func scanEnv(row pgx.Row) (Env, error) {
	var e Env
	err := row.Scan(&e.ID, &e.Box, &e.Seq, &e.From, &e.FromRoot, &e.Re, &e.Subject, &e.Size, &e.At, &e.Flags)
	e.Sys = e.From == SysID
	return e, err
}

func readEnvs(rows pgx.Rows, err error) ([]Env, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Env
	for rows.Next() {
		e, err := scanEnv(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// decorate fills the sender standing (lvl, age) of every envelope, one trust.Load per sender.
func decorate(ctx context.Context, q core.Q, envs []Env) error {
	type st struct {
		lvl int
		age time.Duration
	}
	cache := map[string]st{}
	for i := range envs {
		e := &envs[i]
		if e.Sys {
			continue
		}
		s, ok := cache[e.FromRoot]
		if !ok {
			if ld, err := trust.Load(ctx, q, e.FromRoot); err == nil {
				s = st{ld.Level(), ld.Age}
			} else if !errors.Is(err, core.ErrNotFound) {
				return err
			}
			cache[e.FromRoot] = s
		}
		e.Lvl, e.Age = s.lvl, s.age
	}
	return nil
}

// PullBox returns up to k envelopes of box with seq > after (oldest first) and the cursor to
// continue from (the last seq returned, else after).
func PullBox(ctx context.Context, q core.Q, box string, after int64, k int) ([]Env, int64, error) {
	envs, err := readEnvs(q.Query(ctx, `SELECT `+envCols+` FROM mail WHERE box = $1 AND seq > $2 AND delivered AND NOT hidden AND expires > now()
		ORDER BY seq LIMIT $3`, box, after, clampK(k)))
	if err != nil {
		return nil, 0, err
	}
	if err := decorate(ctx, q, envs); err != nil {
		return nil, 0, err
	}
	next := after
	if len(envs) > 0 {
		next = envs[len(envs)-1].Seq
	}
	return envs, next, nil
}

// PullTree returns up to k envelopes across every personal box of a root's tree, ordered by
// (created, id) behind an opaque cursor (?all=1, root full token only).
func PullTree(ctx context.Context, q core.Q, root, cursor string, k int) ([]Env, string, error) {
	var ts time.Time
	var id string
	if cursor != "" {
		var ok bool
		if ts, id, ok = doc.DecodeCursor(cursor); !ok {
			return nil, "", core.Bad("after must be the cursor of the previous reply")
		}
	}
	envs, err := readEnvs(q.Query(ctx, `SELECT m.id, m.box, m.seq, m.from_id, m.from_root, m.re, m.subject, m.size, m.created, m.flags
		FROM mail m JOIN identities i ON i.id = m.box
		WHERE i.root = $1 AND m.delivered AND NOT m.hidden AND m.expires > now() AND (m.created, m.id) > ($2::timestamptz, $3::text)
		ORDER BY m.created, m.id LIMIT $4`, root, ts, id, clampK(k)))
	if err != nil {
		return nil, "", err
	}
	if err := decorate(ctx, q, envs); err != nil {
		return nil, "", err
	}
	next := cursor
	if len(envs) > 0 {
		last := envs[len(envs)-1]
		next = doc.Cursor(last.At, last.ID)
	}
	return envs, next, nil
}

func clampK(k int) int {
	if k <= 0 {
		return DefK
	}
	return min(k, MaxK)
}

// Cursor returns a member's read cursor on a group or room box (0 when none).
func Cursor(ctx context.Context, q core.Q, box, root string) (int64, error) {
	var seq int64
	err := q.QueryRow(ctx, `SELECT coalesce((SELECT seq FROM mb_cursors WHERE box = $1 AND root = $2), 0)`, box, root).Scan(&seq)
	return seq, err
}

func advanceCursor(ctx context.Context, q core.Q, box, root string, seq int64) error {
	_, err := q.Exec(ctx, `INSERT INTO mb_cursors (box, root, seq) VALUES ($1, $2, $3)
		ON CONFLICT (box, root) DO UPDATE SET seq = greatest(mb_cursors.seq, EXCLUDED.seq)`, box, root, seq)
	return err
}

// Load reads one live message (envelope + body); hidden, undelivered, expired and unknown ids are
// all core.ErrNotFound.
func Load(ctx context.Context, q core.Q, id string) (*Env, string, error) {
	if !core.ValidIDPrefix(id, 'm') {
		return nil, "", core.ErrNotFound
	}
	var e Env
	var text string
	err := q.QueryRow(ctx, `SELECT `+envCols+`, text FROM mail WHERE id = $1 AND delivered AND NOT hidden AND expires > now()`, id).
		Scan(&e.ID, &e.Box, &e.Seq, &e.From, &e.FromRoot, &e.Re, &e.Subject, &e.Size, &e.At, &e.Flags, &text)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, "", core.ErrNotFound
	}
	if err != nil {
		return nil, "", err
	}
	e.Sys = e.From == SysID
	if err := decorate(ctx, q, []Env{e}); err != nil {
		return nil, "", err
	}
	return &e, text, nil
}

// MarkRead records a read: read_at is set once (the first member read clears a group row's
// "unread" for the one-pending rule), personal boxes count the pair read, group and room boxes
// advance the reader's cursor.
func MarkRead(ctx context.Context, q core.Q, e *Env, b *Box, readerRoot string) error {
	tag, err := q.Exec(ctx, `UPDATE mail SET read_at = now() WHERE id = $1 AND read_at IS NULL`, e.ID)
	if err != nil {
		return err
	}
	if b.Kind != 'a' {
		return advanceCursor(ctx, q, e.Box, readerRoot, e.Seq)
	}
	if tag.RowsAffected() > 0 && hasFlag(e.Flags, "later") {
		// Self-messages (10.4) came through mem's updatable view: tell it the row was read.
		// Best effort, the view is mem's and may be absent.
		if _, err := q.Exec(ctx, `UPDATE mem_later_delivered SET read_at = now() WHERE id = $1 AND read_at IS NULL
			AND to_regclass('mem_later_delivered') IS NOT NULL`, e.ID); err != nil {
			return nil
		}
	}
	if tag.RowsAffected() == 0 || e.Sys || e.FromRoot == b.OwnerRoot {
		return nil
	}
	_, err = q.Exec(ctx, `UPDATE mb_pairs SET reads = reads + 1 WHERE from_root = $1 AND to_root = $2`, e.FromRoot, b.OwnerRoot)
	return err
}

// Ack removes a message from a personal box (idempotent) or advances a member's cursor past it.
func Ack(ctx context.Context, q core.Q, e *Env, b *Box, readerRoot string) error {
	if b.Kind != 'a' {
		return advanceCursor(ctx, q, e.Box, readerRoot, e.Seq)
	}
	_, err := q.Exec(ctx, `DELETE FROM mail WHERE id = $1 AND box = $2`, e.ID, e.Box)
	return err
}

// Unread counts the live unread messages of a root's personal boxes and the system ones among them.
func Unread(ctx context.Context, q core.Q, root string) (n, sys int, err error) {
	err = q.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE m.from_id = $2) FROM mail m JOIN identities i ON i.id = m.box
		WHERE i.root = $1 AND m.read_at IS NULL AND m.delivered AND NOT m.hidden AND m.expires > now()`, root, SysID).Scan(&n, &sys)
	return
}

// importLater copies delivered self-messages (10.4) into the root's own box through the view
// mem_later_delivered when the mem package is installed; the message id is shared, so the copy
// is idempotent and mail never writes mem's tables.
func importLater(ctx context.Context, q core.Q, root string) error {
	var reg *string
	if err := q.QueryRow(ctx, `SELECT to_regclass('mem_later_delivered')::text`).Scan(&reg); err != nil || reg == nil {
		return err
	}
	rows, err := q.Query(ctx, `SELECT id, coalesce(subject, ''), coalesce(text, '') FROM mem_later_delivered v
		WHERE v.root = $1 AND NOT EXISTS (SELECT 1 FROM mail m WHERE m.id = v.id) ORDER BY delivered_at NULLS LAST, id LIMIT 50`, root)
	if err != nil {
		return err
	}
	type later struct{ id, subject, text string }
	var ls []later
	for rows.Next() {
		var l later
		if err := rows.Scan(&l.id, &l.subject, &l.text); err != nil {
			rows.Close()
			return err
		}
		ls = append(ls, l)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, l := range ls {
		if !core.ValidIDPrefix(l.id, 'm') {
			continue
		}
		text := strings.TrimRight(doc.CleanMulti(l.text), "\n")
		if len(text) > MaxText {
			text = strings.ToValidUTF8(text[:MaxText], "")
		}
		var seq int64
		if err := q.QueryRow(ctx, `INSERT INTO mb_boxes (box, owner_root, next_seq) VALUES ($1, $1, 2)
			ON CONFLICT (box) DO UPDATE SET next_seq = mb_boxes.next_seq + 1 RETURNING next_seq - 1`, root).Scan(&seq); err != nil {
			return err
		}
		if _, err := q.Exec(ctx, `INSERT INTO mail (id, box, seq, from_id, from_root, re, subject, text, size, flags)
			VALUES ($1, $2, $3, $2, $2, 'later', $4, $5, $6, '{later}') ON CONFLICT (id) DO NOTHING`,
			l.id, root, seq, cutRunes(doc.SafeLine(l.subject), MaxSubject), text, len(text)); err != nil {
			return err
		}
	}
	return nil
}
