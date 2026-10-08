package anonwait

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/forge"
)

const (
	maxLiveGroup  = 5                // live wait-lane tickets per IP group
	maxLiveSuper  = 20               // ... and per super-group
	matPerGroup   = 2                // ticket materialisations per IP group per day
	ticketTTL     = 10 * time.Minute // a ticket is -32001 past this
	materialiseAt = 30 * time.Second // ... and materialises no earlier than this
)

// Pending stores an anonymous A2A message/send as a wait-lane ticket (a2a.PendingFn): it mints a
// `q…` id, HMACs the caller's network keys and parks the text, enforcing 5 live tickets per group
// and 20 per super-group. The returned ticket is the working Task id tasks/get polls.
func Pending(ctx context.Context, q core.Q, grp, super, text string) (string, error) {
	if len(text) > 4096 {
		return "", core.Bad("text <= 4 KiB")
	}
	d := depsOrNil()
	if d == nil {
		return "", core.E(500, "internal", "anonwait not registered")
	}
	gh, sh := grpHash(grp), grpHash(super)
	ticket := core.NewID('q')
	err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var live, liveSuper int
		if err := tx.QueryRow(ctx, `SELECT
			count(*) FILTER (WHERE grp_h = $1),
			count(*) FILTER (WHERE super_h = $2)
			FROM a2a_pending WHERE n IS NULL AND created > now() - interval '10 minutes'`, gh, sh).Scan(&live, &liveSuper); err != nil {
			return err
		}
		if live >= maxLiveGroup || liveSuper >= maxLiveSuper {
			return core.E(429, "quota", "too many live tickets, retry when they materialise or expire")
		}
		_, err := tx.Exec(ctx, `INSERT INTO a2a_pending (ticket, text, grp_h, super_h) VALUES ($1, $2, $3, $4)`, ticket, text, gh, sh)
		return err
	})
	if err != nil {
		return "", err
	}
	return ticket, nil
}

// PendingGet materialises or reports a wait-lane ticket (a2a.PendingGetFn). Before 30 s it returns
// the same working Task (n <= 0); between 30 s and 10 min it creates a quarantined board task under
// the /w/t caps and returns its number (which the ticket then keeps); past 10 min it deletes the
// row and reports core.ErrNotFound (-32001).
func PendingGet(ctx context.Context, d *core.Deps, ticket string) (int64, string, error) {
	var (
		text           string
		gh, sh         []byte
		created        time.Time
		n              *int64
		expired, claim bool
	)
	err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		err := tx.QueryRow(ctx, `SELECT text, grp_h, super_h, created, n FROM a2a_pending WHERE ticket = $1 FOR UPDATE`, ticket).
			Scan(&text, &gh, &sh, &created, &n)
		if errors.Is(err, pgx.ErrNoRows) {
			return core.ErrNotFound
		}
		if err != nil {
			return err
		}
		if n != nil {
			return nil // already materialised (or -1: being materialised by a concurrent get)
		}
		age := now().Sub(created)
		if age >= ticketTTL {
			// Commit the delete: return nil and report -32001 afterwards (an error would roll it back).
			expired = true
			_, err := tx.Exec(ctx, `DELETE FROM a2a_pending WHERE ticket = $1`, ticket)
			return err
		}
		if age < materialiseAt {
			return nil // too early: the same working ticket
		}
		// Claim the ticket for materialisation (2/day per group) so concurrent gets do not double-create.
		mat, err := bumpCounter(ctx, tx, "qmat:"+hex.EncodeToString(gh))
		if err != nil {
			return err
		}
		if mat > matPerGroup {
			return core.E(429, "quota", "ticket materialisation limit reached, retry tomorrow")
		}
		claim = true
		_, err = tx.Exec(ctx, `UPDATE a2a_pending SET n = -1 WHERE ticket = $1`, ticket)
		return err
	})
	if err != nil {
		return 0, "", err
	}
	if expired {
		return 0, "", core.ErrNotFound
	}
	if n != nil && *n > 0 {
		return *n, "", nil // settled board task
	}
	if !claim {
		return 0, forgeWorking, nil // too early, or being materialised: the working Task
	}
	// Materialise outside the claim tx (forge.CreateTask runs its own transaction).
	title, body := splitText(text)
	taskN, cerr := forge.CreateTask(ctx, d, nil, forge.TaskInput{
		Title: title, Body: body, Anon: true,
		Grp: hex.EncodeToString(gh), Super: hex.EncodeToString(sh),
	})
	if cerr != nil {
		// Release the claim so a later get can retry.
		d.DB.Exec(ctx, `UPDATE a2a_pending SET n = NULL WHERE ticket = $1 AND n = -1`, ticket)
		return 0, "", cerr
	}
	if _, err := d.DB.Exec(ctx, `UPDATE a2a_pending SET n = $2 WHERE ticket = $1`, ticket, taskN); err != nil {
		return 0, "", err
	}
	return taskN, "", nil
}

const forgeWorking = "working"

// splitText derives a one-line title (<= 160) and the body from a ticket's text.
func splitText(text string) (title, body string) {
	text = strings.TrimSpace(text)
	title = text
	if i := strings.IndexByte(text, '\n'); i >= 0 {
		title, body = strings.TrimSpace(text[:i]), text
	}
	if title == "" {
		title = "anonymous ticket"
	}
	if r := []rune(title); len(r) > 160 {
		title = string(r[:160])
	}
	return title, body
}

// bumpCounter increments today's counter for scope and returns the new value (same shape as
// core.UseIPQuota's backing store, without its 'ip:' prefix convention).
func bumpCounter(ctx context.Context, q core.Q, scope string) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, 'anonwait', current_date, 1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`, scope).Scan(&n)
	return n, err
}
