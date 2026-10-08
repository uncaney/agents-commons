package ctlog

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/notary"
)

// janitor is the ctlog task (added to the 30 s janitor, SPEC-v2 27.6): it stamps the catalog's
// verified versions, pins and distinct-donor attestations into the notary, backfills each sealed
// day's chain, enqueues the Wayback snapshots of freshly sealed days, and flags verified versions
// that stayed out of the log for more than 48 h.
func (s *svc) janitor(ctx context.Context) error {
	if err := s.stampVersions(ctx); err != nil {
		return err
	}
	if err := s.stampPins(ctx); err != nil {
		return err
	}
	if err := s.stampAtts(ctx); err != nil {
		return err
	}
	sealed, err := s.sealChains(ctx)
	if err != nil {
		return err
	}
	for _, day := range sealed {
		if err := s.enqueueWayback(ctx, day); err != nil {
			return err
		}
	}
	return s.scanUnlogged(ctx)
}

// stampLeaf stamps h with note for the system root and records the ctlog_state cursor in one tx.
// First-seen semantics in notary.Stamp make it idempotent; the cursor skips stamped leaves.
func (s *svc) stampLeaf(ctx context.Context, kind, ref string, h []byte, note string) error {
	if len(note) > maxNote {
		note = note[:maxNote]
	}
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		n, _, err := notary.Stamp(ctx, tx, h, note, core.SystemID)
		if err != nil {
			return err
		}
		_, err = tx.Exec(ctx, `INSERT INTO ctlog_state (kind, ref, n) VALUES ($1, $2, $3)
			ON CONFLICT (kind, ref) DO NOTHING`, kind, ref, n)
		return err
	})
}

// stampVersions stamps a svc1 leaf for every verified service version not yet in the log.
func (s *svc) stampVersions(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT v.name, v.ver, v.wasm FROM service_versions v
		WHERE v.state = 'verified'
		AND NOT EXISTS (SELECT 1 FROM ctlog_state c WHERE c.kind = 'svc' AND c.ref = v.name || '@' || v.ver)
		ORDER BY v.verified_at NULLS LAST, v.name, v.ver LIMIT $1`, stampBatch)
	if err != nil {
		return err
	}
	type row struct {
		name, wasm string
		ver        int
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.ver, &r.wasm); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range todo {
		ref := r.name + "@" + strconv.Itoa(r.ver)
		if err := s.stampLeaf(ctx, "svc", ref, svcHash(r.name, r.ver, r.wasm), "svc "+ref); err != nil {
			return err
		}
	}
	return nil
}

// stampPins stamps a pin1 leaf for every pin row not yet in the log.
func (s *svc) stampPins(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT hash FROM pins p
		WHERE NOT EXISTS (SELECT 1 FROM ctlog_state c WHERE c.kind = 'pin' AND c.ref = p.hash)
		ORDER BY p.created LIMIT $1`, stampBatch)
	if err != nil {
		return err
	}
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			rows.Close()
			return err
		}
		hashes = append(hashes, h)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, h := range hashes {
		short := h
		if len(short) > 12 {
			short = short[:12]
		}
		if err := s.stampLeaf(ctx, "pin", h, pinHash(h), "pin "+short); err != nil {
			return err
		}
	}
	return nil
}

// stampAtts stamps the att1 line of every distinct-donor (att_d) job not yet in the log.
func (s *svc) stampAtts(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT id, att FROM jobs
		WHERE att_d AND att <> ''
		AND NOT EXISTS (SELECT 1 FROM ctlog_state c WHERE c.kind = 'att' AND c.ref = jobs.id)
		ORDER BY finished_at NULLS LAST, id LIMIT $1`, stampBatch)
	if err != nil {
		return err
	}
	type row struct{ id, att string }
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.att); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range todo {
		if err := s.stampLeaf(ctx, "att", r.id, attHash(r.att), "att "+r.id); err != nil {
			return err
		}
	}
	return nil
}

// sealChains backfills the chain column of every sealed day in order and returns the days whose
// chain it set for the first time (a fresh seal from this package's point of view).
func (s *svc) sealChains(ctx context.Context) ([]string, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT day, root, chain FROM ts_days ORDER BY day`)
	if err != nil {
		return nil, err
	}
	type day struct {
		day    string
		root   []byte
		hasChn bool
	}
	var days []day
	for rows.Next() {
		var dt time.Time
		var d day
		var chain []byte
		if err := rows.Scan(&dt, &d.root, &chain); err != nil {
			rows.Close()
			return nil, err
		}
		d.day = dt.UTC().Format("2006-01-02")
		d.hasChn = len(chain) == 32
		days = append(days, d)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	running := genesis
	var fresh []string
	for _, d := range days {
		running = chainStep(running, d.root)
		if !d.hasChn {
			if _, err := s.d.DB.Exec(ctx, `UPDATE ts_days SET chain = $1 WHERE day = $2 AND chain IS NULL`, running, d.day); err != nil {
				return nil, err
			}
			fresh = append(fresh, d.day)
		}
	}
	return fresh, nil
}

// enqueueWayback enqueues the fixed set of Wayback snapshots after a day seal, under a 10/day cap.
func (s *svc) enqueueWayback(ctx context.Context, day string) error {
	var used int
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM egress_outbox WHERE kind = 'wayback' AND created > now() - interval '1 day'`).Scan(&used); err != nil {
		return err
	}
	for _, t := range waybackTargets {
		if used >= waybackDaily {
			break
		}
		p := waybackPayload{URL: t.path, Kind: t.kind, File: t.file}
		if t.kind == "ts" {
			p.Day = day
		}
		if err := core.Egress(ctx, s.d.DB, "wayback", p); err != nil {
			if err == core.ErrOutboxFull {
				break
			}
			return err
		}
		used++
	}
	return nil
}

// scanUnlogged flags verified versions still absent from the log 48 h after verification: one inbox
// event per owner (once, tracked in ctlog_state kind 'unlogged').
func (s *svc) scanUnlogged(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT v.name, v.ver, v.wasm, s.owner_root FROM service_versions v
		JOIN services s ON s.name = v.name
		WHERE v.state = 'verified' AND v.verified_at IS NOT NULL
		AND v.verified_at < now() - interval '`+unloggedAfter+`'
		AND NOT EXISTS (SELECT 1 FROM ctlog_state c WHERE c.kind = 'unlogged' AND c.ref = v.name || '@' || v.ver)
		ORDER BY v.verified_at LIMIT $1`, stampBatch)
	if err != nil {
		return err
	}
	type row struct {
		name, wasm, owner string
		ver               int
	}
	var todo []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.name, &r.ver, &r.wasm, &r.owner); err != nil {
			rows.Close()
			return err
		}
		todo = append(todo, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range todo {
		var seq int64
		err := s.d.DB.QueryRow(ctx, `SELECT n FROM ts WHERE h = $1`, svcHash(r.name, r.ver, r.wasm)).Scan(&seq)
		if err == nil {
			continue // actually logged: the warning does not apply
		}
		if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		ref := r.name + "@" + strconv.Itoa(r.ver)
		if txErr := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			if err := core.Event(ctx, tx, "ctlog", ref, r.owner,
				fmt.Sprintf("service %s verified 48h ago is not in the transparency log (unlogged!)", ref)); err != nil {
				return err
			}
			_, err := tx.Exec(ctx, `INSERT INTO ctlog_state (kind, ref, n) VALUES ('unlogged', $1, 0)
				ON CONFLICT (kind, ref) DO NOTHING`, ref)
			return err
		}); txErr != nil {
			return txErr
		}
	}
	return nil
}
