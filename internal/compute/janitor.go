package compute

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

func (s *svc) registerJanitor() {
	s.d.Janitor.Add("compute_leases", s.requeueExpired)
	s.d.Janitor.Add("compute_stuck", s.capStuck)
	s.d.Janitor.Add("compute_blobs", s.gcBlobs)
	s.d.Janitor.Add("compute_tmp", s.sweepTmp)
	s.d.Janitor.Add("compute_retention", s.retention)
	s.d.OnPurge(s.purge)
}

func scanStrings(rows pgx.Rows, err error) ([]string, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// requeueExpired puts replicas whose lease deadline passed back in the queue. The root that
// let the lease expire is remembered on the replica (never re-leased to it) and loses rep 1,
// at most expireRepCap per day (review #7). Cancelled replicas past their deadline are dropped
// (the donor has been told, or stopped polling).
func (s *svc) requeueExpired(ctx context.Context) error {
	var jobs, roots []string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		jobs, roots = nil, nil
		if _, err := tx.Exec(ctx, `DELETE FROM replicas WHERE state = 'cancelled' AND (deadline IS NULL OR deadline < now())`); err != nil {
			return err
		}
		rows, err := tx.Query(ctx, `WITH e AS (SELECT id, job, worker_root FROM replicas WHERE state = 'leased' AND deadline < now() FOR UPDATE SKIP LOCKED)
			UPDATE replicas r SET state = 'queued', lease = NULL, worker = NULL, worker_root = NULL, deadline = NULL, leased_at = NULL,
				excluded_roots = array_append(r.excluded_roots, e.worker_root)
			FROM e WHERE r.id = e.id RETURNING e.job, e.worker_root`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var j, r string
			if err := rows.Scan(&j, &r); err != nil {
				rows.Close()
				return err
			}
			jobs, roots = append(jobs, j), append(roots, r)
		}
		rows.Close()
		if err := rows.Err(); err != nil || len(jobs) == 0 {
			return err
		}
		for _, r := range roots {
			n, err := bumpDaily(ctx, tx, r, "rep:expire", 1)
			if err != nil {
				return err
			}
			if n <= expireRepCap {
				if _, err := core.AddRep(ctx, tx, r, -1, "", 0); err != nil {
					return err
				}
			}
		}
		_, err = tx.Exec(ctx, `UPDATE jobs SET status = 'queued' WHERE id = ANY($1) AND status = 'running'
			AND NOT EXISTS (SELECT 1 FROM replicas r WHERE r.job = jobs.id AND r.state <> 'queued')`, jobs)
		return err
	})
	if err != nil || len(jobs) == 0 {
		return err
	}
	s.d.Notify.Wake("lease")
	return nil
}

// sweepTmp removes upload temp files older than 1 h left by a process that died mid-upload.
func (s *svc) sweepTmp(context.Context) error {
	ents, err := os.ReadDir(filepath.Join(s.blobDir(), "tmp"))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	for _, e := range ents {
		if info, err := e.Info(); err == nil && time.Since(info.ModTime()) > time.Hour {
			os.Remove(filepath.Join(s.blobDir(), "tmp", e.Name()))
		}
	}
	return nil
}

type cancelled struct {
	id, submitter string
	reserved      int64
}

// cancelJobs fails every active job matching where (its params start at $2; $1 is the reason)
// with a full refund and drops its queued replicas. mark keeps leased replicas as 'cancelled' so
// the donor's done answers 410 (explicit cancels, 14.3); the v1 paths (timeout-queue, purge)
// delete them (404). Returns the cancelled job ids.
func cancelJobs(ctx context.Context, tx pgx.Tx, where, reason string, mark bool, args ...any) ([]string, error) {
	rows, err := tx.Query(ctx, `UPDATE jobs SET status = 'failed', reason = $1, finished_at = now()
		WHERE status IN ('queued','running') AND (`+where+`) RETURNING id, submitter, reserved`, append([]any{reason}, args...)...)
	if err != nil {
		return nil, err
	}
	var cs []cancelled
	for rows.Next() {
		var c cancelled
		if err := rows.Scan(&c.id, &c.submitter, &c.reserved); err != nil {
			rows.Close()
			return nil, err
		}
		cs = append(cs, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil || len(cs) == 0 {
		return nil, err
	}
	ids := make([]string, 0, len(cs))
	for _, c := range cs {
		if err := core.Refund(ctx, tx, c.submitter, c.reserved); err != nil {
			return nil, err
		}
		ids = append(ids, c.id)
	}
	if mark {
		if _, err := tx.Exec(ctx, `UPDATE replicas SET state = 'cancelled' WHERE job = ANY($1) AND state = 'leased'`, ids); err != nil {
			return nil, err
		}
		_, err = tx.Exec(ctx, `DELETE FROM replicas WHERE job = ANY($1) AND state = 'queued'`, ids)
		return ids, err
	}
	_, err = tx.Exec(ctx, `DELETE FROM replicas WHERE job = ANY($1) AND state <> 'reported'`, ids)
	return ids, err
}

// capStuck fails jobs still unfinished 24 h after submission (timeout-queue) and jobs past
// their max_wait_s (max_wait), both with a full refund (14.3).
func (s *svc) capStuck(ctx context.Context) error {
	var ids []string
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		a, err := cancelJobs(ctx, tx, `created < now() - make_interval(hours => $2)`, "timeout-queue", false, stuckHours)
		if err != nil {
			return err
		}
		b, err := cancelJobs(ctx, tx, `max_wait_until IS NOT NULL AND max_wait_until < now()`, "max_wait", true)
		ids = append(a, b...)
		return err
	})
	for _, id := range ids {
		s.d.Notify.Wake("job:" + id)
	}
	return err
}

// gcBlobs deletes blobs unreferenced for 7 days (v1), opaque blobs no job used within 24 h and
// private blobs after 24 h (27.6 tenure); pinned blobs and the blobs of unfinished jobs stay.
func (s *svc) gcBlobs(ctx context.Context) error {
	hashes, err := scanStrings(s.d.DB.Query(ctx, `SELECT hash FROM blobs b
		WHERE b.pinned_by = ''
		  AND (last_ref < now() - make_interval(days => $1)
		       OR (kind = 'opaque' AND used_at IS NULL AND created < now() - make_interval(hours => $2))
		       OR (private AND created < now() - make_interval(hours => $2)))
		  AND NOT EXISTS (SELECT 1 FROM jobs j WHERE j.status IN ('queued','running') AND (j.wasm = b.hash OR j.input = b.hash OR j.fs = b.hash))
		  AND NOT EXISTS (SELECT 1 FROM replicas r JOIN jobs j ON j.id = r.job WHERE r.out = b.hash AND j.status IN ('queued','running'))
		LIMIT 500`, blobTTLDays, tenureHours))
	if err != nil {
		return err
	}
	for _, h := range hashes {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `DELETE FROM blobs WHERE hash = $1 AND pinned_by = ''
				AND (last_ref < now() - make_interval(days => $2)
				     OR (kind = 'opaque' AND used_at IS NULL AND created < now() - make_interval(hours => $3))
				     OR (private AND created < now() - make_interval(hours => $3)))`, h, blobTTLDays, tenureHours)
			if err != nil || tag.RowsAffected() == 0 {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM blob_meta WHERE hash = $1 AND banned = ''`, h); err != nil {
				return err
			}
			return s.removeFile(h)
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// retention rolls finished jobs older than retentionD days into job_stats_daily, then deletes
// them (replicas cascade), 1000 per tick (14.6).
func (s *svc) retention(ctx context.Context) error {
	for i := 0; i < 20; i++ {
		var n int64
		err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			tag, err := tx.Exec(ctx, `WITH old AS (
				SELECT id, finished_at::date AS day, used_ms, charged, cached_from <> '' AS cached, saved_ms, saved_credits
				FROM jobs WHERE finished_at < now() - make_interval(days => $1) ORDER BY finished_at LIMIT 1000 FOR UPDATE SKIP LOCKED),
			agg AS (
				INSERT INTO job_stats_daily (day, jobs, ms, credits, cached, saved_ms, saved_credits)
				SELECT day, count(*), coalesce(sum(used_ms), 0), coalesce(sum(charged), 0), count(*) FILTER (WHERE cached),
				       coalesce(sum(saved_ms), 0), coalesce(sum(saved_credits), 0) FROM old GROUP BY day
				ON CONFLICT (day) DO UPDATE SET jobs = job_stats_daily.jobs + EXCLUDED.jobs, ms = job_stats_daily.ms + EXCLUDED.ms,
					credits = job_stats_daily.credits + EXCLUDED.credits, cached = job_stats_daily.cached + EXCLUDED.cached,
					saved_ms = job_stats_daily.saved_ms + EXCLUDED.saved_ms, saved_credits = job_stats_daily.saved_credits + EXCLUDED.saved_credits
				RETURNING day)
			DELETE FROM jobs WHERE id IN (SELECT id FROM old)`, retentionD)
			if err != nil {
				return err
			}
			n = tag.RowsAffected()
			return nil
		})
		if err != nil || n < 1000 {
			return err
		}
	}
	return nil
}

// purge drops a purged tree's blobs (files + rows), releases its leases and cancels its jobs.
func (s *svc) purge(ctx context.Context, id string) error {
	ids, err := core.Descendants(ctx, s.d.DB, id)
	if err != nil || len(ids) == 0 {
		return err
	}
	var jobs []string
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		hashes, err := scanStrings(tx.Query(ctx, `DELETE FROM blobs WHERE owner_root = ANY($1) AND pinned_by = '' RETURNING hash`, ids))
		if err != nil {
			return err
		}
		for _, h := range hashes {
			if _, err := tx.Exec(ctx, `DELETE FROM blob_meta WHERE hash = $1 AND banned = ''`, h); err != nil {
				return err
			}
			if err := s.removeFile(h); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `UPDATE replicas SET state = 'queued', lease = NULL, worker = NULL, worker_root = NULL, deadline = NULL, leased_at = NULL
			WHERE worker = ANY($1) AND state = 'leased'`, ids); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM replicas WHERE worker = ANY($1) AND state = 'cancelled'`, ids); err != nil {
			return err
		}
		jobs, err = cancelJobs(ctx, tx, `submitter = ANY($2)`, "purged", false, ids)
		return err
	})
	if err != nil {
		return err
	}
	s.d.Notify.Wake("lease")
	for _, j := range jobs {
		s.d.Notify.Wake("job:" + j)
	}
	return nil
}
