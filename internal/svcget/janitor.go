package svcget

import (
	"context"
	"sync"
	"time"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
)

var (
	precomputeMu   sync.Mutex
	lastPrecompute time.Time
)

// janitor runs the demand-driven precompute at most hourly (27.6). The work itself lives in
// precompute so tests drive it directly.
func (s *svc) janitor(ctx context.Context) error {
	precomputeMu.Lock()
	due := lastPrecompute.IsZero() || time.Since(lastPrecompute) >= time.Hour
	if due {
		lastPrecompute = time.Now()
	}
	precomputeMu.Unlock()
	if !due {
		return nil
	}
	return s.precompute(ctx)
}

// candidate is one precompute-eligible demand row.
type candidate struct {
	name, sha string
	h         []byte
}

// precompute turns standing demand into system jobs: a verified stable service whose input has been
// missed by at least missGroups distinct day-HMAC'd super-groups within the window is submitted as a
// normal 2-replica system job from the faucet, under the daily cap. It never runs on the gateway and
// never computes from an anonymous GET; the GET only records demand.
func (s *svc) precompute(ctx context.Context) error {
	cands, err := s.candidates(ctx)
	if err != nil || len(cands) == 0 {
		return err
	}
	done, err := s.countToday(ctx)
	if err != nil {
		return err
	}
	for _, c := range cands {
		if done >= precomputeCap {
			return core.Event(ctx, s.d.DB, "ops", "svc_precompute_cap", "", "svc_precompute hit the daily cap")
		}
		v, err := catalog.Stable(ctx, s.d.DB, c.name)
		if err != nil || v == nil || v.State != "verified" {
			continue
		}
		mb := resolveMb(v)
		// Nothing to run without the input bytes (stored at miss time; may have been GC'd).
		if _, ok, err := compute.BlobBytes(ctx, s.d, c.sha); err != nil {
			return err
		} else if !ok {
			continue
		}
		// Already cached globally, or a system job for it is in flight: skip.
		if _, hit, err := compute.CacheLookup(ctx, s.d.DB, v.Wasm, c.sha, v.FS, mb); err != nil {
			return err
		} else if hit {
			continue
		}
		if inflight, err := s.inFlight(ctx, v.Wasm, c.sha, v.FS, mb); err != nil {
			return err
		} else if inflight {
			continue
		}
		spec := compute.Spec{Wasm: v.Wasm, In: c.sha, FS: v.FS, Ms: v.Manifest.MsHint, Mb: mb, Svc: v.Ref()}
		if _, err := compute.SystemSubmit(ctx, s.d, []compute.Spec{spec}, "job"); err != nil {
			if err == compute.ErrUnfunded || err == core.ErrCredits {
				return nil // SystemSubmit already raised the ops 'unfunded' event
			}
			return err
		}
		if done, err = s.bumpToday(ctx); err != nil {
			return err
		}
	}
	return nil
}

// candidates lists the svc demand rows missed by >= missGroups distinct super-groups in the window.
func (s *svc) candidates(ctx context.Context) ([]candidate, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT w.key, w.h
		FROM wanted w
		WHERE w.kind = 'svc' AND w.last > now() - make_interval(days => $1)
		  AND (SELECT count(*) FROM wanted_grp g
		       WHERE g.kind = 'svc' AND g.h = w.h AND g.at > now() - make_interval(days => $1)) >= $2
		ORDER BY w.n DESC
		LIMIT 500`, missWindowD, missGroups)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []candidate
	for rows.Next() {
		var key string
		var h []byte
		if err := rows.Scan(&key, &h); err != nil {
			return nil, err
		}
		if name, sha, ok := splitKey(key); ok {
			out = append(out, candidate{name: name, sha: sha, h: h})
		}
	}
	return out, rows.Err()
}

// splitKey parses the stored wanted key `name/sha` (RecordMiss replaced the NUL separator with '/')
// back into the service name and the 64-hex input hash.
func splitKey(key string) (name, sha string, ok bool) {
	if len(key) < 66 || key[len(key)-65] != '/' {
		return "", "", false
	}
	name, sha = key[:len(key)-65], key[len(key)-64:]
	if name == "" {
		return "", "", false
	}
	for _, r := range sha {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f') {
			return "", "", false
		}
	}
	return name, sha, true
}

func (s *svc) inFlight(ctx context.Context, wasm, in, fs string, mb int) (bool, error) {
	var exists bool
	err := s.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM jobs
		WHERE root = $1 AND wasm = $2 AND input = $3 AND fs = $4 AND mb = $5 AND status IN ('queued', 'running'))`,
		core.SystemID, wasm, in, fs, mb).Scan(&exists)
	return exists, err
}

func (s *svc) countToday(ctx context.Context) (int, error) {
	var n int
	err := s.d.DB.QueryRow(ctx, `SELECT coalesce((SELECT n FROM counters WHERE scope = 'svc_precompute' AND kind = 'day' AND day = current_date), 0)`).Scan(&n)
	return n, err
}

func (s *svc) bumpToday(ctx context.Context) (int, error) {
	var n int
	err := s.d.DB.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ('svc_precompute', 'day', current_date, 1)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + 1 RETURNING n`).Scan(&n)
	return n, err
}
