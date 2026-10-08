package ops

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"ekaii.fr/commons/internal/core"
)

// Report is the result of MigrateCheck.
type Report struct {
	Database        string
	Before, After   []int // schema_migrations versions before and after
	Applied         []int // versions this run applied
	Elapsed         time.Duration
	LongestLockWait time.Duration // longest lock wait observed on the database during the run
	WaitSamples     int           // watcher samples that saw a backend waiting on a lock
}

// Line is the one-line summary printed by `gateway -migrate-check`.
func (r Report) Line() string {
	apps := make([]string, len(r.Applied))
	for i, v := range r.Applied {
		apps[i] = fmt.Sprintf("%04d", v)
	}
	return fmt.Sprintf("migrate-check db=%s applied=%d (%s) elapsed=%s lock_wait_max=%s", r.Database, len(r.Applied),
		dash(strings.Join(apps, ",")), r.Elapsed.Round(time.Millisecond), r.LongestLockWait.Round(time.Millisecond))
}

const migrateCheckApp = "cx-migrate-check"

// MigrateCheck applies the pending embedded migrations to the database dsn points at (the
// deploy script restores the latest dump into commons_preflight first, 21.3) and reports the
// longest lock wait any cx-migrate-check backend experienced while they ran. It never touches the
// gateway's pools: core.Migrate opens its own connection with lock_timeout 30 s.
func MigrateCheck(ctx context.Context, dsn string) (Report, error) {
	var rep Report
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return rep, err
	}
	cfg.MaxConns = 2
	if cfg.ConnConfig.RuntimeParams == nil {
		cfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	cfg.ConnConfig.RuntimeParams["application_name"] = migrateCheckApp
	rep.Database = cfg.ConnConfig.Database
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return rep, err
	}
	defer pool.Close()
	pctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	err = pool.Ping(pctx)
	cancel()
	if err != nil {
		return rep, fmt.Errorf("preflight ping: %w", err)
	}
	w := &lockWatcher{pool: pool}
	wctx, stop := context.WithCancel(ctx)
	go w.run(wctx)
	start := time.Now()
	if rep.Before, err = versions(ctx, pool); err != nil {
		stop()
		return rep, err
	}
	merr := core.Migrate(ctx, pool)
	if rep.After, err = versions(ctx, pool); err == nil {
		err = merr
	}
	rep.Elapsed = time.Since(start)
	stop()
	w.wait()
	rep.LongestLockWait, rep.WaitSamples = w.max, w.samples
	before := map[int]bool{}
	for _, v := range rep.Before {
		before[v] = true
	}
	for _, v := range rep.After {
		if !before[v] {
			rep.Applied = append(rep.Applied, v)
		}
	}
	sort.Ints(rep.Applied)
	return rep, err
}

// versions lists schema_migrations (empty when the table does not exist yet).
func versions(ctx context.Context, q core.Q) ([]int, error) {
	var exists bool
	if err := q.QueryRow(ctx, `SELECT to_regclass('schema_migrations') IS NOT NULL`).Scan(&exists); err != nil {
		return nil, err
	}
	if !exists {
		return nil, nil
	}
	rows, err := q.Query(ctx, `SELECT version FROM schema_migrations ORDER BY version`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// lockWatcher polls pg_locks (waitstart, PG 14+) for ungranted locks held by this run's backends
// and keeps the longest wait seen.
type lockWatcher struct {
	pool    *pgxpool.Pool
	max     time.Duration
	samples int
	done    sync.WaitGroup
}

func (w *lockWatcher) run(ctx context.Context) {
	w.done.Add(1)
	defer w.done.Done()
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		var secs float64
		qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
		err := w.pool.QueryRow(qctx, `SELECT coalesce(max(extract(epoch FROM now() - l.waitstart)), 0)
			FROM pg_locks l JOIN pg_stat_activity a ON a.pid = l.pid
			WHERE NOT l.granted AND l.waitstart IS NOT NULL AND a.datname = current_database() AND a.application_name = $1`, migrateCheckApp).Scan(&secs)
		cancel()
		if err != nil {
			continue
		}
		if d := time.Duration(secs * float64(time.Second)); d > 0 {
			w.samples++
			if d > w.max {
				w.max = d
			}
		}
	}
}

func (w *lockWatcher) wait() {
	// run has started by the time stop() is called (goroutine scheduled before the migration); a
	// short grace covers the pathological case where it has not.
	time.Sleep(10 * time.Millisecond)
	w.done.Wait()
}
