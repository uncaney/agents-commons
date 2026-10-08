package kb

import (
	"context"
	"hash/maphash"
	"sync"
	"time"

	"ekaii.fr/commons/internal/core"
)

// Read telemetry (SPEC-v2 6.4): entry reads (g, HTML, .md) count as views and hit appearances as
// impressions, one per (root or IP group, entry, day) through a daily in-memory bloom filter, then
// buffered and written to kb_reads_daily in batched UPSERTs by the janitor (every tick, 30 s). The
// request path never touches the database. The stale janitor marks entries read 50+ times without
// a confirmation for 30 days (`stale?` marker, rank penalty) and clears the mark once confirmed.

const (
	bloomBits   = 1 << 24 // 2 MiB per day: ~0.2 % false positives at a million distinct reads
	bloomHashes = 4
	pendingMax  = 50000 // (entry, day) rows buffered between flushes; beyond, reads are dropped
	flushBatch  = 2000  // rows per UPSERT statement
	staleViews  = 50
	staleAfter  = 30 * 24 * time.Hour
	staleEvery  = time.Hour
)

type pendKey struct{ day, id string }

type counts struct{ views, impressions int32 }

type telemetry struct {
	mu      sync.Mutex
	day     string // UTC day the bloom covers
	bits    []uint64
	seed    maphash.Seed
	pending map[pendKey]*counts
	dropped int
}

var tel = &telemetry{seed: maphash.MakeSeed(), pending: map[pendKey]*counts{}}

func utcDay(t time.Time) string { return t.UTC().Format("2006-01-02") }

// seen tests and sets key in the day's bloom filter: true when it was probably recorded already.
func (t *telemetry) seen(day, key string) bool {
	if t.day != day {
		if t.bits == nil {
			t.bits = make([]uint64, bloomBits/64)
		} else {
			clear(t.bits)
		}
		t.day = day
	}
	h := maphash.String(t.seed, key)
	h1, h2 := h&0xffffffff, (h>>32)|1
	hit := true
	for i := uint64(0); i < bloomHashes; i++ {
		idx := (h1 + i*h2) & (bloomBits - 1)
		w, b := idx>>6, uint64(1)<<(idx&63)
		if t.bits[w]&b == 0 {
			hit = false
			t.bits[w] |= b
		}
	}
	return hit
}

// reset forgets the bloom and the buffer (tests, and a process never needs it otherwise).
func (t *telemetry) reset() {
	t.mu.Lock()
	t.day, t.bits, t.pending, t.dropped = "", nil, map[pendKey]*counts{}, 0
	t.mu.Unlock()
}

// Bump records one read of entry id: kind is view (g, HTML, .md) or impression (a search hit); key
// is the reader's dedupe key, the root for token callers or the IP group otherwise. Repeats of the
// same (key, entry, kind) within a UTC day are dropped by the bloom filter. Never blocks on I/O;
// installed as TelemetryFn by RegisterEdit.
func Bump(_ context.Context, id, kind, key string) {
	if !core.ValidIDPrefix(id, 'k') || (kind != "view" && kind != "impression") {
		return
	}
	day := utcDay(time.Now())
	tel.mu.Lock()
	defer tel.mu.Unlock()
	if tel.seen(day, kind+"\x00"+id+"\x00"+key) {
		return
	}
	pk := pendKey{day, id}
	c := tel.pending[pk]
	if c == nil {
		if len(tel.pending) >= pendingMax {
			tel.dropped++
			return
		}
		c = &counts{}
		tel.pending[pk] = c
	}
	if kind == "view" {
		c.views++
	} else {
		c.impressions++
	}
}

// FlushTelemetry writes the buffered counts to kb_reads_daily (one UPSERT per batch of
// flushBatch rows; ids whose entry is gone are skipped by the join) and returns the number of
// rows written. On an error the counts go back into the buffer for the next tick. Janitor task
// kb_reads.
func FlushTelemetry(ctx context.Context, q core.Q) (int, error) {
	tel.mu.Lock()
	batch := tel.pending
	tel.pending = map[pendKey]*counts{}
	tel.dropped = 0
	tel.mu.Unlock()
	if len(batch) == 0 {
		return 0, nil
	}
	keys := make([]pendKey, 0, len(batch))
	for k := range batch {
		keys = append(keys, k)
	}
	written := 0
	for start := 0; start < len(keys); start += flushBatch {
		end := min(start+flushBatch, len(keys))
		ids, days := make([]string, 0, end-start), make([]string, 0, end-start)
		views, imps := make([]int32, 0, end-start), make([]int32, 0, end-start)
		for _, k := range keys[start:end] {
			ids, days = append(ids, k.id), append(days, k.day)
			views, imps = append(views, batch[k].views), append(imps, batch[k].impressions)
		}
		tag, err := q.Exec(ctx, `INSERT INTO kb_reads_daily (kb_id, day, views, impressions)
			SELECT u.id, u.day::date, u.v, u.i FROM unnest($1::text[], $2::text[], $3::int[], $4::int[]) AS u(id, day, v, i) JOIN kb k ON k.id = u.id
			ON CONFLICT (kb_id, day) DO UPDATE SET views = kb_reads_daily.views + EXCLUDED.views, impressions = kb_reads_daily.impressions + EXCLUDED.impressions`,
			ids, days, views, imps)
		if err != nil {
			tel.mu.Lock()
			for _, k := range keys[start:] {
				if len(tel.pending) >= pendingMax {
					break
				}
				c := tel.pending[k]
				if c == nil {
					c = &counts{}
					tel.pending[k] = c
				}
				c.views += batch[k].views
				c.impressions += batch[k].impressions
			}
			tel.mu.Unlock()
			return written, err
		}
		written += int(tag.RowsAffected())
	}
	return written, nil
}

// TelemetryPending reports the buffered (entry, day) rows and the reads dropped since the last flush.
func TelemetryPending() (rows, dropped int) {
	tel.mu.Lock()
	defer tel.mu.Unlock()
	return len(tel.pending), tel.dropped
}

var (
	staleMu   sync.Mutex
	staleLast time.Time
)

// staleDue rate-limits the stale janitor to once per staleEvery per instance.
func staleDue() bool {
	staleMu.Lock()
	defer staleMu.Unlock()
	if time.Since(staleLast) < staleEvery {
		return false
	}
	staleLast = time.Now()
	return true
}

// MarkStale sets kb.stale on entries with 50+ views that have gone 30 days without a confirmation
// (ok_w = 0 since creation) and clears it on entries that no longer qualify; returns the number of
// rows whose flag changed. Only rows that are stale or have reached the view threshold are
// examined. Janitor task kb_stale (hourly).
func MarkStale(ctx context.Context, q core.Q) (int, error) {
	tag, err := q.Exec(ctx, `WITH v AS (SELECT kb_id, sum(views) AS views FROM kb_reads_daily GROUP BY kb_id HAVING sum(views) >= $1),
		s AS (SELECT k.id, (k.ok_w = 0 AND k.created <= now() - $2::interval AND coalesce(v.views, 0) >= $1) AS flag
		      FROM kb k LEFT JOIN v ON v.kb_id = k.id WHERE k.stale OR v.kb_id IS NOT NULL)
		UPDATE kb k SET stale = s.flag FROM s WHERE s.id = k.id AND k.stale IS DISTINCT FROM s.flag`, staleViews, staleAfter.String())
	if err != nil {
		return 0, err
	}
	return int(tag.RowsAffected()), nil
}
