package ops

import (
	"context"
	"sync"
	"time"
)

// dailyCounters accumulates per-UTC-day deltas (requests, 5xx, shed seconds) between flushes.
type dailyCounters struct {
	mu sync.Mutex
	m  map[string]*dayDelta
}

type dayDelta struct {
	reqs, e5xx int64
	shed       int
}

func (c *dailyCounters) add(t time.Time, reqs, e5xx int64, shed int) {
	day := t.UTC().Format("2006-01-02")
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]*dayDelta{}
	}
	d := c.m[day]
	if d == nil {
		if len(c.m) >= 8 { // only a clock jump could grow this; never unbounded
			c.mu.Unlock()
			return
		}
		d = &dayDelta{}
		c.m[day] = d
	}
	d.reqs += reqs
	d.e5xx += e5xx
	d.shed += shed
	c.mu.Unlock()
}

// drain swaps the pending deltas out.
func (c *dailyCounters) drain() map[string]*dayDelta {
	c.mu.Lock()
	m := c.m
	c.m = nil
	c.mu.Unlock()
	return m
}

// flushDaily upserts the pending deltas into status_daily; a failed day is re-added so nothing is
// lost across a transient error. Janitor task "ops_daily" (every instance flushes its own counters).
func (o *Ops) flushDaily(ctx context.Context) (err error) {
	defer o.timed("ops_daily", time.Now(), &err)
	q := o.q()
	for day, d := range o.daily.drain() {
		if d.reqs == 0 && d.e5xx == 0 && d.shed == 0 {
			continue
		}
		_, e := q.Exec(ctx, `INSERT INTO status_daily (day, reqs, e5xx, shed_s) VALUES ($1::date, $2, $3, $4)
			ON CONFLICT (day) DO UPDATE SET reqs = status_daily.reqs + EXCLUDED.reqs,
			  e5xx = status_daily.e5xx + EXCLUDED.e5xx, shed_s = status_daily.shed_s + EXCLUDED.shed_s`, day, d.reqs, d.e5xx, d.shed)
		if e != nil {
			t, _ := time.Parse("2006-01-02", day)
			o.daily.add(t, d.reqs, d.e5xx, d.shed)
			if err == nil {
				err = e
			}
		}
	}
	return err
}
