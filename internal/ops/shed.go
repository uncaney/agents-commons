package ops

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ekaii.fr/commons/internal/core"
)

// Levels are the shed rungs in ladder order (21.1): each rung's flag is shed:<name>, enforced by
// the owning packages through d.Shed(r, name) with a 503 + Retry-After 120 reply.
var Levels = []string{"feeds", "anon-search", "longpoll", "anon-write", "compute"}

// Sampler knobs (vars so tests can shorten them).
var (
	SampleEvery = 5 * time.Second
	// StaleAfter is the age after which another instance's auto flag may be lifted by a calm
	// instance (its owner died); live owners refresh their stamp every minute.
	StaleAfter = 10 * time.Minute
)

// Ladder is the hysteresis state machine: pressure above the next rung's SetAt for SetAfter
// consecutive samples climbs one rung; pressure at or below the top rung's ClearAt for ClearAfter
// consecutive samples descends one rung. One rung per sample in either direction.
type Ladder struct {
	mu                   sync.Mutex
	level, up, down      int
	SetAt, ClearAt       []float64
	SetAfter, ClearAfter int
	Last                 float64
}

// NewLadder returns the default thresholds: 0.70/0.80/0.88/0.94/0.98 to set, 0.15 lower to clear,
// 2 samples (10 s) up and 6 samples (30 s) down.
func NewLadder() *Ladder {
	return &Ladder{SetAt: []float64{.70, .80, .88, .94, .98}, ClearAt: []float64{.55, .65, .73, .79, .83}, SetAfter: 2, ClearAfter: 6}
}

// Step feeds one pressure sample and returns the ladder level (0..len(Levels)) and whether it moved.
func (l *Ladder) Step(p float64) (level int, changed bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.Last = p
	if l.level < len(Levels) && p >= l.SetAt[l.level] {
		l.up++
		l.down = 0
		if l.up >= l.SetAfter {
			l.level++
			l.up = 0
			return l.level, true
		}
		return l.level, false
	}
	l.up = 0
	if l.level > 0 && p <= l.ClearAt[l.level-1] {
		l.down++
		if l.down >= l.ClearAfter {
			l.level--
			l.down = 0
			return l.level, true
		}
		return l.level, false
	}
	l.down = 0
	return l.level, false
}

// Level is the ladder's current level.
func (l *Ladder) Level() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.level
}

// Signals is one sample of the load the ladder reads; every field is a ratio where 1 means "at
// the limit" (pool full, every acquire waited, median request 1 s, memory at GOMEMLIMIT).
type Signals struct {
	PoolBusy, PoolWaitShare, PoolWait, Waiters, Mem, Latency float64
}

// Pressure is the ladder input: the worst signal.
func (s Signals) Pressure() float64 {
	p := s.PoolBusy
	for _, v := range []float64{s.PoolWaitShare, s.PoolWait, s.Waiters, s.Mem, s.Latency} {
		if v > p {
			p = v
		}
	}
	return p
}

// window collects request durations between samples (first 512 of them) for the median.
type window struct {
	mu    sync.Mutex
	durs  []float64
	count uint64
}

func (w *window) add(d time.Duration) {
	w.mu.Lock()
	if len(w.durs) < 512 {
		w.durs = append(w.durs, d.Seconds())
	}
	w.count++
	w.mu.Unlock()
}

// take returns the median duration of the window and resets it.
func (w *window) take() (median float64, count uint64) {
	w.mu.Lock()
	durs, count := w.durs, w.count
	w.durs, w.count = nil, 0
	w.mu.Unlock()
	if len(durs) == 0 {
		return 0, count
	}
	sort.Float64s(durs)
	return durs[len(durs)/2], count
}

// signals reads one sample: request pool saturation and acquire waits (deltas since the previous
// sample), long-poll waiters, Go memory against GOMEMLIMIT and the median request time.
func (o *Ops) signals() Signals {
	var s Signals
	if o.d.DB != nil {
		st := o.d.DB.Stat()
		if mx := st.MaxConns(); mx > 0 {
			s.PoolBusy = float64(st.AcquiredConns()) / float64(mx)
		}
		cur := poolSnap{st.AcquireCount(), st.EmptyAcquireCount(), st.EmptyAcquireWaitTime()}
		if n := cur.acquires - o.prev.acquires; n > 0 {
			s.PoolWaitShare = float64(cur.empty-o.prev.empty) / float64(n)
			s.PoolWait = (cur.wait - o.prev.wait).Seconds() / float64(n) / 0.1
		}
		o.prev = cur
	}
	s.Waiters = float64(o.d.Waiters.Len()) / core.MaxWaiters
	if used, limit := goMem(); limit > 0 {
		s.Mem = float64(used) / float64(limit)
	}
	med, _ := o.win.take()
	s.Latency = med
	return s
}

// tick is one sampler step: signals -> ladder -> flags, gauges and the daily shed seconds.
func (o *Ops) tick(ctx context.Context, now time.Time) {
	sig := o.signals()
	p := sig.Pressure()
	level, _ := o.ladder.Step(p)
	o.m.Set("cx_pressure", p)
	o.applyLevel(ctx, level, p)
	o.runtimeGauges()
	if lvl, _ := o.Level(); lvl > 0 {
		o.daily.add(now, 0, 0, int(SampleEvery/time.Second))
	}
}

// Level reads the shed state from the flags (operator rungs included): the highest rung on and
// the names of every rung on.
func (o *Ops) Level() (int, []string) {
	lvl, names := 0, []string{}
	for i, n := range Levels {
		if o.d.Flag("shed:" + n) {
			names = append(names, n)
			lvl = i + 1
		}
	}
	return lvl, names
}

// applyLevel makes the flags match the ladder: rungs up to level are set with this instance's
// stamp ("auto <inst> <unix>"), rungs above it are lifted when this instance set them or when
// their owner's stamp went stale; flags without an auto stamp belong to the operator and are
// never touched. Transitions are logged as ops events.
func (o *Ops) applyLevel(ctx context.Context, level int, pressure float64) {
	now := time.Now()
	for i, name := range Levels {
		key := "shed:" + name
		on, s := o.d.Flag(key), o.d.FlagStr(key)
		auto, own, age := parseStamp(s, o.inst, now)
		want := i < level
		var err error
		switch {
		case want && !on:
			if err = o.d.SetFlag(ctx, key, true, o.stamp(now)); err == nil {
				o.m.Add("cx_shed_changes_total", 1, "up")
				o.event(ctx, "shed:"+name, fmt.Sprintf("shed on %s pressure=%.2f", name, pressure))
			}
		case want && on && own && age > time.Minute:
			err = o.d.SetFlag(ctx, key, true, o.stamp(now))
		case !want && on && (own || (auto && age > StaleAfter)):
			if err = o.d.SetFlag(ctx, key, false, ""); err == nil {
				o.m.Add("cx_shed_changes_total", 1, "down")
				o.event(ctx, "shed:"+name, fmt.Sprintf("shed off %s pressure=%.2f", name, pressure))
			}
		}
		if err != nil {
			o.d.Log.Warn("shed flag", "key", key, "err", err)
		}
	}
}

func (o *Ops) stamp(now time.Time) string {
	return "auto " + o.inst + " " + strconv.FormatInt(now.Unix(), 10)
}

// parseStamp decodes a flag's string value: whether the sampler wrote it, whether this instance
// did, and its age.
func parseStamp(s, inst string, now time.Time) (auto, own bool, age time.Duration) {
	f := strings.Fields(s)
	if len(f) != 3 || f[0] != "auto" {
		return false, false, 0
	}
	ts, err := strconv.ParseInt(f[2], 10, 64)
	if err != nil {
		return true, f[1] == inst, StaleAfter + time.Second
	}
	return true, f[1] == inst, now.Sub(time.Unix(ts, 0))
}

func (o *Ops) event(ctx context.Context, ref, title string) {
	if err := core.Event(ctx, o.d.DB, "ops", ref, "", title); err != nil {
		o.d.Log.Warn("ops event", "ref", ref, "err", err)
	}
}
