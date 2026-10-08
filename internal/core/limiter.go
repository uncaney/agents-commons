package core

import (
	"math"
	"net/http"
	"strings"
	"sync"
	"time"
)

// MaxLimiterKeys bounds the bucket map; past it, new anonymous keys share one overflow bucket.
const MaxLimiterKeys = 200_000

// Limiter holds token buckets keyed by string (root id, "id:<sub>", "ip:<group>", "sup:<super>",
// "bot:<cat>"), evicting idle ones.
type Limiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	overflow  bucket
	max       int
	lastEvict time.Time
	now       func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// Spec is one bucket to charge: rate tokens/s, capacity burst.
type Spec struct {
	Key   string
	Rate  float64
	Burst int
}

// RateInfo describes the tightest bucket after a Take, for the RateLimit headers (3.6).
type RateInfo struct {
	Limit      int // burst of the governing bucket
	Remaining  int // whole tokens left in it
	Window     int // seconds to refill it from empty (RateLimit-Policy w=)
	Reset      int // seconds until it is full again
	RetryAfter int // seconds until the refused cost fits (0 when allowed)
}

func NewLimiter() *Limiter {
	return &Limiter{buckets: map[string]*bucket{}, max: MaxLimiterKeys, now: time.Now}
}

// Allow takes one token from key's bucket (rate tokens/s, capacity burst).
func (l *Limiter) Allow(key string, rate float64, burst int) bool {
	return l.AllowCost(key, rate, burst, 1)
}

// AllowCost takes cost tokens from key's bucket.
func (l *Limiter) AllowCost(key string, rate float64, burst int, cost float64) bool {
	ok, _ := l.Take(cost, Spec{key, rate, burst})
	return ok
}

// Take charges cost from every spec's bucket atomically: when any bucket cannot pay, nothing is
// charged. Anonymous keys ("ip:", "sup:") share the overflow bucket once the map is at its cap.
func (l *Limiter) Take(cost float64, specs ...Spec) (bool, RateInfo) {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	bs := make([]*bucket, len(specs))
	for i, s := range specs {
		b := l.bucketLocked(s.Key, s.Burst, now)
		if b.last != now {
			b.tokens += now.Sub(b.last).Seconds() * s.Rate
			if b.tokens > float64(s.Burst) {
				b.tokens = float64(s.Burst)
			}
			b.last = now
		}
		bs[i] = b
	}
	var info RateInfo
	ok := true
	for i, s := range specs {
		b := bs[i]
		if b.tokens < cost {
			ok = false
			wait := int(math.Ceil((cost - b.tokens) / s.Rate))
			if wait < 1 {
				wait = 1
			}
			if info.RetryAfter == 0 || wait > info.RetryAfter {
				info.RetryAfter = wait
			}
		}
	}
	gov := -1
	for i, s := range specs {
		b := bs[i]
		if ok {
			if dup(bs[:i], b) {
				continue
			}
			b.tokens -= cost
		}
		if gov < 0 || b.tokens < bs[gov].tokens {
			gov = i
		}
		_ = s
	}
	if gov >= 0 {
		s, b := specs[gov], bs[gov]
		info.Limit, info.Remaining = s.Burst, int(math.Max(0, math.Floor(b.tokens)))
		if s.Rate > 0 {
			info.Window = int(math.Ceil(float64(s.Burst) / s.Rate))
			info.Reset = int(math.Ceil((float64(s.Burst) - b.tokens) / s.Rate))
		}
	}
	return ok, info
}

func dup(seen []*bucket, b *bucket) bool {
	for _, s := range seen {
		if s == b {
			return true
		}
	}
	return false
}

func anonKey(key string) bool {
	return strings.HasPrefix(key, "ip:") || strings.HasPrefix(key, "sup:")
}

func (l *Limiter) bucketLocked(key string, burst int, now time.Time) *bucket {
	if b := l.buckets[key]; b != nil {
		return b
	}
	if len(l.buckets) >= l.max {
		// Under cap pressure: one cheap eviction pass per 10 s, then anonymous newcomers share
		// the overflow bucket (roots are bounded by PoW registrations and still get their own).
		if now.Sub(l.lastEvict) > 10*time.Second {
			l.lastEvict = now
			l.evictLocked(now.Add(-time.Minute))
		}
		if len(l.buckets) >= l.max && anonKey(key) {
			b := &l.overflow
			if b.last.IsZero() {
				b.tokens, b.last = float64(burst), now
			}
			return b
		}
	}
	b := &bucket{tokens: float64(burst), last: now}
	l.buckets[key] = b
	return b
}

// Evict drops buckets idle for longer than idle.
func (l *Limiter) Evict(idle time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictLocked(l.now().Add(-idle))
}

func (l *Limiter) evictLocked(cut time.Time) {
	for k, b := range l.buckets {
		if b.last.Before(cut) {
			delete(l.buckets, k)
		}
	}
}

func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.buckets)
}

// Rate budgets (3.6).
const (
	rootRate, rootBurst   = 10.0, 30
	groupRate, groupBurst = 5.0, 20
	superRate, superBurst = 20.0, 80
	botRate, botBurst     = 20.0, 100
)

// repFactor scales a root's ceiling: 1 + min(rep,20)/5.
func repFactor(rep int) float64 {
	if rep < 0 {
		rep = 0
	}
	if rep > 20 {
		rep = 20
	}
	return 1 + float64(rep)/5
}

// specsFor builds the buckets a request charges: identity + root ceiling, a verified crawler
// category, or the anonymous group then super-group buckets.
func (d *Deps) specsFor(r *http.Request, id *Ident) []Spec {
	if id != nil {
		f := repFactor(id.Rep)
		specs := []Spec{{id.Root, rootRate * f, int(rootBurst * f)}}
		if id.ID != id.Root {
			specs = append(specs, Spec{"id:" + id.ID, rootRate * f, int(rootBurst * f)})
		}
		return specs
	}
	if ok, cat := BotLane(r.Context()); ok {
		if cat == "" {
			cat = "bot"
		}
		return []Spec{{"bot:" + cat, botRate, botBurst}}
	}
	return []Spec{{"ip:" + d.IPGroup(r), groupRate, groupBurst}, {"sup:" + d.IPSuper(r), superRate, superBurst}}
}

// Take charges cost for the caller and reports the governing bucket (headers are set by Handler).
func (d *Deps) Take(r *http.Request, id *Ident, cost float64) (bool, RateInfo) {
	return d.Lim.Take(cost, d.specsFor(r, id)...)
}

// AllowCost charges cost request tokens for the caller (3.6).
func (d *Deps) AllowCost(r *http.Request, id *Ident, cost float64) bool {
	ok, _ := d.Take(r, id, cost)
	return ok
}

// Allow charges one request token for the caller. Handler calls it once per HTTP request; mcp
// calls it once more per tools/call.
func (d *Deps) Allow(r *http.Request, id *Ident) bool { return d.AllowCost(r, id, 1) }
