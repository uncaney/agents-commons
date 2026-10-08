package compute

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"ekaii.fr/commons/internal/core"
)

const (
	donorOnline  = 2 * time.Minute  // a donor that polled /v1/w/lease this recently counts as online
	statsTTL     = 15 * time.Second // GET /v1/w/stats cache (14.3)
	statsPrivacy = true
)

// donorSeen is one worker root's last lease poll: its offer and free slots.
type donorSeen struct {
	at           time.Time
	free         int
	legacy       bool
	pin, new, l0 bool
}

// donorStats keeps the in-memory donor presence of this gateway instance (approximate under
// several instances, which the coarse buckets absorb) and the 15 s stats cache.
type donorStats struct {
	mu     sync.Mutex
	donors map[string]*donorSeen
	text   string
	json   map[string]any
	at     time.Time
	p50    int
	online int
}

func newDonorStats() *donorStats { return &donorStats{donors: map[string]*donorSeen{}} }

// seen records a lease poll of root offering in, with free live-lease slots.
func (d *donorStats) seen(root string, in leaseIn, free int) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if len(d.donors) > 10_000 {
		d.sweepLocked()
	}
	d.donors[root] = &donorSeen{at: time.Now(), free: max(free, 0), legacy: in.Ver < leaseVer,
		pin: in.has("pin") && len(in.Pins) > 0, new: in.Ver < leaseVer || in.has("new"), l0: in.Ver < leaseVer || in.has("l0")}
}

func (d *donorStats) sweepLocked() {
	cut := time.Now().Add(-donorOnline)
	for k, v := range d.donors {
		if v.at.Before(cut) {
			delete(d.donors, k)
		}
	}
}

// presence counts online donors, free slots and the caps on offer.
func (d *donorStats) presence() (online, slots, nNew, nL0 int, caps []string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.sweepLocked()
	pin := false
	for _, v := range d.donors {
		online++
		slots += v.free
		if v.new {
			nNew++
		}
		if v.l0 {
			nL0++
		}
		pin = pin || v.pin
	}
	caps = []string{"wasm4m"}
	if pin {
		caps = append(caps, "pin")
	}
	if nNew > 0 {
		caps = append(caps, "new")
	}
	if nL0 > 0 {
		caps = append(caps, "l0")
	}
	return
}

// bucket renders a count coarsely (0 / 1-2 / 3-9 / 10+): donor numbers are never exact in public.
func bucket(n int) string {
	switch {
	case n <= 0:
		return "0"
	case n <= 2:
		return "1-2"
	case n <= 9:
		return "3-9"
	}
	return "10+"
}

// eta estimates the wait of a fresh submit: p50 lease wait plus the run time; false when no donor
// is online.
func (d *donorStats) eta(res *submitResult) (int, bool) {
	d.mu.Lock()
	online, p50 := d.online, d.p50
	fresh := time.Since(d.at) < statsTTL
	d.mu.Unlock()
	if !fresh {
		online, _, _, _, _ = d.presence()
	}
	if online == 0 {
		return 0, false
	}
	return p50 + (defMs+999)/1000, true
}

// stats renders GET /v1/w/stats, cached statsTTL.
func (s *svc) wstats(ctx context.Context) (string, map[string]any, error) {
	d := s.stats
	d.mu.Lock()
	if time.Since(d.at) < statsTTL && d.text != "" {
		t, j := d.text, d.json
		d.mu.Unlock()
		return t, j, nil
	}
	d.mu.Unlock()
	var queued, leased int
	var p50 float64
	if err := s.d.DB.QueryRow(ctx, `SELECT (SELECT count(*) FROM replicas r JOIN jobs j ON j.id = r.job WHERE r.state = 'queued' AND j.lane = 'public'),
		(SELECT count(*) FROM replicas WHERE state = 'leased'),
		coalesce((SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM leased_at - created)) FROM replicas
			WHERE leased_at > now() - interval '1 hour'), 0)`).Scan(&queued, &leased, &p50); err != nil {
		return "", nil, err
	}
	online, slots, nNew, nL0, caps := d.presence()
	text := fmt.Sprintf("donors_online=%s slots=%s queued=%d leased=%d p50_wait_s=%d max_ms=%d max_mb=%d caps=%s donors_new=%s donors_l0=%s",
		bucket(online), bucket(slots), queued, leased, int(p50), maxMs, maxMb, strings.Join(caps, ","), bucket(nNew), bucket(nL0))
	j := map[string]any{"donors_online": bucket(online), "slots": bucket(slots), "queued": queued, "leased": leased, "p50_wait_s": int(p50),
		"max_ms": maxMs, "max_mb": maxMb, "caps": caps, "donors_new": bucket(nNew), "donors_l0": bucket(nL0)}
	d.mu.Lock()
	d.text, d.json, d.at, d.p50, d.online = text, j, time.Now(), int(p50), online
	d.mu.Unlock()
	return text, j, nil
}

func (s *svc) hStats(w http.ResponseWriter, r *http.Request) {
	text, j, err := s.wstats(r.Context())
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=15")
	core.OK(w, r, text, j)
}

func (s *svc) opWStats(ctx context.Context, _ *core.Ident, _ json.RawMessage) (string, error) {
	text, _, err := s.wstats(ctx)
	return text, err
}
