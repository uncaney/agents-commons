// Package anonwait implements proof of patience (SPEC-v2 27.2): a wait-mode anonymous lane that
// trades a timed delay for the hashcash of the X-PoW lane.
//
//   - GET|POST /v1/challenge/wait?for=w mints a stateless `w_wait` challenge (pow.PurposeWait, the
//     bits byte carrying wait_s/10, no hashing) that only becomes spendable wait_s seconds after
//     issuance and stays valid until it expires.
//   - Wrap decorates core.XPoWFn: a header `<c>:wait` with purpose w_wait is accepted once (through
//     used_challenges) inside its window and marks the request as wait-mode; every other header
//     falls through to the inner hashcash checker unchanged.
//   - Pending / PendingGet are the a2a wait-lane ticket seams: an anonymous message/send is parked
//     as a `q…` ticket that tasks/get later materialises into a quarantined board task.
//
// No raw IP is ever stored: network keys are HMAC'd (24.24). Callers that want the lane marker read
// WaitMode / IsWait off the request context; when the lane cell is unset (no middleware installed)
// the marker is simply false and the full anonymous caps apply.
package anonwait

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"net/http"
	"sync/atomic"
	"time"

	"ekaii.fr/commons/internal/core"
)

// deps is the Deps captured by Register; Wrap and the ticket seams read the server secret and pool
// through it (the XPoWFn signature carries only a Q, not the Deps).
var deps atomic.Pointer[core.Deps]

func depsOrNil() *core.Deps { return deps.Load() }

// serverSecret returns the configured server secret, or nil before Register has run.
func serverSecret() []byte {
	if d := deps.Load(); d != nil {
		return d.Cfg.ServerSecret
	}
	return nil
}

// grpHash is HMAC(server_secret, "anonwait|"<key>)[:16]: a stable, IP-free handle for a network
// group or super-group. It is deliberately stable (not day-rotated like wanted_grp) so the adaptive
// wait can sum one super-group's writes across the 24 h boundary; it still never reveals the IP.
func grpHash(key string) []byte {
	m := hmac.New(sha256.New, serverSecret())
	m.Write([]byte("anonwait|"))
	m.Write([]byte(key))
	return m.Sum(nil)[:16]
}

// --- request lane marker -------------------------------------------------------------------------

type laneKey struct{}

// lane is the mutable per-request cell Wrap flips when it accepts a wait header; a pointer so a
// decorator that cannot return a new context still makes the flag visible to the handler that
// seeded the cell and then reads WaitMode on the same context.
type lane struct{ wait bool }

// WithLane seeds an empty lane cell on ctx (idempotent); the request context must carry it before
// Wrap runs for WaitMode to observe a wait acceptance.
func WithLane(ctx context.Context) context.Context {
	if laneFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, laneKey{}, &lane{})
}

func laneFrom(ctx context.Context) *lane {
	l, _ := ctx.Value(laneKey{}).(*lane)
	return l
}

// markWait records that the current request was admitted through the wait lane.
func markWait(ctx context.Context) {
	if l := laneFrom(ctx); l != nil {
		l.wait = true
	}
}

// WaitMode reports whether the request on ctx was admitted through the wait lane (so a caller can
// apply the half anonymous caps and the anon-wait quarantine flag). False when no lane cell is
// present, which keeps the full caps in force.
func WaitMode(ctx context.Context) bool {
	l := laneFrom(ctx)
	return l != nil && l.wait
}

// IsWait is the core.ClientFrom-side spelling used by kb anon and forge /w/t (P11b/P12).
func IsWait(ctx context.Context) bool { return WaitMode(ctx) }

// Middleware seeds the lane cell on every request so a downstream Wrap acceptance is observable.
// P60a installs it next to core.XPoWFn = anonwait.Wrap(core.XPoWFn); without it WaitMode is always
// false and the full caps apply.
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r.WithContext(WithLane(r.Context())))
	})
}

// nowFn is overridable in tests to drive the wait windows deterministically.
var nowFn = time.Now

func now() time.Time { return nowFn() }
