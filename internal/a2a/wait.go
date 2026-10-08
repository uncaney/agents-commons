package a2a

import (
	"context"
	"time"

	"ekaii.fr/commons/internal/forge"
)

// waitLimit is the seconds the request may still block: the remaining budget, the client's
// metadata.wait when shorter, the shed cap, and 0 for anonymous callers (3.6).
func (s *server) waitLimit(rc *reqCtx, want int) int {
	if rc.ident == nil || rc.budget <= 0 {
		return 0
	}
	wait := rc.budget
	if want > 0 && want < wait {
		wait = want
	}
	if wait > shedWait && s.d.Shed(rc.r, "longpoll") {
		wait = shedWait
	}
	rc.budget -= wait
	return wait
}

// waitChange blocks on the task's notifier topic until its A2A state differs from `from`, the
// wait elapses or the request ends. The slot comes from d.Waiters: when none is free the call
// answers at once with retry=5. Returns the retry hint and the milliseconds actually waited.
func (s *server) waitChange(ctx context.Context, rc *reqCtx, n int64, from string, want int) (retry, waitedMs int) {
	wait := s.waitLimit(rc, want)
	if wait <= 0 {
		return 0, 0
	}
	release, ok := s.d.Waiters.Acquire(rc.ident.Root, s.d.IPGroup(rc.r))
	if !ok {
		return 5, 0
	}
	defer release()
	start := time.Now()
	deadline := time.NewTimer(time.Duration(wait) * time.Second)
	defer deadline.Stop()
	for {
		// Subscribe before the read so a wake between the two is never lost.
		c, cancel := s.d.Notify.Subscribe(forge.TaskTopic(n))
		st, err := stateOf(ctx, s.d.DB, n)
		if err != nil || st != from {
			cancel()
			break
		}
		select {
		case <-c:
			cancel()
			// The writer wakes after its commit; a short settle covers wakes issued inside a tx.
			time.Sleep(20 * time.Millisecond)
			continue
		case <-deadline.C:
			cancel()
			return 0, max(1, int(time.Since(start).Milliseconds()))
		case <-ctx.Done():
			cancel()
			return 0, max(1, int(time.Since(start).Milliseconds()))
		}
	}
	return 0, max(1, int(time.Since(start).Milliseconds()))
}
