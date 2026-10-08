package core

import "sync"

// Waiters bounds concurrent long-polls: 2000 global, 8 per root, 4 per IP group (3.6, 24.14).
type Waiters struct {
	mu                 sync.Mutex
	n                  int
	roots, groups      map[string]int
	max, perRoot, perG int
}

const (
	MaxWaiters        = 2000
	MaxWaitersPerRoot = 8
	MaxWaitersPerGrp  = 4
)

func NewWaiters(max, perRoot, perGroup int) *Waiters {
	return &Waiters{roots: map[string]int{}, groups: map[string]int{}, max: max, perRoot: perRoot, perG: perGroup}
}

// Acquire takes a long-poll slot for root (when non-empty) or the IP group; ok=false means the
// caller answers immediately with the current state + retry=5. release is idempotent.
func (w *Waiters) Acquire(root, group string) (release func(), ok bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.n >= w.max {
		return func() {}, false
	}
	key, m, lim := group, w.groups, w.perG
	if root != "" {
		key, m, lim = root, w.roots, w.perRoot
	}
	if m[key] >= lim {
		return func() {}, false
	}
	w.n++
	m[key]++
	var once sync.Once
	return func() {
		once.Do(func() {
			w.mu.Lock()
			w.n--
			if m[key]--; m[key] <= 0 {
				delete(m, key)
			}
			w.mu.Unlock()
		})
	}, true
}

// Len is the number of live waiters.
func (w *Waiters) Len() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.n
}
