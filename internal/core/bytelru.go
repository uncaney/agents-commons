package core

import (
	"container/list"
	"sync"
	"time"
)

// ByteLRU is a byte-bounded LRU with per-entry TTLs (section 2: caches are bounded by bytes).
type ByteLRU struct {
	mu   sync.Mutex
	max  int
	size int
	ll   *list.List
	m    map[string]*list.Element
	now  func() time.Time
}

type lruEntry struct {
	key string
	v   []byte
	exp time.Time
}

const lruOverhead = 64 // approximate per-entry bookkeeping

// NewByteLRU returns a cache holding at most maxBytes of keys + values.
func NewByteLRU(maxBytes int) *ByteLRU {
	return &ByteLRU{max: maxBytes, ll: list.New(), m: map[string]*list.Element{}, now: time.Now}
}

// Get returns the cached value (shared slice: callers must not modify it) when present and live.
func (l *ByteLRU) Get(key string) ([]byte, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	e, ok := l.m[key]
	if !ok {
		return nil, false
	}
	ent := e.Value.(*lruEntry)
	if !ent.exp.IsZero() && !l.now().Before(ent.exp) {
		l.removeLocked(e)
		return nil, false
	}
	l.ll.MoveToFront(e)
	return ent.v, true
}

// Put stores v under key for ttl (0 = no expiry); values larger than the cache are ignored.
func (l *ByteLRU) Put(key string, v []byte, ttl time.Duration) {
	n := len(key) + len(v) + lruOverhead
	if n > l.max {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.m[key]; ok {
		l.removeLocked(e)
	}
	var exp time.Time
	if ttl > 0 {
		exp = l.now().Add(ttl)
	}
	e := l.ll.PushFront(&lruEntry{key, v, exp})
	l.m[key] = e
	l.size += n
	for l.size > l.max && l.ll.Len() > 0 {
		l.removeLocked(l.ll.Back())
	}
}

// Delete drops one key.
func (l *ByteLRU) Delete(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if e, ok := l.m[key]; ok {
		l.removeLocked(e)
	}
}

func (l *ByteLRU) removeLocked(e *list.Element) {
	ent := e.Value.(*lruEntry)
	l.ll.Remove(e)
	delete(l.m, ent.key)
	l.size -= len(ent.key) + len(ent.v) + lruOverhead
}

// Len is the number of live entries; Bytes the accounted size.
func (l *ByteLRU) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.ll.Len()
}

func (l *ByteLRU) Bytes() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.size
}
