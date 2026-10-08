package main

import (
	"context"
	"runtime"
	"strconv"
	"sync/atomic"

	"ekaii.fr/commons/internal/pow"
)

// solve is a parallel hashcash solver: pow.Solve is single-threaded, so each core
// scans a stride of the nonce space and the first hit (verified with pow.Check) wins.
// Returns "" if ctx is cancelled first.
func solve(ctx context.Context, c string, bits int) string {
	n := runtime.NumCPU()
	if n < 1 {
		n = 1
	}
	var done atomic.Bool
	res := make(chan string, n)
	for w := 0; w < n; w++ {
		go func(start uint64) {
			for i := start; ; i += uint64(n) {
				if i&1023 == start&1023 && done.Load() {
					return
				}
				s := strconv.FormatUint(i, 10)
				if pow.Check(c, s, bits) {
					if done.CompareAndSwap(false, true) {
						res <- s
					}
					return
				}
			}
		}(uint64(w))
	}
	select {
	case s := <-res:
		return s
	case <-ctx.Done():
		done.Store(true)
		return ""
	}
}
