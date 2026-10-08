package sandbox

// Regression tests for SECURITY-REVIEW-1 #4c (compile-time bomb): size cap, compile deadline,
// and a generated ~4 MiB single-giant-function module compiling within memory limits.

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func leb(n int) []byte {
	var b []byte
	for {
		c := byte(n & 0x7f)
		n >>= 7
		if n == 0 {
			return append(b, c)
		}
		b = append(b, c|0x80)
	}
}

func section(id byte, body []byte) []byte {
	return append(append([]byte{id}, leb(len(body))...), body...)
}

// giantModule builds a module exporting _start: one function with `locals` i32 locals and
// a straight-line body of roughly target bytes cycling local.get/i32.add/local.set over all
// locals (the pattern that made wazero's compiler peak at ~700 MiB for an 18 MiB module).
func giantModule(target, locals int) []byte {
	body := append(leb(1), append(leb(locals), 0x7f)...) // 1 local decl: locals x i32
	for k := 0; len(body) < target; k = (k + 1) % locals {
		body = append(body, 0x20)
		body = append(body, leb(k)...)        // local.get k
		body = append(body, 0x41, 0x01, 0x6a) // i32.const 1; i32.add
		body = append(body, 0x21)
		body = append(body, leb(k)...) // local.set k
	}
	body = append(body, 0x0b)
	code := append(leb(1), append(leb(len(body)), body...)...)
	m := []byte{0, 'a', 's', 'm', 1, 0, 0, 0}
	m = append(m, section(1, []byte{1, 0x60, 0, 0})...)                                 // type () -> ()
	m = append(m, section(3, []byte{1, 0})...)                                          // func 0: type 0
	m = append(m, section(7, append(append([]byte{1, 6}, "_start"...), 0x00, 0x00))...) // export _start
	return append(m, section(10, code)...)
}

func TestWasmSizeCap(t *testing.T) {
	big := make([]byte, MaxWasm+1)
	copy(big, "\x00asm\x01\x00\x00\x00")
	start := time.Now()
	res := runner.Run(context.Background(), big, nil, 5000, 64)
	if res.Status != StatusError || !strings.Contains(res.Detail, "over") || time.Since(start) > time.Second {
		t.Fatalf("got %+v after %v", res, time.Since(start))
	}
}

// waitCompiled blocks until the runner's LRU holds n modules (orphaned compiles landing).
func waitCompiled(t *testing.T, n int, max time.Duration) {
	t.Helper()
	dl := time.Now().Add(max)
	for time.Now().Before(dl) {
		runner.mu.Lock()
		got := runner.lru.Len()
		runner.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Logf("compile still running after %v", max)
}

func TestCompileDeadline(t *testing.T) {
	runner.mu.Lock()
	before := runner.lru.Len()
	runner.mu.Unlock()
	w := giantModule(512<<10, 2000)
	start := time.Now()
	res := runner.Run(context.Background(), w, nil, 1, 64) // compile budget min(1 ms, CompileCap)
	if res.Status != StatusTimeout || !strings.Contains(res.Detail, "compile") || time.Since(start) > 2*time.Second {
		t.Fatalf("got %+v after %v", res, time.Since(start))
	}
	waitCompiled(t, before+1, 60*time.Second) // let the orphaned compile land before the next test
	// Cached now: the same module runs within a normal budget.
	if res := runner.Run(context.Background(), w, nil, 5000, 64); res.Status != StatusOK {
		t.Fatalf("cached run: %+v", res)
	}
}

func TestGiantFunctionCompileBounded(t *testing.T) {
	w := giantModule(MaxWasm-4096, 50000)
	if len(w) > MaxWasm {
		t.Fatalf("generated %d bytes", len(w))
	}
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	stop := make(chan struct{})
	peak := make(chan uint64, 1)
	go func() {
		var m runtime.MemStats
		var max uint64
		for {
			runtime.ReadMemStats(&m)
			if m.HeapInuse > max {
				max = m.HeapInuse
			}
			select {
			case <-stop:
				peak <- max
				return
			case <-time.After(20 * time.Millisecond):
			}
		}
	}()
	start := time.Now()
	res := runner.Run(context.Background(), w, nil, 10000, 64)
	el := time.Since(start)
	if res.Status == StatusTimeout { // deadline hit: wait for the orphan so the peak is measured
		runner.mu.Lock()
		n := runner.lru.Len()
		runner.mu.Unlock()
		waitCompiled(t, n+1, 60*time.Second)
	}
	close(stop)
	p := <-peak
	grow := int64(p) - int64(base.HeapInuse)
	t.Logf("%d bytes module: status=%s detail=%q in %v; heap in use peak +%d MiB (base %d MiB)",
		len(w), res.Status, res.Detail, el, grow>>20, base.HeapInuse>>20)
	switch res.Status {
	case StatusOK:
	case StatusTimeout:
		if el > CompileCap+2*time.Second {
			t.Fatalf("compile deadline not honoured: %v", el)
		}
	default:
		t.Fatalf("got %+v", res)
	}
	if grow > 300<<20 {
		t.Fatalf("compile used %d MiB of heap", grow>>20)
	}
}
