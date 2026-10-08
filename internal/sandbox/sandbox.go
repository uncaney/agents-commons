// Package sandbox runs untrusted WASI preview1 modules under wazero with
// hard memory/time limits, no filesystem (or a read-only zip, 27.6), no env,
// no sockets and a deterministic clock/rand so two runs of the same
// module+input(+fs) produce the same stdout.
package sandbox

import (
	"bytes"
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand/v2"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
	"github.com/tetratelabs/wazero/imports/wasi_snapshot_preview1"
	"github.com/tetratelabs/wazero/sys"

	"ekaii.fr/commons/internal/zipscan"
)

// Status values.
const (
	StatusOK      = "ok"
	StatusExit    = "exit"
	StatusTimeout = "timeout"
	StatusOOM     = "oom"
	StatusError   = "error"
)

// MaxStdout is the stdout cap; exceeding it yields StatusError.
const MaxStdout = 16 << 20

// MaxWasm is the largest module Run accepts by default (StatusError above): compile time and
// memory grow with module size, outside the guest memory limit. Options.MaxWasm raises it for
// pinned modules (14.4).
const MaxWasm = 4 << 20

// CompileCap bounds compilation: a module must compile within min(ms, CompileCap),
// and the time spent compiling counts toward the job's ms budget.
const CompileCap = 10 * time.Second

// MaxFSRead is the per-run cap on bytes read from the mounted filesystem (27.6); past it the
// run ends with StatusError "fs read cap".
const MaxFSRead = 256 << 20

// Diagnostic bounds (27.6): the stderr tail and the wasm stack trace kept in Result.
const (
	MaxStderr = 4 << 10
	MaxTrace  = 2 << 10
)

// DefaultBudget is the byte budget of New's compiled-module LRU (14.4), accounted in module
// bytes: machine code grows roughly with the module.
const DefaultBudget = 64 << 20

// maxPages is the largest memory limit a job may ask for (256 MiB); Precompile decodes under it.
const maxPages = 4096

// Fixed epoch of the fake wall clock (2026-01-01T00:00:00Z) and its step per read.
const (
	fakeEpochNanos = 1767225600 * 1e9
	fakeStep       = int64(time.Millisecond)
)

// Result of one run.
type Result struct {
	Status    string // ok|exit|timeout|oom|error
	Code      int    // exit code (exit)
	Out       []byte // stdout (ok/exit)
	Ms        int    // wall time spent in the guest
	Detail    string // short human detail for error/oom
	Stderr    []byte // tail of the guest's stderr (<= MaxStderr), never part of the fingerprint
	Trace     string // wasm stack trace of a trap (<= MaxTrace)
	CompileMs int    // time spent compiling (0 on a cache hit)
	MemPages  int    // guest linear memory at the end, in 64 KiB pages
}

// Options tune one run; the zero value is the v1 behaviour (no filesystem, MaxWasm cap).
type Options struct {
	MaxWasm int              // per-module size cap in bytes (0 = MaxWasm); a pin raises it to the pin size
	FS      []byte           // zip blob mounted read-only at / (27.6); nil = no filesystem
	Archive *zipscan.Archive // pre-parsed FS (a donor's cache); takes precedence over FS
}

// Runner owns wazero runtimes (one per memory limit) and an LRU of compiled
// modules keyed by sha256(wasm)+limit, bounded by count and by bytes. Safe for concurrent use.
type Runner struct {
	cache  wazero.CompilationCache
	max    int
	budget int64

	mu       sync.Mutex
	runtimes map[uint32]wazero.Runtime
	lru      *list.List
	index    map[string]*list.Element
	size     int64
}

type entry struct {
	key  string
	cm   wazero.CompiledModule
	size int64
}

// New returns a Runner keeping at most maxModules compiled modules (and DefaultBudget module
// bytes) in memory. cacheDir, if non-empty, persists compiled machine code (wazero file cache
// under cacheDir/wazero-<version>-<GOARCH>-<GOOS>, so an upgrade never reads stale code).
func New(cacheDir string, maxModules int) (*Runner, error) {
	return NewWithBudget(cacheDir, maxModules, DefaultBudget)
}

// NewWithBudget is New with an explicit byte budget for the compiled-module LRU: a module is
// accounted at its wasm size and the oldest entries go when either the count or the budget is
// exceeded (the newest entry always stays, even alone over budget).
func NewWithBudget(cacheDir string, maxModules int, budget int64) (*Runner, error) {
	var cache wazero.CompilationCache
	if cacheDir != "" {
		c, err := wazero.NewCompilationCacheWithDir(cacheDir)
		if err != nil {
			return nil, err
		}
		cache = c
	} else {
		cache = wazero.NewCompilationCache()
	}
	if maxModules < 1 {
		maxModules = 1
	}
	if budget < 1 {
		budget = 1
	}
	return &Runner{
		cache:    cache,
		max:      maxModules,
		budget:   budget,
		runtimes: map[uint32]wazero.Runtime{},
		lru:      list.New(),
		index:    map[string]*list.Element{},
	}, nil
}

// Close releases all runtimes and compiled modules.
func (r *Runner) Close(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	var err error
	for k, rt := range r.runtimes {
		err = errors.Join(err, rt.Close(ctx))
		delete(r.runtimes, k)
	}
	r.lru.Init()
	r.index = map[string]*list.Element{}
	r.size = 0
	return errors.Join(err, r.cache.Close(ctx))
}

// Cached reports the compiled modules held in memory and their accounted bytes.
func (r *Runner) Cached() (n int, bytes int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lru.Len(), r.size
}

func runtimeConfig(pages uint32, cache wazero.CompilationCache) wazero.RuntimeConfig {
	// WithCloseOnContextDone is part of wazero's compiled-module identity: Precompile must
	// use the same value for its file cache entries to be the ones a Runner loads.
	return wazero.NewRuntimeConfig().
		WithMemoryLimitPages(pages).
		WithCloseOnContextDone(true).
		WithCompilationCache(cache)
}

func (r *Runner) runtime(ctx context.Context, pages uint32) wazero.Runtime {
	r.mu.Lock()
	defer r.mu.Unlock()
	if rt, ok := r.runtimes[pages]; ok {
		return rt
	}
	rt := wazero.NewRuntimeWithConfig(ctx, runtimeConfig(pages, r.cache))
	wasi_snapshot_preview1.MustInstantiate(ctx, rt)
	r.runtimes[pages] = rt
	return rt
}

// compile returns a compiled module for wasm under the given page limit,
// from the LRU when possible.
func (r *Runner) compile(ctx context.Context, wasm []byte, pages uint32) (wazero.CompiledModule, error) {
	sum := sha256.Sum256(wasm)
	key := hex.EncodeToString(sum[:]) + ":" + fmt.Sprint(pages)

	r.mu.Lock()
	if el, ok := r.index[key]; ok {
		r.lru.MoveToFront(el)
		cm := el.Value.(*entry).cm
		r.mu.Unlock()
		return cm, nil
	}
	r.mu.Unlock()

	cm, err := r.runtime(ctx, pages).CompileModule(ctx, wasm)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if el, ok := r.index[key]; ok { // lost a race; keep the first one
		_ = cm.Close(ctx)
		r.lru.MoveToFront(el)
		return el.Value.(*entry).cm, nil
	}
	r.index[key] = r.lru.PushFront(&entry{key, cm, int64(len(wasm))})
	r.size += int64(len(wasm))
	for r.lru.Len() > 1 && (r.lru.Len() > r.max || r.size > r.budget) {
		el := r.lru.Back()
		e := el.Value.(*entry)
		r.lru.Remove(el)
		delete(r.index, e.key)
		r.size -= e.size
		// Running instances keep their code alive (engine refcount); this
		// only drops our reference.
		_ = e.cm.Close(ctx)
	}
	return cm, nil
}

// Precompile compiles wasm into the wazero file cache under cacheDir, so a Runner opened on the
// same cacheDir loads machine code instead of compiling (14.4 warm phase and the donor's
// child-process compile path: the caller bounds this process's memory with GOMEMLIMIT and its
// time with a deadline). It returns the compile time.
func Precompile(ctx context.Context, cacheDir string, wasm []byte) (time.Duration, error) {
	if cacheDir == "" {
		return 0, errors.New("precompile: cache dir required")
	}
	cache, err := wazero.NewCompilationCacheWithDir(cacheDir)
	if err != nil {
		return 0, err
	}
	defer cache.Close(ctx)
	rt := wazero.NewRuntimeWithConfig(ctx, runtimeConfig(maxPages, cache))
	defer rt.Close(ctx)
	start := time.Now()
	cm, err := rt.CompileModule(ctx, wasm)
	if err != nil {
		return time.Since(start), err
	}
	return time.Since(start), cm.Close(ctx)
}

// Run executes wasm with input on stdin, a wall-clock budget of ms and a
// linear-memory budget of mb MiB. It never panics on guest misbehaviour.
//
// Classification:
//   - exit code 0 -> ok; non-zero -> exit (Code set)
//   - context deadline (ms elapsed, or caller's ctx) -> timeout
//   - declared minimum memory over the limit, or a failed run whose memory
//     reached the limit (see oomHeuristic) -> oom
//   - compile/instantiate failure (bad format, unknown imports), traps,
//     stdout over MaxStdout, module over the size cap, an unusable fs zip or
//     more than MaxFSRead bytes read from it -> error
//   - compilation not finished within min(ms, CompileCap) -> timeout
func (r *Runner) Run(ctx context.Context, wasm, input []byte, ms, mb int) Result {
	return r.RunOpts(ctx, wasm, input, ms, mb, Options{})
}

// RunOpts is Run with Options (27.6 filesystem, 14.4 pinned size cap).
func (r *Runner) RunOpts(ctx context.Context, wasm, input []byte, ms, mb int, o Options) Result {
	if ms <= 0 {
		ms = 1
	}
	if mb <= 0 {
		mb = 1
	}
	pages := uint32(mb) * 16
	start := time.Now()
	res := r.run(ctx, wasm, input, ms, pages, o)
	res.Ms = int(time.Since(start) / time.Millisecond)
	if res.Status != StatusOK && res.Status != StatusExit {
		res.Out = nil
	}
	return res
}

// compileBounded compiles under a deadline of min(budget, CompileCap). wazero does not
// poll ctx while compiling, so the compile runs in a goroutine and we stop waiting at the
// deadline (the orphan finishes and lands in the LRU for a later attempt).
func (r *Runner) compileBounded(ctx context.Context, wasm []byte, pages uint32, budget time.Duration) (wazero.CompiledModule, error) {
	cctx, cancel := context.WithTimeout(ctx, min(budget, CompileCap))
	defer cancel()
	type res struct {
		cm  wazero.CompiledModule
		err error
	}
	ch := make(chan res, 1)
	go func() {
		cm, err := r.compile(context.WithoutCancel(ctx), wasm, pages)
		ch <- res{cm, err}
	}()
	select {
	case x := <-ch:
		return x.cm, x.err
	case <-cctx.Done():
		return nil, cctx.Err()
	}
}

// fsReadCap is MaxFSRead, a variable so tests can lower it.
var fsReadCap = int64(MaxFSRead)

// fsAcct counts guest reads from the mounted filesystem.
type fsAcct struct {
	n    atomic.Int64
	max  int64
	over atomic.Bool
}

func (a *fsAcct) add(n int) bool {
	if a.n.Add(int64(n)) > a.max {
		a.over.Store(true)
		return true
	}
	return false
}

func (r *Runner) run(ctx context.Context, wasm, input []byte, ms int, pages uint32, o Options) Result {
	maxWasm := o.MaxWasm
	if maxWasm <= 0 {
		maxWasm = MaxWasm
	}
	if len(wasm) > maxWasm {
		return Result{Status: StatusError, Detail: fmt.Sprintf("module %d bytes over %d", len(wasm), maxWasm)}
	}
	arc := o.Archive
	if arc == nil && len(o.FS) > 0 {
		a, err := zipscan.Open(o.FS)
		if err != nil {
			return Result{Status: StatusError, Detail: "fs: " + short(err)}
		}
		arc = a
	}
	budget := time.Duration(ms) * time.Millisecond
	start := time.Now()
	cm, err := r.compileBounded(ctx, wasm, pages, budget)
	compileMs := int(time.Since(start) / time.Millisecond)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			return Result{Status: StatusTimeout, Detail: "compile deadline", CompileMs: compileMs}
		}
		if strings.Contains(err.Error(), "over limit of") {
			return Result{Status: StatusOOM, Detail: "declared memory " + short(err), CompileMs: compileMs}
		}
		return Result{Status: StatusError, Detail: "compile: " + short(err), CompileMs: compileMs}
	}
	if budget -= time.Since(start); budget <= 0 {
		return Result{Status: StatusTimeout, Detail: "compile used the budget", CompileMs: compileMs}
	}
	if min := declaredMinPages(cm); min > pages {
		return Result{Status: StatusOOM, Detail: fmt.Sprintf("declared min memory %d pages > limit %d", min, pages), CompileMs: compileMs}
	}

	stdout := &capped{max: MaxStdout}
	stderr := &headTail{max: MaxStderr}
	seed := mrand.NewChaCha8([32]byte{})
	wall, mono := fakeClocks()
	mcfg := wazero.NewModuleConfig().
		WithName("").
		WithArgs("m").
		WithStdin(bytes.NewReader(input)).
		WithStdout(stdout).
		WithStderr(stderr).
		WithRandSource(seed).
		WithWalltime(wall, sys.ClockResolution(fakeStep)).
		WithNanotime(mono, sys.ClockResolution(fakeStep)).
		WithNanosleep(func(int64) {}).
		WithOsyield(func() {})

	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()

	acct := &fsAcct{max: fsReadCap}
	if arc != nil {
		// Past the read cap the run is cancelled; WithCloseOnContextDone stops the guest.
		fsys := arc.FS(func(n int) {
			if acct.add(n) {
				cancel()
			}
		})
		mcfg = mcfg.WithFSConfig(wazero.NewFSConfig().WithFSMount(fsys, "/"))
	}

	mod, err := r.runtime(ctx, pages).InstantiateModule(ctx, cm, mcfg)
	// Go/WASI modules run from _start during instantiation; mod may be nil
	// when the guest exited, so memory usage is read from mod only when set.
	var memPages uint32
	if mod != nil {
		memPages = memPagesOf(mod)
		defer mod.Close(context.WithoutCancel(ctx))
	}
	res := Result{Stderr: stderr.tail(), CompileMs: compileMs, MemPages: int(memPages)}
	if acct.over.Load() {
		res.Status, res.Detail = StatusError, fmt.Sprintf("fs read cap: over %d bytes", acct.max)
		return res
	}
	if ctx.Err() != nil {
		res.Status = StatusTimeout
		return res
	}
	var code int
	if err != nil {
		var ee *sys.ExitError
		switch {
		case errors.As(err, &ee):
			switch ee.ExitCode() {
			case sys.ExitCodeDeadlineExceeded, sys.ExitCodeContextCanceled:
				res.Status = StatusTimeout
				return res
			}
			code = int(ee.ExitCode())
		default: // trap (unreachable, OOB) or missing imports
			res.Trace = traceOf(err)
			if oomHeuristic(memPages, pages, stderr.all()) {
				res.Status, res.Detail = StatusOOM, "trap near memory limit: "+short(err)
				return res
			}
			res.Status, res.Detail = StatusError, short(err)
			return res
		}
	}
	if code != 0 && oomHeuristic(memPages, pages, stderr.all()) {
		res.Status, res.Code, res.Detail = StatusOOM, code, fmt.Sprintf("exit %d with %d/%d pages", code, memPages, pages)
		return res
	}
	if stdout.over {
		res.Status, res.Code, res.Detail = StatusError, code, "stdout exceeds 16 MiB"
		return res
	}
	res.Out = stdout.buf.Bytes()
	if code != 0 {
		res.Status, res.Code = StatusExit, code
		return res
	}
	res.Status = StatusOK
	return res
}

// memPagesOf returns the guest's current linear memory size in pages. A module without a
// memory section yields a nil *MemoryInstance inside a non-nil api.Memory, so the pointer is
// checked before calling Size (that nil call faults in a way the runtime cannot recover).
func memPagesOf(mod api.Module) uint32 {
	m := mod.Memory()
	if m == nil {
		return 0
	}
	if v := reflect.ValueOf(m); v.Kind() == reflect.Pointer && v.IsNil() {
		return 0
	}
	return m.Size() / 65536
}

// oomHeuristic decides whether a failed run died of memory exhaustion.
// wazero offers no hook on memory.grow, so after a non-zero exit or trap we
// combine two signals:
//  1. the guest's linear memory sits in the top 25% of the limit (a Go
//     runtime grows in arenas of up to 4 MiB on wasm, Rust/wasi-libc in
//     smaller steps, so a failed grow leaves the memory near the ceiling);
//  2. stderr (head and tail, 4 KiB each) carries a known allocator failure
//     message (Go "fatal error: out of memory", TinyGo "panic: out of
//     memory", Rust "memory allocation of ... failed", libc ENOMEM).
//
// Either signal with memory above half the limit is enough; the message
// alone is enough when the module is tiny (limit <= 4 MiB).
func oomHeuristic(used, limit uint32, stderr []byte) bool {
	if limit == 0 {
		return false
	}
	msg := false
	for _, m := range oomMarkers {
		if bytes.Contains(stderr, []byte(m)) {
			msg = true
			break
		}
	}
	switch {
	case used*4 >= limit*3:
		return true
	case msg && used*2 >= limit:
		return true
	case msg && limit <= 64:
		return true
	}
	return false
}

var oomMarkers = []string{
	"out of memory",
	"memory allocation of",
	"cannot allocate memory",
	"allocation failed",
	"OutOfMemory",
}

func declaredMinPages(cm wazero.CompiledModule) uint32 {
	var min uint32
	for _, d := range cm.ExportedMemories() {
		if d.Min() > min {
			min = d.Min()
		}
	}
	return min
}

// fakeClocks returns deterministic wall and monotonic clocks, each advancing
// fakeStep per read, fresh per run.
func fakeClocks() (sys.Walltime, sys.Nanotime) {
	var mu sync.Mutex
	w := int64(fakeEpochNanos) - fakeStep
	n := -fakeStep
	wall := func() (int64, int32) {
		mu.Lock()
		defer mu.Unlock()
		w += fakeStep
		return w / 1e9, int32(w % 1e9)
	}
	mono := func() int64 {
		mu.Lock()
		defer mu.Unlock()
		n += fakeStep
		return n
	}
	return wall, mono
}

// capped is a bytes buffer refusing writes beyond max.
type capped struct {
	buf  bytes.Buffer
	max  int
	over bool
}

func (c *capped) Write(p []byte) (int, error) {
	if c.buf.Len()+len(p) > c.max {
		c.over = true
		return 0, errors.New("output cap exceeded")
	}
	return c.buf.Write(p)
}

// headTail keeps the first and the last max bytes written: the head carries the allocator's
// failure message for oomHeuristic, the tail is what a submitter gets as diagnostics.
type headTail struct {
	mu        sync.Mutex
	head, end []byte
	max       int
	n         int
}

func (h *headTail) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.n += len(p)
	if room := h.max - len(h.head); room > 0 {
		h.head = append(h.head, p[:min(room, len(p))]...)
	}
	if len(p) >= h.max {
		h.end = append(h.end[:0], p[len(p)-h.max:]...)
	} else {
		h.end = append(h.end, p...)
		if len(h.end) > 2*h.max {
			h.end = append(h.end[:0], h.end[len(h.end)-h.max:]...)
		}
	}
	return len(p), nil
}

// tail is the last max bytes (nil when nothing was written).
func (h *headTail) tail() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.n == 0 {
		return nil
	}
	t := h.end
	if len(t) > h.max {
		t = t[len(t)-h.max:]
	}
	return bytes.Clone(t)
}

// all is head + tail for marker scans (a 4 KiB message never hides in the gap).
func (h *headTail) all() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append(bytes.Clone(h.head), h.end...)
}

// traceOf extracts the wasm stack trace wazero appends to a trap error.
func traceOf(err error) string {
	const marker = "wasm stack trace:"
	s := err.Error()
	i := strings.Index(s, marker)
	if i < 0 {
		return ""
	}
	s = strings.TrimSpace(s[i+len(marker):])
	if len(s) > MaxTrace {
		s = s[:MaxTrace]
	}
	return s
}

func short(err error) string {
	s := err.Error()
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}
