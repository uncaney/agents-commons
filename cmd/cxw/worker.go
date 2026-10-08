package main

import (
	"container/list"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	mrand "math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"ekaii.fr/commons/internal/sandbox"
	"ekaii.fr/commons/internal/zipscan"
)

const (
	leaseWait    = 55
	maxBackoff   = 60 * time.Second
	blobBudget   = 64 << 20 // raw modules and parsed fs zips kept in memory (14.4 byte-budget LRU)
	moduleCached = 8        // compiled modules kept by the sandbox LRU
	maxLeasePins = 32       // pins a lease request may list
	warmTimeout  = 180 * time.Second
	upgradeEvery = 24 * time.Hour // the lease reply's upgrade=/sunset= hint is logged once a day
	dsigDomain   = "cx-dsig-v1\x00"
)

var (
	errCompileTimeout = errors.New("compile-timeout")
	errCompileKilled  = errors.New("compile child killed")
	errBadFS          = errors.New("fs unusable")
)

// Worker pulls leases and runs them in the sandbox.
type Worker struct {
	cfg    Config
	cl     *Client
	sb     *sandbox.Runner
	log    *slog.Logger
	cheat  bool
	once   bool
	now    func() time.Time
	child  func(ctx context.Context, path string) *exec.Cmd // `cxw precompile <path>` (14.4)
	blobs  *blobCache
	leases sync.WaitGroup

	mu        sync.Mutex
	pins      map[string]int64 // warmed pinned modules: hash -> size (download and module size cap)
	compiled  map[string]bool  // modules this process precompiled into the wazero file cache
	key       ed25519.PrivateKey
	upgradeAt time.Time
}

func NewWorker(cfg Config, cl *Client, sb *sandbox.Runner, log *slog.Logger) *Worker {
	return &Worker{cfg: cfg, cl: cl, sb: sb, log: log, now: time.Now, child: defaultChild(cfg),
		blobs: newBlobCache(blobBudget), pins: map[string]int64{}, compiled: map[string]bool{}}
}

// defaultChild runs this binary's precompile subcommand with a minimal environment: the Go
// memory limit bounds the child, so an OOM-killed compile skips the module instead of taking
// the worker down.
func defaultChild(cfg Config) func(context.Context, string) *exec.Cmd {
	exe, err := os.Executable()
	if err != nil {
		exe = os.Args[0]
	}
	return func(ctx context.Context, path string) *exec.Cmd {
		cmd := exec.CommandContext(ctx, exe, "precompile", path)
		cmd.Env = []string{"GOMEMLIMIT=" + strconv.Itoa(cfg.MemLimit) + "MiB", "CACHE_DIR=" + cfg.CacheDir}
		for _, k := range []string{"PATH", "TMPDIR"} {
			if v := os.Getenv(k); v != "" {
				cmd.Env = append(cmd.Env, k+"="+v)
			}
		}
		return cmd
	}
}

// Run starts cfg.Parallel loops and returns when ctx is done and all leases
// held at that moment have been reported (or in -once mode after one lease).
func (w *Worker) Run(ctx context.Context) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < w.cfg.Parallel; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			w.loop(ctx, cancel, w.log.With("slot", n))
		}(i)
	}
	wg.Wait()
	w.leases.Wait()
}

// leaseReq is the donor's offer (14.4, 27.6): ver 2, the caps it accepts and the pins it warmed.
// With PIN_MAX_MB=0 the offer carries no pin cap and no pins (the v1 contract: modules <= 4 MiB).
func (w *Worker) leaseReq() LeaseReq {
	req := LeaseReq{MaxMs: w.cfg.MaxMs, MaxMb: w.cfg.MaxMb, Ver: leaseVer, Caps: []string{capWasm}, Lanes: []string{"public", "own"}}
	if w.cfg.PinMaxMb > 0 {
		req.Caps = append(req.Caps, capPin)
		req.Pins = w.pinList()
	}
	if w.cfg.AcceptNew {
		req.Caps = append(req.Caps, capNew)
	}
	if w.cfg.AcceptL0 {
		req.Caps = append(req.Caps, capL0)
	}
	return req
}

func (w *Worker) loop(ctx context.Context, stop context.CancelFunc, log *slog.Logger) {
	var fails int
	for ctx.Err() == nil {
		if d := w.cfg.Hours.Until(w.now()); d > 0 {
			log.Info("outside window, sleeping", "window", w.cfg.Hours.String(), "sleep_s", int(d.Seconds()))
			if !sleep(ctx, d) {
				return
			}
			continue
		}
		l, err := w.cl.LeaseV2(ctx, leaseWait, w.leaseReq())
		switch {
		case errors.Is(err, ErrNoLease):
			fails = 0
			continue
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			fails++
			d := backoff(fails)
			log.Warn("lease failed", "err", err.Error(), "retry_s", int(d.Seconds()))
			if !sleep(ctx, d) {
				return
			}
			continue
		}
		fails = 0
		w.noteUpgrade(l, log)
		w.leases.Add(1)
		func() {
			defer w.leases.Done()
			// A held lease is finished even if shutdown starts meanwhile.
			w.process(context.WithoutCancel(ctx), l, log.With("job", l.Job, "lease", l.Lease))
		}()
		if w.once {
			stop()
			return
		}
	}
}

// noteUpgrade logs the gateway's upgrade/sunset hint at most once per upgradeEvery.
func (w *Worker) noteUpgrade(l *Lease, log *slog.Logger) {
	if l.Upgrade == "" && l.Sunset == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if now := w.now(); now.Sub(w.upgradeAt) >= upgradeEvery {
		w.upgradeAt = now
		log.Warn("gateway asks for a worker upgrade", "upgrade", l.Upgrade, "sunset", l.Sunset)
	}
}

func (w *Worker) process(ctx context.Context, l *Lease, log *slog.Logger) {
	ms, mb := min(l.Ms, w.cfg.MaxMs), min(l.Mb, w.cfg.MaxMb)
	// Fetching, running and reporting must fit in the lease deadline (2×ms+60s).
	ctx, cancel := context.WithTimeout(ctx, time.Duration(ms)*time.Millisecond+50*time.Second)
	defer cancel()

	pin := w.pinSize(l.Wasm)
	wasm, err := w.fetchWasm(ctx, l.Wasm, pin, l.Lease)
	if errors.Is(err, ErrTooBig) {
		// Refused before compiling: oversized modules are a compile-time memory bomb (review #4c).
		log.Warn("wasm over size cap, reporting error", "err", err.Error())
		w.report(ctx, l, w.done(l, sandbox.Result{Status: sandbox.StatusError}), "module too big", log)
		return
	}
	if err != nil {
		log.Error("wasm download failed", "err", err.Error())
		return
	}
	in, err := w.cl.fetch(ctx, l.In, maxBlob, l.Lease)
	if err != nil {
		log.Error("input download failed", "err", err.Error())
		return
	}
	opts := sandbox.Options{MaxWasm: int(pin)}
	if l.FS != "" {
		arc, err := w.fetchFS(ctx, l.FS, l.Lease)
		switch {
		case errors.Is(err, ErrTooBig), errors.Is(err, errBadFS):
			log.Warn("fs blob refused, reporting error", "err", err.Error())
			w.report(ctx, l, w.done(l, sandbox.Result{Status: sandbox.StatusError}), err.Error(), log)
			return
		case err != nil:
			log.Error("fs download failed", "err", err.Error())
			return
		}
		opts.Archive = arc
	}

	var compileMs int
	if w.cfg.CacheDir != "" && !w.isCompiled(l.Wasm) {
		start := time.Now()
		cms, err := w.compileChild(ctx, l.Wasm, wasm, pin > 0)
		if err != nil {
			el := int(time.Since(start) / time.Millisecond)
			res := sandbox.Result{Status: sandbox.StatusError, Ms: el, CompileMs: el}
			d := w.done(l, res)
			switch {
			case errors.Is(err, errCompileTimeout):
				d.Code = DoneCode{Word: "compile-timeout"}
			case strings.Contains(err.Error(), "over limit of"):
				d.Status = sandbox.StatusOOM // declared memory over the 256 MiB ceiling (v1 classification)
			}
			w.report(ctx, l, d, "compile: "+err.Error(), log)
			return
		}
		compileMs = cms
	}

	res := w.sb.RunOpts(ctx, wasm, in, ms, mb, opts)
	if compileMs > 0 {
		res.CompileMs = compileMs // the child did the compile; the runner only loaded its output
	}
	d := w.done(l, res)
	if res.Status == sandbox.StatusOK || res.Status == sandbox.StatusExit {
		out := res.Out
		if w.cheat {
			out = append(append([]byte{}, out...), "cheat\n"...)
		}
		h, err := w.cl.PutBlob(ctx, out, l.Lease)
		if err != nil {
			// Report rather than let the lease expire (which costs rep): the job output could
			// not be stored, so from the network's point of view this replica errored.
			log.Error("output upload failed, reporting error", "err", err.Error())
			w.report(ctx, l, w.done(l, sandbox.Result{Status: sandbox.StatusError, Ms: res.Ms}), "output upload failed", log)
			return
		}
		d.Out = h
	}
	w.report(ctx, l, d, res.Detail, log)
}

// done builds the report of a run: status, exit code, ms and the failure diagnostics (27.6).
func (w *Worker) done(l *Lease, res sandbox.Result) Done {
	return Done{Lease: l.Lease, Status: res.Status, Code: DoneCode{N: res.Code}, Ms: res.Ms, Diag: diagOf(res)}
}

func diagOf(res sandbox.Result) *Diag {
	d := Diag{Trace: res.Trace, CompileMs: res.CompileMs, MemPages: res.MemPages}
	if len(res.Stderr) > 0 {
		d.Stderr = base64.RawURLEncoding.EncodeToString(res.Stderr)
	}
	if d == (Diag{}) {
		return nil
	}
	return &d
}

// report signs (when a key is registered) and sends a finished lease.
func (w *Worker) report(ctx context.Context, l *Lease, d Done, detail string, log *slog.Logger) {
	if key := w.signer(); key != nil {
		d.Dsig = base64.RawURLEncoding.EncodeToString(ed25519.Sign(key, dsigMessage(l.Job, l.Lease, fingerprint(d))))
	}
	if err := w.cl.Done(ctx, d); err != nil {
		log.Error("done failed", "err", err.Error(), "status", d.Status)
		return
	}
	log.Info("job done", "status", d.Status, "code", d.Code.N, "ms", d.Ms, "detail", detail, "signed", d.Dsig != "")
}

// fingerprint mirrors the gateway's replica fingerprint `status:code:out`: the code counts only
// for status exit and the output hash only for ok/exit (code words and diag never enter it).
func fingerprint(d Done) string {
	code, out := 0, ""
	if d.Status == sandbox.StatusExit {
		code = d.Code.N
	}
	if d.Status == sandbox.StatusOK || d.Status == sandbox.StatusExit {
		out = d.Out
	}
	return d.Status + ":" + strconv.Itoa(code) + ":" + out
}

// dsigMessage is the donor-signed message: "cx-dsig-v1\0" || job || "\0" || lease || "\0" || fingerprint.
func dsigMessage(job, lease, fp string) []byte {
	return []byte(dsigDomain + job + "\x00" + lease + "\x00" + fp)
}

// --- blobs ---------------------------------------------------------------------------------------

// fetchWasm returns the module bytes: from memory, from CACHE_DIR/mod for a warmed pin, else
// downloaded under the pin's size (pin > 0) or the 4 MiB cap of unpinned modules (14.4).
func (w *Worker) fetchWasm(ctx context.Context, hash string, pin int64, lease string) ([]byte, error) {
	if v, ok := w.blobs.get("w:" + hash); ok {
		return v.([]byte), nil
	}
	max := maxWasm
	if pin > 0 {
		max = int(pin)
		if w.cfg.CacheDir != "" {
			if b, err := os.ReadFile(w.modPath(hash)); err == nil && len(b) <= max && sha256hex(b) == hash {
				w.blobs.put("w:"+hash, b, int64(len(b)))
				return b, nil
			}
		}
	}
	b, err := w.cl.fetch(ctx, hash, max, lease)
	if err != nil {
		return nil, err
	}
	w.blobs.put("w:"+hash, b, int64(len(b)))
	return b, nil
}

// fetchFS returns the lease's zip filesystem parsed, cached by its byte size; the download cap is
// 16 MiB unless the hash is a warmed pin (27.6).
func (w *Worker) fetchFS(ctx context.Context, hash, lease string) (*zipscan.Archive, error) {
	if v, ok := w.blobs.get("fs:" + hash); ok {
		return v.(*zipscan.Archive), nil
	}
	max := maxBlob
	if pin := w.pinSize(hash); pin > 0 {
		max = int(pin)
	}
	b, err := w.cl.fetch(ctx, hash, max, lease)
	if err != nil {
		return nil, err
	}
	arc, err := zipscan.Open(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", errBadFS, err)
	}
	w.blobs.put("fs:"+hash, arc, int64(len(b)))
	return arc, nil
}

func (w *Worker) modPath(hash string) string { return filepath.Join(w.cfg.CacheDir, "mod", hash) }

func (w *Worker) pinSize(hash string) int64 {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.pins[hash]
}

func (w *Worker) setPin(hash string, size int64) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pins[hash] = size
}

// pinList is the sorted list of warmed pins (at most maxLeasePins).
func (w *Worker) pinList() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	out := make([]string, 0, len(w.pins))
	for h := range w.pins {
		out = append(out, h)
	}
	sort.Strings(out)
	if len(out) > maxLeasePins {
		out = out[:maxLeasePins]
	}
	return out
}

func (w *Worker) isCompiled(hash string) bool {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.compiled[hash]
}

func (w *Worker) markCompiled(hash string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.compiled[hash] = true
}

func (w *Worker) signer() ed25519.PrivateKey {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.key
}

// --- warm phase and the child-process compile (14.4, 27.6) ---------------------------------------

// Warm downloads every pin up to PIN_MAX_MB (sha256 verified, kept under CACHE_DIR/mod) and
// precompiles it in a child process; a pin whose download or compile fails is skipped and never
// offered. No-op with PIN_MAX_MB=0.
func (w *Worker) Warm(ctx context.Context) {
	if w.cfg.PinMaxMb <= 0 || w.cfg.CacheDir == "" {
		return
	}
	pins, err := w.cl.Pins(ctx)
	if err != nil {
		w.log.Warn("pins list failed, offering no pins", "err", err.Error())
		return
	}
	limit, n := int64(w.cfg.PinMaxMb)<<20, 0
	for _, p := range pins {
		if n >= maxLeasePins || ctx.Err() != nil {
			break
		}
		log := w.log.With("pin", p.Name+"@"+p.Ver, "hash", p.Hash[:12], "size", p.Size)
		if p.Size > limit {
			log.Info("pin over PIN_MAX_MB, skipped")
			continue
		}
		start := time.Now()
		ms, err := w.warmPin(ctx, p)
		if err != nil {
			log.Warn("pin skipped", "err", err.Error())
			continue
		}
		n++
		log.Info("pin warmed", "compile_ms", ms, "total_ms", int(time.Since(start)/time.Millisecond))
	}
}

func (w *Worker) warmPin(ctx context.Context, p Pin) (int, error) {
	path := w.modPath(p.Hash)
	if b, err := os.ReadFile(path); err != nil || sha256hex(b) != p.Hash {
		b, err = w.cl.fetch(ctx, p.Hash, int(p.Size), "")
		if err != nil {
			return 0, err
		}
		if err := writeFile(path, b, 0o600); err != nil {
			return 0, err
		}
	}
	cctx, cancel := context.WithTimeout(ctx, warmTimeout)
	defer cancel()
	ms, err := w.precompile(cctx, path)
	if err != nil {
		os.Remove(path)
		return 0, err
	}
	w.markCompiled(p.Hash)
	w.setPin(p.Hash, p.Size)
	return ms, nil
}

// compileChild compiles a job's module in a child process under COMPILE_MS, so a compile bomb
// costs the child, not the worker: a deadline is reported as code compile-timeout, a killed
// (OOM) or failing child as an error. The module file stays only for pinned modules.
func (w *Worker) compileChild(ctx context.Context, hash string, wasm []byte, keep bool) (int, error) {
	path := w.modPath(hash)
	if err := writeFile(path, wasm, 0o600); err != nil {
		return 0, err
	}
	if !keep {
		defer os.Remove(path)
	}
	cctx, cancel := context.WithTimeout(ctx, time.Duration(w.cfg.CompileMs)*time.Millisecond)
	defer cancel()
	ms, err := w.precompile(cctx, path)
	if err != nil {
		if errors.Is(err, errCompileTimeout) && ctx.Err() != nil {
			return 0, ctx.Err() // the lease deadline, not the compile budget, ended the child
		}
		return 0, err
	}
	w.markCompiled(hash)
	return ms, nil
}

// precompile runs `cxw precompile <path>` and parses its compile_ms= line.
func (w *Worker) precompile(ctx context.Context, path string) (int, error) {
	cmd := w.child(ctx, path)
	out := &headBuf{max: 4 << 10}
	cmd.Stdout, cmd.Stderr = out, out
	cmd.WaitDelay = 2 * time.Second
	err := cmd.Run()
	if ctx.Err() != nil {
		return 0, errCompileTimeout
	}
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && ee.ProcessState != nil && !ee.Exited() {
			return 0, fmt.Errorf("%w: %s", errCompileKilled, ee.ProcessState.String())
		}
		return 0, fmt.Errorf("precompile: %s", firstLine(out.String(), err.Error()))
	}
	ms := 0
	for _, f := range strings.Fields(out.String()) {
		if v, ok := strings.CutPrefix(f, "compile_ms="); ok {
			ms, _ = strconv.Atoi(v)
		}
	}
	return ms, nil
}

// headBuf keeps the first max bytes written (a child's output is diagnostics, not data).
type headBuf struct {
	mu  sync.Mutex
	b   []byte
	max int
}

func (h *headBuf) Write(p []byte) (int, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if room := h.max - len(h.b); room > 0 {
		h.b = append(h.b, p[:min(room, len(p))]...)
	}
	return len(p), nil
}

func (h *headBuf) String() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return string(h.b)
}

func firstLine(s, def string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return def
	}
	return s
}

// writeFile writes b to path atomically (temp file + rename) with mode, creating the directory.
func writeFile(path string, b []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	if _, err = f.Write(b); err == nil {
		err = f.Chmod(mode)
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// --- donor key (27.6) -----------------------------------------------------------------------------

// loadKey returns the donor's ed25519 key from dir/key (hex seed, mode 0600), generated at the
// first start.
func loadKey(dir string) (ed25519.PrivateKey, error) {
	p := filepath.Join(dir, "key")
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		if err := writeFile(p, []byte(hex.EncodeToString(k.Seed())+"\n"), 0o600); err != nil {
			return nil, err
		}
		return k, nil
	}
	if err != nil {
		return nil, err
	}
	seed, err := hex.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s: want a 32-byte hex seed", p)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// RegisterKey loads the donor key from CACHE_DIR/key and registers its public half (PUT /v1/me
// {pub}). Reports are signed only once the gateway confirms it holds this key; otherwise (scoped
// token, rotation quota, an older key) they go unsigned, which the gateway accepts. No-op
// without CACHE_DIR.
func (w *Worker) RegisterKey(ctx context.Context) error {
	if w.cfg.CacheDir == "" {
		return nil
	}
	key, err := loadKey(w.cfg.CacheDir)
	if err != nil {
		return err
	}
	pub := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	got, err := w.cl.PutPub(ctx, pub)
	if err != nil {
		return fmt.Errorf("pub registration: %w", err)
	}
	if got != pub {
		return fmt.Errorf("gateway holds another key (%.12s…); rotation is once per 30 d", got)
	}
	w.mu.Lock()
	w.key = key
	w.mu.Unlock()
	return nil
}

// --- misc ----------------------------------------------------------------------------------------

// backoff returns an exponential delay jittered in [d/2, d], capped at maxBackoff.
func backoff(n int) time.Duration {
	d := time.Second << min(n-1, 6)
	if d > maxBackoff {
		d = maxBackoff
	}
	return d/2 + time.Duration(mrand.Int64N(int64(d/2)+1))
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

// blobCache is a byte-budget LRU of values by key (raw modules, parsed fs archives); a value
// over the whole budget is not kept.
type blobCache struct {
	mu    sync.Mutex
	max   int64
	size  int64
	order *list.List
	m     map[string]*list.Element
}

type blobEntry struct {
	key  string
	v    any
	size int64
}

func newBlobCache(max int64) *blobCache {
	return &blobCache{max: max, order: list.New(), m: map[string]*list.Element{}}
}

func (c *blobCache) get(key string) (any, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.m[key]
	if !ok {
		return nil, false
	}
	c.order.MoveToFront(el)
	return el.Value.(*blobEntry).v, true
}

func (c *blobCache) put(key string, v any, size int64) {
	if size > c.max {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.m[key]; ok {
		c.order.MoveToFront(el)
		return
	}
	c.m[key] = c.order.PushFront(&blobEntry{key, v, size})
	c.size += size
	for c.size > c.max && c.order.Len() > 1 {
		el := c.order.Back()
		e := el.Value.(*blobEntry)
		delete(c.m, e.key)
		c.order.Remove(el)
		c.size -= e.size
	}
}

// bytes is the accounted size of the cached values.
func (c *blobCache) bytes() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.size
}
