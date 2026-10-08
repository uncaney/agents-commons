// cxw is the donor worker: it leases sandboxed WASM jobs from the commons
// gateway, runs them under wazero and reports the results.
//
// `cxw precompile <path>` is the child process the worker spawns to compile a module into its
// file cache under a memory limit and a deadline (SPEC-v2 14.4, 27.6).
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"runtime/debug"
	"syscall"

	"ekaii.fr/commons/internal/sandbox"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "precompile" {
		os.Exit(precompileMain(os.Args[2:], os.Getenv, os.Stdout, os.Stderr))
	}
	once := flag.Bool("once", false, "process one lease then exit")
	cheat := flag.Bool("cheat", false, "")
	flag.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: cxw [-once] | cxw precompile <path>\nconfig via env: CX_URL CX_TOKEN_FILE MAX_MS MAX_MB PARALLEL HOURS CACHE_DIR MEM_LIMIT_MB PIN_MAX_MB COMPILE_MS ACCEPT_NEW ACCEPT_L0")
	}
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	cfg, err := loadConfig(os.Getenv)
	if err != nil {
		log.Error("config", "err", err.Error())
		os.Exit(2)
	}
	if *cheat && os.Getenv("CXW_ALLOW_CHEAT") != "1" {
		log.Error("-cheat requires CXW_ALLOW_CHEAT=1")
		os.Exit(2)
	}
	// Process-level guard: compiled code and compiler scratch live outside the guest
	// memory limit; the GC works harder as we approach MEM_LIMIT_MB (review #4c).
	debug.SetMemoryLimit(int64(cfg.MemLimit) << 20)
	sb, err := sandbox.New(cfg.CacheDir, moduleCached)
	if err != nil {
		log.Error("sandbox", "err", err.Error())
		os.Exit(2)
	}
	defer sb.Close(context.Background())

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	w := NewWorker(cfg, NewClient(cfg.URL, cfg.Token), sb, log)
	w.once, w.cheat = *once, *cheat
	if err := w.RegisterKey(ctx); err != nil {
		log.Warn("donor key not registered, reports go unsigned", "err", err.Error())
	}
	w.Warm(ctx)
	log.Info("cxw starting", "url", cfg.URL, "max_ms", cfg.MaxMs, "max_mb", cfg.MaxMb,
		"parallel", cfg.Parallel, "hours", cfg.Hours.String(), "mem_limit_mb", cfg.MemLimit,
		"pin_max_mb", cfg.PinMaxMb, "pins", len(w.pinList()), "compile_ms", cfg.CompileMs,
		"accept_new", cfg.AcceptNew, "accept_l0", cfg.AcceptL0, "signed", w.signer() != nil, "cheat", *cheat)
	w.Run(ctx)
	log.Info("cxw stopped")
}
