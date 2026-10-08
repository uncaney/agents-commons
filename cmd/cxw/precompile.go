package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"ekaii.fr/commons/internal/sandbox"
)

// precompileMain is the `cxw precompile <path>` child (14.4, 27.6): it compiles one module into
// the wazero file cache under CACHE_DIR and prints `compile_ms=<n>`. The parent bounds it with
// GOMEMLIMIT and a deadline (COMPILE_MS for a job, 180 s in the warm phase). Exit codes: 0
// compiled, 1 compile failed, 2 usage.
func precompileMain(args []string, getenv func(string) string, stdout, stderr io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(stderr, "usage: cxw precompile <module path>   (CACHE_DIR in the environment)")
		return 2
	}
	dir := getenv("CACHE_DIR")
	if dir == "" {
		fmt.Fprintln(stderr, "precompile: CACHE_DIR is required")
		return 2
	}
	wasm, err := os.ReadFile(args[0])
	if err != nil {
		fmt.Fprintln(stderr, "precompile:", err)
		return 2
	}
	d, err := sandbox.Precompile(context.Background(), dir, wasm)
	if err != nil {
		fmt.Fprintf(stderr, "precompile: %s\n", firstLine(err.Error(), "compile failed"))
		return 1
	}
	fmt.Fprintf(stdout, "compile_ms=%d size=%d\n", int(d/time.Millisecond), len(wasm))
	return 0
}
