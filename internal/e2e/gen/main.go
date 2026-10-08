// Command gen regenerates internal/e2e/vectors from the kat package:
//
//	go run ./internal/e2e/gen -seed 0
//
// Generation is deterministic from the seed; HPKE encapsulations (which the standard library randomizes)
// are reused from the existing files when they still open, so a rerun is byte-identical.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ekaii.fr/commons/internal/e2e/kat"
)

func main() {
	seed := flag.Uint64("seed", 0, "generator seed (SHAKE256 stream)")
	out := flag.String("out", "internal/e2e/vectors", "output directory")
	check := flag.Bool("check", false, "only verify that the directory is byte-identical to a regeneration")
	flag.Parse()
	prior := map[string][]byte{}
	entries, err := os.ReadDir(*out)
	if err != nil && !os.IsNotExist(err) {
		fail(err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(*out, e.Name()))
		if err != nil {
			fail(err)
		}
		prior[e.Name()] = b
	}
	files, err := kat.Generate(*seed, prior)
	if err != nil {
		fail(err)
	}
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fail(err)
	}
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	changed := 0
	for _, n := range names {
		status := "unchanged"
		if !bytes.Equal(prior[n], files[n]) {
			changed++
			status = "written"
			if *check {
				status = "DIFFERS"
			} else if err := os.WriteFile(filepath.Join(*out, n), files[n], 0o644); err != nil {
				fail(err)
			}
		}
		fmt.Printf("%-14s %7d bytes  %s\n", n, len(files[n]), status)
	}
	for n := range prior {
		if _, ok := files[n]; !ok {
			fmt.Printf("%-14s stale: not generated any more, delete it\n", n)
		}
	}
	if *check && changed > 0 {
		fail(fmt.Errorf("%d file(s) differ", changed))
	}
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "gen:", err)
	os.Exit(1)
}
