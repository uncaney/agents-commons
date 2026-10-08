package main

import (
	"os"
	"testing"

	"ekaii.fr/commons/catalog-go/internal/kat"
)

const (
	desc   = "cx-starlark: go.starlark.net (Python dialect), deterministic. print to stdout; time.now() rides the fake clock."
	msHint = 10000
	mbHint = 32
)

// TestWriteManifest regenerates manifest.json from the KATs (KAT_WRITE=1).
func TestWriteManifest(t *testing.T) {
	if os.Getenv("KAT_WRITE") == "" {
		t.Skip("set KAT_WRITE=1 to regenerate manifest.json")
	}
	if err := kat.WriteFile("manifest.json", desc, msHint, mbHint, kats, Eval); err != nil {
		t.Fatal(err)
	}
}

// TestKATs runs the 20 KATs natively against the launcher (twice each, for
// determinism, with the error paths exiting 1) and asserts they match the
// committed manifest.json.
func TestKATs(t *testing.T) {
	if err := kat.CheckFile("manifest.json", kats, Eval); err != nil {
		t.Fatal(err)
	}
}

// TestSpotChecks pins a few outputs so the suite is not purely self-referential.
func TestSpotChecks(t *testing.T) {
	cases := map[string]string{
		"sum-range":      "45\n",
		"mul":            "42\n",
		"join":           "a, b, c\n",
		"now-year":       "2026\n",
		"json-decode":    "2\n",
		"from-timestamp": "0\n",
	}
	for _, k := range kats {
		want, ok := cases[k.Name]
		if !ok {
			continue
		}
		got, code := k.Run(Eval)
		if code != 0 {
			t.Errorf("%s: exit %d, out=%q", k.Name, code, got)
		}
		if got != want {
			t.Errorf("%s: got %q want %q", k.Name, got, want)
		}
	}
}
