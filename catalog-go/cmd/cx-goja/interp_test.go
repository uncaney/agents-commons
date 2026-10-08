package main

import (
	"os"
	"testing"

	"ekaii.fr/commons/catalog-go/internal/kat"
)

const (
	desc   = "cx-goja: github.com/dop251/goja (ES5.1+). print/console.log to stdout; Date and Math.random ride a constant clock/rand source."
	msHint = 10000
	mbHint = 32
)

func TestWriteManifest(t *testing.T) {
	if os.Getenv("KAT_WRITE") == "" {
		t.Skip("set KAT_WRITE=1 to regenerate manifest.json")
	}
	if err := kat.WriteFile("manifest.json", desc, msHint, mbHint, kats, Eval); err != nil {
		t.Fatal(err)
	}
}

func TestKATs(t *testing.T) {
	if err := kat.CheckFile("manifest.json", kats, Eval); err != nil {
		t.Fatal(err)
	}
}

func TestSpotChecks(t *testing.T) {
	cases := map[string]string{
		"precedence":  "7\n",
		"for-sum":     "45\n",
		"stringify":   "{\"a\":1,\"b\":[2,3]}\n",
		"now-year":    "2026\n",
		"epoch-year":  "1970\n",
		"random-type": "number\n",
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
