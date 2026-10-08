package e2e_test

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/e2e/kat"
)

func readVectors(t *testing.T) map[string][]byte {
	t.Helper()
	entries, err := os.ReadDir("vectors")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]byte{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join("vectors", e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[e.Name()] = b
	}
	return out
}

// TestVectorsAllCompositions: every KAT in vectors/ round-trips through the e2e package and every negative
// vector fails (kat.Check does both); the set of files is exactly kat.Files, and every file that has a
// negative section has at least three entries.
func TestVectorsAllCompositions(t *testing.T) {
	files := readVectors(t)
	for _, name := range kat.Files {
		data, ok := files[name]
		if !ok {
			t.Errorf("%s missing: go run ./internal/e2e/gen", name)
			continue
		}
		if err := kat.Check(name, data); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		var doc struct {
			Name     string            `json:"name"`
			Negative []json.RawMessage `json:"negative"`
			Cases    []struct {
				Expect string `json:"expect"`
			} `json:"cases"`
		}
		if err := json.Unmarshal(data, &doc); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if doc.Name+".json" != name {
			t.Errorf("%s: name field %q", name, doc.Name)
		}
		failing := len(doc.Negative)
		for _, c := range doc.Cases {
			if strings.HasPrefix(c.Expect, "err") {
				failing++
			}
		}
		switch name {
		case "labels.json", "derive.json", "att.json":
		default:
			if failing < 3 {
				t.Errorf("%s: only %d negative vectors", name, failing)
			}
		}
	}
	for name := range files {
		found := false
		for _, f := range kat.Files {
			found = found || f == name
		}
		if !found {
			t.Errorf("%s is not a generated vector file", name)
		}
	}
	if err := kat.Check("nope.json", nil); err == nil {
		t.Error("unknown file accepted")
	}
}

// TestGenByteIdentical: `go run ./internal/e2e/gen -seed 0` over the checked-in files reproduces them.
func TestGenByteIdentical(t *testing.T) {
	prior := readVectors(t)
	out, err := kat.Generate(0, prior)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range kat.Files {
		if !bytes.Equal(out[name], prior[name]) {
			t.Errorf("%s differs from a regeneration (run go run ./internal/e2e/gen)", name)
		}
	}
	// without the prior files the deterministic parts still agree: only the HPKE-recorded fields may move
	fresh, err := kat.Generate(0, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"labels.json", "derive.json", "pad.json", "merkle.json", "reqsig.json", "cxs1.json", "state.json", "att.json", "bundle.json", "dvr.json"} {
		if !bytes.Equal(fresh[name], prior[name]) {
			t.Errorf("%s is not deterministic from the seed", name)
		}
	}
	if _, err := kat.Generate(1, nil); err != nil {
		t.Fatal(err)
	}
}
