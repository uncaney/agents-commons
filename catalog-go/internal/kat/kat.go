// Package kat defines the known-answer tests shared by the three launchers and
// the helpers that run them natively and materialise catalog manifests. A KAT
// is one framed program plus the expectation (exit 0 with pinned stdout, or
// the error path with exit 1); 20 per interpreter cover arithmetic, strings,
// json, regex-ish, dates under the fake clock and error paths (15.4, 27.6).
package kat

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"ekaii.fr/commons/catalog-go/internal/launch"
)

// KAT is one known-answer test.
type KAT struct {
	Name  string // stable id
	Cat   string // arithmetic|strings|json|regex|dates|error
	Code  string // program source
	Stdin string // stdin fed to the program
	Err   bool   // true when the program must exit 1 (error path)
}

// Frame renders the KAT as the 15.4 {"code","stdin"} launcher payload.
func (k KAT) Frame() string {
	b, _ := json.Marshal(map[string]string{"code": k.Code, "stdin": k.Stdin})
	return string(b)
}

// Run executes the framed KAT through eval and returns stdout and the exit code.
func (k KAT) Run(eval launch.Eval) (string, int) {
	var out bytes.Buffer
	code := launch.Dispatch([]byte(k.Frame()), &out, eval)
	return out.String(), code
}

// Manifest mirrors the fields catalog.Manifest reads from a published service's
// manifest.json (15.1, 27.6); only the subset the interpreters set is present.
type Manifest struct {
	Desc   string `json:"desc,omitempty"`
	Usage  string `json:"usage,omitempty"`
	ABI    string `json:"abi,omitempty"`
	In     string `json:"in,omitempty"`
	Out    string `json:"out,omitempty"`
	MsHint int    `json:"ms_hint,omitempty"`
	MbHint int    `json:"mb_hint,omitempty"`
	Fee    int    `json:"fee,omitempty"`
	Tests  []Test `json:"tests"`
}

// Test is one catalog known-answer test: a framed input and the sha256 of the
// expected stdout.
type Test struct {
	InText    string `json:"in_text"`
	OutSHA256 string `json:"out_sha256"`
}

// SHA256 is the lowercase hex digest of s.
func SHA256(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])
}

// BuildManifest runs every KAT through eval and returns a manifest whose tests
// pin each KAT's framed input to the sha256 of its (deterministic) stdout. It
// errors if a non-error KAT does not exit 0, an error KAT does not exit 1, or a
// second run differs from the first (nondeterminism).
func BuildManifest(desc string, msHint, mbHint int, kats []KAT, eval launch.Eval) (*Manifest, error) {
	m := &Manifest{Desc: desc, ABI: "text", In: "{code,stdin} or NUL-split (15.4)", Out: "program stdout; traceback + exit 1 on error", MsHint: msHint, MbHint: mbHint}
	for _, k := range kats {
		out, code := k.Run(eval)
		out2, code2 := k.Run(eval)
		if out != out2 || code != code2 {
			return nil, fmt.Errorf("kat %s nondeterministic: %q/%d vs %q/%d", k.Name, out, code, out2, code2)
		}
		if k.Err && code != 1 {
			return nil, fmt.Errorf("kat %s expected error exit 1, got %d: %q", k.Name, code, out)
		}
		if !k.Err && code != 0 {
			return nil, fmt.Errorf("kat %s expected exit 0, got %d: %q", k.Name, code, out)
		}
		m.Tests = append(m.Tests, Test{InText: k.Frame(), OutSHA256: SHA256(out)})
	}
	return m, nil
}

// Marshal renders the manifest as the pretty JSON written to manifest.json.
func (m *Manifest) Marshal() ([]byte, error) {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// WriteFile materialises manifest.json at path from the KATs (generator, run
// with KAT_WRITE=1). It requires exactly 20 KATs.
func WriteFile(path, desc string, msHint, mbHint int, kats []KAT, eval launch.Eval) error {
	if len(kats) != 20 {
		return fmt.Errorf("want 20 KATs, have %d", len(kats))
	}
	m, err := BuildManifest(desc, msHint, mbHint, kats, eval)
	if err != nil {
		return err
	}
	b, err := m.Marshal()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// CheckFile rebuilds the manifest from the KATs and eval (which re-verifies
// determinism and the error-path exit codes) and asserts it equals the committed
// manifest.json at path, which must carry exactly 20 tests.
func CheckFile(path string, kats []KAT, eval launch.Eval) error {
	if len(kats) != 20 {
		return fmt.Errorf("want 20 KATs, have %d", len(kats))
	}
	built, err := BuildManifest("", 0, 0, kats, eval)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var on Manifest
	if err := json.Unmarshal(raw, &on); err != nil {
		return fmt.Errorf("%s: %v", path, err)
	}
	if len(on.Tests) != 20 {
		return fmt.Errorf("%s: want 20 tests, have %d", path, len(on.Tests))
	}
	for i, tt := range built.Tests {
		if on.Tests[i].InText != tt.InText {
			return fmt.Errorf("%s test %d (%s): in_text drift", path, i, kats[i].Name)
		}
		if on.Tests[i].OutSHA256 != tt.OutSHA256 {
			return fmt.Errorf("%s test %d (%s): out_sha256 %s, launcher produces %s", path, i, kats[i].Name, on.Tests[i].OutSHA256, tt.OutSHA256)
		}
	}
	return nil
}
