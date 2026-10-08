package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"
	"unicode/utf8"

	"ekaii.fr/commons/internal/scrub"
)

// Caps mirror kb.Input (internal/kb) so a gated entry is accepted by POST /v1/kb unchanged.
const (
	maxTitle, maxSymptom, maxCause, maxFix, maxVersions = 160, 1000, 1000, 3000, 200
	maxTags                                             = 8
	maxEntryFile                                        = 64 << 10
	maxListFile                                         = 1 << 20
	maxEntries                                          = 10000
	license                                             = "CC0-1.0"
	dupThreshold                                        = 0.6
)

var tagRe = regexp.MustCompile(`^[a-z0-9.+-]{1,32}$`)

// Entry is one draft or gated entry on disk: the kb.Input fields plus local pipeline state.
// hazard_ok and dup_ok are operator decisions written into the draft; hazard, reviewed and
// review_hash are written by the tool.
type Entry struct {
	Kind       string   `json:"kind"`
	Title      string   `json:"title"`
	Symptom    string   `json:"symptom"`
	Cause      string   `json:"cause"`
	Fix        string   `json:"fix"`
	Versions   string   `json:"versions"`
	Tags       []string `json:"tags"`
	License    string   `json:"license,omitempty"`
	Hazard     []string `json:"hazard,omitempty"`
	HazardOK   bool     `json:"hazard_ok,omitempty"`
	DupOK      bool     `json:"dup_ok,omitempty"`
	Reviewed   bool     `json:"reviewed"`
	ReviewHash string   `json:"review_hash,omitempty"`
}

// hash covers every field a reviewer sees or that changes what is posted; any edit after the
// review changes it and so clears the approval.
func (e *Entry) hash() string {
	b, _ := json.Marshal(struct {
		Kind, Title, Symptom, Cause, Fix, Versions string
		Tags                                       []string
		License                                    string
		HazardOK, DupOK                            bool
	}{e.Kind, e.Title, e.Symptom, e.Cause, e.Fix, e.Versions, e.Tags, e.License, e.HazardOK, e.DupOK})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// approved: reviewed with an explicit y and unchanged since.
func (e *Entry) approved() bool { return e.Reviewed && e.ReviewHash != "" && e.ReviewHash == e.hash() }

// normalize applies the server's write order locally (scrub.Normalize, trim, control chars) so
// what the operator reviews is byte-for-byte what the server stores.
func (e *Entry) normalize() {
	e.Kind = strings.TrimSpace(e.Kind)
	e.Title = squash(scrub.Normalize(e.Title))
	e.Versions = squash(scrub.Normalize(e.Versions))
	e.Symptom = strings.TrimRight(cleanMulti(scrub.Normalize(e.Symptom)), "\n")
	e.Cause = strings.TrimRight(cleanMulti(scrub.Normalize(e.Cause)), "\n")
	e.Fix = strings.TrimRight(cleanMulti(scrub.Normalize(e.Fix)), "\n")
	for i, t := range e.Tags {
		e.Tags[i] = strings.ToLower(strings.TrimSpace(t))
	}
	if e.Tags == nil {
		e.Tags = []string{}
	}
	if e.License == "" {
		e.License = license
	}
}

// check returns the cap/format rejection classes (fixed vocabulary, never text).
func (e *Entry) check(tags map[string]bool) []string {
	var cs []string
	switch e.Kind {
	case "fix", "status", "note":
	default:
		cs = append(cs, "kind")
	}
	switch {
	case e.Title == "":
		cs = append(cs, "empty.title")
	case !oneLine(e.Title):
		cs = append(cs, "line.title")
	case len(e.Title) > maxTitle:
		cs = append(cs, "cap.title")
	}
	if !oneLine(e.Versions) {
		cs = append(cs, "line.versions")
	} else if len(e.Versions) > maxVersions {
		cs = append(cs, "cap.versions")
	}
	for _, f := range []struct {
		n   string
		v   string
		max int
	}{{"symptom", e.Symptom, maxSymptom}, {"cause", e.Cause, maxCause}, {"fix", e.Fix, maxFix}} {
		if len(f.v) > f.max {
			cs = append(cs, "cap."+f.n)
		}
	}
	if e.Kind == "fix" && strings.TrimSpace(e.Fix) == "" {
		cs = append(cs, "empty.fix")
	}
	if len(e.Tags) > maxTags {
		cs = append(cs, "cap.tags")
	}
	for _, t := range e.Tags {
		switch {
		case !tagRe.MatchString(t):
			cs = append(cs, "tag.format")
		case tags != nil && !tags[t]:
			cs = append(cs, "tag.unknown")
		}
	}
	if e.License != license {
		cs = append(cs, "license")
	}
	return uniq(cs)
}

// text is the scan input: every field, newline separated.
func (e *Entry) text() string {
	return strings.Join([]string{e.Title, e.Symptom, e.Cause, e.Fix, e.Versions, strings.Join(e.Tags, " ")}, "\n")
}

func loadEntry(path string) (*Entry, error) {
	b, err := readCapped(path, maxEntryFile)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	var e Entry
	if err := dec.Decode(&e); err != nil {
		return nil, fmt.Errorf("%s: json: %v", filepath.Base(path), err)
	}
	if dec.More() {
		return nil, fmt.Errorf("%s: json: trailing data", filepath.Base(path))
	}
	return &e, nil
}

func saveEntry(path string, e *Entry) error {
	b, err := marshalEntry(e)
	if err != nil {
		return err
	}
	return writeFile(path, b)
}

// marshalEntry renders an entry for hand editing: indented, without HTML escapes.
func marshalEntry(e *Entry) ([]byte, error) {
	if e.Tags == nil {
		e.Tags = []string{}
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(e); err != nil {
		return nil, err
	}
	return b.Bytes(), nil
}

// listEntries returns the sorted *.json files of dir (missing dir = none).
func listEntries(dir string) ([]string, error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, d := range ents {
		if d.Type().IsRegular() && strings.HasSuffix(d.Name(), ".json") && !strings.HasPrefix(d.Name(), ".") {
			out = append(out, filepath.Join(dir, d.Name()))
		}
	}
	sort.Strings(out)
	if len(out) > maxEntries {
		return nil, fmt.Errorf("%s: more than %d entries", dir, maxEntries)
	}
	return out, nil
}

// --- text hygiene (same rules as internal/kb/text.go: user text never starts a line) ---

func isCtl(r rune) bool {
	return unicode.IsControl(r) || r == utf8.RuneError || r == ' ' || r == ' '
}

func oneLine(s string) bool { return utf8.ValidString(s) && strings.IndexFunc(s, isCtl) < 0 }

// squash makes a one-line field: whitespace runs (incl. newlines) collapse to one space.
func squash(s string) string {
	return strings.Join(strings.FieldsFunc(s, func(r rune) bool { return unicode.IsSpace(r) || isCtl(r) }), " ")
}

// cleanMulti keeps \n and \t only among the control characters and folds CRLF.
func cleanMulti(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || !isCtl(r) {
			return r
		}
		return -1
	}, s)
}

// cut truncates to max bytes, preferring a line boundary, never splitting a rune.
func cut(s string, max int) string {
	if len(s) <= max {
		return s
	}
	if i := strings.LastIndexByte(s[:max], '\n'); i > max/2 {
		return s[:i]
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

// term renders a value for the operator's terminal: control characters become visible escapes so
// note content can never drive the terminal; continuation lines are indented.
func term(s string, indent string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r == '\n':
			b.WriteString("\n" + indent)
		case r == '\t':
			b.WriteString("    ")
		case isCtl(r):
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func uniq(ss []string) []string {
	seen := map[string]bool{}
	out := ss[:0]
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// --- dedupe: pg_trgm-style trigram similarity on the normalised title ---

func normTitle(s string) string {
	return strings.Join(strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
		return !unicode.IsLetter(r) && !unicode.IsDigit(r)
	}), " ")
}

func trigrams(s string) map[string]bool {
	out := map[string]bool{}
	for _, w := range strings.Fields(normTitle(s)) {
		p := []rune("  " + w + " ")
		for i := 0; i+3 <= len(p); i++ {
			out[string(p[i:i+3])] = true
		}
	}
	return out
}

func similarity(a, b map[string]bool) float64 {
	if len(a) == 0 || len(b) == 0 {
		return 0
	}
	inter := 0
	for t := range a {
		if b[t] {
			inter++
		}
	}
	return float64(inter) / float64(len(a)+len(b)-inter)
}
