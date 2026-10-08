package kb

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Versions and applies (SPEC-v2 6.1, 13.4): `versions` is free text parsed into lib@ver pairs for
// kb_versions; `applies` is a list of (lib, range) items matched against a caller's `env=`.

// LibVer is one lib@ver pair.
type LibVer struct {
	Lib string `json:"lib"`
	Ver string `json:"ver"`
}

const maxLibs = 8

// versionRe is the 6.1 grammar: `([a-z][a-z0-9_.-]{0,40})[ @/=:]*v?([0-9]+(?:\.[0-9]+){0,3}[0-9a-z.+-]{0,20})`.
var versionRe = regexp.MustCompile(`([a-z][a-z0-9_.-]{0,40})[ @/=:]*v?([0-9]+(?:\.[0-9]+){0,3}[0-9a-z.+-]{0,20})`)

// ParseVersions extracts at most 8 distinct lib@ver pairs from a versions string (preferred form
// `lib@ver, lib@ver`; `lib ver`, `lib/ver`, `lib=ver` and `lib:ver` are accepted).
func ParseVersions(s string) []LibVer {
	var out []LibVer
	seen := map[LibVer]bool{}
	for _, m := range versionRe.FindAllStringSubmatch(strings.ToLower(s), -1) {
		lv := LibVer{strings.Trim(m[1], "._-"), strings.TrimRight(m[2], ".-+")}
		if lv.Lib == "" || lv.Ver == "" || seen[lv] {
			continue
		}
		seen[lv] = true
		out = append(out, lv)
		if len(out) == maxLibs {
			break
		}
	}
	return out
}

// AppliesItem is one (lib, range) pair; Fails marks a range a bad vote reported as failing (6.3).
type AppliesItem struct {
	Lib   string `json:"lib"`
	Range string `json:"range"`
	Fails bool   `json:"fails,omitempty"`
}

// Applies is the `applies` field: JSON array of items, or the text form `lib range; lib range`.
type Applies []AppliesItem

const (
	maxApplies    = 8
	maxAppliesLib = 80
	maxRange      = 60
)

var (
	libKeyRe = regexp.MustCompile(`^[a-z0-9@][a-z0-9@._/:+-]{0,79}$`)
	rangeTok = regexp.MustCompile(`^(>=|<=|==|!=|~=|~>|>|<|=|\^|~)?v?([0-9]+(\.[0-9]+)*(\.[xX*])?|[xX*])([0-9a-zA-Z.+-]*)$`)
)

// UnmarshalJSON accepts an array of {lib, range} objects or a single string in the text form.
func (a *Applies) UnmarshalJSON(b []byte) error {
	b = []byte(strings.TrimSpace(string(b)))
	if len(b) == 0 || string(b) == "null" {
		*a = nil
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		p, err := ParseApplies(s)
		if err != nil {
			return err
		}
		*a = p
		return nil
	}
	var items []AppliesItem
	if err := json.Unmarshal(b, &items); err != nil {
		return err
	}
	*a = items
	return nil
}

// ParseApplies parses `lib range; lib range` (`lib@range` also accepted) into items.
func ParseApplies(s string) (Applies, error) {
	var out Applies
	for _, part := range strings.Split(s, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lib, rng, ok := strings.Cut(part, " ")
		if !ok {
			lib, rng, ok = strings.Cut(part, "@")
			if !ok {
				return nil, core.Bad("applies item needs `lib range`: " + doc.SafeLine(part))
			}
		}
		out = append(out, AppliesItem{Lib: strings.TrimSpace(lib), Range: strings.TrimSpace(rng)})
	}
	return out, nil
}

// Validate normalises (lowercase libs, trimmed ranges) and checks bounds and grammar.
func (a Applies) Validate() error {
	if len(a) > maxApplies {
		return core.Bad("applies > 8 items")
	}
	for i := range a {
		a[i].Lib = strings.ToLower(strings.TrimSpace(a[i].Lib))
		a[i].Range = strings.Join(strings.Fields(a[i].Range), " ")
		if !libKeyRe.MatchString(a[i].Lib) || len(a[i].Lib) > maxAppliesLib {
			return core.Bad("applies lib must match [a-z0-9@._/:+-]{1,80}")
		}
		if len(a[i].Range) > maxRange || !ValidRange(a[i].Range) {
			return core.Bad("applies range not understood: " + doc.SafeLine(a[i].Range))
		}
	}
	return nil
}

// String renders the text form: `npm:react >=18 <19; node 22.x (fails)`.
func (a Applies) String() string {
	parts := make([]string, 0, len(a))
	for _, it := range a {
		s := it.Lib + " " + it.Range
		if it.Fails {
			s += " (fails)"
		}
		parts = append(parts, s)
	}
	return doc.SafeLine(strings.Join(parts, "; "))
}

// JSON is the jsonb value stored for the row ([] when empty).
func (a Applies) JSON() []byte {
	if len(a) == 0 {
		return []byte("[]")
	}
	b, _ := json.Marshal(a)
	return b
}

// find returns the index of the first non-failing item for lib (eco prefix ignored), or -1.
func (a Applies) find(lib string) int {
	for i, it := range a {
		if !it.Fails && sameLib(it.Lib, lib) {
			return i
		}
	}
	return -1
}

// sameLib compares lib keys ignoring an `eco:` prefix on either side (13.4).
func sameLib(a, b string) bool {
	a, b = strings.ToLower(a), strings.ToLower(b)
	if a == b {
		return true
	}
	if i := strings.LastIndexByte(a, ':'); i >= 0 {
		a = a[i+1:]
	}
	if i := strings.LastIndexByte(b, ':'); i >= 0 {
		b = b[i+1:]
	}
	return a == b
}

// ValidRange reports whether s is a range the matcher understands: comparator sets separated by
// `||`, comparators separated by spaces or commas, `a - b` hyphen ranges, wildcards (`22.x`, `*`),
// `^`, `~`, `~=` (PEP 440), `==`, `!=`, `>=`, `>`, `<=`, `<`.
func ValidRange(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || !doc.OneLine(s) {
		return false
	}
	for _, set := range strings.Split(s, "||") {
		toks := strings.FieldsFunc(set, func(r rune) bool { return r == ' ' || r == ',' })
		if len(toks) == 0 {
			return false
		}
		for i, t := range toks {
			if t == "-" {
				if i == 0 || i == len(toks)-1 {
					return false
				}
				continue
			}
			if !rangeTok.MatchString(t) {
				return false
			}
		}
	}
	return true
}

// version is a parsed version: numeric components plus a pre-release/build tail.
type version struct {
	nums []int
	pre  string
}

func parseVersion(s string) (version, bool) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(s), "v"))
	if s == "" || !unicode.IsDigit(rune(s[0])) {
		return version{}, false
	}
	var v version
	rest := s
	for rest != "" && unicode.IsDigit(rune(rest[0])) {
		j := 0
		for j < len(rest) && unicode.IsDigit(rune(rest[j])) {
			j++
		}
		n, err := strconv.Atoi(rest[:j])
		if err != nil || len(v.nums) == 8 {
			return version{}, false
		}
		v.nums = append(v.nums, n)
		rest = rest[j:]
		if strings.HasPrefix(rest, ".") && len(rest) > 1 && unicode.IsDigit(rune(rest[1])) {
			rest = rest[1:]
			continue
		}
		break
	}
	v.pre = strings.TrimLeft(rest, ".-+")
	if i := strings.IndexByte(v.pre, '+'); i >= 0 { // build metadata never orders
		v.pre = v.pre[:i]
	}
	return v, true
}

func (v version) num(i int) int {
	if i < len(v.nums) {
		return v.nums[i]
	}
	return 0
}

// cmp orders two versions: numeric components first, then a pre-release sorts before none.
func (v version) cmp(o version) int {
	for i := 0; i < max(len(v.nums), len(o.nums)); i++ {
		if a, b := v.num(i), o.num(i); a != b {
			if a < b {
				return -1
			}
			return 1
		}
	}
	switch {
	case v.pre == o.pre:
		return 0
	case v.pre == "":
		return 1
	case o.pre == "":
		return -1
	}
	return strings.Compare(v.pre, o.pre)
}

// bump returns the version with component i incremented and the rest zeroed (the open upper bound
// of ^, ~, ~= and wildcard ranges).
func (v version) bump(i int) version {
	nums := make([]int, i+1)
	copy(nums, v.nums)
	nums[i]++
	return version{nums: nums}
}

// Satisfies reports whether ver is inside the range rng (false for unparseable input).
func Satisfies(rng, ver string) bool {
	v, ok := parseVersion(ver)
	if !ok || !ValidRange(rng) {
		return false
	}
	for _, set := range strings.Split(rng, "||") {
		if satisfiesSet(strings.FieldsFunc(set, func(r rune) bool { return r == ' ' || r == ',' }), v) {
			return true
		}
	}
	return false
}

func satisfiesSet(toks []string, v version) bool {
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if i+2 < len(toks) && toks[i+1] == "-" { // a - b
			lo, ok1 := parseVersion(t)
			hi, ok2 := parseVersion(toks[i+2])
			if !ok1 || !ok2 || v.cmp(lo) < 0 || v.cmp(hi) > 0 {
				return false
			}
			i += 2
			continue
		}
		if !satisfiesOne(t, v) {
			return false
		}
	}
	return true
}

func satisfiesOne(t string, v version) bool {
	m := rangeTok.FindStringSubmatch(t)
	if m == nil {
		return false
	}
	op, body := m[1], m[2]+m[5]
	if body == "x" || body == "X" || body == "*" {
		return true
	}
	wild := false
	if strings.HasSuffix(body, ".x") || strings.HasSuffix(body, ".X") || strings.HasSuffix(body, ".*") {
		wild, body = true, body[:len(body)-2]
	}
	b, ok := parseVersion(body)
	if !ok {
		return false
	}
	switch op {
	case ">":
		return v.cmp(b) > 0
	case ">=":
		return v.cmp(b) >= 0
	case "<":
		return v.cmp(b) < 0
	case "<=":
		return v.cmp(b) <= 0
	case "!=":
		return !inPrefix(v, b, wild || len(b.nums) < 3 && b.pre == "")
	case "^": // first non-zero component is fixed
		i := 0
		for i < len(b.nums)-1 && b.nums[i] == 0 {
			i++
		}
		return v.cmp(b) >= 0 && v.cmp(b.bump(i)) < 0
	case "~", "~>": // patch-level changes when a minor is given, else minor-level
		i := min(len(b.nums), 2) - 1
		return v.cmp(b) >= 0 && v.cmp(b.bump(i)) < 0
	case "~=": // PEP 440 compatible release
		i := max(len(b.nums)-2, 0)
		return v.cmp(b) >= 0 && v.cmp(b.bump(i)) < 0
	}
	// "=", "==" or bare: exact when fully specified, prefix match otherwise (22 matches 22.9).
	return inPrefix(v, b, wild || len(b.nums) < 3 && b.pre == "")
}

// inPrefix: v equals b, or (prefix) shares b's leading components with any tail.
func inPrefix(v, b version, prefix bool) bool {
	if !prefix {
		return v.cmp(b) == 0
	}
	for i := range b.nums {
		if v.num(i) != b.nums[i] {
			return false
		}
	}
	return true
}

// ParseEnv reads `env=linux/arm64,node@22.9,pnpm@11`: items with an `@` become lib@ver pairs,
// the rest (os/arch words) is ignored. At most 8 pairs.
func ParseEnv(s string) []LibVer {
	var out []LibVer
	for _, part := range strings.Split(strings.ToLower(s), ",") {
		lib, ver, ok := strings.Cut(strings.TrimSpace(part), "@")
		lib, ver = strings.TrimSpace(lib), strings.TrimSpace(ver)
		if !ok || lib == "" || ver == "" || !libKeyRe.MatchString(lib) || len(ver) > 40 {
			continue
		}
		if _, ok := parseVersion(ver); !ok {
			continue
		}
		out = append(out, LibVer{lib, ver})
		if len(out) == maxLibs {
			break
		}
	}
	return out
}

// envVerdict is how an entry relates to a caller's env (6.2): match ranks first, mismatch is
// marked `(range mismatch)`, fails is marked `[fails on your env]`.
type envVerdict struct{ match, mismatch, fails bool }

// matchEnv evaluates the entry's applies plus the failing ranges reported by bad votes.
func matchEnv(applies Applies, failing []Applies, env []LibVer) envVerdict {
	var v envVerdict
	for _, e := range env {
		for _, it := range applies {
			if !sameLib(it.Lib, e.Lib) {
				continue
			}
			switch sat := Satisfies(it.Range, e.Ver); {
			case it.Fails && sat:
				v.fails = true
			case !it.Fails && sat:
				v.match = true
			case !it.Fails:
				v.mismatch = true
			}
		}
		for _, fa := range failing {
			for _, it := range fa {
				if sameLib(it.Lib, e.Lib) && Satisfies(it.Range, e.Ver) {
					v.fails = true
				}
			}
		}
	}
	return v
}

// splitRange reports whether a bad vote's applies names a range narrower than (different from)
// what the entry declares for the same lib, which marks a failing range instead of counting
// toward hiding (6.3 negative knowledge). Votes without applies, or on libs the entry does not
// declare, or on exactly the declared range count as plain bad votes.
func splitRange(entry, vote Applies) (split Applies, ok bool) {
	for _, vi := range vote {
		i := entry.find(vi.Lib)
		if i < 0 || strings.EqualFold(entry[i].Range, vi.Range) {
			continue
		}
		split = append(split, AppliesItem{Lib: entry[i].Lib, Range: vi.Range, Fails: true})
	}
	return split, len(split) > 0
}

// withFails appends failing ranges to the entry's applies (deduplicated, capped at 16 items).
func withFails(entry Applies, fails Applies) Applies {
	out := append(Applies(nil), entry...)
	for _, f := range fails {
		dup := false
		for _, it := range out {
			if it.Fails && sameLib(it.Lib, f.Lib) && strings.EqualFold(it.Range, f.Range) {
				dup = true
				break
			}
		}
		if !dup && len(out) < 2*maxApplies {
			out = append(out, f)
		}
	}
	return out
}

// decodeApplies reads a jsonb applies value ([] or null -> nil).
func decodeApplies(b []byte) Applies {
	if len(b) == 0 {
		return nil
	}
	var a Applies
	if json.Unmarshal(b, &a) != nil {
		return nil
	}
	return a
}
