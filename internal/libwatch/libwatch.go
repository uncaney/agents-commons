// Package libwatch implements SPEC-v2 27.3: environment manifests and drift reports
// (POST /v1/env), verified-claim alerts, the anonymous /v/env read, lib_releases and the cutoff
// probe. Manifests are root-private (export-me, purge). Every write path is size-capped, quota'd
// and line-injection-safe through the core and know helpers.
package libwatch

import (
	"context"
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/know"
)

func itoa(n int) string { return strconv.Itoa(n) }

func nowYM() string { return time.Now().UTC().Format("2006-01") }

const (
	// MaxBody caps the raw manifest body (27.3: <= 64 KiB).
	MaxBody = 64 << 10
	// MaxLibs caps the libs parsed from one manifest (27.3).
	MaxLibs = 400
	// MaxName caps a manifest name.
	MaxName = 32
	// MaxAnonLibs caps the anonymous /v/env read (27.3).
	MaxAnonLibs = 20
	// StorageCap bounds the two owned tables.
	StorageCap = 64 << 20
)

// manifestCap returns the per-root manifest cap (27.3: 5 at L0, 20 at L1+).
func manifestCap(lvl int) int {
	if lvl >= 1 {
		return 20
	}
	return 5
}

// entry is one parsed, resolved manifest member stored in env_manifests.libs.
type entry struct {
	Key  string `json:"k"`
	Have string `json:"v"`
}

// rawDep is a (name, version) pair a per-format parser extracts before alias resolution.
type rawDep struct{ name, ver string }

// --- per-format RE2 line parsers (27.3) ---------------------------------------------------------

// ecoOf maps a manifest format to the ecosystem its bare names belong to; env has none (its
// tokens are resolved as written, bare alias or eco:name).
var ecoOf = map[string]string{"pkg": "npm", "req": "pypi", "gomod": "go", "cargo": "crates", "env": ""}

var (
	reqRe   = regexp.MustCompile(`(?m)^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*(?:\[[^\]]*\])?[ \t]*==[ \t]*([A-Za-z0-9][A-Za-z0-9.*+!_-]*)`)
	gomodRe = regexp.MustCompile(`(?m)^[ \t]*(?:require[ \t]+)?([a-zA-Z0-9][a-zA-Z0-9._~-]*(?:\.[a-zA-Z0-9._~-]+)+(?:/[A-Za-z0-9._~+-]+)*)[ \t]+(v[0-9]+[0-9A-Za-z.\-+]*)`)
	cargoRe = regexp.MustCompile(`^[ \t]*([A-Za-z0-9][A-Za-z0-9._-]*)[ \t]*=[ \t]*(?:"([^"]+)"|\{[^}]*\bversion[ \t]*=[ \t]*"([^"]+)"[^}]*\})`)
	envTok  = regexp.MustCompile(`[,\s]+`)
	sectRe  = regexp.MustCompile(`^[ \t]*\[([^\]]+)\]`)
)

// ParseFormat parses a raw manifest body of the given format into deduped (name, version) deps,
// bounded to MaxLibs. An unknown format is a bad request; a malformed body yields whatever lines
// parse (never an error) so a stray line never sinks the whole manifest.
func ParseFormat(format string, body []byte) ([]rawDep, error) {
	if _, ok := ecoOf[format]; !ok {
		return nil, core.Bad("fmt must be pkg|req|gomod|cargo|env")
	}
	var deps []rawDep
	add := func(name, ver string) {
		if len(deps) >= MaxLibs {
			return
		}
		name = strings.TrimSpace(name)
		ver = cleanVer(ver)
		if name == "" || ver == "" {
			return
		}
		deps = append(deps, rawDep{name, ver})
	}
	switch format {
	case "pkg":
		parsePkg(body, add)
	case "req":
		for _, m := range reqRe.FindAllSubmatch(body, MaxLibs) {
			add(string(m[1]), string(m[2]))
		}
	case "gomod":
		for _, m := range gomodRe.FindAllSubmatch(body, MaxLibs*2) {
			add(string(m[1]), string(m[2]))
		}
	case "cargo":
		parseCargo(body, add)
	case "env":
		for _, tok := range envTok.Split(string(body), -1) {
			if name, ver, ok := splitAt(tok); ok {
				add(name, ver)
			}
		}
	}
	return deps, nil
}

// splitAt splits an env token `name@ver` or `name=ver` (the `:` of an eco:name key is kept).
func splitAt(tok string) (name, ver string, ok bool) {
	tok = strings.TrimSpace(tok)
	if tok == "" {
		return "", "", false
	}
	i := strings.LastIndexAny(tok, "@=")
	if i <= 0 || i == len(tok)-1 {
		return "", "", false
	}
	// a leading `@` is an npm scope, not a separator.
	if tok[i] == '@' && strings.IndexByte(tok, '@') == 0 && strings.LastIndexByte(tok, '@') == 0 {
		return "", "", false
	}
	return tok[:i], tok[i+1:], true
}

// cleanVer strips a leading range operator and keeps the first concrete token; dynamic specs
// (*, latest, workspace:, file:, git/url) are dropped (empty).
func cleanVer(v string) string {
	v = strings.TrimSpace(v)
	v = strings.TrimLeft(v, "^~>=<= v")
	if i := strings.IndexAny(v, " ,|"); i >= 0 {
		v = v[:i]
	}
	v = strings.TrimSpace(v)
	switch {
	case v == "" || v == "*" || strings.EqualFold(v, "latest") || strings.ContainsAny(v, "*"):
		return ""
	case strings.Contains(v, ":") || strings.Contains(v, "/"):
		return "" // workspace:, file:, git+https://…
	}
	return v
}

// parsePkg reads the dependency maps of a package.json or package-lock.json (dependencies,
// devDependencies, peerDependencies, optionalDependencies, and a lockfile's packages map); a
// value is a version spec string or an object carrying a "version" field.
func parsePkg(body []byte, add func(name, ver string)) {
	var top map[string]json.RawMessage
	if json.Unmarshal(body, &top) != nil {
		return
	}
	for _, field := range []string{"dependencies", "devDependencies", "peerDependencies", "optionalDependencies", "packages"} {
		raw, ok := top[field]
		if !ok {
			continue
		}
		var m map[string]json.RawMessage
		if json.Unmarshal(raw, &m) != nil {
			continue
		}
		for name, val := range m {
			var s string
			if json.Unmarshal(val, &s) == nil {
				add(pkgName(field, name), s)
				continue
			}
			var o struct {
				Version string `json:"version"`
			}
			if json.Unmarshal(val, &o) == nil && o.Version != "" {
				add(pkgName(field, name), o.Version)
			}
		}
	}
}

// pkgName normalises a lockfile "packages" key (node_modules/<pkg>) to the bare package name.
func pkgName(field, name string) string {
	if field == "packages" {
		if i := strings.LastIndex(name, "node_modules/"); i >= 0 {
			name = name[i+len("node_modules/"):]
		}
	}
	return name
}

// parseCargo reads simple [dependencies]/[dev-dependencies]/[build-dependencies] tables of a
// Cargo.toml (inline tables with a version key included).
func parseCargo(body []byte, add func(name, ver string)) {
	in := false
	for _, line := range strings.Split(string(body), "\n") {
		if m := sectRe.FindStringSubmatch(line); m != nil {
			sec := strings.TrimSpace(m[1])
			in = sec == "dependencies" || sec == "dev-dependencies" || sec == "build-dependencies"
			continue
		}
		if !in {
			continue
		}
		if m := cargoRe.FindStringSubmatch(line); m != nil {
			ver := m[2]
			if ver == "" {
				ver = m[3]
			}
			add(m[1], ver)
		}
	}
}

// --- resolution -------------------------------------------------------------------------------

// resolve maps parsed deps to canonical keys. Formatted manifests force the format's ecosystem;
// env tokens resolve as written (bare alias via know.ResolveLib or an explicit eco:name). Entries
// that do not resolve are dropped. Keys are deduped, keeping the first version seen.
func resolve(ctx context.Context, q core.Q, format string, deps []rawDep) []entry {
	eco := ecoOf[format]
	seen := map[string]bool{}
	out := make([]entry, 0, len(deps))
	for _, d := range deps {
		var key string
		var ok bool
		if eco == "" {
			key, ok = know.ResolveLib(ctx, q, d.name)
		} else {
			key, ok = resolveEco(eco, d.name)
		}
		if !ok || seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, entry{Key: key, Have: cutVer(d.ver)})
	}
	return out
}

// resolveEco builds and validates an eco:name key from a bare package name.
func resolveEco(eco, name string) (string, bool) {
	key, err := know.ParseKey(eco + ":" + name)
	if err != nil {
		return "", false
	}
	return key, true
}

func cutVer(v string) string {
	if len(v) > 60 {
		return v[:60]
	}
	return v
}

// --- drift report -----------------------------------------------------------------------------

// libDrift is one line of a drift report.
type libDrift struct {
	Key, Have, Latest, Newest string
	Brk, Sec, Eol             int
	drifts                    bool
}

// report is a rendered drift report over a set of manifest entries.
type report struct {
	name              string
	total, known, cnt int
	lines             []libDrift
	anon              bool
}

// buildReport resolves every entry's latest version, newest release date and claim counts and
// marks which libs drift. all keeps libs without claims; otherwise only drifting libs are listed.
func buildReport(ctx context.Context, q core.Q, name string, entries []entry, all, anon bool) (*report, error) {
	rep := &report{name: name, total: len(entries), anon: anon}
	for _, e := range entries {
		ld := libDrift{Key: e.Key, Have: e.Have}
		latest, newest, hasRow, err := libInfo(ctx, q, e.Key)
		if err != nil {
			return nil, err
		}
		ld.Latest, ld.Newest = latest, newest
		lines, err := know.ClaimsAfter(ctx, q, e.Key, e.Have, nil)
		if err == nil {
			for _, l := range lines {
				switch l.Kind {
				case "breaking":
					ld.Brk++
				case "security":
					ld.Sec++
				case "eol":
					ld.Eol++
				}
			}
		}
		if hasRow || len(lines) > 0 {
			rep.known++
		}
		ld.drifts = ld.Brk > 0 || ld.Sec > 0 || ld.Eol > 0 || behind(e.Have, latest)
		if ld.drifts {
			rep.cnt++
		}
		if ld.drifts || all {
			rep.lines = append(rep.lines, ld)
		}
	}
	sort.SliceStable(rep.lines, func(i, j int) bool {
		a, b := rep.lines[i], rep.lines[j]
		if a.Sec != b.Sec {
			return a.Sec > b.Sec
		}
		if a.Brk != b.Brk {
			return a.Brk > b.Brk
		}
		return a.Key < b.Key
	})
	return rep, nil
}

// libInfo returns the registry latest version, the newest release date (YYYY-MM-DD or "-") and
// whether a libs row exists for key.
func libInfo(ctx context.Context, q core.Q, key string) (latest, newest string, hasRow bool, err error) {
	var l string
	var lt *time.Time
	err = q.QueryRow(ctx, `SELECT latest, latest_at FROM libs WHERE key = $1`, key).Scan(&l, &lt)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return "", "-", false, nil
		}
		return "", "-", false, err
	}
	newest = "-"
	if lt != nil && !lt.IsZero() {
		newest = core.Date(*lt)
	}
	return l, newest, true, nil
}

// behind reports whether have is a parseable version strictly older than latest.
func behind(have, latest string) bool {
	if have == "" || latest == "" || !know.Parseable(have) || !know.Parseable(latest) {
		return false
	}
	return know.VKey(have) < know.VKey(latest)
}

// Text renders a report: the head line, one line per lib, and a next: hint.
func (rep *report) Text() string {
	var b strings.Builder
	head := "env " + doc.SafeLine(rep.name)
	if rep.anon {
		head = "env (anon)"
	}
	b.WriteString(head)
	b.WriteString(" libs=")
	b.WriteString(itoa(rep.total))
	b.WriteString(" known=")
	b.WriteString(itoa(rep.known))
	b.WriteString(" drift=")
	b.WriteString(itoa(rep.cnt))
	b.WriteByte('\n')
	for _, l := range rep.lines {
		b.WriteString(l.line())
		b.WriteByte('\n')
	}
	b.WriteString(rep.next())
	b.WriteByte('\n')
	return b.String()
}

func (l libDrift) line() string {
	return doc.SafeLine(l.Key) + " have=" + orDash(l.Have) + " latest=" + orDash(l.Latest) +
		" brk=" + itoa(l.Brk) + " sec=" + itoa(l.Sec) + " eol=" + eolField(l.Eol) + " newest=" + orDash(l.Newest)
}

// next offers the deepest follow-up: a breaking-change range on the top drifting lib and a /since
// window for the whole manifest.
func (rep *report) next() string {
	ym := nowYM()
	if len(rep.lines) > 0 {
		l := rep.lines[0]
		seg := know.EncodeKey(l.Key)
		rng := ""
		if l.Have != "" && l.Latest != "" {
			rng = "/" + l.Have + ".." + l.Latest
		}
		return "next: GET /v/" + seg + rng + "?kind=breaking | GET /since/" + ym + "?libs=" + libsParam(rep.lines)
	}
	return "next: GET /since/" + ym
}

func libsParam(lines []libDrift) string {
	parts := make([]string, 0, len(lines))
	for i, l := range lines {
		if i >= 10 {
			break
		}
		parts = append(parts, know.EncodeKey(l.Key))
	}
	return strings.Join(parts, ",")
}

func eolField(n int) string {
	if n == 0 {
		return "-"
	}
	return itoa(n)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return doc.SafeLine(s)
}
