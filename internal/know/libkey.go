package know

import (
	"context"
	"errors"
	"net/url"
	"regexp"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Library identity (13.4): keys are `eco:name`; bare names resolve through lib_alias; keys in
// paths are percent-encoded (`/v/go%3Agithub.com%2Fjackc%2Fpgx%2Fv5/5.7`).

var (
	ecos = map[string]bool{"pypi": true, "npm": true, "go": true, "crates": true, "gem": true, "maven": true,
		"nuget": true, "apt": true, "docker": true, "api": true}
	nameRe  = regexp.MustCompile(`^[A-Za-z0-9@_][A-Za-z0-9_.:/@+-]{0,199}$`)
	aliasRe = regexp.MustCompile(`^[a-z0-9@][a-z0-9_.+-]{0,63}$`)
	// registries: the page prefix of a key's registry record (host/path, lowercase), 13.1
	registryPrefix = map[string]string{"pypi": "pypi.org/project/", "npm": "npmjs.com/package/", "crates": "crates.io/crates/",
		"go": "pkg.go.dev/", "gem": "rubygems.org/gems/"}
)

var errBadKey = core.Bad("lib must be eco:name (eco pypi|npm|go|crates|gem|maven|nuget|apt|docker|api)")

// ParseKey validates and normalises an `eco:name` key: eco lowercase, names lowercase except for
// case-sensitive ecosystems (go, maven, nuget), PEP 503 folding for pypi (`_` and `.` -> `-`).
func ParseKey(s string) (string, error) {
	s = strings.TrimSpace(s)
	eco, name, ok := strings.Cut(s, ":")
	eco = strings.ToLower(eco)
	if !ok || !ecos[eco] || !nameRe.MatchString(name) || strings.Contains(name, "..") || strings.Contains(name, "//") ||
		strings.HasSuffix(name, "/") || strings.HasPrefix(name, "/") {
		return "", errBadKey
	}
	switch eco {
	case "pypi":
		name = strings.NewReplacer("_", "-", ".", "-").Replace(strings.ToLower(name))
	case "go":
		host, rest, found := strings.Cut(name, "/")
		name = strings.ToLower(host)
		if found {
			name += "/" + rest
		}
	case "maven", "nuget":
	default:
		name = strings.ToLower(name)
	}
	return eco + ":" + name, nil
}

// Eco returns the ecosystem and name of a (valid) key.
func Eco(key string) (eco, name string) {
	eco, name, _ = strings.Cut(key, ":")
	return eco, name
}

// EncodeKey percent-encodes a key for one path segment (`:` and `/` included).
func EncodeKey(key string) string {
	return strings.NewReplacer(":", "%3A", "/", "%2F", "@", "%40", "+", "%2B").Replace(url.PathEscape(key))
}

// LibPath is the percent-encoded page path of a lib (and optional version/range segment).
func LibPath(key, seg string) string {
	p := "/v/" + EncodeKey(key)
	if seg != "" {
		p += "/" + url.PathEscape(seg)
	}
	return p
}

// ResolveLib maps a key or a bare alias to its canonical key (13.4). An `eco:name` string is
// normalised without touching the database; a bare name is looked up in lib_alias (seeded rows
// and rows confirmed by an L2 root).
func ResolveLib(ctx context.Context, q core.Q, name string) (string, bool) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 220 {
		return "", false
	}
	if strings.Contains(name, ":") {
		k, err := ParseKey(name)
		return k, err == nil
	}
	alias := strings.ToLower(name)
	if !aliasRe.MatchString(alias) || q == nil {
		return "", false
	}
	var key string
	err := q.QueryRow(ctx, `SELECT key FROM lib_alias WHERE alias = $1 AND (seeded OR confirms >= 1)`, alias).Scan(&key)
	if err != nil {
		return "", false
	}
	return key, true
}

// ProposeAlias adds `alias -> key` (13.4): a bare lowercase alias, a valid key, never crossing
// ecosystems (an alias already bound to another ecosystem is refused); an L2+ proposer counts as
// the confirmation that makes the row live, lower levels leave it pending (confirms = 0) until an
// L2 root proposes the same mapping.
func ProposeAlias(ctx context.Context, q core.Q, alias, key, root string, lvl int) error {
	alias = strings.ToLower(strings.TrimSpace(alias))
	if !aliasRe.MatchString(alias) || strings.Contains(alias, ":") {
		return core.Bad("alias must match [a-z0-9@][a-z0-9_.+-]{0,63}")
	}
	key, err := ParseKey(key)
	if err != nil {
		return err
	}
	var cur string
	var seeded bool
	switch err := q.QueryRow(ctx, `SELECT key, seeded FROM lib_alias WHERE alias = $1`, alias).Scan(&cur, &seeded); {
	case errors.Is(err, pgx.ErrNoRows):
		confirms := 0
		if lvl >= 2 {
			confirms = 1
		}
		_, err := q.Exec(ctx, `INSERT INTO lib_alias (alias, key, confirms, by_root) VALUES ($1, $2, $3, $4) ON CONFLICT DO NOTHING`, alias, key, confirms, root)
		return err
	case err != nil:
		return err
	}
	if seeded {
		return core.E(409, "taken", "seeded alias")
	}
	if ce, _ := Eco(cur); strings.ToLower(ce) != strings.ToLower(strings.SplitN(key, ":", 2)[0]) {
		return core.E(409, "taken", "alias bound to "+ce)
	}
	if cur != key {
		return core.E(409, "taken", "alias bound to "+cur)
	}
	if lvl >= 2 {
		_, err := q.Exec(ctx, `UPDATE lib_alias SET confirms = confirms + 1 WHERE alias = $1 AND by_root <> $2`, alias, root)
		return err
	}
	return nil
}

// seedAliases inserts the embedded top list (idempotent; seeded rows are never overwritten).
func seedAliases(ctx context.Context, q core.Q) error {
	aliases := make([]string, 0, len(seedAliasList))
	keys := make([]string, 0, len(seedAliasList))
	for _, line := range strings.Split(strings.TrimSpace(seedAliasList), "\n") {
		a, k, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok {
			continue
		}
		if _, err := ParseKey(k); err != nil || !aliasRe.MatchString(a) {
			continue
		}
		aliases, keys = append(aliases, a), append(keys, k)
	}
	_, err := q.Exec(ctx, `INSERT INTO lib_alias (alias, key, confirms, seeded)
		SELECT a, k, 1, true FROM unnest($1::text[], $2::text[]) AS t(a, k) ON CONFLICT (alias) DO NOTHING`, aliases, keys)
	return err
}

// seededKey reports whether key is the target of a seeded alias (libmeta enqueue rule).
func seededKey(ctx context.Context, q core.Q, key string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM lib_alias WHERE key = $1 AND seeded)`, key).Scan(&ok)
	return ok, err
}
