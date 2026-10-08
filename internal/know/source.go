package know

import (
	"context"
	"errors"
	"net"
	"net/url"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Source URLs (13.1): http(s) only, no literal IP, localhost or userinfo, secret-looking query
// parameters stripped, <= 400 bytes. source_tier is `official` only on a path-prefix match against
// the lib's registry record; shared hosts are never official.

const maxSourceURL = 400

var (
	strippedParams = map[string]bool{"key": true, "token": true, "sig": true, "signature": true, "apikey": true, "api_key": true,
		"access_token": true, "auth": true, "secret": true}
	// shared hosts (13.1): hosting anyone's content, so a match on the host alone proves nothing
	sharedHosts = map[string]bool{"github.com": true, "gitlab.com": true, "gist.github.com": true, "readthedocs.io": true,
		"medium.com": true, "dev.to": true, "stackoverflow.com": true, "bitbucket.org": true, "codeberg.org": true,
		"pypi.org": true, "npmjs.com": true, "registry.npmjs.org": true, "crates.io": true, "pkg.go.dev": true,
		"proxy.golang.org": true, "rubygems.org": true, "docs.rs": true, "hub.docker.com": true, "sourceforge.net": true,
		"huggingface.co": true, "reddit.com": true, "x.com": true, "twitter.com": true, "youtube.com": true}
	sharedSuffixes = []string{".github.io", ".gitlab.io", ".readthedocs.io", ".readthedocs.org", ".pages.dev", ".vercel.app",
		".netlify.app", ".medium.com", ".substack.com", ".hashnode.dev", ".blogspot.com", ".wordpress.com"}
)

var errBadSource = core.Bad("source_url must be http(s) without IP literal, localhost or userinfo (<= 400 bytes)")

// CleanSourceURL validates and normalises a source URL ("" stays ""): lowercase scheme and host,
// fragment dropped, secret-looking query parameters removed.
func CleanSourceURL(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", nil
	}
	if len(s) > maxSourceURL+200 || strings.ContainsAny(s, " \t\r\n<>\"'`\\") {
		return "", errBadSource
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.User != nil || u.Host == "" || u.Opaque != "" {
		return "", errBadSource
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") ||
		strings.HasSuffix(host, ".internal") || !strings.Contains(host, ".") || net.ParseIP(strings.Trim(u.Host, "[]")) != nil ||
		net.ParseIP(host) != nil {
		return "", errBadSource
	}
	if p := u.Port(); p != "" && p != "80" && p != "443" {
		return "", errBadSource
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = host
	u.Fragment = ""
	if u.RawQuery != "" {
		q := u.Query()
		for k := range q {
			if strippedParams[strings.ToLower(k)] {
				q.Del(k)
			}
		}
		u.RawQuery = q.Encode()
	}
	out := u.String()
	if len(out) > maxSourceURL {
		return "", errBadSource
	}
	return out, nil
}

// sharedHost reports a host anyone can publish under (13.1 list plus the registries).
func sharedHost(host string) bool {
	host = strings.TrimPrefix(strings.ToLower(host), "www.")
	if sharedHosts[host] {
		return true
	}
	for _, suf := range sharedSuffixes {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	return false
}

// hostPath renders a URL as lowercase `host/path/` for prefix matching (www. and a trailing slash
// normalised, .git dropped, query ignored).
func hostPath(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www.")
	p := strings.ToLower(strings.TrimSuffix(strings.TrimSuffix(u.EscapedPath(), "/"), ".git"))
	return host + p + "/"
}

// LibMeta is the registry record of a lib (13.4), as far as official-source matching needs it.
type LibMeta struct {
	Key, Display, Homepage, Repo, Docs, Registry, Latest string
	Versions                                             []Release
	Fetched                                              bool
}

// officialPrefixes lists the `host/path/` prefixes under which a source is official for key: the
// registry record page derived from the key, the repository (libs.repo or a go module path on a
// forge), and the docs/homepage host when that host is not shared.
func officialPrefixes(key string, m *LibMeta) []string {
	eco, name := Eco(key)
	var out []string
	add := func(p string) {
		if p != "" && p != "/" {
			out = append(out, p)
		}
	}
	switch eco {
	case "pypi", "npm", "crates", "gem":
		add(registryPrefix[eco] + strings.ToLower(name) + "/")
	case "go":
		add("pkg.go.dev/" + strings.ToLower(name) + "/")
		if parts := strings.Split(name, "/"); len(parts) >= 3 {
			switch parts[0] {
			case "github.com", "gitlab.com", "codeberg.org", "bitbucket.org":
				add(strings.ToLower(strings.Join(parts[:3], "/")) + "/")
			}
		}
	}
	if m != nil {
		if hp := hostPath(m.Repo); hp != "" {
			// a forge repo is official only down to owner/repo, never the whole host
			if host, p, _ := strings.Cut(hp, "/"); sharedHost(host) {
				if segs := strings.Split(strings.Trim(p, "/"), "/"); len(segs) >= 2 && segs[0] != "" && segs[1] != "" {
					add(host + "/" + segs[0] + "/" + segs[1] + "/")
				}
			} else {
				add(hp)
			}
		}
		for _, raw := range []string{m.Docs, m.Homepage} {
			u, err := url.Parse(strings.TrimSpace(raw))
			if err != nil || u.Host == "" {
				continue
			}
			if host := strings.TrimPrefix(strings.ToLower(u.Hostname()), "www."); !sharedHost(host) {
				add(host + "/")
			}
		}
	}
	return out
}

// SourceTier classifies a (clean) source URL for key: official on a path-prefix match against
// officialPrefixes, community otherwise ("" for no URL).
func SourceTier(key, src string, m *LibMeta) string {
	hp := hostPath(src)
	if src == "" || hp == "" {
		return "community"
	}
	for _, p := range officialPrefixes(key, m) {
		if strings.HasPrefix(hp, p) {
			return "official"
		}
	}
	return "community"
}

// loadLibMeta reads the registry record of key (nil when unknown).
func loadLibMeta(ctx context.Context, q core.Q, key string) (*LibMeta, error) {
	m := &LibMeta{Key: key}
	var fetched *bool
	err := q.QueryRow(ctx, `SELECT display, homepage, repo, docs, registry, latest, fetched_at IS NOT NULL FROM libs WHERE key = $1`, key).
		Scan(&m.Display, &m.Homepage, &m.Repo, &m.Docs, &m.Registry, &m.Latest, &fetched)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m.Fetched = fetched != nil && *fetched
	return m, nil
}

// sourceTierOf is SourceTier against the stored registry record.
func sourceTierOf(ctx context.Context, q core.Q, key, src string) (string, error) {
	if src == "" {
		return "community", nil
	}
	m, err := loadLibMeta(ctx, q, key)
	if err != nil {
		return "", err
	}
	return SourceTier(key, src, m), nil
}
