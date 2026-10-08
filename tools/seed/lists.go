package main

import (
	_ "embed"
	"fmt"
	"regexp"
	"strings"

	"ekaii.fr/commons/internal/scrub"
)

//go:embed tags.txt
var embeddedTags string

//go:embed hosts.txt
var embeddedHosts string

const maxListLines = 5000

// loadTags returns the controlled tag set: the embedded tools/seed/tags.txt plus, additively, an
// explicit file or $CX_SEED_DIR/tags.txt.
func (a *app) loadTags(explicit string) (map[string]bool, error) {
	tags := map[string]bool{}
	add := func(b []byte) {
		for _, l := range lines(b, maxListLines) {
			tags[strings.ToLower(l)] = true
		}
	}
	add([]byte(embeddedTags))
	if p := a.optional(explicit, "tags.txt"); p != "" {
		b, err := readCapped(p, maxListFile)
		if err != nil {
			return nil, err
		}
		add(b)
	}
	return tags, nil
}

// hostList is the public host allowlist of hosts.txt: `host` (exact or any subdomain), `*.host`
// (same, explicit) and `prefix.*` (any host starting with prefix.).
type hostList struct {
	exact    map[string]bool
	prefixes []string
}

func parseHosts(b []byte, into *hostList) {
	for _, l := range lines(b, maxListLines) {
		l = strings.ToLower(l)
		switch {
		case strings.HasSuffix(l, ".*"):
			into.prefixes = append(into.prefixes, strings.TrimSuffix(l, "*"))
		case strings.HasPrefix(l, "*."):
			into.exact[l[2:]] = true
		default:
			into.exact[l] = true
		}
	}
}

func (h *hostList) allow(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if h.exact[host] {
		return true
	}
	for _, p := range h.prefixes {
		if strings.HasPrefix(host, p) {
			return true
		}
	}
	for i := strings.IndexByte(host, '.'); i > 0; i = strings.IndexByte(host, '.') {
		host = host[i+1:]
		if h.exact[host] {
			return true
		}
	}
	return false
}

// loadHosts builds the Strict host predicate: scrub's public defaults, the embedded hosts.txt and,
// additively, an explicit file or $CX_SEED_DIR/hosts.txt.
func (a *app) loadHosts(explicit string) (func(string) bool, error) {
	hl := &hostList{exact: map[string]bool{}}
	parseHosts([]byte(embeddedHosts), hl)
	if p := a.optional(explicit, "hosts.txt"); p != "" {
		b, err := readCapped(p, maxListFile)
		if err != nil {
			return nil, err
		}
		parseHosts(b, hl)
	}
	return func(host string) bool { return scrub.HostAllowed(host) || hl.allow(host) }, nil
}

// denylist is the operator's private list: exact tokens (case-insensitive, on word boundaries)
// and `re:` RE2 regexes. Matches are reported as classes only, never as text.
type denylist struct {
	tokens []string
	res    []*regexp.Regexp
}

func parseDenylist(b []byte) (*denylist, error) {
	d := &denylist{}
	for i, l := range lines(b, maxListLines) {
		if len(l) > 500 {
			return nil, fmt.Errorf("denylist line %d: longer than 500 bytes", i+1)
		}
		if strings.HasPrefix(l, "re:") {
			re, err := regexp.Compile(strings.TrimSpace(l[3:]))
			if err != nil {
				return nil, fmt.Errorf("denylist line %d: bad regex", i+1)
			}
			d.res = append(d.res, re)
			continue
		}
		if t := strings.ToLower(l); len(t) >= 2 {
			d.tokens = append(d.tokens, t)
		}
	}
	return d, nil
}

func loadDenylist(path string) (*denylist, error) {
	b, err := readCapped(path, maxListFile)
	if err != nil {
		return nil, err
	}
	return parseDenylist(b)
}

func alnum(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// classes returns "denylist" when an exact token occurs on word boundaries and "denylist.re" when
// a regex matches; the scanned text is the normalised, lower-cased entry.
func (d *denylist) classes(text string) []string {
	if d == nil {
		return nil
	}
	var cs []string
	low := strings.ToLower(scrub.Normalize(text))
	for _, t := range d.tokens {
		for i := strings.Index(low, t); i >= 0; {
			end := i + len(t)
			if (i == 0 || !alnum(low[i-1])) && (end == len(low) || !alnum(low[end])) {
				cs = append(cs, "denylist")
				break
			}
			j := strings.Index(low[i+1:], t)
			if j < 0 {
				break
			}
			i += 1 + j
		}
		if len(cs) > 0 {
			break
		}
	}
	for _, re := range d.res {
		if re.MatchString(low) || re.MatchString(text) {
			cs = append(cs, "denylist.re")
			break
		}
	}
	return cs
}
