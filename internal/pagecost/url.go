package pagecost

import (
	"crypto/sha256"
	"encoding/hex"
	"math"
	"net"
	"net/url"
	"path"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

// Canonical URL rules (27.9): lowercase scheme and host, path only (query and fragment dropped),
// userinfo refused, private hosts and IP literals refused, capability-looking path segments
// refused, tier-1 scrub on the result. uh = sha256(canonical url).
const (
	MaxPath    = 200
	maxRawURL  = 2048
	maxHost    = 253
	capSegLen  = 20
	capEntropy = 3.5
)

var (
	errURL      = core.Bad("url must be an absolute http(s) URL (ASCII, <= 2048 bytes)")
	errUserinfo = core.Bad("url must not carry userinfo (user:password@)")
	errHost     = core.Bad("url host must be a public hostname (no localhost, single labels, local names, ports or IP literals)")
	errPath     = core.Bad("url path must be <= 200 bytes of printable ASCII")
	errCap      = core.Bad("url looks like a capability URL (high-entropy path segment); not recorded")
	errPII      = core.Bad("url path carries personal data; not recorded")
	errAltSame  = core.Bad("alt must differ from url")
	errAltRD    = core.Bad("alt must share the registrable domain of url")

	// localTLDs never resolve on the public Internet.
	localTLDs = map[string]bool{"local": true, "localhost": true, "internal": true, "lan": true, "home": true,
		"intranet": true, "corp": true, "test": true, "invalid": true, "example": true, "arpa": true, "onion": true, "localdomain": true}
	// multiSuffix lists common two-label public suffixes (no PSL dependency): the registrable
	// domain under them is one label longer.
	multiSuffix = map[string]bool{}
)

func init() {
	for _, s := range strings.Fields(`co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk nhs.uk
		com.au net.au org.au edu.au gov.au co.nz net.nz org.nz ac.nz co.jp ne.jp or.jp ac.jp go.jp co.kr or.kr ac.kr
		com.cn net.cn org.cn edu.cn com.hk org.hk com.tw org.tw com.sg org.sg co.in net.in org.in ac.in
		com.br org.br gov.br com.mx org.mx com.ar org.ar com.co co.za org.za co.ke com.ng com.tr org.tr co.il org.il
		com.pl org.pl co.id com.my com.ph com.vn co.th com.pk com.ua org.ua com.ru org.ru co.at or.at co.hu
		com.gr com.pt com.es org.es asso.fr gouv.fr com.fr co.it co.nl co.de com.de com.ch
		github.io gitlab.io bitbucket.io pages.dev workers.dev vercel.app netlify.app herokuapp.com fly.dev onrender.com
		web.app firebaseapp.com appspot.com azurewebsites.net cloudfront.net amazonaws.com readthedocs.io rtfd.io
		blogspot.com wordpress.com substack.com medium.com notion.site webflow.io wixsite.com squarespace.com
		myshopify.com ghost.io surge.sh glitch.me replit.app hf.space huggingface.co deno.dev val.run
		dyndns.org no-ip.org duckdns.org ddns.net`) {
		multiSuffix[s] = true
	}
}

// Page is a canonicalised URL.
type Page struct {
	URL, Scheme, Host, Path string
	UH                      []byte // sha256(URL)
}

// Short is the 16-hex id used in replies and paths.
func (p Page) Short() string { return hex.EncodeToString(p.UH)[:16] }

// Display is host + path, the form pages print.
func (p Page) Display() string { return p.Host + p.Path }

// Canon applies the canonical URL rules to raw and returns the Page or the first refusal.
func Canon(raw string) (Page, error) {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > maxRawURL || !doc.OneLine(s) || !printableASCII(s) {
		return Page{}, errURL
	}
	u, err := url.Parse(s)
	if err != nil || u.Opaque != "" {
		return Page{}, errURL
	}
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Page{}, errURL
	}
	if u.User != nil {
		return Page{}, errUserinfo
	}
	if port := u.Port(); port != "" && !(scheme == "http" && port == "80" || scheme == "https" && port == "443") {
		return Page{}, errHost
	}
	host, err := NormHost(u.Hostname())
	if err != nil {
		return Page{}, err
	}
	p, err := cleanPath(u.EscapedPath())
	if err != nil {
		return Page{}, err
	}
	for _, seg := range strings.Split(p, "/") {
		if capabilityLike(seg) {
			return Page{}, errCap
		}
	}
	c := scheme + "://" + host + p
	masked := c
	if _, aerr := scrub.RejectOrMask(map[string]*string{"url": &masked}); aerr != nil {
		return Page{}, aerr
	}
	if masked != c {
		return Page{}, errPII
	}
	h := sha256.Sum256([]byte(c))
	return Page{URL: c, Scheme: scheme, Host: host, Path: p, UH: h[:]}, nil
}

// NormHost lowercases and validates a public hostname (>= 2 labels, no local TLD, no IP literal).
func NormHost(s string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if h == "" || len(h) > maxHost || strings.ContainsAny(h, ":/[]") || net.ParseIP(h) != nil {
		return "", errHost
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", errHost
	}
	for _, l := range labels {
		if !labelOK(l) {
			return "", errHost
		}
	}
	tld := labels[len(labels)-1]
	if localTLDs[tld] || strings.Trim(tld, "0123456789") == "" {
		return "", errHost
	}
	return h, nil
}

func labelOK(l string) bool {
	if l == "" || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
		return false
	}
	for i := 0; i < len(l); i++ {
		if c := l[i]; !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// Registrable is the registrable domain of a normalised host (example.com for docs.example.com,
// example.co.uk and user.github.io under the embedded multi-label suffixes).
func Registrable(host string) string {
	labels := strings.Split(host, ".")
	n := len(labels)
	if n <= 2 {
		return host
	}
	if multiSuffix[labels[n-2]+"."+labels[n-1]] {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

// cleanPath keeps the escaped path only: dot segments resolved, repeated slashes collapsed, the
// trailing slash kept, printable ASCII with well-formed percent-encoding, <= MaxPath bytes.
func cleanPath(p string) (string, error) {
	if p == "" {
		p = "/"
	}
	if p[0] != '/' {
		return "", errPath
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~:/@!$&'()*+,;=", c) >= 0:
		case c == '%':
			if i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
				return "", errPath
			}
			i += 2
		default:
			return "", errPath
		}
	}
	trail := strings.HasSuffix(p, "/")
	c := path.Clean(p)
	if trail && c != "/" {
		c += "/"
	}
	if len(c) > MaxPath {
		return "", errPath
	}
	return c, nil
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// printableASCII accepts printable ASCII including spaces (percent-encoded by cleanPath).
func printableASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] > 0x7e {
			return false
		}
	}
	return true
}

// capabilityLike reports whether a path segment looks like a secret or capability: an
// alphanumeric run of >= 20 chars with entropy >= 3.5 (tokens, JWT parts, digests, base64),
// a hex-only segment of >= 20 digits once separators are removed (dashed UUIDs and digests), or a
// >= 20-char mixed-case segment with >= 4 digits and entropy >= 3.5 (base64url split by - or _).
// Slugs made of lowercase words joined by dashes are never capability-like.
func capabilityLike(seg string) bool {
	if len(seg) < capSegLen {
		return false
	}
	var runs []string
	var cur, stripped strings.Builder
	flush := func() {
		if cur.Len() > 0 {
			runs = append(runs, cur.String())
			cur.Reset()
		}
	}
	upper, lower, digits, hexOnly := false, false, 0, true
	for i := 0; i < len(seg); i++ {
		c := seg[i]
		switch {
		case c >= '0' && c <= '9':
			digits++
		case c >= 'a' && c <= 'z':
			lower = true
			if c > 'f' {
				hexOnly = false
			}
		case c >= 'A' && c <= 'Z':
			upper = true
			if c > 'F' {
				hexOnly = false
			}
		default:
			flush()
			continue
		}
		cur.WriteByte(c)
		stripped.WriteByte(c)
	}
	flush()
	for _, r := range runs {
		if len(r) >= capSegLen && entropy(r) >= capEntropy {
			return true
		}
	}
	st := stripped.String()
	if len(st) < capSegLen {
		return false
	}
	if hexOnly && digits > 0 {
		return true
	}
	return upper && lower && digits >= 4 && entropy(st) >= capEntropy
}

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n, h := float64(len(s)), 0.0
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// CanonAlt canonicalises a cheaper-twin URL for page: same registrable domain, not the page itself.
func CanonAlt(page Page, raw string) (Page, error) {
	alt, err := Canon(raw)
	if err != nil {
		return Page{}, err
	}
	if alt.URL == page.URL {
		return Page{}, errAltSame
	}
	if Registrable(alt.Host) != Registrable(page.Host) {
		return Page{}, errAltRD
	}
	return alt, nil
}

// AltPattern names the transformation from a page URL to its alt (both canonical) so a host
// summary can state a rule such as "append .md": "" when no simple rule fits.
func AltPattern(pageURL, altURL string) string {
	p, err1 := url.Parse(pageURL)
	a, err2 := url.Parse(altURL)
	if err1 != nil || err2 != nil {
		return ""
	}
	pp, ap := p.EscapedPath(), a.EscapedPath()
	if p.Host != a.Host {
		if pp == ap {
			return "host " + a.Host
		}
		return ""
	}
	base := strings.TrimSuffix(pp, "/")
	for _, ext := range []string{".md", ".txt", ".json"} {
		if ap == base+ext || ap == pp+ext {
			return "append " + ext
		}
		if ap == pp+"index"+ext || ap == base+"/index"+ext {
			return "append index" + ext
		}
	}
	if ext := path.Ext(base); ext != "" && ext != ".md" {
		for _, to := range []string{".md", ".txt", ".json"} {
			if ap == strings.TrimSuffix(base, ext)+to {
				return "replace " + ext + " with " + to
			}
		}
	}
	if strings.HasSuffix(ap, pp) && len(ap) > len(pp) {
		if pre := strings.TrimSuffix(ap, pp); len(pre) <= 24 && strings.HasPrefix(pre, "/") {
			return "prefix " + pre
		}
	}
	return ""
}
