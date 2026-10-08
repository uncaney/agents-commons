package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// baseHosts is the compiled-in allowlist (SPEC-v2 20 + rev 3 additions). Kinds contribute more
// through Kind.Hosts and S3_ENDPOINT adds its host; nothing else is ever dialled.
var baseHosts = []string{
	"api.indexnow.org", "www.bing.com", "api.github.com", "huggingface.co", "pypi.org",
	"registry.npmjs.org", "proxy.golang.org", "crates.io", "rubygems.org", "api.cloudflare.com",
	"web.archive.org", "api.osv.dev", "endoflife.date", "ssl.bing.com", "chatgpt.com", "openai.com",
}

const (
	dialTimeout  = 15 * time.Second
	readCap      = 1 << 20 // responses are read up to 1 MiB, the rest is never read
	maxRedirects = 3
	userAgent    = "agents-commons-courier/2 (+https://agents.ekaii.fr/about)"
)

var (
	errNotAllowed = errors.New("egress: host not in allowlist")
	errPrivateIP  = errors.New("egress: host resolves to a non-public address")
	errTLSOnly    = errors.New("egress: only port 443 is dialled")
	errIPLiteral  = errors.New("egress: IP literals are refused")
	errTooLarge   = errors.New("egress: response larger than 1 MiB")
	errRedirect   = errors.New("egress: cross-host or non-https redirect refused")
	errNoAddrs    = errors.New("egress: host has no addresses")
)

var hostRe = regexp.MustCompile(`^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)

// validHost reports whether h is a lowercase, fully qualified hostname (no IP, no port, no wildcard).
func validHost(h string) bool { return len(h) <= 253 && hostRe.MatchString(h) }

// Allowlist is the set of hosts the egress transport may dial.
type Allowlist map[string]bool

// Allow reports whether host (any case, optional trailing dot) is allowlisted.
func (a Allowlist) Allow(host string) bool { return a[normHost(host)] }

func normHost(h string) string { return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), ".")) }

// buildAllowlist is baseHosts plus the Hosts of the given kinds and extra hosts (S3_ENDPOINT).
// Invalid names panic: they are compile-time or operator configuration errors.
func buildAllowlist(kinds []*Kind, extra ...string) Allowlist {
	a := Allowlist{}
	add := func(h, from string) {
		h = normHost(h)
		if !validHost(h) {
			panic(fmt.Sprintf("allowlist: invalid host %q from %s", h, from))
		}
		a[h] = true
	}
	for _, h := range baseHosts {
		add(h, "base")
	}
	for _, k := range kinds {
		for _, h := range k.Hosts {
			add(h, "kind "+k.Name)
		}
	}
	for _, h := range extra {
		if h != "" {
			add(h, "extra")
		}
	}
	return a
}

// dialer is the DialContext of the egress transport: allowlisted hostnames only, port 443 only,
// resolved addresses all public (a name with one private address is refused as a whole).
type dialer struct {
	allow   func(host string) bool
	resolve func(ctx context.Context, host string) ([]netip.Addr, error)
	dial    func(ctx context.Context, network, addr string) (net.Conn, error)
}

func newDialer(allow Allowlist) *dialer {
	nd := &net.Dialer{Timeout: dialTimeout, KeepAlive: 30 * time.Second}
	r := &net.Resolver{}
	return &dialer{
		allow:   allow.Allow,
		resolve: func(ctx context.Context, host string) ([]netip.Addr, error) { return r.LookupNetIP(ctx, "ip", host) },
		dial:    nd.DialContext,
	}
}

func (d *dialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("egress: network %s refused", network)
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	if port != "443" {
		return nil, errTLSOnly
	}
	if _, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		return nil, errIPLiteral
	}
	host = normHost(host)
	if !validHost(host) || !d.allow(host) {
		return nil, errNotAllowed
	}
	addrs, err := d.resolve(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("egress: resolve %s: %w", host, err)
	}
	if len(addrs) == 0 {
		return nil, errNoAddrs
	}
	for _, a := range addrs {
		if !publicIP(a) {
			return nil, errPrivateIP
		}
	}
	var last error
	for _, a := range addrs {
		c, err := d.dial(ctx, "tcp", netip.AddrPortFrom(a.Unmap(), 443).String())
		if err == nil {
			return c, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, last
}

var reservedNets = func() []netip.Prefix {
	var out []netip.Prefix
	for _, s := range []string{
		"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "198.18.0.0/15", "198.51.100.0/24",
		"203.0.113.0/24", "240.0.0.0/4", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64", "2001::/32",
		"2001:db8::/32", "2002::/16",
	} {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// publicIP reports whether a is a globally routable unicast address.
func publicIP(a netip.Addr) bool {
	a = a.Unmap()
	if !a.IsValid() || a.IsUnspecified() || a.IsLoopback() || a.IsPrivate() || a.IsLinkLocalUnicast() ||
		a.IsLinkLocalMulticast() || a.IsInterfaceLocalMulticast() || a.IsMulticast() {
		return false
	}
	for _, p := range reservedNets {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// newTransport is the egress http.Transport: no proxy, the allowlist dialer, TLS 1.2+, 15 s
// dial / handshake / response-header timeouts.
func newTransport(allow Allowlist) *http.Transport { return transportWith(newDialer(allow)) }

func transportWith(d *dialer) *http.Transport {
	return &http.Transport{
		Proxy:                  nil,
		DialContext:            d.DialContext,
		ForceAttemptHTTP2:      true,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    dialTimeout,
		ResponseHeaderTimeout:  dialTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxIdleConns:           8,
		IdleConnTimeout:        60 * time.Second,
		MaxResponseHeaderBytes: 64 << 10,
	}
}

// newClient wraps a transport with the redirect policy (same host, https, <= 3 hops).
func newClient(tr http.RoundTripper) *http.Client {
	return &http.Client{Transport: tr, CheckRedirect: checkRedirect}
}

func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return errors.New("egress: too many redirects")
	}
	if req.URL.Scheme != "https" || !strings.EqualFold(normHost(req.URL.Hostname()), normHost(via[0].URL.Hostname())) {
		return errRedirect
	}
	return nil
}

// readAll reads at most cap bytes of r, failing when more is available (the rest is never read).
func readAll(r io.Reader, cap int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, cap+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > cap {
		return nil, errTooLarge
	}
	return b, nil
}

// lockedDialer only dials the configured internal hosts (gateway) on any port: the internal client
// is plain HTTP on the courier network and must never be usable for anything else.
func lockedDialer(hosts ...string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	ok := map[string]bool{}
	for _, h := range hosts {
		ok[normHost(h)] = true
	}
	nd := &net.Dialer{Timeout: 10 * time.Second}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if !ok[normHost(host)] {
			return nil, fmt.Errorf("internal client: host %s is not the gateway", host)
		}
		return nd.DialContext(ctx, network, addr)
	}
}

// rewriteTransport sends every request to base instead of its own host, keeping the path and
// query and recording the intended host in X-Egress-Host (COURIER_TEST_BASE: tests and the e2e
// harness only; the allowlist is bypassed, which the courier logs loudly at boot).
type rewriteTransport struct {
	base *url.URL
	next http.RoundTripper
}

func (t rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r := req.Clone(req.Context())
	r.Header.Set("X-Egress-Host", req.URL.Host)
	r.URL.Scheme, r.URL.Host = t.base.Scheme, t.base.Host
	r.Host = t.base.Host
	return t.next.RoundTrip(r)
}
