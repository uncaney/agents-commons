// Package doc is the v2 wire format (SPEC-v2 section 2): one Doc model rendered as txt, md, json,
// html or sh after content negotiation, with next: tails, ETag/304, cache rules, token budgets,
// field selection, keyset cursors, the shared HTML layout and the reverse (text/plain) parser.
package doc

import (
	"encoding/base64"
	"errors"
	"html/template"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"ekaii.fr/commons/internal/core"
)

// Format is a rendering of a Doc.
type Format string

const (
	Txt     Format = "txt"
	MD      Format = "md"
	JSON    Format = "json"
	HTML    Format = "html"
	Sh      Format = "sh"
	Problem Format = "problem" // RFC 9457 application/problem+json (errors; JSON otherwise)
	JSONLD  Format = "jsonld"  // the LD graph alone (application/ld+json)
)

// F is one field line: Name (server-chosen) and a user-text Val, multi-line when Multi.
type F struct {
	Name, Val string
	Multi     bool
}

// Action is one next: entry: "<METHOD> <path>[ <hint>]". A bare Action (no Method/Path) renders its
// Hint alone (e.g. "retry 2026-10-07").
type Action struct{ Method, Path, Hint string }

// Link is a Link header / <link> tag.
type Link struct{ Rel, Href, Type, Title string }

// Form is an HTML <form method=post> for anonymous-feasible POSTs; Token is the caller-supplied
// HMAC form token (core.FormToken) sent as the hidden field ft.
type Form struct {
	Action, Legend, Token, Submit string
	Fields                        []Field
}

// Field is one form input.
type Field struct {
	Name, Label, Value string
	Multi, Hidden      bool
	Max                int
}

// Doc is what every handler builds; Reply renders it in the negotiated format.
type Doc struct {
	Head   string   // head line (user text embedded after a server prefix is fine; SafeLine applies)
	Code   string   // error code: when set the doc is an error "err <Code> <Head>"
	Fields []F      // field lines in order; repeated names allowed (JSON collects them)
	Cols   []string // optional column names for Rows (enables ?s= column selection, JSON objects)
	Rows   [][]string
	Next   []Action
	LD     any    // JSON-LD graph for the HTML head (encoding/json, HTML-escaped)
	Links  []Link // extra Link headers / <link> tags (alternates, feeds, cite-as…)

	Title, Desc, Canonical string // HTML <title>, description, canonical path (relative)
	NoIndex                bool
	Forms                  []Form
	Body                   template.HTML // custom HTML body replacing the <pre> rendering

	MaxAge int // Cache-Control override in seconds (> 0 public, < 0 no-store, 0 default rules)
	RetryS int // 429/503: retry_s=<n> on the next: line and Retry-After when unset
	Budget int // v2 default token budget for this kind of reply (search/lists 400); 0 = DefaultBudget
	// Cursor returns the opaque ?after= cursor for continuing after row i (budget truncation).
	Cursor func(i int) string
}

// Site is the package configuration shared by every renderer (set once at boot).
type Site struct {
	Base              string // PUBLIC_URL without trailing slash
	UmamiSrc, UmamiID string
	License           string // license URL for <link rel=license> and Link headers
	MCP               string // MCP endpoint shown in the footer
}

const defaultLicense = "https://creativecommons.org/publicdomain/zero/1.0/"

var siteP atomic.Pointer[Site]

func init() { SetSite(Site{Base: "https://agents.ekaii.fr"}) }

// SetSite installs the site configuration (missing License/MCP get defaults).
func SetSite(s Site) {
	s.Base = strings.TrimRight(s.Base, "/")
	if s.License == "" {
		s.License = defaultLicense
	}
	if s.MCP == "" {
		s.MCP = s.Base + "/mcp"
	}
	siteP.Store(&s)
}

// Configure derives the Site from the gateway config (PUBLIC_URL, Umami); license stays as set.
func Configure(cfg *core.Config) {
	cur := CurrentSite()
	SetSite(Site{Base: cfg.PublicURL, UmamiSrc: cfg.UmamiSrc, UmamiID: cfg.UmamiID, License: cur.License})
}

// CurrentSite returns the active configuration.
func CurrentSite() Site { return *siteP.Load() }

// Base is PUBLIC_URL without trailing slash.
func Base() string { return siteP.Load().Base }

// --- negotiation -------------------------------------------------------------------------------

var suffixes = map[string]Format{".txt": Txt, ".md": MD, ".json": JSON, ".html": HTML, ".sh": Sh, ".jsonld": JSONLD}

// SplitSuffix strips a format suffix from a path segment ("k7x2a9q.md" -> "k7x2a9q", MD); segments
// without a known suffix come back unchanged with Format "".
func SplitSuffix(seg string) (string, Format) {
	if i := strings.LastIndexByte(seg, '.'); i > 0 {
		if f, ok := suffixes[seg[i:]]; ok {
			return seg[:i], f
		}
	}
	return seg, ""
}

var fParam = map[string]Format{"txt": Txt, "text": Txt, "md": MD, "markdown": MD, "json": JSON, "html": HTML, "sh": Sh, "problem": Problem, "jsonld": JSONLD}

// Negotiate picks the format: path suffix > ?f= > Accept (highest q among text/html, text/markdown,
// application/json, text/plain, text/x-shellscript, application/problem+json; ties by header order;
// */* or absent -> text/plain) > text/plain.
func Negotiate(r *http.Request) Format {
	if _, f := SplitSuffix(path.Base(r.URL.Path)); f != "" {
		return f
	}
	if f, ok := fParam[strings.ToLower(r.URL.Query().Get("f"))]; ok {
		return f
	}
	if f := NegotiateAccept(r.Header.Get("Accept")); f != "" {
		return f
	}
	return Txt
}

var acceptTypes = map[string]Format{
	"text/html": HTML, "application/xhtml+xml": HTML, "text/markdown": MD, "application/json": JSON,
	"text/plain": Txt, "text/x-shellscript": Sh, "application/problem+json": Problem, "application/ld+json": JSONLD,
}

// NegotiateAccept resolves an Accept header to a Format ("" when nothing specific is listed).
func NegotiateAccept(accept string) Format {
	var best Format
	bestQ := -1.0
	for _, part := range strings.Split(accept, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		f, ok := acceptTypes[strings.ToLower(strings.TrimSpace(fields[0]))]
		if !ok {
			continue
		}
		q := 1.0
		for _, p := range fields[1:] {
			if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(k, "q") {
				if x, err := strconv.ParseFloat(v, 64); err == nil {
					q = x
				}
			}
		}
		if q > bestQ {
			best, bestQ = f, q
		}
	}
	if bestQ <= 0 {
		return ""
	}
	return best
}

// --- query helpers -----------------------------------------------------------------------------

const (
	MaxBudget     = 4000 // tokens
	DefaultBudget = 800  // tokens when ?v=2 without ?b= (gets); lists use BudgetFor(r, 400)
)

// V2 reports the v2 wire flag (?v=2 or X-CX-V: 2).
func V2(r *http.Request) bool {
	return r.URL.Query().Get("v") == "2" || strings.TrimSpace(r.Header.Get("X-CX-V")) == "2"
}

// Budget is the token budget: 0 (unbounded) unless ?b= is present or V2; ?b=0 means unbounded.
func Budget(r *http.Request) int { return BudgetFor(r, DefaultBudget) }

// BudgetFor is Budget with the v2 default for this kind of reply (search/lists 400, get 800).
func BudgetFor(r *http.Request, def int) int {
	if b, ok := r.URL.Query()["b"]; ok && len(b) > 0 {
		n, err := strconv.Atoi(strings.TrimSpace(b[0]))
		if err != nil || n < 0 {
			n = def
		}
		return min(n, MaxBudget)
	}
	if V2(r) {
		return min(def, MaxBudget)
	}
	return 0
}

var nameRe = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,23}$`)

// Fields parses ?s=<f1,f2> (validated names, <= 32); nil when absent.
func Fields(r *http.Request) []string {
	s := r.URL.Query().Get("s")
	if s == "" {
		return nil
	}
	var out []string
	for _, n := range strings.Split(s, ",") {
		n = strings.TrimSpace(n)
		if nameRe.MatchString(n) && len(out) < 32 {
			out = append(out, n)
		}
	}
	return out
}

// NextOff reports ?next=0 or X-Next: 0 (no tail, no JSON next).
func NextOff(r *http.Request) bool {
	return r.URL.Query().Get("next") == "0" || strings.TrimSpace(r.Header.Get("X-Next")) == "0"
}

// Abs reports ?abs=1 or X-CX-Abs: 1 (absolute URLs in next: and Link).
func Abs(r *http.Request) bool {
	return r.URL.Query().Get("abs") == "1" || strings.TrimSpace(r.Header.Get("X-CX-Abs")) == "1"
}

var markRe = regexp.MustCompile(`^[a-z0-9]{6,12}$`)

// Mark returns the validated X-CX-Mark data marker ("" when absent or invalid).
func Mark(r *http.Request) string {
	m := strings.TrimSpace(r.Header.Get("X-CX-Mark"))
	if markRe.MatchString(m) {
		return m
	}
	return ""
}

// HasToken reports a request carrying credentials (bearer header or ?t= url token).
func HasToken(r *http.Request) bool {
	return r.Header.Get("Authorization") != "" || r.URL.Query().Get("t") != ""
}

// Cursor encodes a keyset position (ts, id) as an opaque base64url string.
func Cursor(ts time.Time, id string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.FormatInt(ts.UnixNano(), 10) + "|" + id))
}

// DecodeCursor reverses Cursor.
func DecodeCursor(s string) (time.Time, string, bool) {
	if len(s) == 0 || len(s) > 128 {
		return time.Time{}, "", false
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return time.Time{}, "", false
	}
	ns, id, ok := strings.Cut(string(b), "|")
	n, err := strconv.ParseInt(ns, 10, 64)
	if !ok || err != nil || !OneLine(id) || len(id) > 64 {
		return time.Time{}, "", false
	}
	return time.Unix(0, n).UTC(), id, true
}

// After decodes ?after= (ok false when absent or malformed).
func After(r *http.Request) (time.Time, string, bool) {
	return DecodeCursor(r.URL.Query().Get("after"))
}

// --- next: actions -----------------------------------------------------------------------------

const (
	MaxActions   = 4
	MaxActionLen = 160
)

var methods = map[string]bool{"GET": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// pathOK accepts a relative request target made of unreserved/reserved URL characters and
// well-formed percent-encoding only (no spaces, controls, quotes, angle brackets or non-ASCII).
func pathOK(p string) bool {
	if p == "" || p[0] != '/' || strings.HasPrefix(p, "//") {
		return false
	}
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case strings.IndexByte("-._~:/?#[]@!$&'()*+,;=", c) >= 0:
		case c == '%':
			if i+2 >= len(p) || !isHex(p[i+1]) || !isHex(p[i+2]) {
				return false
			}
			i += 2
		default:
			return false
		}
	}
	_, err := url.ParseRequestURI(p)
	return err == nil
}

func isHex(c byte) bool { return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F' }

// CheckAction reports why an Action is not renderable (nil when valid).
func CheckAction(a Action) error {
	if a.Method == "" && a.Path == "" {
		if a.Hint == "" || !OneLine(a.Hint) || strings.Contains(a.Hint, "|") || len(a.Hint) > MaxActionLen {
			return errors.New("bare action needs a short hint")
		}
		return nil
	}
	if !methods[a.Method] {
		return errors.New("bad method")
	}
	if !pathOK(a.Path) {
		return errors.New("path must be relative and percent-encoded")
	}
	if !OneLine(a.Hint) || strings.Contains(a.Hint, "|") {
		return errors.New("bad hint")
	}
	if len(a.String()) > MaxActionLen {
		return errors.New("action too long")
	}
	return nil
}

// String renders "<METHOD> <path>[ <hint>]".
func (a Action) String() string {
	if a.Method == "" && a.Path == "" {
		return a.Hint
	}
	if a.Hint != "" {
		return a.Method + " " + a.Path + " " + a.Hint
	}
	return a.Method + " " + a.Path
}

// Next validates and sanitises actions: hints are cut to three words, invalid or over-long
// actions are dropped and at most MaxActions survive.
func Next(acts ...Action) []Action {
	out := make([]Action, 0, len(acts))
	for _, a := range acts {
		if f := strings.Fields(SafeLine(strings.ReplaceAll(a.Hint, "|", " "))); len(f) > 3 {
			a.Hint = strings.Join(f[:3], " ")
		} else {
			a.Hint = strings.Join(f, " ")
		}
		if CheckAction(a) == nil {
			out = append(out, a)
		}
		if len(out) == MaxActions {
			break
		}
	}
	return out
}

// GET builds a GET action.
func GET(p, hint string) Action { return Action{"GET", p, hint} }

// POST builds a POST action.
func POST(p, hint string) Action { return Action{"POST", p, hint} }

// absPath prefixes a relative action/link path with the site base when abs is set.
func absPath(p string, abs bool) string {
	if abs && strings.HasPrefix(p, "/") {
		return Base() + p
	}
	return p
}

// tailLine renders the next: line (abs rewrites paths; retryS adds retry_s=<n>).
func tailLine(acts []Action, abs bool, retryS int) string {
	parts := make([]string, 0, len(acts)+1)
	for _, a := range acts {
		a.Path = absPath(a.Path, abs)
		parts = append(parts, a.String())
	}
	if retryS > 0 {
		parts = append(parts, "retry_s="+strconv.Itoa(retryS))
	}
	if len(parts) == 0 {
		return ""
	}
	return "next: " + strings.Join(parts, " | ")
}
