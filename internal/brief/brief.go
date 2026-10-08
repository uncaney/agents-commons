// Package brief serves one budgeted pre-flight pack for an agent about to work: a single read
// transaction that fans across the KB (fixes), post-cutoff change claims, API/behaviour digests,
// the result cache and the demand gaps, rendered in a fixed section order under a token budget
// whose unused share flows on to the next section (SPEC-v2 27.3 brief, P89).
package brief

import (
	"context"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/cache"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/know"
)

// Limits (27.3). Vars so tests can tighten them.
var (
	MinBudget     = 200
	MaxBudget     = 2000
	DefaultBudget = 600
	AnonBudget    = 400 // the ceiling an anonymous caller may ask for
	MaxQ          = 400 // bytes of q
	MaxEnvLibs    = 20  // env=  parses at most this many lib@ver pairs
	MaxLibs       = 20  // libs (q + env) we fetch change claims for
	KBHits        = 5
	Digests       = 2

	statementTimeoutMS = 2500
)

// Cost is the limiter / semaphore charge of a brief (3.6: searches cost 2, a brief fans out, so 3).
var Cost float64 = 3

// errBusy is returned when the shared trigram semaphore is saturated (503, retry).
var errBusy = core.E(503, "busy", "brief busy, retry 2")

// section budget shares (27.3): unused share flows on to the sections that follow.
var shares = []struct {
	name  string
	share float64
}{
	{"kb", 0.45},
	{"changes", 0.25},
	{"digests", 0.15},
	{"cache", 0.10},
	{"wanted", 0.05},
}

// SearchLogFn, when set by the integration package, accounts the kb part of a brief in the
// anonymised search_log exactly as GET /q/ does (raw query, top hit id, super-group). It is a
// nil-safe cross-package seam: brief owns no search_log schema of its own (27.3).
var SearchLogFn func(ctx context.Context, raw, topID, super string)

// Req is a brief request (the HTTP query string or the MCP op argument).
type Req struct {
	Q   string `json:"q"`
	Env string `json:"env"`
	B   int    `json:"b"`
	NS  string `json:"ns"`
}

// model is the computed, format-independent brief: the head counts, the rendered section bodies in
// fixed order and the follow-up actions. It is what the anonymous ByteLRU caches.
type model struct {
	Q        string       `json:"q"`
	Libs     int          `json:"libs"`
	Hits     int          `json:"hits"`
	Changes  int          `json:"changes"`
	Cached   int          `json:"cached"`
	B        int          `json:"b"`
	Used     int          `json:"used"`
	Sections []doc.F      `json:"sections"`
	Next     []doc.Action `json:"next"`
	topID    string       `json:"-"`
	super    string       `json:"-"`
	recorded bool         `json:"-"`
}

// nsOK validates the optional cache namespace (same grammar as cache_ns, 27.3 P90).
func nsOK(ns string) bool {
	if len(ns) > 32 {
		return false
	}
	for _, c := range ns {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-') {
			return false
		}
	}
	return true
}

// clampBudget bounds b to [MinBudget, MaxBudget] with the default, then caps an anonymous caller.
func clampBudget(b int, anon bool) int {
	if b <= 0 {
		b = DefaultBudget
	}
	if b < MinBudget {
		b = MinBudget
	}
	if b > MaxBudget {
		b = MaxBudget
	}
	if anon && b > AnonBudget {
		b = AnonBudget
	}
	return b
}

// parseLibs collects the distinct libs to fetch change claims for: lib@ver pairs in q (the 6.1
// versions grammar) first, then the env manifest (node@22.9, pnpm@11). Env order is preserved so
// the caller's declared runtime weighs the change list.
func parseLibs(q, env string) []kb.LibVer {
	var out []kb.LibVer
	seen := map[string]bool{}
	add := func(lv kb.LibVer) {
		k := strings.ToLower(lv.Lib)
		if k == "" || seen[k] || len(out) >= MaxLibs {
			return
		}
		seen[k] = true
		out = append(out, lv)
	}
	for _, lv := range kb.ParseVersions(q) {
		add(lv)
	}
	for _, lv := range kb.ParseEnv(env) {
		add(lv)
	}
	return out
}

// build runs the one read transaction and assembles the budgeted model. anon selects the
// Anon-false kb search (the brief holds the shared semaphore itself, so kb must not re-acquire it).
func build(ctx context.Context, d *core.Deps, req Req, anon bool) (*model, error) {
	q := strings.TrimSpace(req.Q)
	if len(q) > MaxQ {
		return nil, core.Bad("q <= 400 bytes")
	}
	if !nsOK(req.NS) {
		return nil, core.Bad("ns must match [a-z0-9.-]{0,32}")
	}
	env := req.Env
	if len(kb.ParseEnv(env)) > MaxEnvLibs {
		return nil, core.Bad("env <= 20 libs")
	}
	b := clampBudget(req.B, anon)
	_, _, super := core.ClientFrom(ctx)
	libs := parseLibs(q, env)

	var (
		hits    []kb.Hit
		changes []know.Line
		digs    []know.Line
		crow    *cache.Row
		chit    bool
		ckey    string
	)
	ckey, _, _ = cache.Derive(req.NS, q)

	// The whole fan-out runs under one shared trigram semaphore slot (cost 3): bound the DB work,
	// then open one read tx with a hard statement timeout.
	release, ok := kb.AcquireSearch(ctx)
	if !ok {
		return nil, errBusy
	}
	defer release()
	if err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, "SET LOCAL statement_timeout = "+strconv.Itoa(statementTimeoutMS)); err != nil {
			return err
		}
		var err error
		if hits, err = kb.SearchV2(ctx, tx, kb.SearchOpts{Q: q, Env: env, K: KBHits, Anon: false}); err != nil {
			return err
		}
		for _, lv := range libs {
			ls, err := know.ClaimsAfter(ctx, tx, lv.Lib, lv.Ver, nil)
			if err != nil {
				continue // an unresolvable lib name is not a brief failure
			}
			changes = append(changes, ls...)
		}
		rankChanges(changes)
		if digs, err = know.DigestSearch(ctx, tx, "", "", q, Digests); err != nil {
			return err
		}
		if crow, chit, err = cache.Get(ctx, tx, ckey); err != nil {
			return err
		}
		return nil
	}); err != nil {
		return nil, err
	}

	m := &model{Q: q, Libs: len(libs), Hits: len(hits), Changes: len(changes), B: b, super: super}
	if chit {
		m.Cached = 1
	}
	if len(hits) > 0 {
		m.topID = hits[0].ID
	}

	// wanted: a gap is recorded once when neither the KB nor the change notes answered (27.3).
	gap := len(hits) == 0 && len(changes) == 0
	if gap {
		m.recorded = true
	}

	m.render(hits, changes, digs, crow, chit, ckey, b)
	return m, nil
}

// rankChanges orders merged change claims breaking first, then security, then the rest, keeping
// each lib's internal (conf-weighted) order (27.3 "breaking/security first").
func rankChanges(ls []know.Line) {
	rank := func(k string) int {
		switch k {
		case "breaking":
			return 0
		case "security":
			return 1
		}
		return 2
	}
	sort.SliceStable(ls, func(i, j int) bool { return rank(ls[i].Kind) < rank(ls[j].Kind) })
}

// render fills the fixed-order sections under the byte budget, flowing each section's unused share
// on to the ones that follow, and builds the deepest follow-up per non-empty section.
func (m *model) render(hits []kb.Hit, changes, digs []know.Line, crow *cache.Row, chit bool, ckey string, b int) {
	// Reserve a slice of the budget for the head and the next: tail; the rest is the section body.
	byteBudget := b * 4
	reserve := 260
	if reserve > byteBudget/2 {
		reserve = byteBudget / 2
	}
	body := byteBudget - reserve

	lines := map[string][]string{}
	lines["kb"] = kbLines(hits)
	lines["changes"] = changeLines(changes)
	lines["digests"] = digestLines(digs)
	if chit {
		lines["cache"] = []string{crow.Line()}
	}
	if len(hits) == 0 && len(changes) == 0 {
		lines["wanted"] = []string{"gap: no fix or change note for this query — recorded"}
	}

	used := 0
	carry := 0
	for _, s := range shares {
		base := int(float64(body) * s.share)
		allow := base + carry
		ls := lines[s.name]
		kept, spent := fitLines(ls, allow)
		carry = allow - spent
		used += spent
		if len(kept) == 0 {
			continue
		}
		m.Sections = append(m.Sections, doc.F{Name: s.name, Val: strings.Join(kept, "\n"), Multi: true})
	}
	m.Used = min(b, (used+reserve+3)/4)

	// next: the deepest follow-up per section that produced something.
	if len(hits) > 0 {
		m.Next = append(m.Next, doc.GET("/k/"+hits[0].ID, "top fix"))
	}
	if len(changes) > 0 {
		m.Next = append(m.Next, doc.GET(changeFollow(changes[0]), "change detail"))
	}
	if len(digs) > 0 {
		m.Next = append(m.Next, doc.GET("/dg/"+know.EncodeKey(digs[0].Lib)+"/"+digRange(digs[0]), "digest"))
	}
	if chit {
		m.Next = append(m.Next, doc.GET("/c/"+ckey, "cached body"))
	}
	if len(hits) == 0 && len(changes) == 0 {
		m.Next = append(m.Next, doc.GET("/wanted", "demand gaps"))
	}
	if q := strings.TrimSpace(m.Q); q != "" {
		m.Next = append(m.Next, doc.GET("/q/"+url.PathEscape(q)+"?k=20", "wider search"))
	}
}

// fitLines keeps whole lines while their cumulative byte length (with newlines) fits in allow;
// returns the kept lines and the bytes they cost.
func fitLines(ls []string, allow int) ([]string, int) {
	if allow <= 0 {
		return nil, 0
	}
	var kept []string
	n := 0
	for _, l := range ls {
		cost := len(l) + 1
		if n+cost > allow && len(kept) > 0 {
			break
		}
		if n+cost > allow {
			// first line alone overflows: take it clipped so the section is never empty.
			kept = append(kept, clip(l, allow))
			n = allow
			break
		}
		kept = append(kept, l)
		n += cost
	}
	return kept, n
}

func clip(s string, max int) string {
	if max < 1 || len(s) <= max {
		return s
	}
	if max < 2 {
		return s[:max]
	}
	b := max - 1
	for b > 0 && s[b]&0xc0 == 0x80 { // keep a whole UTF-8 rune
		b--
	}
	return s[:b] + "…"
}

// kbLines renders the KB hits: `k… <kind> <title> [hazard] [fails] [stale]`.
func kbLines(hits []kb.Hit) []string {
	out := make([]string, 0, len(hits))
	for _, h := range hits {
		parts := []string{h.ID, h.Kind, doc.SafeLine(h.Title)}
		if h.Fails {
			parts = append(parts, "[fails on your env]")
		} else if h.Mismatch {
			parts = append(parts, "(env mismatch)")
		}
		if h.Hazard {
			parts = append(parts, "hazard")
		}
		if h.Stale {
			parts = append(parts, "stale?")
		}
		out = append(out, strings.Join(parts, " "))
	}
	return out
}

func changeLines(ls []know.Line) []string {
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.Text)
	}
	return out
}

func digestLines(ls []know.Line) []string {
	out := make([]string, 0, len(ls))
	for _, l := range ls {
		out = append(out, l.Text)
	}
	return out
}

// changeFollow is the deepest follow-up for a change claim: the version page for its lib/range.
func changeFollow(l know.Line) string {
	p := "/v/" + know.EncodeKey(l.Lib)
	if r := digRange(l); r != "" {
		p += "/" + r
	}
	if l.Kind != "" {
		p += "?kind=" + l.Kind
	}
	return p
}

// digRange is the `from..to` segment of a line (just `to` when no from).
func digRange(l know.Line) string {
	switch {
	case l.VFrom != "" && l.VTo != "":
		return l.VFrom + ".." + l.VTo
	case l.VTo != "":
		return l.VTo
	default:
		return ""
	}
}

// head is the brief head line (27.3): `brief q="…" libs=2 hits=5 changes=3 cached=0 b=600/600`.
func (m *model) head() string {
	return "brief q=\"" + doc.SafeLine(clip(m.Q, 80)) + "\" libs=" + strconv.Itoa(m.Libs) +
		" hits=" + strconv.Itoa(m.Hits) + " changes=" + strconv.Itoa(m.Changes) +
		" cached=" + strconv.Itoa(m.Cached) + " b=" + strconv.Itoa(m.Used) + "/" + strconv.Itoa(m.B)
}

// toDoc renders the model as a doc.Doc (one field per section, in order).
func (m *model) toDoc() *doc.Doc {
	d := &doc.Doc{
		Head:    m.head(),
		Title:   "brief · pre-flight pack",
		Desc:    "One budgeted pre-flight pack: top fixes, post-cutoff changes, digests, cached work and demand gaps for a query.",
		NoIndex: true,
		Budget:  m.B,
		Fields:  m.Sections,
		Next:    m.Next,
	}
	return d
}

// text renders the model as the plain brief text an MCP op returns.
func (m *model) text() string {
	var b strings.Builder
	b.WriteString(m.head())
	for _, f := range m.Sections {
		b.WriteString("\n" + f.Name + ":\n  " + strings.ReplaceAll(f.Val, "\n", "\n  "))
	}
	if len(m.Next) > 0 {
		b.WriteString("\nnext:")
		for _, a := range m.Next {
			b.WriteString("\n  " + a.Method + " " + a.Path)
			if a.Hint != "" {
				b.WriteString(" " + a.Hint)
			}
		}
	}
	return b.String()
}
