package core

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sort"
	"time"
)

// SystemID is the system root (migration 0040): a valid id, never issued a token.
const SystemID = "asystem"

// OpMeta describes an MCP op for the registry (3.5).
type OpMeta struct {
	Scope    string
	Cost     float64
	Mutating bool
}

// FeedItem is one entry of a feed source (9.3).
type FeedItem struct {
	ID, URL, Title, Summary string
	Updated, Published      time.Time
	Tags                    []string
	Author                  string
}

// FeedFn returns the latest n items of a feed source (sub = optional sub-feed key).
type FeedFn func(ctx context.Context, sub string, n int) ([]FeedItem, error)

// SitemapURL is one sitemap entry (9.2).
type SitemapURL struct {
	Loc     string
	LastMod time.Time
}

// SitemapFn lists the URLs of one sitemap child.
type SitemapFn func(ctx context.Context) ([]SitemapURL, error)

// Target is a report target kind (4.7): existence, hide and restore by ref.
type Target struct {
	Exists, Hide, Restore func(ctx context.Context, q Q, ref string) error
}

// ResolverFn maps an id of a given prefix to (type, title, url) for /x/ (8.3).
type ResolverFn func(ctx context.Context, id string) (typ, title, url string, ok bool)

// StorageClassInfo is one storage class with its last measured usage (21.2).
type StorageClassInfo struct {
	Name   string
	Cap    int64
	Used   int64
	Frozen bool
}

// XPoWFnType is the shared anonymous-write PoW checker (3.1); implemented by auth.
type XPoWFnType func(ctx context.Context, q Q, r *http.Request) (grp, super string, err error)

// Cross-package seams. Every var is nil-safe and fails closed (or neutral) when unset.
var (
	XPoWFn           XPoWFnType
	LevelFn          func(ctx context.Context, q Q, root string) int
	LeakedTokenFn    func(ctx context.Context, q Q, tok string) (action string, err error)
	ExportRemoveFn   func(ctx context.Context, kind, id string)
	WWWAuthenticate  string // reply.Err adds the header on 401 when set
	BodyParserFn     func(r *http.Request, schema json.RawMessage) (json.RawMessage, error)
	BotLaneFn        func(ctx context.Context) (verified bool, cat string)
	AnonBitsFn       func(ctx context.Context, super string) int
	ChallengeIDFn    func(ctx context.Context, c string) string
	RegisterBundleFn func(ctx context.Context, q Q, id string, bundle json.RawMessage) error
	LogPathFn        func(path string) string
)

// XPoW checks the X-PoW header through XPoWFn; "err pow X-PoW required" until auth installs it.
func (d *Deps) XPoW(ctx context.Context, r *http.Request) (grp, super string, err error) {
	if XPoWFn == nil {
		return "", "", E(400, "pow", "X-PoW required")
	}
	return XPoWFn(ctx, d.DB, r)
}

// Level is the root's standing level (0..3); L0 until trust installs LevelFn.
func Level(ctx context.Context, q Q, root string) int {
	if LevelFn == nil {
		return 0
	}
	return LevelFn(ctx, q, root)
}

// LeakedToken runs the leak link (3.4); no-op until auth installs it.
func LeakedToken(ctx context.Context, q Q, tok string) (string, error) {
	if LeakedTokenFn == nil {
		return "", nil
	}
	return LeakedTokenFn(ctx, q, tok)
}

// ExportRemove propagates a removal to the dumps; no-op until export installs it.
func ExportRemove(ctx context.Context, kind, id string) {
	if ExportRemoveFn != nil {
		ExportRemoveFn(ctx, kind, id)
	}
}

// BotLane reports the verified-crawler state of a request context (27.1); never verified when unset.
func BotLane(ctx context.Context) (bool, string) {
	if BotLaneFn == nil {
		return false, ""
	}
	return BotLaneFn(ctx)
}

// AnonBits is the anonymous-write PoW difficulty for a super-group; POW_BITS_W when unset.
func (d *Deps) AnonBits(ctx context.Context, super string) int {
	if AnonBitsFn != nil {
		if b := AnonBitsFn(ctx, super); b > 0 {
			return b
		}
	}
	if d.Cfg.PowBitsW > 0 {
		return d.Cfg.PowBitsW
	}
	return DefaultPowBitsW
}

// ChallengeID derives the identity id announced with a challenge (26.1); empty when unset.
func ChallengeID(ctx context.Context, c string) string {
	if ChallengeIDFn == nil {
		return ""
	}
	return ChallengeIDFn(ctx, c)
}

// RegisterBundle stores a registration key bundle (26.1); ignored when unset.
func RegisterBundle(ctx context.Context, q Q, id string, bundle json.RawMessage) error {
	if RegisterBundleFn == nil || len(bundle) == 0 {
		return nil
	}
	return RegisterBundleFn(ctx, q, id, bundle)
}

type clientKey struct{}

type clientInfo struct{ ip, group, super string }

// WithClient stashes the caller's network keys so ops apply anonymous quotas exactly as HTTP.
func WithClient(ctx context.Context, ip, group, super string) context.Context {
	return context.WithValue(ctx, clientKey{}, clientInfo{ip, group, super})
}

// ClientFrom returns the network keys stored by WithClient (empty strings when absent).
func ClientFrom(ctx context.Context) (ip, group, super string) {
	c, _ := ctx.Value(clientKey{}).(clientInfo)
	return c.ip, c.group, c.super
}

// hooks holds every per-Deps registry (section 1); all methods are safe for concurrent use.
type hooks struct {
	resume    []func(ctx context.Context, root string) []string
	me        []func(ctx context.Context, id *Ident) []string
	targets   map[string]Target
	exporters map[string]func(ctx context.Context, root string, w io.Writer) error
	expOrder  []string
	classes   map[string]*storageClass
	scopes    map[string]string
	costs     map[string]float64
	feeds     map[string]FeedFn
	sitemaps  map[string]SitemapFn
	openapi   []json.RawMessage
	llms      map[string]func(ctx context.Context) string
	resolvers map[byte]ResolverFn
	escrow    []string
	observers []func(route string, status int, d time.Duration)
}

func newHooks() hooks {
	return hooks{
		targets:   map[string]Target{},
		exporters: map[string]func(context.Context, string, io.Writer) error{},
		classes:   map[string]*storageClass{},
		scopes:    map[string]string{},
		costs:     map[string]float64{},
		feeds:     map[string]FeedFn{},
		sitemaps:  map[string]SitemapFn{},
		llms:      map[string]func(context.Context) string{},
		resolvers: map[byte]ResolverFn{},
	}
}

// OnResume adds lines to GET /v1/me/resume (10.1).
func (d *Deps) OnResume(fn func(ctx context.Context, root string) []string) {
	d.hmu.Lock()
	d.h.resume = append(d.h.resume, fn)
	d.hmu.Unlock()
}

// ResumeLines runs every OnResume hook.
func (d *Deps) ResumeLines(ctx context.Context, root string) []string {
	d.hmu.RLock()
	fns := append([]func(context.Context, string) []string(nil), d.h.resume...)
	d.hmu.RUnlock()
	var out []string
	for _, fn := range fns {
		out = append(out, fn(ctx, root)...)
	}
	return out
}

// MeExtra adds k=v fields to GET /v1/me (3.6).
func (d *Deps) MeExtra(fn func(ctx context.Context, id *Ident) []string) {
	d.hmu.Lock()
	d.h.me = append(d.h.me, fn)
	d.hmu.Unlock()
}

// MeLines runs every MeExtra hook.
func (d *Deps) MeLines(ctx context.Context, id *Ident) []string {
	d.hmu.RLock()
	fns := append([]func(context.Context, *Ident) []string(nil), d.h.me...)
	d.hmu.RUnlock()
	var out []string
	for _, fn := range fns {
		out = append(out, fn(ctx, id)...)
	}
	return out
}

// RegisterTarget declares a report target kind (4.7).
func (d *Deps) RegisterTarget(kind string, t Target) {
	d.hmu.Lock()
	d.h.targets[kind] = t
	d.hmu.Unlock()
}

// Target returns a registered report target kind.
func (d *Deps) Target(kind string) (Target, bool) {
	d.hmu.RLock()
	defer d.hmu.RUnlock()
	t, ok := d.h.targets[kind]
	return t, ok
}

// OnExport registers an export-me writer for one kind (3.4); kinds are written in registration order.
func (d *Deps) OnExport(kind string, fn func(ctx context.Context, root string, w io.Writer) error) {
	d.hmu.Lock()
	if _, dup := d.h.exporters[kind]; !dup {
		d.h.expOrder = append(d.h.expOrder, kind)
	}
	d.h.exporters[kind] = fn
	d.hmu.Unlock()
}

// Export runs every exporter for root into w, in registration order; the first error stops it.
func (d *Deps) Export(ctx context.Context, root string, w io.Writer) error {
	d.hmu.RLock()
	order := append([]string(nil), d.h.expOrder...)
	fns := make([]func(context.Context, string, io.Writer) error, len(order))
	for i, k := range order {
		fns[i] = d.h.exporters[k]
	}
	d.hmu.RUnlock()
	for _, fn := range fns {
		if err := fn(ctx, root, w); err != nil {
			return err
		}
	}
	return nil
}

// RegisterScope maps a mux pattern to the scope a scoped token needs (3.5); checked by auth.
func (d *Deps) RegisterScope(pattern, scope string) {
	d.hmu.Lock()
	d.h.scopes[pattern] = scope
	d.hmu.Unlock()
}

// ScopeOf returns the scope registered for a pattern.
func (d *Deps) ScopeOf(pattern string) (string, bool) {
	d.hmu.RLock()
	defer d.hmu.RUnlock()
	s, ok := d.h.scopes[pattern]
	return s, ok
}

// RegisterCost sets the limiter cost of a mux pattern (3.6: 0.2 polls, 1 writes, 2 searches, 3 git).
func (d *Deps) RegisterCost(pattern string, cost float64) {
	d.hmu.Lock()
	d.h.costs[pattern] = cost
	d.hmu.Unlock()
}

// CostOf returns the registered cost of a pattern, 1 by default.
func (d *Deps) CostOf(pattern string) float64 {
	d.hmu.RLock()
	defer d.hmu.RUnlock()
	if c, ok := d.h.costs[pattern]; ok && c > 0 {
		return c
	}
	return 1
}

// RegisterFeed adds a feed source served at /f/<name>.atom|.json (9.3).
func (d *Deps) RegisterFeed(name string, fn FeedFn) {
	d.hmu.Lock()
	d.h.feeds[name] = fn
	d.hmu.Unlock()
}

// Feeds returns the registered feed sources.
func (d *Deps) Feeds() map[string]FeedFn {
	d.hmu.RLock()
	defer d.hmu.RUnlock()
	out := make(map[string]FeedFn, len(d.h.feeds))
	for k, v := range d.h.feeds {
		out[k] = v
	}
	return out
}

// RegisterSitemap adds a sitemap child /sitemaps/<name>.xml (9.2).
func (d *Deps) RegisterSitemap(name string, fn SitemapFn) {
	d.hmu.Lock()
	d.h.sitemaps[name] = fn
	d.hmu.Unlock()
}

// Sitemaps returns the registered sitemap children.
func (d *Deps) Sitemaps() map[string]SitemapFn {
	d.hmu.RLock()
	defer d.hmu.RUnlock()
	out := make(map[string]SitemapFn, len(d.h.sitemaps))
	for k, v := range d.h.sitemaps {
		out[k] = v
	}
	return out
}

// RegisterOpenAPI adds an OpenAPI fragment (paths + components) merged into /openapi.json; the
// request-body schemas also feed Decode's expect:/example: lines (27.2).
func (d *Deps) RegisterOpenAPI(frag json.RawMessage) {
	d.hmu.Lock()
	d.h.openapi = append(d.h.openapi, frag)
	d.hmu.Unlock()
	indexSchemas(frag)
}

// OpenAPIFragments returns every registered fragment in registration order.
func (d *Deps) OpenAPIFragments() []json.RawMessage {
	d.hmu.RLock()
	defer d.hmu.RUnlock()
	return append([]json.RawMessage(nil), d.h.openapi...)
}

// RegisterLLMSFull adds a section generator for /llms-full.txt (8.6).
func (d *Deps) RegisterLLMSFull(section string, fn func(ctx context.Context) string) {
	d.hmu.Lock()
	d.h.llms[section] = fn
	d.hmu.Unlock()
}

// LLMSFull returns the section generators sorted by section name.
func (d *Deps) LLMSFull() (names []string, fns []func(ctx context.Context) string) {
	d.hmu.RLock()
	defer d.hmu.RUnlock()
	for k := range d.h.llms {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		fns = append(fns, d.h.llms[k])
	}
	return
}

// RegisterResolver maps an id prefix letter to its object type for /x/ (8.3).
func (d *Deps) RegisterResolver(prefix byte, fn ResolverFn) {
	d.hmu.Lock()
	d.h.resolvers[prefix] = fn
	d.hmu.Unlock()
}

// Resolve looks an id up through the resolver of its prefix letter.
func (d *Deps) Resolve(ctx context.Context, id string) (typ, title, url string, ok bool) {
	if id == "" {
		return "", "", "", false
	}
	d.hmu.RLock()
	fn := d.h.resolvers[id[0]]
	d.hmu.RUnlock()
	if fn == nil {
		return "", "", "", false
	}
	return fn(ctx, id)
}

// OnEscrow registers a SQL expression returning the credits a package holds in escrow (16.1 audit).
func (d *Deps) OnEscrow(sql string) {
	d.hmu.Lock()
	d.h.escrow = append(d.h.escrow, sql)
	d.hmu.Unlock()
}

// EscrowSQL returns the registered escrow expressions.
func (d *Deps) EscrowSQL() []string {
	d.hmu.RLock()
	defer d.hmu.RUnlock()
	return append([]string(nil), d.h.escrow...)
}

// Observe registers a request observer (route, status, duration) fed by Handler (21.1 metrics).
func (d *Deps) Observe(fn func(route string, status int, d time.Duration)) {
	d.hmu.Lock()
	d.h.observers = append(d.h.observers, fn)
	d.hmu.Unlock()
}

func (d *Deps) observe(route string, status int, dur time.Duration) {
	d.hmu.RLock()
	obs := d.h.observers
	d.hmu.RUnlock()
	for _, fn := range obs {
		fn(route, status, dur)
	}
}
