// Package cachens are the result-cache namespaces of SPEC-v2 27.3: a namespace owner (L2+) declares
// a canonicalisation recipe (up to 8 RE2 regexp rules plus the built-in booleans lower, strip_ts,
// strip_hex, strip_paths, strip_lines) that the server applies to an input before keying the result
// cache, so a producer and a reader meeting the same post-canonical input share one key even when
// the raw strings differ by a timestamp, a hex id, a home path or a line:col. A recipe change bumps
// the namespace version so rows written under the old recipe stay reachable under the old version.
//
// The package also serves the pure key-derivation route (POST /v1/c/key, no storage) and the
// near-miss lookup (GET /v1/c/near) over the scrubbed input previews written by the cput path.
// Canon implements cache.CanonFn (wired by the integration package); everything read back from the
// cache is untrusted data and is only ever shown as a scrubbed preview here, never as a body.
package cachens

import (
	"context"
	"encoding/json"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/cache"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Op is an MCP operation: a compact text result, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Limits (27.3, 4.3). Vars so tests can tighten them.
var (
	MaxIn       = 64 << 10 // input bytes accepted for canonicalisation / near lookup
	MaxRules    = 8        // declared regexp rules per recipe
	MaxRe       = 200      // one rule's pattern length
	MaxTo       = 40       // one rule's replacement length
	MaxDesc     = 120      // recipe description runes
	MaxPreview  = 300      // in_preview runes (mirrors cache)
	NearMin     = 0.55     // similarity threshold for a near-miss hit
	NearMax     = 3        // near-miss lines returned
	NearPreview = 80       // preview runes on a near line
	recipeTTL   = 30 * time.Second
)

var (
	nsRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,31}$`)

	errNS = core.Bad("ns must match [a-z0-9][a-z0-9.-]{0,31}")
)

// --- built-in replacements (27.3) ------------------------------------------------------------------

var (
	reISOTimestamp = regexp.MustCompile(`\d{4}-\d{2}-\d{2}[Tt ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:?\d{2})?`)
	reHex12        = regexp.MustCompile(`(?i)\b[0-9a-f]{12,}\b`)
	reHomePath     = regexp.MustCompile(`(?:/Users|/home)/[^/\s]+`)
	reLineCol      = regexp.MustCompile(`:\d+:\d+\b`)
)

// --- recipe ----------------------------------------------------------------------------------------

// spec is the declared recipe as stored in cache_ns.rules (jsonb). desc lives in its own column.
type spec struct {
	Rules      []rule `json:"rules,omitempty"`
	Lower      bool   `json:"lower,omitempty"`
	StripTS    bool   `json:"strip_ts,omitempty"`
	StripHex   bool   `json:"strip_hex,omitempty"`
	StripPaths bool   `json:"strip_paths,omitempty"`
	StripLines bool   `json:"strip_lines,omitempty"`
}

type rule struct {
	Re string `json:"re"`
	To string `json:"to"`
}

// recipe is a compiled spec at a version.
type recipe struct {
	v     int
	owner string
	descr string
	spec  spec
	res   []*regexp.Regexp // compiled, parallel to spec.Rules
}

// apply runs the recipe on a default-canonicalised input and returns the canonical string.
func (rc *recipe) apply(in string) string {
	s := cache.Canonical(in)
	for i, rl := range rc.spec.Rules {
		s = rc.res[i].ReplaceAllString(s, rl.To)
	}
	if rc.spec.StripPaths {
		s = reHomePath.ReplaceAllString(s, "~")
	}
	if rc.spec.StripTS {
		s = reISOTimestamp.ReplaceAllString(s, "<ts>")
	}
	if rc.spec.StripHex {
		s = reHex12.ReplaceAllString(s, "<hex>")
	}
	if rc.spec.StripLines {
		s = reLineCol.ReplaceAllString(s, ":n")
	}
	if rc.spec.Lower {
		s = strings.ToLower(s)
	}
	return strings.TrimSpace(s)
}

// compile validates a spec and compiles its rules (RE2, the Go regexp engine). A bad pattern,
// over-long pattern or replacement, or too many rules is rejected.
func compile(sp spec, descr string) (*recipe, error) {
	if len(sp.Rules) > MaxRules {
		return nil, core.Bad("at most " + strconv.Itoa(MaxRules) + " rules")
	}
	if utf8.RuneCountInString(descr) > MaxDesc {
		return nil, core.Bad("desc must be <= " + strconv.Itoa(MaxDesc) + " chars")
	}
	rc := &recipe{spec: sp, descr: strings.TrimSpace(doc.SafeLine(descr))}
	for i, rl := range sp.Rules {
		if rl.Re == "" {
			return nil, core.Bad("rule " + strconv.Itoa(i+1) + ": empty re")
		}
		if len(rl.Re) > MaxRe {
			return nil, core.Bad("rule " + strconv.Itoa(i+1) + ": re > " + strconv.Itoa(MaxRe))
		}
		if len(rl.To) > MaxTo {
			return nil, core.Bad("rule " + strconv.Itoa(i+1) + ": to > " + strconv.Itoa(MaxTo))
		}
		re, err := regexp.Compile(rl.Re)
		if err != nil {
			return nil, core.Bad("rule " + strconv.Itoa(i+1) + ": " + err.Error())
		}
		rc.res = append(rc.res, re)
	}
	return rc, nil
}

// canonJSON is the deterministic jsonb form used to detect a recipe change (and store rules).
func (sp spec) canonJSON() []byte {
	b, _ := json.Marshal(sp)
	return b
}

// --- recipe cache ----------------------------------------------------------------------------------

// recipeCache resolves ns -> *recipe (nil for an undeclared namespace) and holds compiled recipes
// for recipeTTL to keep Canon off the database on the hot path. A PUT invalidates the entry.
type recipeCache struct {
	mu  sync.Mutex
	m   map[string]cached
	srv *svc
}

type cached struct {
	rc *recipe // nil = undeclared (default canonicalisation, v=0)
	at time.Time
}

func (c *recipeCache) get(ns string) *recipe {
	c.mu.Lock()
	e, ok := c.m[ns]
	c.mu.Unlock()
	if ok && time.Since(e.at) < recipeTTL {
		return e.rc
	}
	rc, err := c.srv.load(ns)
	if err != nil {
		// A transient DB error must not change keys: fall back to default without caching.
		return nil
	}
	c.mu.Lock()
	if c.m == nil {
		c.m = map[string]cached{}
	}
	c.m[ns] = cached{rc, time.Now()}
	c.mu.Unlock()
	return rc
}

func (c *recipeCache) drop(ns string) {
	c.mu.Lock()
	delete(c.m, ns)
	c.mu.Unlock()
}

// --- service ---------------------------------------------------------------------------------------

type svc struct {
	d  *core.Deps
	rc *recipeCache
}

var (
	pkgMu  sync.Mutex
	pkgSvc *svc // set by Register so Canon (cache.CanonFn, no ctx) can reach the DB
)

func newSvc(d *core.Deps) *svc {
	s := &svc{d: d}
	s.rc = &recipeCache{srv: s}
	return s
}

// load reads and compiles the recipe for ns (nil, nil for an undeclared namespace).
func (s *svc) load(ns string) (*recipe, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var (
		v     int
		owner string
		raw   []byte
		descr string
	)
	err := s.d.DB.QueryRow(ctx, `SELECT v, owner_root, rules, descr FROM cache_ns WHERE ns = $1`, ns).Scan(&v, &owner, &raw, &descr)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			return nil, nil
		}
		return nil, err
	}
	var sp spec
	if len(raw) > 0 {
		_ = json.Unmarshal(raw, &sp)
	}
	rc, err := compile(sp, descr)
	if err != nil {
		// A stored recipe that no longer compiles must not wedge the cache: default it.
		return nil, nil
	}
	rc.v, rc.owner = v, owner
	return rc, nil
}

// Canon implements cache.CanonFn (27.3, nil-safe, wired by the integration package): it returns the
// canonical input and the recipe version for ns. An undeclared namespace gets the default NFC/LF/
// trim canonicalisation at v=0; a DB error also falls back to the default so keys never shift under
// an outage.
func Canon(ns, in string) (canonical string, keyVersion int) {
	pkgMu.Lock()
	s := pkgSvc
	pkgMu.Unlock()
	if s == nil || !nsRe.MatchString(ns) {
		return cache.Canonical(in), 0
	}
	rc := s.rc.get(ns)
	if rc == nil {
		return cache.Canonical(in), 0
	}
	return rc.apply(in), rc.v
}

// preview mirrors the cput write path: one scrubbed, safe line of <= MaxPreview runes.
func preview(canonical string) string {
	if canonical == "" {
		return ""
	}
	p := doc.SafeLine(canonical)
	if utf8.RuneCountInString(p) > MaxPreview {
		p = string([]rune(p)[:MaxPreview])
	}
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	masked, _ := scrub.Mask(p)
	return strings.TrimSpace(doc.SafeLine(masked))
}

// --- PUT recipe ------------------------------------------------------------------------------------

// putReq is the PUT /v1/cns/{ns} body.
type putReq struct {
	Rules      []rule `json:"rules"`
	Lower      bool   `json:"lower"`
	StripTS    bool   `json:"strip_ts"`
	StripHex   bool   `json:"strip_hex"`
	StripPaths bool   `json:"strip_paths"`
	StripLines bool   `json:"strip_lines"`
	Desc       string `json:"desc"`
}

// put declares or updates the recipe of ns for id's root (27.3): L2+, at most Cap(cache_ns) owned
// namespaces per root, a compile-checked RE2 recipe. A namespace owned by another live root is
// refused; an unowned row (post-purge) or the root's own row may be rewritten. A real change bumps
// the version so old rows stay reachable; an identical submission is idempotent.
func (s *svc) put(ctx context.Context, id *core.Ident, ns string, req putReq) (*recipe, error) {
	if s.d.Frozen("write") {
		return nil, core.Frozen("write")
	}
	if !nsRe.MatchString(ns) {
		return nil, errNS
	}
	sp := spec{Rules: req.Rules, Lower: req.Lower, StripTS: req.StripTS, StripHex: req.StripHex,
		StripPaths: req.StripPaths, StripLines: req.StripLines}
	rc, err := compile(sp, req.Desc)
	if err != nil {
		return nil, err
	}
	lvl := levelOf(ctx, s.d.DB, id.Root)
	if lvl < 2 {
		return nil, core.E(403, "auth", "L2 required for cache namespaces")
	}
	newRules := sp.canonJSON()
	txErr := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, "cachens:"+id.Root); err != nil {
			return err
		}
		var (
			curV     int
			curOwner string
			curRules []byte
			curDescr string
			exists   bool
		)
		row := tx.QueryRow(ctx, `SELECT v, owner_root, rules, descr FROM cache_ns WHERE ns = $1 FOR UPDATE`, ns)
		switch err := row.Scan(&curV, &curOwner, &curRules, &curDescr); {
		case err == nil:
			exists = true
		case strings.Contains(err.Error(), "no rows"):
			exists = false
		default:
			return err
		}
		if exists && curOwner != "" && curOwner != id.Root {
			return core.E(409, "taken", "namespace owned by another root")
		}
		if !exists || curOwner != id.Root {
			// Claiming a new or unowned namespace consumes one of the root's live slots.
			var owned int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM cache_ns WHERE owner_root = $1`, id.Root).Scan(&owned); err != nil {
				return err
			}
			if owned >= trust.Cap("cache_ns", lvl) {
				return core.E(429, "quota", "cache namespaces live")
			}
		}
		if !exists {
			if _, err := tx.Exec(ctx, `INSERT INTO cache_ns (ns, owner_root, v, rules, descr) VALUES ($1, $2, 1, $3, $4)`,
				ns, id.Root, string(newRules), rc.descr); err != nil {
				return err
			}
			rc.v, rc.owner = 1, id.Root
			return core.Audit(ctx, tx, id.ID, "cns", ns, rc.v)
		}
		changed := string(curRules) != string(newRules) || curDescr != rc.descr
		v := curV
		if changed {
			v = curV + 1
		}
		if _, err := tx.Exec(ctx, `UPDATE cache_ns SET owner_root = $2, v = $3, rules = $4, descr = $5, updated = now() WHERE ns = $1`,
			ns, id.Root, v, string(newRules), rc.descr); err != nil {
			return err
		}
		rc.v, rc.owner = v, id.Root
		if changed {
			return core.Audit(ctx, tx, id.ID, "cns", ns, v)
		}
		return nil
	})
	if txErr != nil {
		return nil, txErr
	}
	s.rc.drop(ns)
	return rc, nil
}

// get returns the recipe of ns for display (nil = undeclared, default canonicalisation).
func (s *svc) get(ctx context.Context, ns string) (*recipe, error) {
	if !nsRe.MatchString(ns) {
		return nil, errNS
	}
	return s.load(ns)
}

// purge clears the owner of a root's namespaces while keeping the rows, so keys stay reachable
// (27.3 OnPurge: owned namespaces keep rows, lose owner).
func purge(ctx context.Context, q core.Q, root string) error {
	_, err := q.Exec(ctx, `UPDATE cache_ns SET owner_root = '', updated = now() WHERE owner_root = $1`, root)
	return err
}

// --- helpers ---------------------------------------------------------------------------------------

// levelOf is the root's standing level clamped to 0..3 (L0 until trust installs LevelFn).
func levelOf(ctx context.Context, q core.Q, root string) int {
	l := core.Level(ctx, q, root)
	if l < 0 {
		return 0
	}
	if l > 3 {
		return 3
	}
	return l
}

// keyResult is a pure key derivation (POST /v1/c/key, no storage).
type keyResult struct {
	Key, NS, Canonical string
	V                  int
}

// head is "ns=build-errors@3" or "ns=foo" at v=0.
func nsVer(ns string, v int) string {
	if v > 0 {
		return ns + "@" + strconv.Itoa(v)
	}
	return ns
}

// deriveKey canonicalises in through ns's recipe and returns the cache key.
func deriveKey(ns, in string) (keyResult, error) {
	if !nsRe.MatchString(ns) {
		return keyResult{}, errNS
	}
	if len(in) > MaxIn {
		return keyResult{}, core.ErrSize
	}
	canonical, v := Canon(ns, in)
	if canonical == "" {
		return keyResult{}, core.Bad("in is empty after canonicalisation")
	}
	return keyResult{Key: cache.Key(ns, canonical, v), NS: ns, Canonical: canonical, V: v}, nil
}
