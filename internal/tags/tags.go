// Package tags is the tag-alias layer and canonical tag hub (SPEC-v2 27.9, P104). A seeded
// tag_alias table (0057) maps non-canonical tags to their canonical form (postgresql -> postgres,
// js -> javascript, k8s -> kubernetes, …, never crossing a lib ecosystem). Canon implements
// kb.TagAliasFn so CreateEntry/task/claim writes store the canonical tag and reply
// `tags: postgres (from postgresql)`; Canonical implements pages.TagCanonFn so GET /tag/{alias}
// and /f/kb/{alias} answer 301. New aliases are added by a passed `alias` governance proposal
// (platform scope, L2, 48 h) or by two L2 confirmations from distinct super-groups
// (POST /v1/tags/alias then .../ok). GET /tags is the indexable CollectionPage of canonical tags
// with entry counts; the janitor re-tags existing rows forward only (alias -> canonical). The
// alias map is held in an atomic.Pointer cache refreshed on every change and by the janitor.
package tags

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
	"ekaii.fr/commons/internal/trust"
)

// Bounds. Vars so tests can lower them.
var (
	RetagBatch  = 500           // kb rows retagged per alias per janitor pass
	SuggestSim  = float32(0.42) // trigram threshold for a `did you mean` suggestion
	ConfirmsReq = 2             // distinct L2 super-groups that promote a pending alias
	topTags     = 200           // canonical tags listed on /tags
	maxBody     = int64(1) << 10
)

var (
	tagRe = regexp.MustCompile(`^[a-z0-9][a-z0-9._+-]{0,31}$`)

	errTag      = core.Bad("alias and tag must each match ^[a-z0-9][a-z0-9._+-]{0,31}$")
	errSame     = core.Bad("alias and tag must differ")
	errCanonAl  = core.Bad("alias is already a canonical tag (nothing maps onto a canonical tag)")
	errTagAlias = core.Bad("tag is itself an alias; point the new alias at its canonical form")
	errCrossEco = core.Bad("alias and tag are in different lib ecosystems (aliases never cross an ecosystem)")
	errScope    = core.Bad("alias proposals are platform-wide (scope must be empty)")
	errConflict = core.E(409, "conflict", "alias already maps to another tag")
	errSeeded   = core.E(409, "conflict", "alias is seeded and cannot be re-pointed")
	errPending  = core.E(404, "notfound", "no pending alias by that name")
)

// aliasMap is the immutable snapshot the cache holds: live aliases (seeded or twice-confirmed)
// mapped to their canonical tag, plus the set of canonical tags (the right-hand sides). Ecosystem
// of a tag is derived from this: an alias's ecosystem is the canonical it maps to, a canonical's is
// itself, anything else is unknown.
type aliasMap struct {
	alias map[string]string
	canon map[string]bool
}

var cache atomic.Pointer[aliasMap]

func init() { cache.Store(&aliasMap{alias: map[string]string{}, canon: map[string]bool{}}) }

// Canon maps a tag to its canonical form, implementing kb.TagAliasFn: (canon, from, true) on a hit.
func Canon(tag string) (canon, from string, ok bool) {
	t := strings.ToLower(tag)
	m := cache.Load()
	if c, hit := m.alias[t]; hit && c != t {
		return c, t, true
	}
	return "", "", false
}

// Canonical maps a tag alias to its canonical tag, implementing pages.TagCanonFn (301 source).
func Canonical(tag string) (string, bool) {
	c, _, ok := Canon(tag)
	return c, ok
}

// ecoOf returns the ecosystem of a tag and whether it is known: an alias -> its canonical, a
// canonical -> itself, otherwise unknown.
func (m *aliasMap) ecoOf(tag string) (string, bool) {
	if c, ok := m.alias[tag]; ok {
		return c, true
	}
	if m.canon[tag] {
		return tag, true
	}
	return "", false
}

// validatePair checks a would-be (alias -> tag) mapping against the current snapshot: both well
// formed and distinct, the alias is not itself a canonical tag, the target is not itself an alias,
// and the two are not in different known ecosystems.
func validatePair(m *aliasMap, alias, tag string) error {
	alias, tag = strings.ToLower(alias), strings.ToLower(tag)
	if !tagRe.MatchString(alias) || !tagRe.MatchString(tag) {
		return errTag
	}
	if alias == tag {
		return errSame
	}
	if m.canon[alias] {
		return errCanonAl
	}
	if _, isAlias := m.alias[tag]; isAlias {
		return errTagAlias
	}
	ea, oka := m.ecoOf(alias)
	eb, okb := m.ecoOf(tag)
	if oka && okb && ea != eb {
		return errCrossEco
	}
	return nil
}

type svc struct{ d *core.Deps }

// superKey HMACs a super-group with the server secret (24.24): distinct-super confirmations work,
// raw addresses never reach the table.
func (s *svc) superKey(k string) string {
	m := hmac.New(sha256.New, s.d.Cfg.ServerSecret)
	m.Write([]byte("cx-tags-super-v1\x00" + k))
	return hex.EncodeToString(m.Sum(nil))[:24]
}

// rootSuper is the HMAC'd registration super-group of a token root (its own root key when none).
func (s *svc) rootSuper(st trust.Standing, root string) string {
	if st.Super == "" {
		return s.superKey("root:" + root)
	}
	return s.superKey(st.Super)
}

var exts = []string{".txt", ".md", ".json", ".html", ".sh", ".jsonld"}

// Register mounts the write paths (POST /v1/tags/alias, POST /v1/tags/alias/ok), the hubs
// (GET /tags, GET /tags/about and twins), registers the `alias` governance kind, the scopes, cost,
// OpenAPI, llms-full, the tags-hub sitemap child (a single URL; tags.xml itself is P42's) and the
// forward-retag janitor, then loads the alias cache.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}
	mux.HandleFunc("POST /v1/tags/alias", s.propose)
	mux.HandleFunc("POST /v1/tags/alias/ok", s.confirm)
	mux.HandleFunc("GET /tags", s.hub)
	mux.HandleFunc("GET /tags/about", s.about)
	for _, ext := range exts {
		mux.HandleFunc("GET /tags"+ext, s.hub)
		mux.HandleFunc("GET /tags/about"+ext, s.about)
	}
	d.RegisterScope("POST /v1/tags/alias", "kb:w")
	d.RegisterScope("POST /v1/tags/alias/ok", "kb:w")
	d.RegisterCost("GET /tags", 2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("tags", func(context.Context) string { return llmsText })
	d.RegisterSitemap("tags-hub", func(context.Context) ([]core.SitemapURL, error) {
		return []core.SitemapURL{{Loc: doc.Base() + "/tags", LastMod: time.Now().UTC()}}, nil
	})
	gov.RegisterKind("alias", validateKind, applyAlias)
	d.Janitor.Add("tags", func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	if d.DB != nil {
		_ = Reload(context.Background(), d.DB)
	}
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// Reload rebuilds the alias cache from the live rows (seeded or twice-confirmed) and stores it
// atomically. Callers refresh after a change; the janitor refreshes every pass.
func Reload(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT alias, tag FROM tag_alias WHERE seeded OR confirms >= $1`, ConfirmsReq)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := &aliasMap{alias: map[string]string{}, canon: map[string]bool{}}
	for rows.Next() {
		var a, t string
		if err := rows.Scan(&a, &t); err != nil {
			return err
		}
		m.alias[a] = t
		m.canon[t] = true
	}
	if err := rows.Err(); err != nil {
		return err
	}
	cache.Store(m)
	return nil
}

// Suggest returns the nearest canonical tag to t by trigram similarity (>= SuggestSim) for the
// `did you mean tag: postgres` write hint; "" when nothing is close. It never suggests t itself.
func Suggest(ctx context.Context, q core.Q, t string) (string, bool) {
	t = strings.ToLower(strings.TrimSpace(t))
	if !tagRe.MatchString(t) {
		return "", false
	}
	if _, _, ok := Canon(t); ok {
		return "", false // already an alias: the caller resolves it directly
	}
	if cache.Load().canon[t] {
		return "", false // already canonical
	}
	var best string
	var sim float32
	err := q.QueryRow(ctx, `SELECT tag, similarity(tag, $1) s FROM (SELECT DISTINCT tag FROM tag_alias WHERE seeded OR confirms >= $2) c
		WHERE tag <> $1 AND similarity(tag, $1) >= $3 ORDER BY s DESC, tag LIMIT 1`, t, ConfirmsReq, SuggestSim).Scan(&best, &sim)
	if err != nil {
		return "", false
	}
	return best, best != ""
}

// --- governance kind `alias` ---------------------------------------------------------------------

type aliasPatch struct {
	Alias string `json:"alias"`
	Tag   string `json:"tag"`
}

// validateKind is the gov.Validator for the `alias` kind: platform scope only, fixed shape, the
// pair passes validatePair against the current snapshot (alias not canonical, same ecosystem).
func validateKind(scope string, patch json.RawMessage) error {
	if scope != "" {
		return errScope
	}
	var p aliasPatch
	dec := json.NewDecoder(strings.NewReader(string(patch)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&p); err != nil {
		return core.Bad("patch: {alias, tag}")
	}
	return validatePair(cache.Load(), p.Alias, p.Tag)
}

// applyAlias is the gov.Applier for a passed `alias` proposal: it makes the alias live
// (confirms = ConfirmsReq, not seeded), refreshes the cache, and notes the change in /changelog.
// prev is the previous mapping ({} when the alias was new) for revert.
func applyAlias(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
	var in aliasPatch
	if err := json.Unmarshal(p.Patch, &in); err != nil {
		return nil, core.Bad("patch: {alias, tag}")
	}
	alias, tag := strings.ToLower(in.Alias), strings.ToLower(in.Tag)
	var prevTag string
	if err := tx.QueryRow(ctx, `SELECT tag FROM tag_alias WHERE alias = $1`, alias).Scan(&prevTag); err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO tag_alias (alias, tag, confirms, seeded) VALUES ($1, $2, $3, false)
		ON CONFLICT (alias) DO UPDATE SET tag = EXCLUDED.tag, confirms = GREATEST(tag_alias.confirms, $3)
		WHERE NOT tag_alias.seeded`, alias, tag, ConfirmsReq); err != nil {
		return nil, err
	}
	if err := gov.ChangelogNote(ctx, tx, "", p.ID+" alias "+alias+" -> "+tag); err != nil {
		return nil, err
	}
	_ = Reload(ctx, tx)
	prev := json.RawMessage(`{}`)
	if prevTag != "" {
		prev, _ = json.Marshal(aliasPatch{Alias: alias, Tag: prevTag})
	}
	return prev, nil
}

// --- confirmation path (two L2 from distinct super-groups) ---------------------------------------

type aliasInput struct {
	Alias string `json:"alias"`
	Tag   string `json:"tag"`
}

// propose is POST /v1/tags/alias: an L2 root records {alias, tag} as a pending alias (or adds its
// super-group to an existing pending one with the same target). It becomes live on the second
// distinct super-group.
func (s *svc) propose(w http.ResponseWriter, r *http.Request) { s.write(w, r, false) }

// confirm is POST /v1/tags/alias/ok: an L2 root backs an existing pending alias; {tag} is optional
// and must match when given.
func (s *svc) confirm(w http.ResponseWriter, r *http.Request) { s.write(w, r, true) }

func (s *svc) write(w http.ResponseWriter, r *http.Request, okPath bool) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") {
		return
	}
	var in aliasInput
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	in.Alias, in.Tag = strings.ToLower(strings.TrimSpace(in.Alias)), strings.ToLower(strings.TrimSpace(in.Tag))
	if !tagRe.MatchString(in.Alias) {
		doc.Fail(w, r, errTag)
		return
	}
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if id.Banned {
		doc.Fail(w, r, core.ErrBanned)
		return
	}
	ctx := r.Context()
	res, err := s.apply(ctx, id, in, okPath)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, res.status, res.line(s.d.DB, ctx), doc.GET("/tag/"+res.tag, ""), doc.GET("/tags", ""))
}

// apply runs one confirmation in a transaction (L2 check included) and refreshes the cache on
// promotion; shared by the HTTP handlers and the tagalias op.
func (s *svc) apply(ctx context.Context, id *core.Ident, in aliasInput, okPath bool) (*result, error) {
	if id == nil {
		return nil, core.ErrAuth
	}
	if id.Banned {
		return nil, core.ErrBanned
	}
	in.Alias, in.Tag = strings.ToLower(strings.TrimSpace(in.Alias)), strings.ToLower(strings.TrimSpace(in.Tag))
	if !tagRe.MatchString(in.Alias) {
		return nil, errTag
	}
	var res *result
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		st, err := trust.Load(ctx, tx, id.Root)
		if err != nil {
			return err
		}
		if st.Banned {
			return core.ErrBanned
		}
		if st.Level() < 2 {
			return core.E(403, "forbidden", "alias confirmations need an L2 root")
		}
		res, err = s.record(ctx, tx, id, s.rootSuper(st, id.Root), in, okPath)
		return err
	})
	if err != nil {
		return nil, err
	}
	if res.promoted {
		_ = Reload(ctx, s.d.DB)
	}
	return res, nil
}

// result is the outcome of one confirmation.
type result struct {
	alias, tag string
	confirms   int
	promoted   bool
	status     int
}

func (res *result) line(q core.Q, ctx context.Context) string {
	state := "pending"
	if res.confirms >= ConfirmsReq {
		state = "live"
	}
	line := "ok alias " + res.alias + " -> " + res.tag + " " + state + " confirms=" + strconv.Itoa(res.confirms) + "/" + strconv.Itoa(ConfirmsReq)
	if s, ok := Suggest(ctx, q, res.tag); ok {
		line += " (did you mean tag: " + s + "?)"
	}
	return line
}

// record inserts or confirms the pending alias under one super-group and promotes it on the second
// distinct super-group. On the propose path the target tag is required and validated; on the ok
// path the row must already exist (its tag is reused).
func (s *svc) record(ctx context.Context, tx core.Q, id *core.Ident, super string, in aliasInput, okPath bool) (*result, error) {
	var curTag string
	var confirmers []string
	var confirms int
	var seeded bool
	err := tx.QueryRow(ctx, `SELECT tag, confirmers, confirms, seeded FROM tag_alias WHERE alias = $1 FOR UPDATE`, in.Alias).
		Scan(&curTag, &confirmers, &confirms, &seeded)
	existing := err == nil
	if err != nil && err != pgx.ErrNoRows {
		return nil, err
	}
	if existing && seeded {
		return nil, errSeeded
	}
	tag := in.Tag
	switch {
	case okPath && !existing:
		return nil, errPending
	case existing:
		if tag != "" && tag != curTag {
			return nil, errConflict
		}
		tag = curTag
	default: // propose, new row
		if tag == "" {
			return nil, core.Bad("tag is required to propose a new alias")
		}
	}
	if err := validatePair(cache.Load(), in.Alias, tag); err != nil {
		return nil, err
	}
	// Add this super-group if new.
	if !existing {
		confirmers = nil
	}
	seen := false
	for _, c := range confirmers {
		if c == super {
			seen = true
			break
		}
	}
	if !seen {
		confirmers = append(confirmers, super)
	}
	confirms = len(confirmers)
	if _, err := tx.Exec(ctx, `INSERT INTO tag_alias (alias, tag, confirms, seeded, confirmers) VALUES ($1, $2, $3, false, $4)
		ON CONFLICT (alias) DO UPDATE SET tag = EXCLUDED.tag, confirms = EXCLUDED.confirms, confirmers = EXCLUDED.confirmers
		WHERE NOT tag_alias.seeded`, in.Alias, tag, confirms, confirmers); err != nil {
		return nil, err
	}
	if err := core.Audit(ctx, tx, id.ID, "tagalias", in.Alias+"->"+tag, confirms); err != nil {
		return nil, err
	}
	res := &result{alias: in.Alias, tag: tag, confirms: confirms, status: http.StatusOK}
	if confirms >= ConfirmsReq && (!existing || len(confirmers) > 1) {
		res.promoted = true
		res.status = http.StatusCreated
		if err := gov.ChangelogNote(ctx, tx, "", "alias "+in.Alias+" -> "+tag+" (two L2 confirmations)"); err != nil {
			return nil, err
		}
	}
	return res, nil
}

// --- forward-retag janitor -----------------------------------------------------------------------

// Janitor refreshes the alias cache then re-tags existing kb rows forward only (alias ->
// canonical), one batch per live alias, deduplicating when the canonical is already present.
func Janitor(ctx context.Context, q core.Q) error {
	if err := Reload(ctx, q); err != nil {
		return err
	}
	return Retag(ctx, q)
}

// Retag rewrites kb.tags in place: for every live alias still present on some row, replace it with
// its canonical tag (at most RetagBatch rows per alias per pass). Forward only: canonical -> alias
// never happens, and a row already carrying the canonical just drops the alias.
func Retag(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT alias, tag FROM tag_alias WHERE seeded OR confirms >= $1`, ConfirmsReq)
	if err != nil {
		return err
	}
	type pair struct{ alias, tag string }
	var pairs []pair
	for rows.Next() {
		var p pair
		if err := rows.Scan(&p.alias, &p.tag); err != nil {
			rows.Close()
			return err
		}
		pairs = append(pairs, p)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, p := range pairs {
		if _, err := q.Exec(ctx, `UPDATE kb k SET tags = (
			SELECT coalesce(array_agg(DISTINCT CASE WHEN t = $1 THEN $2 ELSE t END ORDER BY (CASE WHEN t = $1 THEN $2 ELSE t END)), '{}')
			FROM unnest(k.tags) t)
			WHERE k.id IN (SELECT id FROM kb WHERE $1 = ANY(tags) LIMIT $3)`, p.alias, p.tag, RetagBatch); err != nil {
			return err
		}
	}
	return nil
}
