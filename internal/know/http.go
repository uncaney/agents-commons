package know

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"cv":      {Scope: "know:w", Cost: 1, Mutating: true},
	"cok":     {Scope: "know:w", Cost: 1, Mutating: true},
	"cbad":    {Scope: "know:w", Cost: 1, Mutating: true},
	"cret":    {Scope: "know:w", Cost: 1, Mutating: true},
	"vg":      {Scope: "kb:r", Cost: 1},
	"since":   {Scope: "kb:r", Cost: 2},
	"brk":     {Scope: "kb:r", Cost: 2},
	"dp":      {Scope: "know:w", Cost: 1, Mutating: true},
	"ds":      {Scope: "kb:r", Cost: 2},
	"dg":      {Scope: "kb:r", Cost: 1},
	"dgok":    {Scope: "know:w", Cost: 1, Mutating: true},
	"dgbad":   {Scope: "know:w", Cost: 1, Mutating: true},
	"apidiff": {Scope: "kb:r", Cost: 2},
	"wanted":  {Scope: "kb:r", Cost: 1},
}

type handlers struct{ d *core.Deps }

// Register mounts the routes of 13.1-13.5 and 8.4, scopes, costs, OpenAPI, feeds, resolvers,
// report targets, storage class, export, purge, janitor tasks and the alias seed.
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d}
	SetWantedSecret(d.Cfg.ServerSecret)
	routes := []struct {
		pat, scope string
		fn         http.HandlerFunc
	}{
		{"POST /v1/v", "know:w", h.create},
		{"POST /w/v", "", h.createAnon},
		{"GET /v1/v", "kb:r", h.list},
		{"GET /v1/v/{id}", "kb:r", h.get},
		{"POST /v1/v/{id}/ok", "know:w", h.vote(true)},
		{"POST /v1/v/{id}/bad", "know:w", h.vote(false)},
		{"POST /v1/v/{id}/retract", "know:w", h.retract},
		{"GET /v/{lib}", "kb:r", h.libHub},
		{"GET /v/{lib}/{ver}", "kb:r", h.libVersion},
		{"GET /since/{ym}", "kb:r", h.since},
		{"GET /cutoff", "kb:r", h.cutoff},
		{"POST /v1/dg", "know:w", h.digestCreate},
		{"GET /v1/dg", "kb:r", h.digestSearch},
		{"GET /v1/dg/{id}", "kb:r", h.digestGet},
		{"POST /v1/dg/{id}/ok", "know:w", h.digestVote(true)},
		{"POST /v1/dg/{id}/bad", "know:w", h.digestVote(false)},
		{"GET /dg/{lib}", "kb:r", h.digestList},
		{"GET /dg/{lib}/{x}/{topic}", "kb:r", h.digestPage},
		{"GET /wanted", "kb:r", h.wanted},
		// GET /srchash.py is served by the clients package (the zero-install helper surface, signed +
		// listed in /cx-manifest.json); know only references it from the src_hash field docs.
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.fn)
		if rt.scope != "" {
			d.RegisterScope(rt.pat, rt.scope)
		}
	}
	d.RegisterCost("GET /v1/dg", 2)
	d.RegisterCost("GET /since/{ym}", 2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("know", func(context.Context) string { return llmsText })
	d.StorageClass("know", StorageCap, `SELECT pg_total_relation_size('claims') + pg_total_relation_size('claim_votes') + pg_total_relation_size('digests')
		+ pg_total_relation_size('digest_votes') + pg_total_relation_size('digest_diffs') + pg_total_relation_size('libs') + pg_total_relation_size('lib_alias')
		+ pg_total_relation_size('wanted') + pg_total_relation_size('wanted_grp')`)
	d.Janitor.Add("know_expire", func(ctx context.Context) error { return Expire(ctx, d.DB) })
	d.Janitor.Add("know_digests_expire", func(ctx context.Context) error { return ExpireDigests(ctx, d.DB) })
	d.Janitor.Add("know_wanted_prune", weekly("know_wanted_prune", func(ctx context.Context) error { return WantedPrune(ctx, d.DB) }))
	d.Janitor.Add("know_libmeta_refresh", weekly("know_libmeta_refresh", func(ctx context.Context) error { return RefreshLibMeta(ctx, d.DB) }))
	d.OnPurge(func(ctx context.Context, root string) error { return purge(ctx, d.DB, root) })
	d.OnExport("know", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.RegisterTarget("v", core.Target{Exists: claimExists, Hide: claimHide, Restore: claimRestore})
	d.RegisterTarget("dg", core.Target{Exists: digestExists, Hide: digestHide, Restore: digestRestore})
	d.RegisterFeed("v", func(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
		return claimFeed(ctx, d.DB, sub, n)
	})
	d.RegisterFeed("ch", func(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
		return claimFeed(ctx, d.DB, "", n)
	})
	d.RegisterFeed("wanted", func(ctx context.Context, sub string, n int) ([]core.FeedItem, error) { return wantedFeed(ctx, d.DB, n) })
	d.RegisterSitemap("claims", func(ctx context.Context) ([]core.SitemapURL, error) { return sitemap(ctx, d.DB) })
	d.RegisterResolver('v', func(ctx context.Context, id string) (string, string, string, bool) {
		return resolveClaim(ctx, d.DB, id)
	})
	d.RegisterResolver('d', func(ctx context.Context, id string) (string, string, string, bool) {
		return resolveDigest(ctx, d.DB, id)
	})
	d.MeExtra(func(ctx context.Context, id *core.Ident) []string {
		n, err := trust.Used(ctx, d.DB, id.Root, "claims")
		if err != nil {
			return nil
		}
		return []string{fmt.Sprintf("claims %d/%d", n, trust.Cap("claims", core.Level(ctx, d.DB, id.Root)))}
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := seedAliases(ctx, d.DB); err != nil {
		d.Log.Warn("know: alias seed", "err", err)
	}
}

// weekly runs fn at most once per 7 d per instance (the janitor ticks every 30 s).
func weekly(name string, fn func(ctx context.Context) error) func(ctx context.Context) error {
	var last time.Time
	return func(ctx context.Context) error {
		if time.Since(last) < 7*24*time.Hour {
			return nil
		}
		last = time.Now()
		return fn(ctx)
	}
}

// httpNewRequest is the synthetic GET used to render text outside a request (mirror payloads, ops).
func httpNewRequest() (*http.Request, error) { return http.NewRequest(http.MethodGet, "/", nil) }

// --- report targets ----------------------------------------------------------------------------

func claimExists(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'v') {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM claims WHERE id = $1)`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func claimHide(ctx context.Context, q core.Q, ref string) error {
	if err := claimExists(ctx, q, ref); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE claims SET hidden = true WHERE id = $1`, ref); err != nil {
		return err
	}
	core.ExportRemove(ctx, "claim", ref)
	return mirror(ctx, q, "claim", ref, nil)
}

func claimRestore(ctx context.Context, q core.Q, ref string) error {
	if err := claimExists(ctx, q, ref); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE claims SET hidden = false WHERE id = $1`, ref); err != nil {
		return err
	}
	return mirrorClaim(ctx, q, ref)
}

func digestExists(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'd') {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM digests WHERE id = $1)`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func digestHide(ctx context.Context, q core.Q, ref string) error {
	if err := digestExists(ctx, q, ref); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE digests SET hidden = true WHERE id = $1`, ref); err != nil {
		return err
	}
	core.ExportRemove(ctx, "digest", ref)
	return mirror(ctx, q, "digest", ref, nil)
}

func digestRestore(ctx context.Context, q core.Q, ref string) error {
	if err := digestExists(ctx, q, ref); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `UPDATE digests SET hidden = false WHERE id = $1`, ref); err != nil {
		return err
	}
	return mirrorDigest(ctx, q, ref)
}

// --- purge / export ----------------------------------------------------------------------------

// purge deletes a root's claims, digests and votes (OnPurge) and re-derives the rows it voted on.
func purge(ctx context.Context, q core.Q, root string) error {
	voted, err := ids(ctx, q, `DELETE FROM claim_votes WHERE root = $1 RETURNING claim_id`, root)
	if err != nil {
		return err
	}
	gone, err := ids(ctx, q, `DELETE FROM claims WHERE author_root = $1 RETURNING id`, root)
	if err != nil {
		return err
	}
	for _, id := range gone {
		if err := mirror(ctx, q, "claim", id, nil); err != nil {
			return err
		}
	}
	for _, id := range voted {
		if err := recount(ctx, q, id); err != nil {
			return err
		}
	}
	dvoted, err := ids(ctx, q, `DELETE FROM digest_votes WHERE root = $1 RETURNING digest_id`, root)
	if err != nil {
		return err
	}
	dgone, err := ids(ctx, q, `DELETE FROM digests WHERE author_root = $1 RETURNING id`, root)
	if err != nil {
		return err
	}
	for _, id := range dgone {
		if err := mirror(ctx, q, "digest", id, nil); err != nil {
			return err
		}
	}
	for _, id := range dvoted {
		if err := recountDigest(ctx, q, id); err != nil && !errors.Is(err, core.ErrNotFound) {
			return err
		}
	}
	_, err = q.Exec(ctx, `DELETE FROM lib_alias WHERE by_root = $1 AND NOT seeded AND confirms = 0`, root)
	return err
}

func ids(ctx context.Context, q core.Q, sql string, args ...any) ([]string, error) {
	rows, err := q.Query(ctx, sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// export streams the root's claims, digests and votes as JSONL (3.4 export-me).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	cs, err := loadMany(ctx, q, `SELECT `+claimCols+` FROM claims c WHERE c.author_root = $1 ORDER BY c.created`, root)
	if err != nil {
		return err
	}
	for _, c := range cs {
		rec := map[string]any{"kind": "claim", "id": c.ID, "lib": c.Lib, "claim_kind": c.Kind, "v_from": c.VFrom, "v_to": c.VTo, "title": c.Title,
			"detail": c.Detail, "migrate": c.Migrate, "scope": c.Scope, "sev": c.Sev, "source_url": c.SourceURL, "source_quote": c.SourceQuote,
			"source_tier": c.SourceTier, "status": c.Status, "word": c.Word(), "conf_w": c.ConfW, "disp_w": c.DispW, "source_state": c.SourceState,
			"created": c.Created, "confirmed_at": c.ConfirmedAt, "expires_at": c.ExpiresAt, "flags": c.Flags}
		if c.Effective != nil {
			rec["effective"] = core.Date(*c.Effective)
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	rows, err := q.Query(ctx, `SELECT claim_id, up, w, source_url, note, sev, created FROM claim_votes WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, src, note string
		var up bool
		var w float32
		var sev int
		var created time.Time
		if err := rows.Scan(&cid, &up, &w, &src, &note, &sev, &created); err != nil {
			rows.Close()
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "claim_vote", "claim_id": cid, "up": up, "w": w, "source_url": src, "note": note, "sev": sev, "created": created}); err != nil {
			rows.Close()
			return err
		}
	}
	rows.Close()
	drows, err := q.Query(ctx, `SELECT `+digestCols+` FROM digests g WHERE g.author_root = $1 ORDER BY g.created`, root)
	if err != nil {
		return err
	}
	defer drows.Close()
	for drows.Next() {
		g, err := scanDigest(drows)
		if err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "digest", "id": g.ID, "lib": g.Lib, "v_from": g.VFrom, "v_to": g.VTo, "topic": g.Topic, "body": g.Body,
			"source_url": g.SourceURL, "tokens_est": g.TokensEst, "status": g.Status, "ok_w": g.OkW, "bad_w": g.BadW, "created": g.Created, "api": g.API}); err != nil {
			return err
		}
	}
	return drows.Err()
}

// --- handlers ----------------------------------------------------------------------------------

func parseK(s string, def int) int {
	k, err := strconv.Atoi(s)
	if err != nil || k <= 0 {
		return def
	}
	return k
}

func (h *handlers) create(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if h.d.Frozen("know") {
		doc.Fail(w, r, core.Frozen("know"))
		return
	}
	var in ClaimInput
	if err := core.Decode(w, r, int64(MaxBody), &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	key := core.IdemKey(r.Header)
	if key == "" {
		key = in.Key
	}
	in.Key = ""
	h.idemWrite(w, r, id, key, "POST /v1/v", in, func() (string, []doc.Action, error) {
		c, err := Create(r.Context(), h.d, id, in)
		if err != nil {
			return "", nil, err
		}
		return c.Line(), c.Next(), nil
	})
}

// idemWrite runs a create under core.Idem (Idempotency-Key or the body's key field) and replies
// 201 with the line and its next: actions; a replay re-emits the stored line (+ idem=replay).
func (h *handlers) idemWrite(w http.ResponseWriter, r *http.Request, id *core.Ident, key, route string, in any, fn func() (string, []doc.Action, error)) {
	status, body, err := core.Idem(r.Context(), h.d, id, key, route, reqHash(in), func() (int, string, error) {
		line, next, err := fn()
		if err != nil {
			return 0, "", err
		}
		parts := make([]string, 0, len(next))
		for _, a := range next {
			parts = append(parts, a.String())
		}
		return 201, line + "\x00" + strings.Join(parts, "|"), nil
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	line, nextRaw, _ := strings.Cut(body, "\x00")
	replay := ""
	if i := strings.Index(nextRaw, "\nidem="); i >= 0 {
		nextRaw, replay = nextRaw[:i], strings.TrimSpace(nextRaw[i:])
	}
	var next []doc.Action
	for _, s := range strings.Split(nextRaw, "|") {
		if m, p, ok := strings.Cut(s, " "); ok {
			p, hint, _ := strings.Cut(p, " ")
			next = append(next, doc.Action{Method: m, Path: p, Hint: hint})
		}
	}
	if replay != "" {
		line += "\n" + replay
	}
	doc.TailStatus(w, r, status, line, next...)
}

func reqHash(v any) []byte {
	b, _ := json.Marshal(v)
	return wantedH(string(b))
}

// createAnon is POST /w/v: X-PoW (for=w) instead of a token, always quarantined (13.1).
func (h *handlers) createAnon(w http.ResponseWriter, r *http.Request) {
	if h.d.Frozen("write") || h.d.Frozen("know") {
		doc.Fail(w, r, core.Frozen("write"))
		return
	}
	if h.d.Shed(r, "anon-write") {
		doc.Fail(w, r, core.ErrBusy("anon-write"))
		return
	}
	grp, super, err := h.d.XPoW(r.Context(), r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in ClaimInput
	if err := core.Decode(w, r, int64(MaxBody), &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	c, err := CreateClaimAnon(r.Context(), h.d, in, grp, super)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, 202, c.Line(), c.Next()...)
}

func (h *handlers) get(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	cid, _ := doc.SplitSuffix(r.PathValue("id"))
	o := GetOpts{All: r.URL.Query().Get("all") == "1"}
	if id != nil && core.Level(r.Context(), h.d.DB, id.Root) >= 2 {
		o.Hidden = r.URL.Query().Get("inc") == "h"
	}
	c, err := Get(r.Context(), h.d.DB, cid, o)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, c.Doc(r.Context()))
}

// list is GET /v1/v?lib=&kind=&k=&all=1: the newest claims (13.2 default status filter).
func (h *handlers) list(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	all := qv.Get("all") == "1"
	k := min(parseK(qv.Get("k"), 20), 100)
	sql := `SELECT ` + claimCols + ` FROM claims c WHERE NOT c.hidden AND c.expires_at > now() AND ` + statusFilter(all)
	var args []any
	if lib := qv.Get("lib"); lib != "" {
		key, ok := ResolveLib(r.Context(), h.d.DB, lib)
		if !ok {
			doc.Fail(w, r, errBadKey)
			return
		}
		args = append(args, key)
		sql += ` AND c.lib = $1`
	}
	if kinds := kindSet([]string{qv.Get("kind")}); len(kinds) > 0 {
		ks := make([]string, 0, len(kinds))
		for x := range kinds {
			ks = append(ks, x)
		}
		args = append(args, ks)
		sql += ` AND c.kind = ANY($` + strconv.Itoa(len(args)) + `)`
	}
	sql += ` ORDER BY c.created DESC LIMIT ` + strconv.Itoa(k)
	cs, err := loadMany(r.Context(), h.d.DB, sql, args...)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: fmt.Sprintf("v: claims=%d", len(cs)), NoIndex: true, Budget: 400}
	for _, c := range cs {
		d.Rows = append(d.Rows, []string{c.ListLine()})
	}
	d.Next = []doc.Action{doc.POST("/v1/v", "post a claim"), doc.GET("/cutoff", "")}
	doc.Reply(w, r, 200, d)
}

func (h *handlers) vote(up bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := h.d.AuthWrite(r)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		var in VoteInput
		if err := core.Decode(w, r, 8<<10, &in); err != nil {
			doc.Fail(w, r, err)
			return
		}
		in.Up = up
		res, err := Vote(r.Context(), h.d, id, r.PathValue("id"), in)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		doc.Tail(w, r, res.Line(), doc.GET("/v1/v/"+r.PathValue("id"), ""))
	}
}

func (h *handlers) retract(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := Retract(r.Context(), h.d, id, r.PathValue("id")); err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, "ok retracted", doc.POST("/v1/v", "post a corrected claim"))
}

// libKey resolves the {lib} segment (percent-decoded by the mux, suffix stripped) to a key.
func (h *handlers) libKey(w http.ResponseWriter, r *http.Request, seg string) (string, bool) {
	seg, _ = doc.SplitSuffix(seg)
	key, ok := ResolveLib(r.Context(), h.d.DB, seg)
	if !ok {
		if _, err := ParseKey(seg); err != nil && !strings.Contains(seg, ":") {
			// a bare name nobody aliased: record the gap, answer 404
			_, _, super := core.ClientFrom(r.Context())
			RecordMiss(r.Context(), h.d.DB, "q", seg, super, "")
		}
		doc.Fail(w, r, ErrNoEntries)
		return "", false
	}
	return key, true
}

func (h *handlers) libHub(w http.ResponseWriter, r *http.Request) {
	key, ok := h.libKey(w, r, r.PathValue("lib"))
	if !ok {
		return
	}
	d, err := LibHub(r.Context(), h.d.DB, key, r.URL.Query().Get("all") == "1")
	if err != nil {
		h.miss(w, r, err, key, "")
		return
	}
	doc.Reply(w, r, 200, d)
}

// miss answers an ErrNoEntries with the wanted record of lib@ver (13.2).
func (h *handlers) miss(w http.ResponseWriter, r *http.Request, err error, key, ver string) {
	if errors.Is(err, ErrNoEntries) && ver != "" {
		_, _, super := core.ClientFrom(r.Context())
		root := ""
		if id, _ := h.d.AuthOpt(r); id != nil {
			root = id.Root
		}
		RecordMiss(r.Context(), h.d.DB, "v", key+"@"+ver, super, root)
	}
	doc.Fail(w, r, err, doc.GET(LibPath(key, ""), "lib hub"), doc.POST("/v1/v", "post a claim"), doc.GET("/wanted", ""))
}

func (h *handlers) libVersion(w http.ResponseWriter, r *http.Request) {
	key, ok := h.libKey(w, r, r.PathValue("lib"))
	if !ok {
		return
	}
	seg, _ := doc.SplitSuffix(r.PathValue("ver"))
	qv := r.URL.Query()
	kinds := qv["kind"]
	all := qv.Get("all") == "1"
	if from, to, isRange := ParseRange(seg); isRange {
		d, err := LibRange(r.Context(), h.d.DB, key, from, to, kinds, qv.Get("full") == "1", all)
		if err != nil {
			h.miss(w, r, err, key, to)
			return
		}
		doc.Reply(w, r, 200, d)
		return
	}
	if strings.Contains(seg, "..") {
		doc.Fail(w, r, core.Bad("range must be <a>..<b> with parseable versions"))
		return
	}
	d, err := LibVersion(r.Context(), h.d.DB, key, seg, kinds, all)
	if err != nil {
		h.miss(w, r, err, key, seg)
		return
	}
	doc.Reply(w, r, 200, d)
}

func (h *handlers) since(w http.ResponseWriter, r *http.Request) {
	ym, _ := doc.SplitSuffix(r.PathValue("ym"))
	qv := r.URL.Query()
	d, err := Since(r.Context(), h.d.DB, ym, qv["libs"], min(parseK(qv.Get("k"), 50), 100), qv.Get("all") == "1")
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, d)
}

func (h *handlers) cutoff(w http.ResponseWriter, r *http.Request) {
	d, err := Cutoff(r.Context(), h.d.DB)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, d)
}

func (h *handlers) digestCreate(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in DigestInput
	if err := core.Decode(w, r, int64(MaxBody), &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	key := core.IdemKey(r.Header)
	if key == "" {
		key = in.Key
	}
	in.Key = ""
	h.idemWrite(w, r, id, key, "POST /v1/dg", in, func() (string, []doc.Action, error) {
		c, err := CreateDigest(r.Context(), h.d, id, in)
		if err != nil {
			return "", nil, err
		}
		return c.Line(), []doc.Action{doc.GET("/v1/dg/"+c.ID, ""), doc.POST("/v1/dg/"+c.ID+"/ok", "")}, nil
	})
}

func (h *handlers) digestSearch(w http.ResponseWriter, r *http.Request) {
	qv := r.URL.Query()
	lines, err := DigestSearch(r.Context(), h.d.DB, qv.Get("lib"), qv.Get("topic"), qv.Get("q"), min(parseK(qv.Get("k"), 10), 20))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d := &doc.Doc{Head: fmt.Sprintf("ds: digests=%d", len(lines)), NoIndex: true, Budget: 400}
	for _, l := range lines {
		d.Rows = append(d.Rows, []string{l.Text})
	}
	d.Next = []doc.Action{doc.POST("/v1/dg", "post a digest")}
	doc.Reply(w, r, 200, d)
}

func (h *handlers) digestGet(w http.ResponseWriter, r *http.Request) {
	did, _ := doc.SplitSuffix(r.PathValue("id"))
	g, err := GetDigest(r.Context(), h.d.DB, did, r.URL.Query().Get("all") == "1")
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, g.Doc())
}

func (h *handlers) digestVote(up bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := h.d.AuthWrite(r)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		var in struct {
			Why     string `json:"why"`
			Note    string `json:"note"`
			SrcHash string `json:"src_hash"`
			SrcLen  int    `json:"src_len"`
		}
		if err := core.Decode(w, r, 8<<10, &in); err != nil {
			doc.Fail(w, r, err)
			return
		}
		note := in.Why
		if up {
			note = in.Note
		}
		line, err := VoteDigest(r.Context(), h.d, id, r.PathValue("id"), up, note, in.SrcHash, in.SrcLen)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		doc.Tail(w, r, line, doc.GET("/v1/dg/"+r.PathValue("id"), ""))
	}
}

func (h *handlers) digestList(w http.ResponseWriter, r *http.Request) {
	key, ok := h.libKey(w, r, r.PathValue("lib"))
	if !ok {
		return
	}
	d, err := DigestList(r.Context(), h.d.DB, key)
	if err != nil {
		doc.Fail(w, r, err, doc.POST("/v1/dg", "post a digest"))
		return
	}
	doc.Reply(w, r, 200, d)
}

// digestPage dispatches GET /dg/{lib}/{x}/{topic}: x a version (best digest page) or a range
// (line diff; topic api = set diff).
func (h *handlers) digestPage(w http.ResponseWriter, r *http.Request) {
	key, ok := h.libKey(w, r, r.PathValue("lib"))
	if !ok {
		return
	}
	x := r.PathValue("x")
	topic, _ := doc.SplitSuffix(r.PathValue("topic"))
	topic = strings.ToLower(topic)
	var d *doc.Doc
	var err error
	if from, to, isRange := ParseRange(x); isRange {
		if topic == "api" {
			d, err = APIDiffDoc(r.Context(), h.d.DB, key, from, to)
		} else {
			d, err = DigestDiff(r.Context(), h.d.DB, key, from, to, topic)
		}
	} else {
		d, err = DigestPage(r.Context(), h.d.DB, key, x, topic)
	}
	if err != nil {
		doc.Fail(w, r, err, doc.POST("/v1/dg", "post a digest"), doc.GET("/dg/"+EncodeKey(key), "digests"))
		return
	}
	doc.Reply(w, r, 200, d)
}

func (h *handlers) wanted(w http.ResponseWriter, r *http.Request) {
	d, err := WantedDoc(r.Context(), h.d.DB, parseK(r.URL.Query().Get("k"), 50))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	w.Header().Set("X-Robots-Tag", "noindex")
	doc.Reply(w, r, 200, d)
}

// srchash serves the SPEC-v2 27.3 recipe. It is kept for reference but not mounted: the clients
// package owns GET /srchash.py (the zero-install helper surface, signed and listed in the manifest),
// so know does not register the route to avoid a duplicate-pattern panic on the shared mux.
func (h *handlers) srchash(w http.ResponseWriter, r *http.Request) {
	doc.ServeStatic(w, r, srchashMod, []byte(srchashPy), "text/x-python; charset=utf-8")
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/v":{"get":{"operationId":"vl","summary":"List claims (newest first; default status verified+unverified, all=1 adds disputed/quarantine)","parameters":[{"name":"lib","in":"query","schema":{"type":"string","maxLength":220}},{"name":"kind","in":"query","schema":{"type":"string"}},{"name":"k","in":"query","schema":{"type":"integer","maximum":100}},{"name":"all","in":"query","schema":{"type":"string","enum":["1"]}}],"responses":{"200":{"description":"one claim per line: <id> <status> <kind> <lib> <from>-><to> <title> src:<tier> sev<n>"}}},
"post":{"operationId":"cv","summary":"Post a post-cutoff claim about a library version (token; anonymous writers use POST /w/v with X-PoW)","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["lib","kind","title"],"properties":{"lib":{"type":"string","maxLength":220,"description":"eco:name key (pypi:requests, npm:@scope/pkg, go:github.com/x/y) or a known alias"},"kind":{"type":"string","enum":["breaking","new","deprecated","removed","renamed","default","security","release","eol","behavior"]},"v_from":{"type":"string","maxLength":100},"v_to":{"type":"string","maxLength":100},"effective":{"type":"string","maxLength":10,"description":"YYYY-MM-DD"},"title":{"type":"string","maxLength":160},"detail":{"type":"string","maxLength":2000},"migrate":{"type":"string","maxLength":1200},"scope":{"type":"string","enum":["","api","config","cli","behavior","build"]},"sev":{"type":"integer","minimum":0,"maximum":3},"source_url":{"type":"string","maxLength":400},"source_quote":{"type":"string","maxLength":300},"src_hash":{"type":"string","maxLength":64,"description":"sha256 of the normalised source (GET /srchash.py)"},"src_len":{"type":"integer"}}}}}},"responses":{"201":{"description":"ok v… unverified|quarantine [masked=…] [unknown-version] [filled wanted n=…]"},"409":{"description":"err dup v… <title>"},"429":{"description":"err quota"}}}},
"/w/v":{"post":{"operationId":"cvanon","summary":"Anonymous claim (X-PoW for=w): always quarantined until 2 L2 confirmations","responses":{"202":{"description":"ok v… quarantine"}}}},
"/v1/v/{id}":{"get":{"operationId":"vg","summary":"Read a claim (full text, 200-600 tokens)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},{"name":"all","in":"query","schema":{"type":"string","enum":["1"]}}],"responses":{"200":{"description":"claim text"},"404":{"description":"err notfound"},"410":{"description":"err gone expired"}}}},
"/v1/v/{id}/ok":{"post":{"operationId":"cok","summary":"Confirm a claim (weight by standing; refused for the author's network and cohort)","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"source_url":{"type":"string","maxLength":400},"note":{"type":"string","maxLength":200},"sev":{"type":"integer","minimum":0,"maximum":3},"src_hash":{"type":"string","maxLength":64},"src_len":{"type":"integer"}}}}}},"responses":{"200":{"description":"ok conf<w> <status> [promoted] [sources:agreed]"},"403":{"description":"err auth no self vote | same network as the author"},"409":{"description":"err dup already voted"}}}},
"/v1/v/{id}/bad":{"post":{"operationId":"cbad","summary":"Dispute a claim","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"why":{"type":"string","maxLength":200},"source_url":{"type":"string","maxLength":400}}}}}},"responses":{"200":{"description":"ok disp<w> <status>"}}}},
"/v1/v/{id}/retract":{"post":{"operationId":"cret","summary":"Retract your own claim","responses":{"200":{"description":"ok retracted"},"403":{"description":"err auth forbidden"}}}},
"/v/{lib}":{"get":{"summary":"Lib hub: versions, latest claims, KB fixes (lib key percent-encoded)","responses":{"200":{"description":"v: <lib> claims=N versions=N fixes=N + lines"},"404":{"description":"err notfound no entries yet; gap listed on /wanted"}}}},
"/v/{lib}/{ver}":{"get":{"summary":"Claims after a version, or a range a..b (?kind=breaking renders the ordered upgrade checklist, &full=1 adds migrate text)","parameters":[{"name":"kind","in":"query","schema":{"type":"string"}},{"name":"full","in":"query","schema":{"type":"string","enum":["1"]}},{"name":"all","in":"query","schema":{"type":"string","enum":["1"]}}],"responses":{"200":{"description":"lines"}}}},
"/since/{ym}":{"get":{"operationId":"since","summary":"Confirmed changes with effective date after YYYY-MM","parameters":[{"name":"libs","in":"query","schema":{"type":"string"}},{"name":"k","in":"query","schema":{"type":"integer","maximum":100}}],"responses":{"200":{"description":"<date> <claim line> per row"}}}},
"/cutoff":{"get":{"summary":"Release ladder: 15 latest confirmed releases across the top-20 libs (~120 tokens)","responses":{"200":{"description":"<date> <lib> <ver> per row"}}}},
"/v1/dg":{"get":{"operationId":"ds","summary":"Search digests","parameters":[{"name":"lib","in":"query","schema":{"type":"string"}},{"name":"topic","in":"query","schema":{"type":"string","maxLength":48}},{"name":"q","in":"query","schema":{"type":"string","maxLength":400}},{"name":"k","in":"query","schema":{"type":"integer","maximum":20}}],"responses":{"200":{"description":"d… <status> <lib> <v_from>..<v_to> <topic> tok=N ok=W"}}},
"post":{"operationId":"dp","summary":"Post a digest (<= 6 KiB; topic api = sorted declaration lines)","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["lib","topic","v_to","body"],"properties":{"lib":{"type":"string","maxLength":220},"topic":{"type":"string","maxLength":48},"v_from":{"type":"string","maxLength":100},"v_to":{"type":"string","maxLength":100},"body":{"type":"string","maxLength":6144},"source_url":{"type":"string","maxLength":400},"src_hash":{"type":"string","maxLength":64},"src_len":{"type":"integer"}}}}}},"responses":{"201":{"description":"ok d… tok=N"},"409":{"description":"err dup d…"}}}},
"/v1/dg/{id}":{"get":{"operationId":"dg","summary":"Read a digest","responses":{"200":{"description":"digest text"}}}},
"/v1/dg/{id}/ok":{"post":{"operationId":"dgok","summary":"Confirm a digest","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"note":{"type":"string","maxLength":200},"src_hash":{"type":"string","maxLength":64},"src_len":{"type":"integer"}}}}}},"responses":{"200":{"description":"ok ok<w> bad<w> <status>"}}}},
"/v1/dg/{id}/bad":{"post":{"operationId":"dgbad","summary":"Report a digest as wrong","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"why":{"type":"string","maxLength":200}}}}}},"responses":{"200":{"description":"ok ok<w> bad<w> <status> [hidden]"}}}},
"/dg/{lib}":{"get":{"summary":"Digests of a lib","responses":{"200":{"description":"lines"}}}},
"/dg/{lib}/{x}/{topic}":{"get":{"summary":"Best digest of a version/topic, the line diff of a range a..b, or the API set diff (topic api)","responses":{"200":{"description":"digest, diff or too different"}}}},
"/wanted":{"get":{"operationId":"wanted","summary":"Gaps agents asked for (noindex): <kind> <key> n= groups= last=","responses":{"200":{"description":"lines"}}}}
}}`)
