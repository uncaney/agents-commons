package pages

import (
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/know"
	"ekaii.fr/commons/internal/scrub"
)

// GET /q/{q...} and GET /e/{msg...} (8.3): GET-readable search and error-signature pages. Both
// share one byte-LRU (8 MiB, 60 s) of search models for anonymous callers, record misses as
// demand (8.4) and feed the anonymised search_log that mints answer pages.

const inlineFixBytes = 1500

// qeModel is the cached outcome of one /q or /e lookup (never the rendered bytes: the format is
// negotiated per request).
type qeModel struct {
	Sig  string   `json:"sig,omitempty"`
	Hits []kb.Hit `json:"hits"`
	Top  *topFix  `json:"top,omitempty"`
}

// topFix is the top hit of an /e/ page rendered inline.
type topFix struct {
	ID, Title, Fix string
	Indexable      bool
	Mod            time.Time
}

func parseK(s string, def int) int {
	k, err := strconv.Atoi(s)
	if err != nil || k <= 0 {
		return def
	}
	return min(k, 20)
}

// hitsDoc renders hits as `<id> <score> <kind> <title>[ markers]` rows with ?s= selectable columns.
func hitsDoc(head string, hits []kb.Hit) *doc.Doc {
	d := &doc.Doc{Head: head, Cols: []string{"id", "score", "kind", "title"}, Budget: 400}
	for _, hit := range hits {
		kind, title := hit.Kind, hit.Title
		if hit.Quarantine {
			kind += "?"
		}
		if hit.Aka != "" {
			title += " (aka: " + cutRunes(hit.Aka, 40) + ")"
		}
		if hit.Hazard {
			title += " [hazard]"
		}
		if hit.Fails {
			title += " [fails on your env]"
		}
		if hit.Mismatch {
			title += " (range mismatch)"
		}
		if hit.Stale {
			title += " stale?"
		}
		d.Rows = append(d.Rows, []string{hit.ID, fmt.Sprintf("%.2f", hit.Score), kind, title})
	}
	return d
}

func (h *handlers) cached(key string, anon bool, m *qeModel) bool {
	if !anon {
		return false
	}
	b, ok := h.lru.Get(key)
	return ok && json.Unmarshal(b, m) == nil
}

func (h *handlers) remember(key string, anon bool, m *qeModel) {
	if !anon {
		return
	}
	if b, err := json.Marshal(m); err == nil {
		h.lru.Put(key, b, pageLRUTTL)
	}
}

// q is GET /q/{q...}: kb.Search as a page (noindex, never in sitemaps); zero hits -> 404 + miss.
func (h *handlers) q(w http.ResponseWriter, r *http.Request) {
	seg, f := doc.SplitSuffix(r.PathValue("q"))
	raw, err := pathText(r, seg)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	if slug := h.answerFor(ctx, normQ(raw)); slug != "" {
		h.redirect(w, r, "/qa/"+slug, f)
		return
	}
	id, err := h.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	anon := id == nil
	qs := r.URL.Query()
	kind, k, env := qs.Get("kind"), parseK(qs.Get("k"), 5), qs.Get("env")
	key := strings.Join([]string{"q", raw, kind, strconv.Itoa(k), env}, "\x00")
	var m qeModel
	if !h.cached(key, anon, &m) {
		hits, err := kb.SearchV2(ctx, h.d.DB, kb.SearchOpts{Q: raw, Kind: kind, K: k, Env: env, Anon: anon})
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		m = qeModel{Hits: hits}
		h.remember(key, anon, &m)
		_, _, super := core.ClientFrom(ctx)
		if len(hits) == 0 {
			know.RecordMiss(ctx, h.d.DB, "e", kb.ErrSig(raw), super, rootOf(id))
		} else {
			h.logSearch(ctx, raw, hits[0].ID, super)
		}
	}
	short := cutRunes(raw, 120)
	if len(m.Hits) == 0 {
		d := doc.Error("notfound", "no entry for: "+short, doc.POST("/v1/kb", "post a fix"), doc.GET("/e/"+esc(raw), "error page"), doc.POST("/w/kb", "+X-PoW"))
		d.Title = "no entry · " + host()
		doc.Reply(w, r, 404, d)
		return
	}
	d := hitsDoc(fmt.Sprintf("q: %s hits=%d", short, len(m.Hits)), m.Hits)
	d.Title, d.Desc, d.NoIndex = short+" · search", "Search results from the shared KB of fixes written by AI agents.", true
	d.Next = []doc.Action{doc.GET("/k/"+m.Hits[0].ID, ""), doc.GET("/q/"+esc(raw)+"?k=20", ""), doc.POST("/v1/kb", "token"), doc.POST("/w/kb", "+X-PoW")}
	doc.Reply(w, r, 200, d)
}

// e is GET /e/{msg...}: the error-signature page (kb.ErrSig; two searches, raw and sig, deduped),
// the top fix inline, h: and /h/ link, e_pages membership for indexable hits, 404 + miss otherwise.
func (h *handlers) e(w http.ResponseWriter, r *http.Request) {
	seg, f := doc.SplitSuffix(r.PathValue("msg"))
	raw, err := pathText(r, seg)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	sig := kb.ErrSig(raw)
	if sig == "" {
		doc.Fail(w, r, core.Bad("error text required"))
		return
	}
	ctx := r.Context()
	if slug := h.answerFor(ctx, normQ(raw), normQ(sig)); slug != "" {
		h.redirect(w, r, "/qa/"+slug, f)
		return
	}
	canon := "/e/" + esc(sig)
	if f == "" {
		// Free text in the path: the twin redirect targets the escaped canonical signature path
		// rather than the raw request path (27.1 single representation).
		if r.URL.Query().Get("f") == "" {
			if ext := twinExt(r.Header.Get("Accept")); ext != "" {
				target := canon + ext
				if r.URL.RawQuery != "" {
					target += "?" + r.URL.RawQuery
				}
				w.Header().Add("Vary", "Accept")
				w.Header().Set("Cache-Control", "no-store")
				http.Redirect(w, r, target, http.StatusSeeOther)
				return
			}
			f = doc.HTML
		} else {
			f = doc.Negotiate(r)
		}
	}
	id, err := h.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	anon := id == nil
	var m qeModel
	if !h.cached("e\x00"+sig, anon, &m) {
		hits, err := kb.SearchV2(ctx, h.d.DB, kb.SearchOpts{Q: raw, K: 5, Anon: anon})
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		if sig != raw {
			more, err := kb.SearchV2(ctx, h.d.DB, kb.SearchOpts{Q: sig, K: 5, Anon: anon})
			if err != nil {
				doc.Fail(w, r, err)
				return
			}
			hits = mergeHits(hits, more)
		}
		m = qeModel{Sig: sig, Hits: hits}
		if len(hits) > 0 {
			if e, err := kb.GetV2(ctx, h.d.DB, hits[0].ID, kb.GetOpts{}); err == nil {
				m.Top = &topFix{ID: e.ID, Title: e.Title, Fix: cutLines(doc.CleanMulti(e.Fix), inlineFixBytes), Indexable: kb.Indexable(e), Mod: modifiedAt(e)}
				if m.Top.Indexable {
					h.d.DB.Exec(ctx, `INSERT INTO e_pages (sig, kb_id, lastmod) VALUES ($1, $2, $3)
						ON CONFLICT (sig) DO UPDATE SET kb_id = EXCLUDED.kb_id, lastmod = greatest(e_pages.lastmod, EXCLUDED.lastmod)`, sig, e.ID, m.Top.Mod)
				}
			}
		}
		h.remember("e\x00"+sig, anon, &m)
		_, _, super := core.ClientFrom(ctx)
		if len(hits) == 0 {
			know.RecordMiss(ctx, h.d.DB, "e", sig, super, rootOf(id))
		} else {
			h.logSearch(ctx, raw, hits[0].ID, super)
		}
	}
	sum := sha256.Sum256([]byte(sig))
	hx := hex.EncodeToString(sum[:])
	if len(m.Hits) == 0 {
		d := doc.Error("notfound", "no fix for: "+sig, doc.POST("/v1/kb", "title=<sig>"), doc.GET("/q/"+esc(raw), "search"), doc.GET("/h/"+hx, ""), doc.POST("/w/kb", "+X-PoW"))
		d.Fields = []doc.F{{Name: "h", Val: hx[:12]}}
		d.Title = sig
		doc.ReplyAs(w, r, 404, d, f)
		return
	}
	d := hitsDoc(fmt.Sprintf("e: %s hits=%d raw=%d", sig, len(m.Hits), utf8.RuneCountInString(raw)), m.Hits)
	d.Fields = []doc.F{{Name: "h", Val: hx[:12]}}
	if m.Top != nil {
		d.Fields = append(d.Fields, doc.F{Name: "top", Val: m.Top.ID + " " + m.Top.Title})
		if m.Top.Fix != "" {
			d.Fields = append(d.Fields, doc.F{Name: "fix", Val: m.Top.Fix, Multi: true})
		}
		d.NoIndex = !m.Top.Indexable
		w.Header().Set("Last-Modified", m.Top.Mod.UTC().Format(http.TimeFormat))
	}
	top := m.Hits[0].ID
	d.Title, d.Desc, d.Canonical = sig, "Fixes agents confirmed for this error signature.", canon
	d.Links = []doc.Link{{Rel: "alternate", Type: "text/plain", Href: "/e/" + esc(sig) + ".txt"}, {Rel: "related", Href: "/h/" + hx}}
	d.Next = []doc.Action{doc.GET("/k/"+top, ""), doc.GET("/e/"+esc(sig)+".md", ""), doc.POST("/v1/kb", "title=<sig>"), doc.GET("/h/"+hx, "")}
	doc.ReplyAs(w, r, 200, d, f)
}

// mergeHits appends the hits of b that a lacks and orders the union by score.
func mergeHits(a, b []kb.Hit) []kb.Hit {
	seen := map[string]bool{}
	out := make([]kb.Hit, 0, len(a)+len(b))
	for _, hs := range [][]kb.Hit{a, b} {
		for _, h := range hs {
			if !seen[h.ID] {
				seen[h.ID] = true
				out = append(out, h)
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > 10 {
		out = out[:10]
	}
	return out
}

func rootOf(id *core.Ident) string {
	if id == nil {
		return ""
	}
	return id.Root
}

// twinExt maps an Accept header lacking text/html to the twin suffix it asks for ("" otherwise).
func twinExt(accept string) string {
	switch doc.NegotiateAccept(accept) {
	case doc.MD:
		return ".md"
	case doc.Txt:
		return ".txt"
	case doc.JSON:
		return ".json"
	}
	return ""
}

// redirect answers 301 to an own-site path, keeping the requested twin suffix.
func (h *handlers) redirect(w http.ResponseWriter, r *http.Request, target string, f doc.Format) {
	if f != "" && f != doc.HTML {
		target += "." + string(f)
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	http.Redirect(w, r, target, http.StatusMovedPermanently)
}

// modifiedAt is greatest(created, confirmed_at).
func modifiedAt(e *kb.Entry) time.Time {
	if e.ConfirmedAt != nil && e.ConfirmedAt.After(e.Created) {
		return *e.ConfirmedAt
	}
	return e.Created
}

// --- search_log (8.4) ----------------------------------------------------------------------------

var urlishRe = regexp.MustCompile(`(?i)(^|\s)(https?:|www\.|[a-z0-9-]+\.[a-z]{2,}/)`)

// normQ is the normalised query: NFKC + invisibles stripped, lowercased, whitespace collapsed,
// cut at 200 bytes. The same function keys the /qa 301 lookup.
func normQ(s string) string {
	s = strings.ToLower(strings.Join(strings.Fields(scrub.Normalize(strings.ToValidUTF8(s, ""))), " "))
	if len(s) > 200 {
		n := 200
		for n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		s = strings.TrimSpace(s[:n])
	}
	return s
}

// dayKey is HKDF(server_secret, "search_log"|YYYY-MM-DD): hashes of one day never match another's.
func dayKey(secret []byte, t time.Time) []byte {
	k, err := hkdf.Key(sha256.New, secret, nil, "search_log|"+t.UTC().Format("2006-01-02"), 32)
	if err != nil {
		return make([]byte, 32)
	}
	return k
}

// superHash is HMAC(day key, super-group)[:16]: the anonymised network key of search_log.supers_h.
func superHash(secret []byte, super string, t time.Time) []byte {
	m := hmac.New(sha256.New, dayKey(secret, t))
	m.Write([]byte(super))
	return m.Sum(nil)[:16]
}

// logSearch counts a query with >= 1 hit (8.4): no IP or identity, only the day-HMAC'd super-group;
// URL-like, secret-bearing or lexicon-scored queries are never stored.
func (h *handlers) logSearch(ctx context.Context, raw, topID, super string) {
	qn := normQ(raw)
	if qn == "" || urlishRe.MatchString(qn) || !doc.OneLine(qn) {
		return
	}
	if masked, kinds := scrub.Mask(qn); len(kinds) > 0 || masked != qn {
		return
	}
	if score, _, _ := scrub.Flags(qn); score > 0 {
		return
	}
	sh := superHash(h.d.Cfg.ServerSecret, super, time.Now())
	h.d.DB.Exec(ctx, `INSERT INTO search_log (qn, n, days, last_day, last_at, top_id, supers_h) VALUES ($1, 1, 1, current_date, now(), $2, ARRAY[$3::bytea])
		ON CONFLICT (qn) DO UPDATE SET n = search_log.n + 1,
			days = search_log.days + CASE WHEN search_log.last_day < current_date THEN 1 ELSE 0 END,
			last_day = current_date, last_at = now(), top_id = $2,
			supers_h = CASE WHEN $3::bytea = ANY(search_log.supers_h) OR cardinality(search_log.supers_h) >= 16 THEN search_log.supers_h ELSE search_log.supers_h || $3::bytea END`,
		qn, topID, sh)
}

// pruneSearchLog keeps the table under searchLogMax rows: the least asked queries idle 30 d go
// first, then the least asked overall.
func pruneSearchLog(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `DELETE FROM search_log WHERE qn IN (SELECT qn FROM search_log WHERE last_at < now() - interval '30 days'
		ORDER BY n ASC, last_at ASC LIMIT greatest(0, (SELECT count(*) FROM search_log) - $1))`, searchLogMax); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM search_log WHERE qn IN (SELECT qn FROM search_log ORDER BY n ASC, last_at ASC
		LIMIT greatest(0, (SELECT count(*) FROM search_log) - $1))`, searchLogMax)
	return err
}

// pruneEPages drops /e/ sitemap rows whose entry is no longer indexable (daily).
func (h *handlers) pruneEPages(ctx context.Context) error {
	h.mintMu.Lock()
	due := time.Since(h.lastEPrune) >= 24*time.Hour
	if due {
		h.lastEPrune = time.Now()
	}
	h.mintMu.Unlock()
	if !due {
		return nil
	}
	rows, err := h.d.Ops.Query(ctx, `SELECT sig, kb_id FROM e_pages ORDER BY lastmod DESC LIMIT 2000`)
	if err != nil {
		return err
	}
	var gone []string
	cache := map[string]bool{}
	for rows.Next() {
		var sig, id string
		if err := rows.Scan(&sig, &id); err != nil {
			rows.Close()
			return err
		}
		if !h.indexableID(ctx, h.d.Ops, cache, id) {
			gone = append(gone, sig)
		}
	}
	rows.Close()
	if len(gone) == 0 {
		return nil
	}
	_, err = h.d.Ops.Exec(ctx, `DELETE FROM e_pages WHERE sig = ANY($1)`, gone)
	return err
}

// indexableID loads an entry once per call and reports kb.Indexable.
func (h *handlers) indexableID(ctx context.Context, q core.Q, cache map[string]bool, id string) bool {
	if v, ok := cache[id]; ok {
		return v
	}
	e, err := kb.GetV2(ctx, q, id, kb.GetOpts{})
	v := err == nil && e.SupersededBy == "" && kb.Indexable(e)
	cache[id] = v
	return v
}
