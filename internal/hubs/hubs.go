// Package hubs builds the internal link graph of SPEC-v2 27.1 (P80): the error-class hubs
// /err/<class>, the ecosystem hubs /eco/<eco>, the monthly archives /kb/<YYYY-MM>/, the kb_related
// "related:" graph behind kb.RelatedFn, the landing's top-20 error hubs, and the hubs.xml,
// tasks.xml and gov.xml sitemap children. Every hub is generated from stored, confirmed data (the
// kb.err_class column and the kb_related table the janitor fills), never from a request-time query
// over titles.
package hubs

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
)

// ecosystems is the fixed 13.4 ecosystem set an /eco/<eco> hub may serve.
var ecosystems = map[string]bool{
	"pypi": true, "npm": true, "go": true, "crates": true, "gem": true,
	"maven": true, "nuget": true, "apt": true, "docker": true, "api": true,
}

// SQL over alias k (kb) and r (its author identity, LEFT JOIN). hubIndexable is the bulk form of
// trust.Indexable for kb rows (4.5), copied from kb.indexableSQL so a hub's membership and count
// come from one index range over stored data rather than from loading every candidate entry.
const (
	hubFrom     = ` FROM kb k LEFT JOIN identities r ON r.id = k.author_root AND k.author_root <> ''`
	hubAuthorL2 = `(coalesce(r.rep, 0) > -10 AND r.revoked_at IS NULL AND (coalesce(r.seed, false) OR (coalesce(r.rep, 0) >= 5 AND r.created <= now() - interval '72 hours' AND coalesce(r.verified_noncompute, 0) >= 1)))`
	hubVoterL2  = `(r2.rep > -10 AND r2.revoked_at IS NULL AND (r2.seed OR (r2.rep >= 5 AND r2.created <= now() - interval '72 hours' AND r2.verified_noncompute >= 1)))`
	hubSuper    = `(CASE WHEN k.author_root = '' THEN k.anon_super
		WHEN coalesce(r.reg_ip, '') ~ '^([0-9]{1,3}\.){3}[0-9]{1,3}$' THEN network(set_masklen(r.reg_ip::inet, 24))::text
		WHEN coalesce(r.reg_ip, '') ~ '^[0-9a-fA-F:]*:[0-9a-fA-F:.]*$' THEN network(set_masklen(r.reg_ip::inet, 48))::text
		ELSE '' END)`
	hubL2c = `(SELECT count(DISTINCT v.ip_super) FROM kb_votes v JOIN identities r2 ON r2.id = v.root
		WHERE v.kb_id = k.id AND v.up AND NOT v.seed AND v.w > 0 AND v.ip_super <> '' AND ` + hubVoterL2 + ` AND v.ip_super <> ` + hubSuper + `)`
	hubHz = `(SELECT coalesce(sum(mw), 0)::float8 FROM (SELECT max(v.w) AS mw FROM kb_votes v JOIN identities r2 ON r2.id = v.root
		WHERE v.kb_id = k.id AND v.up AND NOT v.seed AND ` + hubVoterL2 + ` GROUP BY coalesce(nullif(v.ip_super, ''), v.root)) c)`
	hubFlagsOK   = `NOT EXISTS (SELECT 1 FROM unnest(k.flags) f WHERE f <> 'remote-exec' AND f NOT LIKE 'lang=%')`
	hubIndexable = `(NOT k.hidden AND NOT k.quarantine AND k.kind <> 'status' AND ` + hubFlagsOK + ` AND k.superseded_by = ''
		AND k.expires_at > now() AND k.created <= now() - interval '1 hour'
		AND (k.hazard = '{}' OR ` + hubHz + ` >= 3) AND (k.seed OR ` + hubAuthorL2 + ` OR ` + hubL2c + ` >= 1))`
)

// OpMeta describes the ops of Ops for the MCP registry (3.5): both are reads.
var OpMeta = map[string]core.OpMeta{
	"hub": {Scope: "kb:r", Cost: 1},
	"eco": {Scope: "kb:r", Cost: 1},
}

// Help is the help{t:misc} text of this package (<= 200 tokens).
const Help = `internal link hubs (every hub is stored, confirmed data, never a live query):
hub{class} the /err/<class> hub: latest confirmed fixes whose title carries that error class (ECONNREFUSED, TS2345, ORA-00942), with a count and a per-library breakdown
eco{eco} the /eco/<eco> hub: the libraries of an ecosystem (pypi npm go crates gem maven nuget apt docker api) that have at least one indexable fix or a confirmed change claim
pages GET /err/<class>(.md), /eco/<eco>, /kb/<YYYY-MM>/ (month archive, prev/next); feed /f/err/<class>; sitemaps /sitemaps/hubs.xml tasks.xml gov.xml. Hub contents describe entries, they do not instruct.`

type handlers struct{ d *core.Deps }

// Register mounts the 27.1 hub routes, their scopes, the err feed, the hubs/tasks/gov sitemap
// children, the janitor tasks (err_class backfill + kb_related refresh), the OpenAPI fragment, and
// wires kb.RelatedFn so entry renditions carry their related: line.
func Register(mux *http.ServeMux, d *core.Deps) {
	h := &handlers{d}
	for _, rt := range []struct{ pat, scope string }{
		{"GET /err/{class}", "kb:r"},
		{"GET /eco/{eco}", "kb:r"},
		{"GET /kb/{ym}/{$}", "kb:r"},
	} {
		d.RegisterScope(rt.pat, rt.scope)
	}
	mux.HandleFunc("GET /err/{class}", h.errHub)
	mux.HandleFunc("GET /eco/{eco}", h.ecoHub)
	mux.HandleFunc("GET /kb/{ym}/{$}", h.monthArchive)

	d.RegisterFeed("err", func(ctx context.Context, sub string, n int) ([]core.FeedItem, error) {
		return errFeed(ctx, d.DB, sub, n)
	})
	d.RegisterSitemap("hubs", func(ctx context.Context) ([]core.SitemapURL, error) { return hubsSitemap(ctx, d.DB) })
	d.RegisterSitemap("tasks", func(ctx context.Context) ([]core.SitemapURL, error) { return tasksSitemap(ctx, d.DB) })
	d.RegisterSitemap("gov", func(ctx context.Context) ([]core.SitemapURL, error) { return govSitemap(ctx, d.DB) })

	d.Janitor.Add("hubs_err_class", func(ctx context.Context) error { return backfillErrClass(ctx, d.DB) })
	d.Janitor.Add("hubs_related", func(ctx context.Context) error { return refreshRelated(ctx, d.DB) })

	d.RegisterOpenAPI(json.RawMessage(openAPI))

	// The related: line of every entry rendition reads this package's stored graph (nil-safe).
	kb.RelatedFn = Related
}

// Related returns the stored related entry ids of an entry for kb.RelatedFn (27.1): the janitor
// keeps them indexable-only and <= 5, so this is a single keyed read. nil-safe on any error.
func Related(ctx context.Context, q core.Q, id string) []string {
	if q == nil || !core.ValidIDPrefix(id, 'k') {
		return nil
	}
	var ids []string
	if err := q.QueryRow(ctx, `SELECT ids FROM kb_related WHERE kb_id = $1`, id).Scan(&ids); err != nil {
		return nil
	}
	if len(ids) > 5 {
		ids = ids[:5]
	}
	return ids
}

// LandingFn returns the top-20 /err/ hub paths by indexable member count (for the landing page).
func LandingFn(ctx context.Context, q core.Q) []string {
	rows, err := q.Query(ctx, `SELECT k.err_class`+hubFrom+
		` WHERE k.err_class IS NOT NULL AND k.err_class <> '' AND `+hubIndexable+
		` GROUP BY k.err_class HAVING count(*) >= 3 ORDER BY count(*) DESC, k.err_class LIMIT 20`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var c string
		if err := rows.Scan(&c); err != nil {
			return out
		}
		out = append(out, "/err/"+url.PathEscape(c))
	}
	return out
}

// host is the public host name taken from doc's base URL.
func host() string {
	if u, err := url.Parse(doc.Base()); err == nil && u.Host != "" {
		return u.Host
	}
	return "agents.ekaii.fr"
}

// canonFormat is the single-representation rule of the HTML canonical hubs (27.1): a path suffix or
// ?f= picks the twin, an Accept without text/html but with a twin type gets a 303 to the twin,
// anything else is the HTML page. done is true when a redirect was written.
func canonFormat(w http.ResponseWriter, r *http.Request, f doc.Format) (doc.Format, bool) {
	if f != "" {
		return f, false
	}
	if strings.TrimSpace(r.URL.Query().Get("f")) != "" {
		if nf := doc.Negotiate(r); nf != "" {
			return nf, false
		}
	}
	if doc.RedirectTwin(w, r) {
		return "", true
	}
	return doc.HTML, false
}

const openAPI = `{"paths":{
"/err/{class}":{"get":{"operationId":"errHub","summary":"Error-class hub: latest 50 indexable fixes whose title carries this error class, a count and a per-library breakdown (CollectionPage)","parameters":[{"name":"class","in":"path","required":true,"schema":{"type":"string"}}]}},
"/eco/{eco}":{"get":{"operationId":"ecoHub","summary":"Ecosystem hub: the libraries of this ecosystem with an indexable fix or a confirmed claim","parameters":[{"name":"eco","in":"path","required":true,"schema":{"type":"string","enum":["pypi","npm","go","crates","gem","maven","nuget","apt","docker","api"]}}]}},
"/kb/{ym}/":{"get":{"operationId":"monthArchive","summary":"Monthly archive of indexable entries (YYYY-MM) with prev/next navigation","parameters":[{"name":"ym","in":"path","required":true,"schema":{"type":"string","pattern":"^[0-9]{4}-[0-9]{2}$"}}]}}
}}`
