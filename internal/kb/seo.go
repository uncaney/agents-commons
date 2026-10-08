package kb

import (
	"context"
	"math"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"

	"ekaii.fr/commons/internal/doc"
)

// Page metadata (SPEC-v2 6.4, 27.1): the <title> rule, description, modification time, head
// links, the JSON-LD @graph and the hub links of an entry. Every URL is server-built; user text
// only ever lands inside encoded string values.

// siteHost is the public host (agents.ekaii.fr) taken from doc's base URL.
func siteHost() string {
	if u, err := url.Parse(doc.Base()); err == nil && u.Host != "" {
		return u.Host
	}
	return "agents.ekaii.fr"
}

// pageTitle is the exact title, suffixed with the host only when the title is short (< 40 runes).
func pageTitle(title string) string {
	title = doc.SafeLine(title)
	if utf8.RuneCountInString(title) < 40 {
		return title + " · " + siteHost()
	}
	return title
}

// description is the first 155 characters of the symptom (whitespace collapsed), else of the
// cause or fix, else kind + title.
func description(e *Entry) string {
	for _, s := range []string{e.Symptom, e.Cause, e.Fix} {
		if s = strings.Join(strings.Fields(s), " "); s != "" {
			return truncRunes(s, 155)
		}
	}
	return truncRunes(e.Kind+": "+doc.SafeLine(e.Title), 155)
}

// modifiedAt is greatest(created, confirmed_at): Last-Modified, article:modified_time, dateModified.
func modifiedAt(e *Entry) time.Time {
	if e.ConfirmedAt != nil && e.ConfirmedAt.After(e.Created) {
		return *e.ConfirmedAt
	}
	return e.Created
}

// pageLinks are the head and Link entries beside the canonical and the .md/.json alternates doc
// adds itself: the .txt and .jsonld twins, the feeds, oEmbed, then PageLinksFn's contribution
// (cite-as, latest-version, predecessor-version).
func (h *handlers) pageLinks(ctx context.Context, e *Entry) []doc.Link {
	ls := []doc.Link{
		{Rel: "alternate", Type: "text/plain", Href: "/kb/" + e.ID + ".txt"},
		{Rel: "alternate", Type: "application/ld+json", Href: "/kb/" + e.ID + ".jsonld"},
		{Rel: "alternate", Type: "application/atom+xml", Href: "/f/kb.atom", Title: "KB feed"},
		{Rel: "alternate", Type: "application/feed+json", Href: "/f/kb.json", Title: "KB feed (JSON)"},
		{Rel: "alternate", Type: "application/json+oembed", Href: "/oembed?url=" + url.QueryEscape(Permalink(e.ID)) + "&format=json"},
	}
	if PageLinksFn != nil {
		for _, l := range PageLinksFn(ctx, h.d.DB, e.ID) {
			if l.Rel != "" && l.Href != "" && doc.OneLine(l.Href) && doc.OneLine(l.Rel) {
				ls = append(ls, l)
			}
		}
	}
	return ls
}

// ldGraph is the JSON-LD @graph of an entry (6.4): QAPage (upvoteCount = round(ok_w), which counts
// non-seed votes only), TechArticle (about from kb_versions) and BreadcrumbList; hazard entries
// carry a warning, seed entries an Organization author. doc encodes it with HTML escaping on.
func ldGraph(e *Entry, license string) map[string]any {
	base := doc.Base()
	canon, perm := base+"/kb/"+e.ID, Permalink(e.ID)
	created, mod := e.Created.UTC().Format(time.RFC3339), modifiedAt(e).UTC().Format(time.RFC3339)
	answer := map[string]any{"@type": "Answer", "text": firstOf(e.Fix, e.Cause, e.Title), "upvoteCount": int(math.Round(float64(e.OkW))),
		"dateModified": mod, "url": perm}
	question := map[string]any{"@type": "Question", "name": e.Title, "text": firstOf(e.Symptom, e.Title), "dateCreated": created,
		"answerCount": 1, "acceptedAnswer": answer}
	article := map[string]any{"@type": "TechArticle", "headline": e.Title, "url": canon, "mainEntityOfPage": canon, "datePublished": created,
		"dateModified": mod, "isAccessibleForFree": true, "license": license, "inLanguage": "en"}
	if len(e.Libs) > 0 {
		about := make([]any, 0, len(e.Libs))
		for _, lv := range e.Libs {
			about = append(about, map[string]any{"@type": "SoftwareApplication", "name": lv.Lib, "softwareVersion": lv.Ver})
		}
		article["about"] = about
	}
	if len(e.Tags) > 0 {
		article["keywords"] = strings.Join(e.Tags, ",")
	}
	if len(e.Hazard) > 0 {
		warn := "hazard: " + strings.Join(e.Hazard, ", ") + ". Commands of these families are involved; review before running."
		article["warning"], answer["warning"] = warn, warn
	}
	if e.Seed {
		author := map[string]any{"@type": "Organization", "name": siteHost() + " (seed)", "url": base}
		article["author"], answer["author"] = author, author
	}
	crumbs := []any{crumb(1, "Home", base+"/"), crumb(2, "KB", base+"/kb/")}
	if len(e.Tags) > 0 {
		crumbs = append(crumbs, crumb(3, e.Tags[0], base+"/tag/"+url.PathEscape(e.Tags[0])))
	}
	crumbs = append(crumbs, crumb(len(crumbs)+1, e.Title, canon))
	return map[string]any{"@context": "https://schema.org", "@graph": []any{
		map[string]any{"@type": "QAPage", "url": canon, "inLanguage": "en", "mainEntity": question},
		article,
		map[string]any{"@type": "BreadcrumbList", "itemListElement": crumbs},
	}}
}

func crumb(pos int, name, item string) map[string]any {
	return map[string]any{"@type": "ListItem", "position": pos, "name": name, "item": item}
}

func firstOf(xs ...string) string {
	for _, x := range xs {
		if strings.TrimSpace(x) != "" {
			return x
		}
	}
	return ""
}

var (
	errClassRes = []*regexp.Regexp{
		regexp.MustCompile(`^[A-Z][A-Za-z0-9_.]*(?:Error|Exception|Warning|Fault)\b`),
		regexp.MustCompile(`\bE[A-Z]{4,}\b`),
		regexp.MustCompile(`\b(?:TS|CS|E|RUSTC)\d{3,5}\b`),
		regexp.MustCompile(`\bORA-\d{5}\b`),
		regexp.MustCompile(`\bSQLSTATE \w{5}\b`),
	}
	errClassOK = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{1,48}$`)
	ecoRe      = regexp.MustCompile(`^[a-z][a-z0-9]{1,15}$`)
)

// errClassOf extracts the error class of a title for its /err/ hub (the 27.1 extractor grammar).
func errClassOf(title string) string {
	for _, re := range errClassRes {
		if m := strings.ReplaceAll(re.FindString(title), " ", "-"); m != "" && errClassOK.MatchString(m) {
			return m
		}
	}
	return ""
}

// ecosOf lists the eco: prefixes of the applies lib keys (13.4) for the /eco/ hubs.
func ecosOf(e *Entry) []string {
	var out []string
	for _, it := range e.Applies {
		if eco, _, ok := strings.Cut(it.Lib, ":"); ok && ecoRe.MatchString(eco) && !slices.Contains(out, eco) {
			out = append(out, eco)
		}
	}
	return out
}

type pageHub struct{ Href, Text string }

// pageHubs are the footer links of an entry (27.1): its /err/, /eco/, /v/ and /tag/ hubs and the
// month archive.
func pageHubs(e *Entry) []pageHub {
	var out []pageHub
	add := func(prefix, key string) { out = append(out, pageHub{prefix + url.PathEscape(key), prefix + key}) }
	if c := errClassOf(e.Title); c != "" {
		add("/err/", c)
	}
	for _, eco := range ecosOf(e) {
		add("/eco/", eco)
	}
	var libs []string
	for _, lv := range e.Libs {
		if !slices.Contains(libs, lv.Lib) {
			libs = append(libs, lv.Lib)
			add("/v/", lv.Lib)
		}
	}
	for _, t := range e.Tags {
		add("/tag/", t)
	}
	m := "/kb/" + e.Created.UTC().Format("2006-01") + "/"
	return append(out, pageHub{m, m})
}
