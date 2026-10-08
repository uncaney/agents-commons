package kb

import (
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// The v1 HTML shell moved to doc (SPEC-v2 2); CSP, Page and Status stay as thin wrappers so web
// keeps compiling. kb's own handlers call doc.Layout / doc.ReplyAs with the request at hand.

// CSP returns the strict Content-Security-Policy for HTML pages (doc.CSP).
func CSP(cfg *core.Config) string { return doc.CSP(cfg) }

// Page writes a full HTML page in the shared shell. body must already be safe HTML (rendered
// through html/template). A Cache-Control the caller set beforehand is kept.
func Page(w http.ResponseWriter, d *core.Deps, title, desc string, body template.HTML) {
	Status(w, d, 200, title, desc, body)
}

// Status is Page with an explicit HTTP status. The shell reads the site (base URL, Umami) from
// doc; when nothing configured doc for this Deps yet, its config is installed first, as v1 did.
func Status(w http.ResponseWriter, d *core.Deps, status int, title, desc string, body template.HTML) {
	syncSite(d)
	r := &http.Request{Method: http.MethodGet, URL: &url.URL{Path: "/"}, Header: http.Header{}}
	doc.Layout(keepCache{w, w.Header().Get("Cache-Control")}, r, status, doc.Page{Title: title, Desc: desc, Body: body})
}

func syncSite(d *core.Deps) {
	base := strings.TrimRight(d.Cfg.PublicURL, "/")
	if base == "" {
		return
	}
	if s := doc.CurrentSite(); s.Base != base || s.UmamiSrc != d.Cfg.UmamiSrc || s.UmamiID != d.Cfg.UmamiID {
		doc.Configure(&d.Cfg)
	}
}

// keepCache restores the caller's Cache-Control over the doc default when the status is written.
type keepCache struct {
	http.ResponseWriter
	cc string
}

func (k keepCache) WriteHeader(status int) {
	if k.cc != "" {
		k.Header().Set("Cache-Control", k.cc)
	}
	k.ResponseWriter.WriteHeader(status)
}
