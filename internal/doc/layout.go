package doc

import (
	"bytes"
	"encoding/json"
	"html/template"
	"net/http"
	"net/url"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// layoutTmpl is the shared HTML shell (v1 kb shell: tiny inline CSS, light/dark, no JS except the
// optional Umami tag). Every value is escaped by html/template; LD is pre-encoded JSON.
var layoutTmpl = template.Must(template.New("layout").Parse(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{{.Title}}</title>
{{if .Desc}}<meta name="description" content="{{.Desc}}">
{{end}}<meta name="robots" content="{{.Robots}}">
{{if .Canonical}}<link rel="canonical" href="{{.Canonical}}">
{{end}}{{range .Links}}<link rel="{{.Rel}}" href="{{.Href}}"{{if .Type}} type="{{.Type}}"{{end}}{{if .Title}} title="{{.Title}}"{{end}}>
{{end}}<link rel="license" href="{{.License}}">
<style>
:root{--bg:#fff;--fg:#1a1a1a;--mute:#666;--line:#ddd;--pre:#f4f4f4;--link:#0645ad}
@media(prefers-color-scheme:dark){:root{--bg:#121212;--fg:#e6e6e6;--mute:#999;--line:#333;--pre:#1e1e1e;--link:#8ab4f8}}
body{background:var(--bg);color:var(--fg);font:15px/1.5 system-ui,sans-serif;margin:0;padding:0 16px}
main{max-width:860px;margin:0 auto;padding:24px 0}
a{color:var(--link)}h1{font-size:1.4em;margin:.2em 0}h2{font-size:1em;margin:1.2em 0 .3em;color:var(--mute)}
pre{background:var(--pre);padding:10px;overflow-x:auto;white-space:pre-wrap;word-break:break-word;border-radius:4px;margin:0}
.meta{color:var(--mute);font-size:.9em}ul{list-style:none;padding:0}li{padding:4px 0;border-bottom:1px solid var(--line)}
form{margin:12px 0}input[type=search],input[type=text],textarea{width:70%;padding:6px;background:var(--bg);color:var(--fg);border:1px solid var(--line)}
button{padding:6px 12px}footer{margin-top:32px;padding-top:12px;border-top:1px solid var(--line);color:var(--mute);font-size:.85em}
</style>
{{if .Umami}}<script defer src="{{.UmamiSrc}}" data-website-id="{{.UmamiID}}"></script>
{{end}}{{if .LD}}<script type="application/ld+json">{{.LD}}</script>
{{end}}</head><body><main>
{{.Body}}
<footer>Machine API: <a href="/llms.txt">/llms.txt</a> · MCP: {{.MCP}} · <a href="/grammar">URL grammar</a></footer>
</main></body></html>
`))

// bodyTmpl renders a Doc as HTML: heading, <pre> of the txt body, <nav> of actions, forms.
var bodyTmpl = template.Must(template.New("body").Parse(`{{if .Title}}<h1>{{.Title}}</h1>
{{end}}{{if .Desc}}<p class="meta">{{.Desc}}</p>
{{end}}<pre>{{.Pre}}</pre>
{{if .Nav}}<nav><ul>{{range .Nav}}<li>{{if .Href}}<a href="{{.Href}}">{{.Text}}</a>{{else}}<code>{{.Text}}</code>{{end}}{{if .Hint}} <span class="meta">{{.Hint}}</span>{{end}}</li>
{{end}}</ul></nav>
{{end}}{{range .Forms}}<form method="post" action="{{.Action}}">{{if .Legend}}<h2>{{.Legend}}</h2>{{end}}<input type="hidden" name="ft" value="{{.Token}}">
{{range .Fields}}{{if .Hidden}}<input type="hidden" name="{{.Name}}" value="{{.Value}}">
{{else}}<label>{{if .Label}}{{.Label}}{{else}}{{.Name}}{{end}}<br>{{if .Multi}}<textarea name="{{.Name}}" rows="4"{{if .Max}} maxlength="{{.Max}}"{{end}}>{{.Value}}</textarea>{{else}}<input type="text" name="{{.Name}}" value="{{.Value}}"{{if .Max}} maxlength="{{.Max}}"{{end}}>{{end}}</label><br>
{{end}}{{end}}<button type="submit">{{if .Submit}}{{.Submit}}{{else}}Send{{end}}</button></form>
{{end}}`))

type navItem struct{ Href, Text, Hint string }

type layoutData struct {
	Title, Desc, Robots, Canonical, License, UmamiSrc, UmamiID, MCP string
	Links                                                           []Link
	Umami                                                           bool
	LD                                                              template.JS
	Body                                                            template.HTML
}

// Page is a custom HTML page rendered in the shared shell by Layout.
type Page struct {
	Title, Desc, Canonical string
	NoIndex                bool
	LD                     any
	Links                  []Link
	Body                   template.HTML
}

const robotsIndex = "index,follow,max-snippet:-1,max-image-preview:large"

// umamiOrigin returns "scheme://host" of the configured Umami script, or "".
func umamiOrigin(src, id string) string {
	if src == "" || id == "" {
		return ""
	}
	u, err := url.Parse(src)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func cspFor(src, id string) string {
	p := "default-src 'none'; style-src 'unsafe-inline'; img-src 'self'; form-action 'self'; base-uri 'none'"
	if o := umamiOrigin(src, id); o != "" {
		p += "; script-src " + o + "; connect-src " + o
	}
	return p
}

// csp is the strict policy for the configured site.
func csp() string {
	s := CurrentSite()
	return cspFor(s.UmamiSrc, s.UmamiID)
}

// CSP returns the strict Content-Security-Policy for HTML pages built from cfg (the v1 kb.CSP
// rule: nothing but inline styles, same-origin images and forms, plus the Umami origin).
func CSP(cfg *core.Config) string { return cspFor(cfg.UmamiSrc, cfg.UmamiID) }

// ldJSON encodes the JSON-LD graph for a <script> element (HTML-escaped, so no "</script").
func ldJSON(v any) template.JS {
	if v == nil {
		return ""
	}
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return ""
	}
	return template.JS(bytes.TrimRight(b.Bytes(), "\n")) //nolint:gosec // encoder output with HTML escaping on
}

// twin returns the suffixed twin of a canonical path ("/k/x" + ".md" -> "/k/x.md", "/" -> "/index.md").
func twin(canonical, ext string) string {
	if strings.HasSuffix(canonical, "/") {
		return canonical + "index" + ext
	}
	return canonical + ext
}

// shell renders a Page in the layout.
func shell(p Page) []byte {
	s := CurrentSite()
	ld := layoutData{Title: p.Title, Desc: p.Desc, Robots: "noindex", License: s.License, MCP: s.MCP, Body: p.Body, LD: ldJSON(p.LD)}
	if !p.NoIndex {
		ld.Robots = robotsIndex
	}
	if p.Canonical != "" {
		ld.Canonical = s.Base + p.Canonical
		ld.Links = append(ld.Links, Link{Rel: "alternate", Type: "text/markdown", Href: twin(p.Canonical, ".md")},
			Link{Rel: "alternate", Type: "application/json", Href: twin(p.Canonical, ".json")})
	}
	for _, l := range p.Links {
		if l.Href != "" && l.Rel != "" {
			ld.Links = append(ld.Links, l)
		}
	}
	if umamiOrigin(s.UmamiSrc, s.UmamiID) != "" {
		ld.Umami, ld.UmamiSrc, ld.UmamiID = true, s.UmamiSrc, s.UmamiID
	}
	var b bytes.Buffer
	if err := layoutTmpl.Execute(&b, ld); err != nil {
		return []byte("<!doctype html><title>error</title>")
	}
	return b.Bytes()
}

// renderHTML renders a Doc as a full page: shell + <pre> body + <nav> + forms.
func renderHTML(d *Doc, o opts) []byte {
	title := d.Title
	if title == "" {
		title = d.headLine()
	}
	body := d.Body
	if body == "" {
		pre := renderTxt(d, o, false)
		var nav []navItem
		if !o.nextOff {
			for _, a := range Next(d.Next...) {
				it := navItem{Text: a.String(), Hint: a.Hint}
				if a.Method == "GET" {
					it.Href, it.Text = a.Path, a.Path
				} else if a.Method != "" {
					it.Text = a.Method + " " + a.Path
				} else {
					it.Hint = ""
				}
				nav = append(nav, it)
			}
		}
		var b bytes.Buffer
		if err := bodyTmpl.Execute(&b, struct {
			Title, Desc, Pre string
			Nav              []navItem
			Forms            []Form
		}{d.Title, d.Desc, strings.TrimRight(pre, "\n"), nav, d.Forms}); err != nil {
			return []byte("<!doctype html><title>error</title>")
		}
		body = template.HTML(b.String()) //nolint:gosec // output of html/template
	}
	return shell(Page{Title: title, Desc: d.Desc, Canonical: d.Canonical, NoIndex: d.NoIndex, LD: d.LD, Links: d.Links, Body: body})
}

// Layout writes a custom HTML page in the shared shell with the full header policy (CSP, ETag/304,
// Cache-Control, Vary, robots). body must be safe HTML (rendered through html/template).
func Layout(w http.ResponseWriter, r *http.Request, status int, p Page) {
	ReplyAs(w, r, status, &Doc{Title: p.Title, Desc: p.Desc, Canonical: p.Canonical, NoIndex: p.NoIndex, LD: p.LD, Links: p.Links, Body: p.Body}, HTML)
}

// LinkTags renders <link> tags for page heads built outside Layout.
func LinkTags(links []Link) template.HTML {
	var b strings.Builder
	for _, l := range links {
		if l.Href == "" || l.Rel == "" {
			continue
		}
		b.WriteString(`<link rel="` + template.HTMLEscapeString(l.Rel) + `" href="` + template.HTMLEscapeString(l.Href) + `"`)
		if l.Type != "" {
			b.WriteString(` type="` + template.HTMLEscapeString(l.Type) + `"`)
		}
		if l.Title != "" {
			b.WriteString(` title="` + template.HTMLEscapeString(l.Title) + `"`)
		}
		b.WriteString(">\n")
	}
	return template.HTML(b.String()) //nolint:gosec // every value escaped above
}
