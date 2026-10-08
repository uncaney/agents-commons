// Package ui is the no-JS browser console at /ui (SPEC-v2 27.2, P84). It lets a person drive the
// commons from a browser with no client install: paste a cx_ token once (POST /ui/login mints a
// short-lived ui-class subkey held in a __Host-cx cookie), then read the same txt pages agents
// read, rendered in <pre>, with every token-requiring next: action turned into a <form> that POSTs
// through /ui/do and dispatches in process against the same mux. The cookie is read only by /ui/*
// handlers; the rest of the site (/v1/*, /mcp, /a2a, pages) ignores it. The only inline script on
// the whole site is the OAuth nonce-CSP WebCrypto solver, reused by /ui/join. CSRF is held off by
// SameSite=Strict + a form token + an Origin check on every POST.
package ui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"html/template"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/oauth"
)

// CookieName is the session cookie: the __Host- prefix pins it to Secure + Path=/ + no Domain.
const CookieName = "__Host-cx"

// SubkeyTTL is the lifetime of the ui-class subkey and its cookie (27.2: 24 h).
const SubkeyTTL = 24 * time.Hour

// maxForm caps a /ui POST body.
const maxForm = 64 << 10

// dropScopes are removed from the parent's set when minting the ui subkey: credit-moving or
// tree-wide scopes a browser session must never hold (27.2).
var dropScopes = map[string]bool{"bt": true, "pr:req": true, "sub": true, "gov": true, "sp": true, "mb:r": true}

// fullScopes is the fixed scope vocabulary (core.scopeFixed) plus the two globs, used as the
// effective set of a full parent token (Scopes == nil) before dropScopes is applied.
var fullScopes = []string{
	"kb:r", "kb:w", "t:r", "t:w", "n:w", "j", "w", "lk", "br", "rv", "ps:r", "ps:w",
	"mb:w", "pr:answer", "cp", "know:w", "svc", "room", "hook", "cp:r", "kv:r", "mb:env",
	"ev:r", "me:r", "kv:*", "wq:*",
}

type svc struct {
	d       *core.Deps
	mux     *http.ServeMux
	base    string
	schemas sync.Once // populates doc's body-schema registry from every registered fragment
}

// Register mounts the /ui console. ui routes carry no MCP ops; they dispatch in process against
// the same mux, so they must be registered after the routes they front (a later integration
// package wires the ordering).
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d, mux: mux, base: strings.TrimRight(d.Cfg.PublicURL, "/")}
	mux.HandleFunc("GET /ui", s.index)
	mux.HandleFunc("GET /ui/", s.index)
	mux.HandleFunc("POST /ui/login", s.login)
	mux.HandleFunc("POST /ui/logout", s.logout)
	mux.HandleFunc("POST /ui/do", s.do)
	mux.HandleFunc("GET /ui/join", s.join)
	mux.HandleFunc("GET /ui/q", s.search)
	mux.HandleFunc("GET /ui/me", s.view("/v1/me"))
	mux.HandleFunc("GET /ui/k/{id}", s.view("/k/{id}"))
	mux.HandleFunc("GET /ui/t/{n}", s.view("/t/{n}"))
	mux.HandleFunc("GET /ui/s/{slug}", s.view("/s/{slug}"))
	// Reads are cheap; the write dispatch carries the underlying route's own cost.
	for _, p := range []string{"GET /ui", "GET /ui/", "GET /ui/join", "GET /ui/k/{id}", "GET /ui/t/{n}", "GET /ui/me", "GET /ui/s/{slug}", "GET /ui/q"} {
		d.RegisterCost(p, 0.5)
	}
}

// ensureSchemas loads every registered OpenAPI request body into doc's schema registry so forms
// can be built from the field templates. Deferred to first use: by the first request every
// package has registered its fragments.
func (s *svc) ensureSchemas() {
	s.schemas.Do(func() {
		for _, f := range s.d.OpenAPIFragments() {
			doc.RegisterFragment(f)
		}
	})
}

// --- cookie ------------------------------------------------------------------------------------

// cookieToken returns the ui subkey carried by the request's __Host-cx cookie, or "".
func cookieToken(r *http.Request) string {
	c, err := r.Cookie(CookieName)
	if err != nil || c == nil {
		return ""
	}
	return c.Value
}

// setCookie writes the session cookie (24 h, __Host- rules: Secure, Path=/, HttpOnly, Strict).
func setCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: token, Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: int(SubkeyTTL / time.Second),
	})
}

// clearCookie expires the session cookie.
func clearCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: CookieName, Value: "", Path: "/", Secure: true, HttpOnly: true,
		SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

// --- response shell ----------------------------------------------------------------------------

// uiWriter layers the /ui header policy over doc's HTML writer: private no-store, Vary: Cookie,
// X-Frame-Options DENY, a no-referrer policy, and (for /ui/join) the nonce CSP that allows the one
// inline solver script. doc sets its own headers right before writing, so these are applied last.
type uiWriter struct {
	http.ResponseWriter
	csp  string
	done bool
}

func (c *uiWriter) WriteHeader(code int) {
	if !c.done {
		c.done = true
		h := c.Header()
		h.Set("Cache-Control", "private, no-store")
		h.Set("Vary", "Cookie")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Robots-Tag", "noindex")
		if c.csp != "" {
			h.Set("Content-Security-Policy", c.csp)
		}
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *uiWriter) Write(b []byte) (int, error) {
	if !c.done {
		c.WriteHeader(http.StatusOK)
	}
	return c.ResponseWriter.Write(b)
}

func (c *uiWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// page renders a body in the shared shell with the /ui header policy. A non-empty nonce switches
// the CSP to the nonce policy (only /ui/join uses it).
func (s *svc) page(w http.ResponseWriter, r *http.Request, status int, title string, body template.HTML, nonce string) {
	wr := &uiWriter{ResponseWriter: w}
	if nonce != "" {
		wr.csp = oauth.NonceCSP(&s.d.Cfg, nonce)
	}
	doc.Layout(wr, r, status, doc.Page{Title: title, NoIndex: true, Body: body})
}

// --- handlers ----------------------------------------------------------------------------------

// index is GET /ui: the paste-token form, or, when a session is live, a short home with links to
// the console pages.
func (s *svc) index(w http.ResponseWriter, r *http.Request) {
	ft := core.FormToken(s.d.Cfg.ServerSecret, "/ui/login", s.d.IPGroup(r), time.Now())
	var b bytes.Buffer
	if tok := cookieToken(r); tok != "" {
		if id, err := s.d.LookupToken(r.Context(), tok); err == nil && id.Class == "ui" {
			home.Execute(&b, struct {
				Name, LogoutFT string
			}{id.Name, core.FormToken(s.d.Cfg.ServerSecret, "/ui/logout", s.d.IPGroup(r), time.Now())})
			s.page(w, r, 200, "console", template.HTML(b.String()), "") //nolint:gosec // template output
			return
		}
	}
	login.Execute(&b, struct{ FT string }{ft})
	s.page(w, r, 200, "console login", template.HTML(b.String()), "") //nolint:gosec // template output
}

// login is POST /ui/login: verifies the pasted token and mints a 24 h ui-class subkey below it.
// The pasted token is only looked up, never stored; the subkey goes into the cookie.
func (s *svc) login(w http.ResponseWriter, r *http.Request) {
	core.MaxBytes(w, r, maxForm)
	if err := s.d.CheckForm(r); err != nil {
		s.fail(w, r, err)
		return
	}
	tok := strings.TrimSpace(r.PostFormValue("token"))
	parent, err := s.d.LookupToken(r.Context(), tok)
	if err != nil {
		s.errPage(w, r, 401, "auth", "that token is not valid")
		return
	}
	_, sub, err := core.CreateSubkeyV2(r.Context(), s.d.DB, parent, core.SubkeyOpts{
		Name: "ui", Class: "ui", Credits: 0, Exp: time.Now().Add(SubkeyTTL), Scopes: uiScopes(parent),
	})
	if err != nil {
		s.fail(w, r, err)
		return
	}
	setCookie(w, sub)
	http.Redirect(&uiWriter{ResponseWriter: w}, r, "/ui", http.StatusSeeOther)
}

// uiScopes is the parent's effective scope set minus the credit-moving and tree-wide scopes.
func uiScopes(parent *core.Ident) []string {
	src := parent.Scopes
	if src == nil {
		src = fullScopes
	}
	out := make([]string, 0, len(src))
	for _, sc := range src {
		if !dropScopes[sc] {
			out = append(out, sc)
		}
	}
	return out
}

// logout is POST /ui/logout: revokes the subkey (and its tree) and clears the cookie.
func (s *svc) logout(w http.ResponseWriter, r *http.Request) {
	core.MaxBytes(w, r, maxForm)
	if err := s.d.CheckForm(r); err != nil {
		s.fail(w, r, err)
		return
	}
	if tok := cookieToken(r); tok != "" {
		if id, err := s.d.LookupToken(r.Context(), tok); err == nil && id.Class == "ui" {
			core.RevokeTree(r.Context(), s.d.DB, id.ID, "") //nolint:errcheck // best effort; cookie is cleared regardless
		}
	}
	clearCookie(w)
	http.Redirect(&uiWriter{ResponseWriter: w}, r, "/ui", http.StatusSeeOther)
}

// view fronts a read page: it fetches template (with {id}/{n}/{slug} filled from the request) in
// process as text/plain and renders it with its next: actions as links and forms.
func (s *svc) view(template string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		path := template
		for _, k := range []string{"id", "n", "slug"} {
			if v := r.PathValue(k); v != "" {
				path = strings.ReplaceAll(path, "{"+k+"}", url.PathEscape(v))
			}
		}
		s.renderPath(w, r, "GET", path, nil, "")
	}
}

// search is GET /ui/q: a search box, and when ?q= is set, the /q/<q> results rendered in process.
func (s *svc) search(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	if q == "" {
		var b bytes.Buffer
		searchBox.Execute(&b, nil)
		s.page(w, r, 200, "search", template.HTML(b.String()), "") //nolint:gosec // template output
		return
	}
	s.renderPath(w, r, "GET", "/q/"+url.PathEscape(q), nil, "")
}

// do is POST /ui/do: the submit target of every rendered form. It reconstructs the underlying
// write from the hidden _method/_path fields plus the schema's inputs, dispatches it in process
// with the cookie subkey as bearer, and renders the reply.
func (s *svc) do(w http.ResponseWriter, r *http.Request) {
	core.MaxBytes(w, r, maxForm)
	if err := s.d.CheckForm(r); err != nil {
		s.fail(w, r, err)
		return
	}
	method := strings.ToUpper(r.PostFormValue("_method"))
	path := r.PostFormValue("_path")
	if !writeMethod[method] || !strings.HasPrefix(path, "/") {
		s.errPage(w, r, 400, "bad", "unknown action")
		return
	}
	s.ensureSchemas()
	body := buildBody(method, path, r.PostForm)
	s.renderPath(w, r, method, path, body, "application/json")
}

// join is GET /ui/join: the nonce-CSP WebCrypto solver page reused from OAuth (the one inline
// script on the site), for people who register a new identity in the browser.
func (s *svc) join(w http.ResponseWriter, r *http.Request) {
	nonce := core.NewID('n') + core.NewID('n')
	var b bytes.Buffer
	joinTmpl.Execute(&b, struct {
		Base   string
		Solver template.HTML
	}{s.base, oauth.SolverFragment(nonce)})
	s.page(w, r, 200, "join", template.HTML(b.String()), nonce) //nolint:gosec // template output
}

// --- in-process dispatch -----------------------------------------------------------------------

var writeMethod = map[string]bool{"POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// renderPath dispatches method+path against the mux as the cookie subkey (text/plain), then
// renders the plaintext reply in <pre> with its next: actions as links and forms. A missing or
// stale session falls back to the login page.
func (s *svc) renderPath(w http.ResponseWriter, r *http.Request, method, path string, body []byte, ctype string) {
	tok := cookieToken(r)
	if tok == "" {
		s.errPage(w, r, 401, "auth", "paste a token at /ui to start a session")
		return
	}
	status, reply := s.dispatch(r, method, path, tok, body, ctype)
	s.ensureSchemas()
	frag := s.renderReply(r, path, reply)
	s.page(w, r, status, "console", frag, "")
}

// dispatch runs one in-process request and returns its status and plaintext body. The sub-request
// carries no cookies (so no other handler ever reads the session) and copies the caller's client
// identity so quotas and grouping match.
func (s *svc) dispatch(r *http.Request, method, path, token string, body []byte, ctype string) (int, string) {
	var rd *bytes.Reader
	if body != nil {
		rd = bytes.NewReader(body)
	} else {
		rd = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rd)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "text/plain")
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if ip := r.Header.Get("CF-Connecting-IP"); ip != "" {
		req.Header.Set("CF-Connecting-IP", ip)
	}
	req.RemoteAddr = r.RemoteAddr
	ip, grp, sup := s.d.ClientIP(r), s.d.IPGroup(r), s.d.IPSuper(r)
	// A fresh context: the outer /ui request resolved to an anonymous identity (its cookie is not a
	// bearer), so inheriting it would mask the subkey we inject here. Client grouping is carried
	// over for quotas; deps fall back to the process global.
	ctx := core.WithClient(context.Background(), ip, grp, sup)
	req = req.WithContext(ctx)
	rec := httptest.NewRecorder()
	s.mux.ServeHTTP(rec, req)
	// Follow the content-negotiation twin redirect (303 to the .txt page) and any other internal
	// redirect, keeping the same identity and client context (GET only, at most 3 hops).
	for hops := 0; hops < 3 && rec.Code >= 301 && rec.Code <= 308; hops++ {
		loc := rec.Result().Header.Get("Location")
		if loc == "" || !strings.HasPrefix(loc, "/") {
			break
		}
		next := httptest.NewRequest("GET", loc, bytes.NewReader(nil))
		next.Header = req.Header.Clone()
		next = next.WithContext(ctx)
		rec = httptest.NewRecorder()
		s.mux.ServeHTTP(rec, next)
	}
	return rec.Code, rec.Body.String()
}

// --- rendering ---------------------------------------------------------------------------------

// renderReply builds the HTML fragment for a plaintext reply: the body in <pre>, then its next:
// actions split into GET links and token-requiring forms.
func (s *svc) renderReply(r *http.Request, path, reply string) template.HTML {
	pre, acts := splitNext(reply)
	var links []navLink
	var forms []formView
	for _, a := range acts {
		if a.Method == "" || a.Method == "GET" || a.Method == "HEAD" {
			links = append(links, navLink{Text: a.String(), Href: s.uiHref(a.Path)})
			continue
		}
		if f, ok := s.buildForm(r, a); ok {
			forms = append(forms, f)
		}
	}
	var b bytes.Buffer
	replyTmpl.Execute(&b, struct {
		Pre   string
		Links []navLink
		Forms []formView
	}{pre, links, forms})
	return template.HTML(b.String()) //nolint:gosec // template output, every value escaped
}

type navLink struct{ Text, Href string }

type formView struct {
	Legend, Method, Path, FT string
	Fields                   []fieldView
}

type fieldView struct {
	Name, Label string
	Max         int
	Multi       bool
}

// buildForm turns a token-requiring action into a form whose fields come from the route's body
// schema; an action with no registered schema still gets a bare confirm form.
func (s *svc) buildForm(r *http.Request, a doc.Action) (formView, bool) {
	fv := formView{
		Legend: actionLabel(a),
		Method: a.Method,
		Path:   a.Path,
		FT:     core.FormToken(s.d.Cfg.ServerSecret, "/ui/do", s.d.IPGroup(r), time.Now()),
	}
	if sc, ok := doc.SchemaFor(a.Method, a.Path); ok && sc != nil {
		for _, p := range sc.Props {
			label := p.Name
			if p.Required {
				label += " *"
			}
			fv.Fields = append(fv.Fields, fieldView{Name: p.Name, Label: label, Max: p.Max, Multi: multiline(p)})
		}
	}
	return fv, true
}

// multiline reports whether a body field is a free-text field that wants a textarea (the text
// grammar's multi-line, continuation-indented values): an unbounded or large string.
func multiline(p doc.Prop) bool {
	return p.Type == "string" && len(p.Enum) == 0 && (!p.HasMax || p.Max > 160)
}

// actionLabel is a short legend for a write form derived from the action's hint or its last path
// segment (ok -> confirm, bad -> report).
func actionLabel(a doc.Action) string {
	seg := a.Path
	if i := strings.LastIndexByte(seg, '/'); i >= 0 {
		seg = seg[i+1:]
	}
	switch seg {
	case "ok":
		return "confirm"
	case "bad":
		return "report a failure"
	}
	if a.Hint != "" {
		return a.Method + " " + a.Path + " (" + a.Hint + ")"
	}
	return a.Method + " " + a.Path
}

// buildBody assembles a JSON object from the submitted form fields, coercing each to the type its
// schema declares; empty values are omitted so optional fields stay unset.
func buildBody(method, path string, form url.Values) []byte {
	sc, ok := doc.SchemaFor(method, path)
	if !ok || sc == nil {
		return nil
	}
	obj := map[string]json.RawMessage{}
	for _, p := range sc.Props {
		raw := strings.TrimSpace(form.Get(p.Name))
		if raw == "" {
			continue
		}
		obj[p.Name] = coerce(p, raw)
	}
	if len(obj) == 0 {
		return nil
	}
	b, err := json.Marshal(obj)
	if err != nil {
		return nil
	}
	return b
}

// coerce encodes one field value as JSON for its schema type.
func coerce(p doc.Prop, raw string) json.RawMessage {
	switch p.Type {
	case "integer", "number":
		if _, err := strconv.ParseFloat(raw, 64); err == nil {
			return json.RawMessage(raw)
		}
	case "boolean":
		if raw == "true" || raw == "1" || raw == "on" {
			return json.RawMessage("true")
		}
		return json.RawMessage("false")
	case "array":
		parts := strings.Split(raw, ",")
		arr := make([]string, 0, len(parts))
		for _, v := range parts {
			if v = strings.TrimSpace(v); v != "" {
				arr = append(arr, v)
			}
		}
		b, _ := json.Marshal(arr)
		return b
	}
	b, _ := json.Marshal(raw)
	return b
}

// uiHref keeps navigation inside the console for the suffix-less read pages it fronts; everything
// else links to the absolute underlying URL (the raw txt/md page).
func (s *svc) uiHref(path string) string {
	p, _, _ := strings.Cut(path, "?")
	if strings.ContainsAny(strings.TrimPrefix(p, "/"), ".") {
		return s.base + path
	}
	switch {
	case p == "/v1/me":
		return "/ui/me"
	case strings.HasPrefix(p, "/k/"):
		return "/ui/k/" + strings.TrimPrefix(p, "/k/")
	case strings.HasPrefix(p, "/t/"):
		return "/ui/t/" + strings.TrimPrefix(p, "/t/")
	case strings.HasPrefix(p, "/s/"):
		return "/ui/s/" + strings.TrimPrefix(p, "/s/")
	case strings.HasPrefix(p, "/q/"):
		return "/ui/q?q=" + url.QueryEscape(strings.TrimPrefix(p, "/q/"))
	}
	return s.base + path
}

// splitNext separates a plaintext reply into its body (next: line removed) and the parsed actions.
func splitNext(reply string) (string, []doc.Action) {
	lines := strings.Split(reply, "\n")
	var body []string
	var acts []doc.Action
	for _, ln := range lines {
		if rest, ok := strings.CutPrefix(ln, "next: "); ok {
			acts = parseActions(rest)
			continue
		}
		body = append(body, ln)
	}
	return strings.TrimRight(strings.Join(body, "\n"), "\n"), acts
}

var httpVerb = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true}

// parseActions parses "GET /a | POST /b hint | retry_s=5" into actions; bare, non-verb members
// (hints such as retry_s) are dropped.
func parseActions(s string) []doc.Action {
	var out []doc.Action
	for _, part := range strings.Split(s, " | ") {
		f := strings.Fields(strings.TrimSpace(part))
		if len(f) < 2 || !httpVerb[f[0]] {
			continue
		}
		a := doc.Action{Method: f[0], Path: f[1]}
		if len(f) > 2 {
			a.Hint = strings.Join(f[2:], " ")
		}
		out = append(out, a)
	}
	return out
}

// --- errors ------------------------------------------------------------------------------------

// fail maps an error to an HTML error page.
func (s *svc) fail(w http.ResponseWriter, r *http.Request, err error) {
	var ae *core.APIError
	if errors.As(err, &ae) {
		s.errPage(w, r, ae.Status, ae.Code, ae.Msg)
		return
	}
	s.errPage(w, r, 500, "internal", "internal error")
}

func (s *svc) errPage(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	var b bytes.Buffer
	errTmpl.Execute(&b, struct{ Code, Msg string }{code, doc.SafeLine(msg)})
	s.page(w, r, status, "error", template.HTML(b.String()), "") //nolint:gosec // template output
}
