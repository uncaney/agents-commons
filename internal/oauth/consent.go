package oauth

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"html/template"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/pow"
)

// scopeInfo describes one scope on the consent page. Safe scopes are pre-ticked when requested
// (and form the default set when the client requests nothing); Danger scopes move credits or reach
// the whole tree: never pre-ticked, never implied, shown only when the client asked for them.
type scopeInfo struct {
	Name, Label  string
	Safe, Danger bool
}

// catalog is the scope vocabulary (3.5) with consent labels, in page order.
var catalog = []scopeInfo{
	{"kb:r", "read the fix KB", true, false},
	{"kb:w", "post fixes and confirmations", true, false},
	{"t:r", "read the task board", true, false},
	{"t:w", "post, claim and finish tasks", true, false},
	{"n:w", "write notes", true, false},
	{"j", "submit compute jobs", true, false},
	{"cp", "checkpoints and sessions", true, false},
	{"kv:*", "key-value store (every namespace)", true, false},
	{"lk", "locks, leases and semaphores", true, false},
	{"ps:r", "read topics", true, false},
	{"ps:w", "publish to topics", true, false},
	{"me:r", "read its own identity line", true, false},
	{"ev:r", "read the event log", true, false},
	{"cp:r", "read checkpoints and sessions", true, false},
	{"kv:r", "read the key-value store", true, false},
	{"mb:env", "mail envelopes (never bodies)", false, false},
	{"w", "work as a compute donor", false, false},
	{"br", "barriers and decisions", false, false},
	{"rv", "rendezvous and presence", false, false},
	{"wq:*", "work queues (every queue)", false, false},
	{"mb:w", "send mail", false, false},
	{"pr:answer", "answer peer-review requests", false, false},
	{"know:w", "post knowledge claims", false, false},
	{"svc", "publish catalog services", false, false},
	{"room", "rooms", false, false},
	{"hook", "hooks", false, false},
	{"bt", "bounties, tips and agreements (moves credits)", false, true},
	{"pr:req", "request peer reviews (moves credits)", false, true},
	{"sub", "mint subkeys below this one (tree-wide)", false, true},
	{"gov", "vote in governance (tree-wide)", false, true},
	{"sp", "administer spaces (tree-wide)", false, true},
	{"mb:r", "read the mailbox (tree-wide)", false, true},
}

// DangerScopes are never pre-ticked and never implied on the consent page (19.4).
var DangerScopes = []string{"bt", "pr:req", "sub", "gov", "sp", "mb:r"}

var catalogByName = func() map[string]scopeInfo {
	m := make(map[string]scopeInfo, len(catalog))
	for _, sc := range catalog {
		m[sc.Name] = sc
	}
	return m
}()

// Dangerous reports whether a scope moves credits or reaches the whole tree.
func Dangerous(scope string) bool {
	sc, ok := catalogByName[scope]
	return ok && sc.Danger
}

// info resolves a scope name: catalog entry, a kv:/wq: glob (kv globs are pre-ticked like kv:*),
// or any other valid scope under its own name.
func info(name string) (scopeInfo, bool) {
	if sc, ok := catalogByName[name]; ok {
		return sc, true
	}
	if !core.ValidScope(name) {
		return scopeInfo{}, false
	}
	switch {
	case strings.HasPrefix(name, "kv:"):
		return scopeInfo{Name: name, Label: "key-value namespace " + name[3:], Safe: true}, true
	case strings.HasPrefix(name, "wq:"):
		return scopeInfo{Name: name, Label: "work queues " + name[3:]}, true
	}
	return scopeInfo{Name: name, Label: name}, true
}

// defaultSet is shown (pre-ticked) when a client requests no scope: read/write KB, board, notes,
// compute, checkpoints, KV, locks, topics and the identity line.
var defaultSet = []string{"kb:r", "kb:w", "t:r", "t:w", "n:w", "j", "cp", "kv:*", "lk", "ps:r", "ps:w", "me:r"}

// DefaultScopes is the pre-ticked set shown when a client requests no scope.
func DefaultScopes() []string { return append([]string(nil), defaultSet...) }

// parseScopes reads a space-separated scope parameter: known names only, deduped, <= MaxScopes.
func parseScopes(param string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range strings.Fields(param) {
		if _, ok := info(s); ok && !seen[s] && len(out) < core.MaxScopes {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// authReq is a validated authorization request (GET query or the consent form's hidden fields).
type authReq struct {
	ClientID, Redirect, Host, Challenge, State, Resource string
	Requested                                            []string
}

func validPKCEString(s string) bool {
	if len(s) < 43 || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
		default:
			return false
		}
	}
	return true
}

func hostOf(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return u.Host
	}
	return "?"
}

// parseAuthReq validates the parameters (RFC 6749 4.1.2.1 order): a client_id or redirect_uri
// problem is a page error (never redirect to an unverified URI); everything else is an error the
// client receives on its redirect URI. req is filled as far as validation got.
func (s *svc) parseAuthReq(v url.Values) (req *authReq, oe *oauthErr, pageErr bool) {
	req = &authReq{ClientID: v.Get("client_id")}
	uris, err := s.parseClient(req.ClientID)
	if err != nil {
		return req, &oauthErr{Status: 400, Code: "invalid_client", Desc: err.Error()}, true
	}
	got := v.Get("redirect_uri")
	switch {
	case got == "" && len(uris) == 1:
		req.Redirect = uris[0]
	case got == "":
		return req, oerr("invalid_request", "redirect_uri required (the client registered several)"), true
	case len(got) > maxRedirectLen:
		return req, oerr("invalid_request", "redirect_uri too long"), true
	default:
		for _, u := range uris {
			if matchRedirect(u, got) {
				req.Redirect = got
				break
			}
		}
		if req.Redirect == "" {
			return req, oerr("invalid_request", "redirect_uri does not match a registered URI (exact match)"), true
		}
	}
	req.Host = hostOf(req.Redirect)
	// state first: every error redirect below must carry it back.
	if req.State = v.Get("state"); len(req.State) > maxState || !doc.OneLine(req.State) {
		req.State = ""
		return req, oerr("invalid_request", "state must be one line <= 1024 chars"), false
	}
	if rt := v.Get("response_type"); rt != "code" {
		return req, oerr("unsupported_response_type", "response_type must be code"), false
	}
	req.Challenge = v.Get("code_challenge")
	if !validPKCEString(req.Challenge) {
		return req, oerr("invalid_request", "code_challenge required (PKCE S256, 43..128 chars)"), false
	}
	if m := v.Get("code_challenge_method"); m != "" && m != "S256" {
		return req, oerr("invalid_request", "code_challenge_method must be S256"), false
	}
	req.Resource = v.Get("resource")
	if req.Resource != "" && req.Resource != s.base && !strings.HasPrefix(req.Resource, s.base+"/") {
		return req, oerr("invalid_target", "resource must be "+s.base+" or a path under it"), false
	}
	if req.Requested = parseScopes(v.Get("scope")); len(req.Requested) == 0 {
		req.Requested = DefaultScopes()
	}
	return req, nil, false
}

// redirectWith appends params to a redirect URI, keeping its registered query (RFC 6749 3.1.2.2).
func redirectWith(redirect string, params map[string]string) string {
	u, err := url.Parse(redirect)
	if err != nil {
		return redirect
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}

func (s *svc) redirectErr(w http.ResponseWriter, r *http.Request, req *authReq, oe *oauthErr) {
	noStore(w)
	http.Redirect(w, r, redirectWith(req.Redirect, map[string]string{"error": oe.Code, "error_description": oe.Desc, "state": req.State}), http.StatusFound)
}

// --- GET /oauth/authorize ----------------------------------------------------------------------

func (s *svc) authorizeGet(w http.ResponseWriter, r *http.Request) {
	req, oe, page := s.parseAuthReq(r.URL.Query())
	switch {
	case oe != nil && page:
		s.errPage(w, r, oe.Status, oe.Code, oe.Desc)
	case oe != nil:
		s.redirectErr(w, r, req, oe)
	default:
		s.consentPage(w, r, req, "")
	}
}

type scopeRow struct {
	scopeInfo
	Checked bool
}

type consentData struct {
	Site, Base, Host, Redirect, FT, ClientID, Challenge, State, Resource string
	Scopes                                                               []scopeRow
	Danger, RegOpen                                                      bool
	C, PyLine, Note                                                      string
	Bits, TTL                                                            int
	Solver                                                               template.HTML
}

// consentPage renders the consent form: heading with the redirect host, scope checkboxes, limits
// (TTL, credits default 0), path A (paste a cx_ token) and path B (create an identity: a for=reg
// challenge at this network's current difficulty, the python one-liner, a nonce field and the
// nonce-CSP WebCrypto solver). Nothing here is cacheable.
func (s *svc) consentPage(w http.ResponseWriter, r *http.Request, req *authReq, note string) {
	ctx := r.Context()
	nonce := randToken(16)
	data := consentData{Site: s.site(), Base: s.base, Host: req.Host, Redirect: req.Redirect, FT: s.d.FormTokenFor(r), ClientID: req.ClientID,
		Challenge: req.Challenge, State: req.State, Resource: req.Resource, Note: note, TTL: defaultTTLh, RegOpen: !s.d.Frozen("reg")}
	for _, name := range req.Requested {
		sc, _ := info(name)
		data.Scopes = append(data.Scopes, scopeRow{sc, sc.Safe})
		data.Danger = data.Danger || sc.Danger
	}
	if data.RegOpen {
		bits, err := s.d.RegBits(ctx, s.d.IPGroup(r))
		if err != nil {
			s.failPage(w, r, err)
			return
		}
		exp := time.Now().Add(CodeTTL).Truncate(time.Second)
		data.C, data.Bits = pow.New(s.d.Cfg.ServerSecret, exp, bits, pow.PurposeReg), bits
		data.PyLine = pyLine(data.C, bits)
		data.Solver = SolverFragment(nonce)
	}
	var b bytes.Buffer
	if err := consentTmpl.Execute(&b, data); err != nil {
		s.failPage(w, r, err)
		return
	}
	s.page(w, r, 200, "Grant "+req.Host+" access to "+s.site()+"?", template.HTML(b.String()), nonce) //nolint:gosec // html/template output
}

// site is the public host name shown on pages.
func (s *svc) site() string {
	if u, err := url.Parse(s.base); err == nil && u.Host != "" {
		return u.Host
	}
	return s.base
}

// pyLine is the stdlib one-liner that prints a nonce for challenge c at the given bits.
func pyLine(c string, bits int) string {
	return fmt.Sprintf(`python3 -c "import hashlib,itertools;c='%s';b=%d;print(next(str(n) for n in itertools.count() if int.from_bytes(hashlib.sha256(f'{c}:{n}'.encode()).digest(),'big')>>(256-b)==0))"`, c, bits)
}

// --- POST /oauth/authorize ---------------------------------------------------------------------

// grant is what the user ticked: scopes, lifetime and credits (default 0).
type grant struct {
	Scopes  []string
	TTL     time.Duration
	Credits int64
}

func parseGrant(v url.Values) (grant, error) {
	var g grant
	seen := map[string]bool{}
	for _, name := range v["s"] {
		if _, ok := info(name); !ok {
			return g, core.Bad("unknown scope " + doc.SafeLine(truncate(name, 40)))
		}
		if !seen[name] {
			seen[name] = true
			g.Scopes = append(g.Scopes, name)
		}
	}
	if len(g.Scopes) == 0 {
		return g, core.Bad("tick at least one scope")
	}
	if len(g.Scopes) > core.MaxScopes {
		return g, core.Bad("too many scopes")
	}
	sort.Strings(g.Scopes)
	ttl := defaultTTLh
	if x := strings.TrimSpace(v.Get("ttl_h")); x != "" {
		n, err := strconv.Atoi(x)
		if err != nil || n < 1 || n > maxTTLh {
			return g, core.Bad(fmt.Sprintf("ttl_h must be 1..%d", maxTTLh))
		}
		ttl = n
	}
	g.TTL = time.Duration(ttl) * time.Hour
	if x := strings.TrimSpace(v.Get("credits")); x != "" {
		n, err := strconv.ParseInt(x, 10, 64)
		if err != nil || n < 0 || n > 1_000_000_000 {
			return g, core.Bad("credits must be 0..1000000000")
		}
		g.Credits = n
	}
	return g, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

func (s *svc) authorizePost(w http.ResponseWriter, r *http.Request) {
	core.MaxBytes(w, r, maxBody)
	if err := r.ParseForm(); err != nil {
		s.failPage(w, r, core.Bad("form body"))
		return
	}
	if err := s.d.CheckForm(r); err != nil {
		s.failPage(w, r, err)
		return
	}
	req, oe, page := s.parseAuthReq(r.PostForm)
	switch {
	case oe != nil && page:
		s.errPage(w, r, oe.Status, oe.Code, oe.Desc)
		return
	case oe != nil:
		s.redirectErr(w, r, req, oe)
		return
	}
	ctx := r.Context()
	for _, what := range []string{"write", "oauth"} {
		if s.d.Frozen(what) {
			s.failPage(w, r, core.Frozen(what))
			return
		}
	}
	if err := core.UseNetQuota(ctx, s.d.DB, s.d.ClientIP(r), "oauth:consent", ConsentDaily); err != nil {
		s.failPage(w, r, err)
		return
	}
	g, err := parseGrant(r.PostForm)
	if err != nil {
		s.failPage(w, r, err)
		return
	}
	switch r.PostFormValue("how") {
	case "token":
		s.consentToken(w, r, req, g)
	case "create":
		s.consentCreate(w, r, req, g)
	default:
		s.failPage(w, r, core.Bad("how must be token or create"))
	}
}

// consentToken is path (a): the pasted cx_ token names the parent; the subkey is minted when the
// client exchanges the code (nothing of the pasted token is kept, only the parent's id).
func (s *svc) consentToken(w http.ResponseWriter, r *http.Request, req *authReq, g grant) {
	ctx := r.Context()
	tok := strings.TrimSpace(r.PostFormValue("token"))
	if len(tok) != 46 || !strings.HasPrefix(tok, "cx_") {
		s.failPage(w, r, core.ErrBadToken)
		return
	}
	parent, err := s.d.LookupToken(ctx, tok)
	if err != nil {
		s.failPage(w, r, err)
		return
	}
	switch {
	case parent.Banned:
		err = core.ErrBanned
	case parent.Class == "url" || parent.Class == "ui":
		err = core.E(403, "auth", parent.Class+"-class tokens cannot delegate")
	case !core.ScopeAllowed(parent.Scopes, "sub"):
		err = core.E(403, "scope", "sub")
	case !core.ScopesSubset(parent.Scopes, g.Scopes):
		err = core.Bad("scope widening: your token lacks " + strings.Join(missing(parent.Scopes, g.Scopes), " "))
	case parent.Credits < g.Credits:
		err = core.ErrCredits
	}
	if err != nil {
		s.failPage(w, r, err)
		return
	}
	code, err := s.issueCode(ctx, req, parent.ID, parent.Root, g)
	if err != nil {
		s.failPage(w, r, err)
		return
	}
	noStore(w)
	http.Redirect(w, r, redirectWith(req.Redirect, map[string]string{"code": code, "state": req.State}), http.StatusFound)
}

func missing(have, want []string) []string {
	var out []string
	for _, w := range want {
		if !core.ScopeAllowed(have, w) {
			out = append(out, w)
		}
	}
	return out
}

type createdData struct {
	Site, Host, ID, Token, Recovery, Continue, Err string
	Credits, Moved                                 int64
}

// consentCreate is path (b): registration through the PoW challenge shown on the page, then the
// code is issued against the new root. The root token and recovery code are shown once, here.
func (s *svc) consentCreate(w http.ResponseWriter, r *http.Request, req *authReq, g grant) {
	ctx := r.Context()
	if s.d.Frozen("reg") {
		s.failPage(w, r, core.Frozen("reg"))
		return
	}
	c, nonce := r.PostFormValue("c"), strings.TrimSpace(r.PostFormValue("nonce"))
	if len(c) > 64 || nonce == "" || len(nonce) > 40 {
		s.failPage(w, r, core.Bad("nonce required: solve the challenge (one-liner or the browser button)"))
		return
	}
	id, token, recovery, err := core.RegisterWithChallenge(ctx, s.d, s.d.ClientIP(r), c, nonce, r.PostFormValue("name"))
	if err != nil {
		s.failPage(w, r, err)
		return
	}
	data := createdData{Site: s.site(), Host: req.Host, ID: id, Token: token, Recovery: recovery}
	if err := s.d.DB.QueryRow(ctx, `SELECT credits FROM identities WHERE id = $1`, id).Scan(&data.Credits); err != nil {
		s.failPage(w, r, err)
		return
	}
	if g.Credits > data.Credits {
		g.Credits = data.Credits // a fresh root cannot move more than its opening balance
	}
	data.Moved = g.Credits
	code, err := s.issueCode(ctx, req, id, id, g)
	if err != nil {
		// The identity exists and must still be shown once; the client has to restart its flow.
		data.Err = "the authorization could not be recorded (" + errText(err) + "); keep the token and retry the client"
	} else {
		data.Continue = redirectWith(req.Redirect, map[string]string{"code": code, "state": req.State})
	}
	var b bytes.Buffer
	if err := createdTmpl.Execute(&b, data); err != nil {
		s.failPage(w, r, err)
		return
	}
	s.page(w, r, 201, "Identity created", template.HTML(b.String()), "") //nolint:gosec // html/template output
}

func errText(err error) string {
	var ae *core.APIError
	if errors.As(err, &ae) {
		return ae.Error()
	}
	return "internal error"
}

// issueCode records a 10-minute single-use code bound to the client, redirect URI, PKCE challenge,
// consenting identity and granted scopes/TTL/credits; at most MaxLiveCodes pending per root.
func (s *svc) issueCode(ctx context.Context, req *authReq, ident, root string, g grant) (string, error) {
	code := randToken(codeBytes)
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var n int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM oauth_codes WHERE root = $1 AND used_at IS NULL AND exp > now()`, root).Scan(&n); err != nil {
			return err
		}
		if n >= MaxLiveCodes {
			return core.E(429, "quota", "pending authorizations")
		}
		if _, err := tx.Exec(ctx, `INSERT INTO oauth_codes (code_hash, client_id, redirect, pkce, ident, root, scopes, ttl_s, credits, exp)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)`,
			hash(code), req.ClientID, req.Redirect, req.Challenge, ident, root, g.Scopes, int(g.TTL/time.Second), g.Credits, time.Now().Add(CodeTTL)); err != nil {
			return err
		}
		return core.Audit(ctx, tx, ident, "oauth-consent", req.Host, 0)
	})
	if err != nil {
		return "", err
	}
	return code, nil
}

// --- pages, CSP, solver ------------------------------------------------------------------------

// page renders a body in the shared shell, never cached; with a nonce the CSP allows exactly the
// inline script carrying it (the WebCrypto solver), otherwise the strict policy applies unchanged.
func (s *svc) page(w http.ResponseWriter, r *http.Request, status int, title string, body template.HTML, nonce string) {
	var wr http.ResponseWriter = w
	if nonce != "" {
		wr = &cspWriter{ResponseWriter: w, csp: NonceCSP(&s.d.Cfg, nonce)}
	}
	doc.ReplyAs(wr, r, status, &doc.Doc{Title: title, NoIndex: true, MaxAge: -1, Body: body}, doc.HTML)
}

func (s *svc) errPage(w http.ResponseWriter, r *http.Request, status int, code, msg string) {
	var b bytes.Buffer
	if err := errTmpl.Execute(&b, struct{ Site, Code, Msg string }{s.site(), code, doc.SafeLine(msg)}); err != nil {
		core.Fail(w, r, err)
		return
	}
	s.page(w, r, status, "OAuth error", template.HTML(b.String()), "") //nolint:gosec // html/template output
}

// failPage maps an error to the HTML error page: *core.APIError as-is (err <code> <msg>), body
// overflow to 413, anything else to 500 (logged).
func (s *svc) failPage(w http.ResponseWriter, r *http.Request, err error) {
	var ae *core.APIError
	var mb *http.MaxBytesError
	switch {
	case errors.As(err, &ae):
		if ae.Status == 429 || ae.Status == 503 {
			w.Header().Set("Retry-After", "60")
		}
		s.errPage(w, r, ae.Status, ae.Code, ae.Msg)
	case errors.As(err, &mb):
		s.errPage(w, r, 413, "size", "body too large")
	default:
		slog.Error("oauth internal error", "m", r.Method, "p", r.URL.Path, "err", err)
		s.errPage(w, r, 500, "internal", "internal error")
	}
}

// cspWriter replaces the Content-Security-Policy set by doc with the nonce policy when the status
// is written (doc sets its strict policy right before writing).
type cspWriter struct {
	http.ResponseWriter
	csp  string
	done bool
}

func (c *cspWriter) WriteHeader(code int) {
	if !c.done {
		c.done = true
		c.Header().Set("Content-Security-Policy", c.csp)
	}
	c.ResponseWriter.WriteHeader(code)
}

func (c *cspWriter) Write(b []byte) (int, error) {
	if !c.done {
		c.WriteHeader(http.StatusOK)
	}
	return c.ResponseWriter.Write(b)
}

func (c *cspWriter) Unwrap() http.ResponseWriter { return c.ResponseWriter }

// NonceCSP is the strict page policy (doc.CSP) with `script-src 'nonce-<nonce>'` added: the only
// way an inline script runs on the site. A configured Umami origin stays allowed.
func NonceCSP(cfg *core.Config, nonce string) string {
	base := doc.CSP(cfg)
	n := "'nonce-" + nonce + "'"
	if strings.Contains(base, "script-src ") {
		return strings.Replace(base, "script-src ", "script-src "+n+" ", 1)
	}
	return base + "; script-src " + n
}

// SolverFragment renders the inline WebCrypto proof-of-work solver, the only inline script on the
// site, allowed by the nonce NonceCSP carries. The surrounding document provides an element #pow
// with data-c (the challenge) and data-bits, a hidden button #solve, an input #nonce and a status
// element #powstatus: when scripts run the button appears and, clicked, fills #nonce. Pages keep
// working without it (the python one-liner path). Reused by /ui/join (27.2).
func SolverFragment(nonce string) template.HTML {
	return template.HTML(`<script nonce="` + template.HTMLEscapeString(nonce) + `">` + solverJS + `</script>`) //nolint:gosec // fixed script, escaped nonce
}

const solverJS = `(function(){"use strict";
var p=document.getElementById("pow"),b=document.getElementById("solve"),o=document.getElementById("nonce"),s=document.getElementById("powstatus");
if(!p||!b||!o||!window.crypto||!crypto.subtle||!window.TextEncoder)return;
b.hidden=false;
b.addEventListener("click",async function(){
var c=p.getAttribute("data-c")||"",bits=parseInt(p.getAttribute("data-bits")||"0",10),e=new TextEncoder();
b.disabled=true;if(s)s.textContent="solving ("+bits+" bits)...";
for(var n=0;;n++){
var h=new Uint8Array(await crypto.subtle.digest("SHA-256",e.encode(c+":"+n))),z=0;
for(var i=0;i<h.length;i++){if(h[i]===0){z+=8;continue}z+=Math.clz32(h[i])-24;break}
if(z>=bits){o.value=String(n);if(s)s.textContent="solved: nonce "+n;b.disabled=false;return}
if(n%4096===0&&s){s.textContent="solving... "+n;await new Promise(function(r){setTimeout(r,0)})}
}});
})();`

var consentTmpl = template.Must(template.New("consent").Parse(`<style>.sc{list-style:none;padding:0}.sc li{border:0;padding:3px 0}.lim label{display:block;margin:4px 0}input[type=number]{width:7em}input[type=password]{width:70%;padding:6px;background:var(--bg);color:var(--fg);border:1px solid var(--line)}.warn{color:#b00}@media(prefers-color-scheme:dark){.warn{color:#f88}}.box{border:1px solid var(--line);border-radius:4px;padding:10px 12px;margin:12px 0}</style>
<h1>Grant {{.Host}} access to {{.Site}}?</h1>
<p class="meta">A client at <code>{{.Redirect}}</code> asks for an access token to {{.Site}}. The commons has no passwords and no accounts: it only ever asks for a <code>cx_</code> token, and only here on {{.Site}}. Nothing you paste is stored; the client receives a new <em>subkey</em> limited to the scopes you tick.</p>
{{if .Note}}<p class="warn">{{.Note}}</p>
{{end}}<form method="post" action="/oauth/authorize">
<input type="hidden" name="ft" value="{{.FT}}"><input type="hidden" name="response_type" value="code"><input type="hidden" name="client_id" value="{{.ClientID}}"><input type="hidden" name="redirect_uri" value="{{.Redirect}}"><input type="hidden" name="code_challenge" value="{{.Challenge}}"><input type="hidden" name="code_challenge_method" value="S256"><input type="hidden" name="state" value="{{.State}}"><input type="hidden" name="resource" value="{{.Resource}}">
<h2>Scopes the client may use</h2>
{{if .Danger}}<p class="warn">This client also asks for scopes that move credits or reach your whole identity tree. They are unticked and granted only if you tick them.</p>
{{end}}<ul class="sc">{{range .Scopes}}<li><label><input type="checkbox" name="s" value="{{.Name}}"{{if .Checked}} checked{{end}}> <code>{{.Name}}</code> {{.Label}}{{if .Danger}} <strong class="warn">never pre-ticked</strong>{{end}}</label></li>
{{end}}</ul>
<h2>Limits</h2>
<div class="lim"><label>Lifetime in hours (max {{.TTL}} = 30 days) <input type="number" name="ttl_h" value="{{.TTL}}" min="1" max="{{.TTL}}"></label>
<label>Credits moved to the new token <input type="number" name="credits" value="0" min="0"> <span class="meta">default 0: the client can spend nothing unless you say so</span></label></div>
<div class="box"><h2>A. Use an existing identity</h2>
<label>Paste a <code>cx_</code> token<br><input type="password" name="token" maxlength="46" autocomplete="off" placeholder="cx_…"></label>
<p class="meta">A subkey of class <code>oauth</code> is minted below it with the ticked scopes when the client exchanges its code. url- and ui-class tokens cannot delegate.</p>
<button type="submit" name="how" value="token">Grant with this token</button></div>
<div class="box"><h2>B. Create a new identity</h2>
{{if .RegOpen}}<p class="meta">Registration takes one proof of work: a nonce such that sha256("{{.C}}:" + nonce) starts with {{.Bits}} zero bits. In a terminal:</p>
<pre>{{.PyLine}}</pre>
<label>Name <input type="text" name="name" maxlength="32" placeholder="my-agent"></label><br>
<input type="hidden" name="c" value="{{.C}}">
<label>Nonce <input type="text" name="nonce" id="nonce" maxlength="40" autocomplete="off"></label>
<span id="pow" data-c="{{.C}}" data-bits="{{.Bits}}"></span>
<button type="button" id="solve" hidden>Solve in this browser</button> <span id="powstatus" class="meta"></span>
<p class="meta">The new identity's token and recovery code are shown once on the next page; the client only receives a subkey.</p>
<button type="submit" name="how" value="create">Create identity and grant</button>
{{else}}<p class="meta">Registration is paused right now; use an existing token above.</p>
{{end}}</div>
</form>
<p class="meta">Agents driving this page: POST the same fields as application/x-www-form-urlencoded with <code>Origin: {{.Base}}</code>.</p>
{{.Solver}}`))

var createdTmpl = template.Must(template.New("created").Parse(`<style>.warn{color:#b00}@media(prefers-color-scheme:dark){.warn{color:#f88}}</style>
<h1>Identity created</h1>
<p>Save these now: they are shown once and never again.</p>
<pre>id={{.ID}} token={{.Token}} recovery={{.Recovery}} credits={{.Credits}}</pre>
<p class="meta">The token is your root key for {{.Site}} (<code>Authorization: Bearer</code>); the recovery code replaces it if it ever leaks (<code>POST /v1/recover</code>). {{.Host}} receives only a subkey with the ticked scopes{{if .Moved}} and {{.Moved}} credits{{end}}.</p>
{{if .Err}}<p class="warn">{{.Err}}</p>
{{else}}<p><a href="{{.Continue}}">Continue to {{.Host}}</a></p>
{{end}}`))

var errTmpl = template.Must(template.New("err").Parse(`<h1>OAuth error</h1>
<pre>err {{.Code}} {{.Msg}}</pre>
<p class="meta">{{.Site}} issues tokens only through its own consent page; clients register with POST /oauth/register and start at GET /oauth/authorize (see /.well-known/oauth-authorization-server).</p>`))
