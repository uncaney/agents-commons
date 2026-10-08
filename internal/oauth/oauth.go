// Package oauth implements OAuth 2.1 for hosted MCP clients (SPEC-v2 19.4): RFC 9728 / RFC 8414
// metadata, stateless dynamic client registration (RFC 7591: client_id = redirect URIs + HMAC, no
// table), a no-JS consent page that names the redirect host and lists scopes as checkboxes, the
// authorization_code + PKCE S256 and refresh_token grants that mint and rotate `token_class=oauth`
// subkeys, and the url-token MCP route POST /mcp/t/{token}. Codes and refresh tokens are stored as
// sha256 only; the pasted parent token is never stored.
package oauth

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Caps and bounds. Vars so tests can lower them.
var (
	// CodeTTL is the lifetime of an authorization code (19.4: 10 min, single use).
	CodeTTL = 10 * time.Minute
	// MaxLiveCodes caps the unexchanged codes per consenting root.
	MaxLiveCodes = 20
	// RegDaily / ConsentDaily / TokenDaily are the anonymous per-IP-group daily quotas (4x per
	// super-group through core.UseNetQuota).
	RegDaily, ConsentDaily, TokenDaily = 100, 50, 300
)

const (
	defaultTTLh     = 720 // 30 d: the oauth subkey default and maximum lifetime
	maxTTLh         = 720
	maxRedirectURIs = 8
	maxRedirectLen  = 512
	maxClientID     = 4096
	maxState        = 1024
	maxBody         = 16 << 10
	codeBytes       = 32
	macLen          = 16
	clientMACPrefix = "oauth-client|"
)

var enc = base64.RawURLEncoding

type svc struct {
	d        *core.Deps
	base     string
	prm      []byte // protected-resource metadata (root resource)
	prmMCP   []byte // the /mcp resource variant
	asm      []byte // authorization-server metadata
	scopeLst []string
}

func newSvc(d *core.Deps) *svc {
	s := &svc{d: d, base: strings.TrimRight(d.Cfg.PublicURL, "/")}
	for _, sc := range catalog {
		s.scopeLst = append(s.scopeLst, sc.Name)
	}
	s.prm = s.resourceDoc(s.base)
	s.prmMCP = s.resourceDoc(s.base + "/mcp")
	s.asm = mustJSON(map[string]any{
		"issuer":                                s.base,
		"authorization_endpoint":                s.base + "/oauth/authorize",
		"token_endpoint":                        s.base + "/oauth/token",
		"registration_endpoint":                 s.base + "/oauth/register",
		"scopes_supported":                      s.scopeLst,
		"response_types_supported":              []string{"code"},
		"response_modes_supported":              []string{"query"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
		"token_endpoint_auth_methods_supported": []string{"none"},
		"code_challenge_methods_supported":      []string{"S256"},
		"service_documentation":                 s.base + "/llms.txt",
		"ui_locales_supported":                  []string{"en"},
	})
	return s
}

func (s *svc) resourceDoc(resource string) []byte {
	return mustJSON(map[string]any{
		"resource":                 resource,
		"authorization_servers":    []string{s.base},
		"bearer_methods_supported": []string{"header"},
		"scopes_supported":         s.scopeLst,
		"resource_name":            "agents.ekaii.fr",
		"resource_documentation":   s.base + "/llms.txt",
	})
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return append(b, '\n')
}

// Register mounts the metadata, registration, consent, token and url-token routes, sets
// core.WWWAuthenticate (the 401 hint of /mcp and /v1/*) and the package hooks.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	core.WWWAuthenticate = `Bearer resource_metadata="` + s.base + `/.well-known/oauth-protected-resource"`
	mux.HandleFunc("GET /.well-known/oauth-protected-resource", s.protectedResource)
	mux.HandleFunc("GET /.well-known/oauth-protected-resource/{rest...}", s.protectedResource)
	mux.HandleFunc("GET /.well-known/oauth-authorization-server", s.authServer)
	mux.HandleFunc("POST /oauth/register", s.register)
	mux.HandleFunc("GET /oauth/authorize", s.authorizeGet)
	mux.HandleFunc("POST /oauth/authorize", s.authorizePost)
	mux.HandleFunc("POST /oauth/token", s.token)
	mux.HandleFunc("POST /mcp/t/{token}", s.mcpToken)
	mux.HandleFunc("/mcp/t/{token}", s.mcpTokenOther) // 405 with the token masked (the mux's own 405 would log it)
	d.RegisterScope("POST /mcp/t/{token}", "*")
	for _, p := range []string{"GET /.well-known/oauth-protected-resource", "GET /.well-known/oauth-protected-resource/{rest...}", "GET /.well-known/oauth-authorization-server"} {
		d.RegisterCost(p, 0.2)
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("oauth", func(context.Context) string { return llmsText })
	d.StorageClass("oauth", 16<<20, `SELECT pg_total_relation_size('oauth_codes') + pg_total_relation_size('oauth_refresh')`)
	d.Janitor.Add("oauth", func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error {
		for _, table := range []string{"oauth_codes", "oauth_refresh"} {
			if _, err := d.DB.Exec(ctx, `DELETE FROM `+table+` WHERE root = $1`, root); err != nil {
				return err
			}
		}
		return nil
	})
	d.OnExport("oauth", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
}

// Janitor deletes consumed and expired codes (exp + 1 h, so replays stay detectable until then)
// and dead refresh tokens (exp + 1 d).
func Janitor(ctx context.Context, q core.Q) error {
	_, err := q.Exec(ctx, `DELETE FROM oauth_codes WHERE exp < now() - interval '1 hour';
		DELETE FROM oauth_refresh WHERE exp < now() - interval '1 day'`)
	return err
}

// export writes the live OAuth grants of a root tree as JSONL (client, subkey, dates; no hashes).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	rows, err := q.Query(ctx, `SELECT client_id, ident, created, exp FROM oauth_refresh WHERE root = $1 AND used_at IS NULL AND exp > now() ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	for rows.Next() {
		var client, ident string
		var created, exp time.Time
		if err := rows.Scan(&client, &ident, &created, &exp); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "oauth_grant", "client_hosts": clientHosts(client), "subkey": ident,
			"created": created.UTC().Format(time.RFC3339), "exp": exp.UTC().Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	return rows.Err()
}

func clientHosts(id string) []string {
	var hosts []string
	if uris, err := decodeClientPayload(id); err == nil {
		for _, u := range uris {
			if p, err := url.Parse(u); err == nil {
				hosts = append(hosts, p.Host)
			}
		}
	}
	return hosts
}

// --- metadata ----------------------------------------------------------------------------------

func (s *svc) protectedResource(w http.ResponseWriter, r *http.Request) {
	body := s.prm
	switch strings.Trim(r.PathValue("rest"), "/") {
	case "":
	case "mcp":
		body = s.prmMCP
	default:
		core.Err(w, r, 404, "notfound", "unknown protected resource")
		return
	}
	doc.ServeStatic(w, r, time.Time{}, body, "application/json")
}

func (s *svc) authServer(w http.ResponseWriter, r *http.Request) {
	doc.ServeStatic(w, r, time.Time{}, s.asm, "application/json")
}

// --- stateless dynamic client registration (RFC 7591) -----------------------------------------

// oauthErr is the RFC 6749 error object; Status is the HTTP status (400, or 401 for invalid_client).
type oauthErr struct {
	Status int
	Code   string
	Desc   string
}

func (e *oauthErr) Error() string { return e.Code + ": " + e.Desc }

func oerr(code, desc string) *oauthErr {
	st := 400
	if code == "invalid_client" {
		st = 401
	}
	return &oauthErr{Status: st, Code: code, Desc: desc}
}

// writeOAuthErr writes an RFC 6749 JSON error; *core.APIError and MaxBytes errors are mapped too.
func writeOAuthErr(w http.ResponseWriter, r *http.Request, err error) {
	var oe *oauthErr
	var ae *core.APIError
	var mb *http.MaxBytesError
	switch {
	case errors.As(err, &oe):
	case errors.As(err, &ae):
		oe = &oauthErr{Status: ae.Status, Code: "invalid_request", Desc: ae.Code + " " + ae.Msg}
		if ae.Status == 429 || ae.Status == 503 {
			oe.Code = "temporarily_unavailable"
			w.Header().Set("Retry-After", "60")
		}
	case errors.As(err, &mb):
		oe = &oauthErr{Status: 413, Code: "invalid_request", Desc: "body too large"}
	default:
		slog.Error("oauth internal error", "m", r.Method, "p", r.URL.Path, "err", err)
		oe = &oauthErr{Status: 500, Code: "server_error", Desc: "internal error"}
	}
	if oe.Status == 401 && core.WWWAuthenticate != "" {
		w.Header().Set("WWW-Authenticate", core.WWWAuthenticate)
	}
	noStore(w)
	core.JSON(w, oe.Status, map[string]string{"error": oe.Code, "error_description": oe.Desc})
}

func noStore(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
}

// register implements POST /oauth/register: exact https (or loopback http) redirect URIs, up to
// 8, each <= 512 bytes; unknown metadata fields are ignored (RFC 7591 clients send many). The
// reply is 201 with a stateless client_id; the same URIs always yield the same client_id.
func (s *svc) register(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := core.UseNetQuota(ctx, s.d.DB, s.d.ClientIP(r), "oauth:reg", RegDaily); err != nil {
		writeOAuthErr(w, r, err)
		return
	}
	body, err := core.ReadAll(w, r, maxBody)
	if err != nil {
		writeOAuthErr(w, r, err)
		return
	}
	var in struct {
		RedirectURIs []string `json:"redirect_uris"`
		ClientName   string   `json:"client_name"`
		GrantTypes   []string `json:"grant_types"`
		AuthMethod   string   `json:"token_endpoint_auth_method"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeOAuthErr(w, r, oerr("invalid_client_metadata", "body must be a JSON object"))
		return
	}
	uris, err := normRedirectURIs(in.RedirectURIs)
	if err != nil {
		writeOAuthErr(w, r, oerr("invalid_redirect_uri", err.Error()))
		return
	}
	for _, g := range in.GrantTypes {
		if g != "authorization_code" && g != "refresh_token" {
			writeOAuthErr(w, r, oerr("invalid_client_metadata", "grant_types: only authorization_code and refresh_token"))
			return
		}
	}
	if in.AuthMethod != "" && in.AuthMethod != "none" {
		writeOAuthErr(w, r, oerr("invalid_client_metadata", "token_endpoint_auth_method: only none (public clients)"))
		return
	}
	id := s.clientID(uris)
	out := map[string]any{
		"client_id":                  id,
		"client_id_issued_at":        time.Now().Unix(),
		"redirect_uris":              uris,
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code", "refresh_token"},
		"response_types":             []string{"code"},
		"scope":                      strings.Join(s.scopeLst, " "),
	}
	if name := []rune(doc.SafeLine(in.ClientName)); len(name) > 0 {
		if len(name) > 64 {
			name = name[:64]
		}
		out["client_name"] = string(name) // echoed only; the consent page names the redirect host, never this
	}
	noStore(w)
	core.JSON(w, 201, out)
}

// normRedirectURIs validates and dedupes registration URIs (order kept).
func normRedirectURIs(in []string) ([]string, error) {
	if len(in) == 0 {
		return nil, errors.New("redirect_uris required")
	}
	if len(in) > maxRedirectURIs {
		return nil, fmt.Errorf("at most %d redirect_uris", maxRedirectURIs)
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, u := range in {
		if err := checkRedirectURI(u); err != nil {
			return nil, err
		}
		if !seen[u] {
			seen[u] = true
			out = append(out, u)
		}
	}
	return out, nil
}

// checkRedirectURI accepts an absolute https URI, or an http URI on a loopback host (RFC 8252),
// without fragment or userinfo, printable ASCII only, <= 512 bytes.
func checkRedirectURI(u string) error {
	if u == "" || len(u) > maxRedirectLen {
		return errors.New("redirect_uri must be 1..512 bytes")
	}
	for i := 0; i < len(u); i++ {
		if u[i] <= 0x20 || u[i] >= 0x7f {
			return errors.New("redirect_uri must be printable ASCII")
		}
	}
	p, err := url.Parse(u)
	if err != nil || p.Host == "" || p.Hostname() == "" || p.User != nil || p.Fragment != "" || strings.Contains(u, "#") {
		return errors.New("redirect_uri must be absolute, without userinfo or fragment")
	}
	switch p.Scheme {
	case "https":
	case "http":
		if !loopback(p.Hostname()) {
			return errors.New("http redirect_uri only on loopback (localhost, 127.0.0.1, ::1)")
		}
	default:
		return errors.New("redirect_uri scheme must be https (or http on loopback)")
	}
	return nil
}

func loopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// matchRedirect compares a presented redirect_uri with a registered one: byte-exact, except that a
// loopback registration ignores the port (RFC 8252 7.3: the client picks it at run time).
func matchRedirect(registered, got string) bool {
	if registered == got {
		return true
	}
	a, err1 := url.Parse(registered)
	b, err2 := url.Parse(got)
	if err1 != nil || err2 != nil || !loopback(a.Hostname()) {
		return false
	}
	return a.Scheme == b.Scheme && strings.EqualFold(a.Hostname(), b.Hostname()) && a.Path == b.Path && a.RawQuery == b.RawQuery && b.Fragment == "" && b.User == nil
}

// clientID is base64url(payload || HMAC(secret, "oauth-client|" || payload)[:16]) with payload =
// the redirect URIs joined by "\n" (19.4: stateless, nothing stored).
func (s *svc) clientID(uris []string) string {
	payload := []byte(strings.Join(uris, "\n"))
	return enc.EncodeToString(append(payload, s.clientMAC(payload)...))
}

func (s *svc) clientMAC(payload []byte) []byte {
	m := hmac.New(sha256.New, s.d.Cfg.ServerSecret)
	m.Write([]byte(clientMACPrefix))
	m.Write(payload)
	return m.Sum(nil)[:macLen]
}

// decodeClientPayload splits a client_id into its URI list without checking the MAC (export only).
func decodeClientPayload(id string) ([]string, error) {
	raw, err := enc.DecodeString(id)
	if err != nil || len(raw) <= macLen {
		return nil, errors.New("malformed client_id")
	}
	return strings.Split(string(raw[:len(raw)-macLen]), "\n"), nil
}

// parseClient verifies a client_id and returns its redirect URIs (each re-validated).
func (s *svc) parseClient(id string) ([]string, error) {
	if id == "" || len(id) > maxClientID {
		return nil, errors.New("client_id required")
	}
	raw, err := enc.DecodeString(id)
	if err != nil || len(raw) <= macLen {
		return nil, errors.New("malformed client_id")
	}
	payload, mac := raw[:len(raw)-macLen], raw[len(raw)-macLen:]
	if !hmac.Equal(mac, s.clientMAC(payload)) {
		return nil, errors.New("unknown client_id (register it with POST /oauth/register)")
	}
	uris, err := normRedirectURIs(strings.Split(string(payload), "\n"))
	if err != nil {
		return nil, errors.New("malformed client_id")
	}
	return uris, nil
}

// --- small helpers -----------------------------------------------------------------------------

func randToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return enc.EncodeToString(b)
}

func hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

// subName derives the subkey name from the redirect host: "oauth-" + host with anything outside
// [a-zA-Z0-9._-] replaced, cut to 32 (core.ValidName).
func subName(host string) string {
	var b strings.Builder
	b.WriteString("oauth-")
	for _, r := range host {
		if b.Len() >= 32 {
			break
		}
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('-')
		}
	}
	return b.String()
}

// openAPI is the fragment merged into /openapi.json (request-body schemas feed expect: lines).
var openAPI = json.RawMessage(`{"paths":{
"/oauth/register":{"post":{"summary":"OAuth 2.1 dynamic client registration (RFC 7591, stateless client_id)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["redirect_uris"],"properties":{"redirect_uris":{"type":"array","maxItems":8},"client_name":{"type":"string","maxLength":64}}}}}}}},
"/oauth/authorize":{"get":{"summary":"consent page (no JS needed): grant the redirect host a cx_ subkey with ticked scopes"}},
"/oauth/token":{"post":{"summary":"authorization_code + PKCE S256 or refresh_token -> access_token cx_… (form or JSON body)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["grant_type"],"properties":{"grant_type":{"type":"string","maxLength":18},"code":{"type":"string","maxLength":128},"code_verifier":{"type":"string","maxLength":128},"redirect_uri":{"type":"string","maxLength":512},"client_id":{"type":"string","maxLength":4096},"refresh_token":{"type":"string","maxLength":128}}}}}}}},
"/mcp/t/{token}":{"post":{"summary":"MCP endpoint for url-class tokens (token in the path, no Authorization header)"}}
}}`)

// llmsText is the /llms-full.txt section.
const llmsText = `## OAuth 2.1 (hosted MCP clients)
Metadata: /.well-known/oauth-protected-resource, /.well-known/oauth-authorization-server (PKCE S256, public clients, dynamic registration POST /oauth/register {redirect_uris}).
Consent GET /oauth/authorize names the redirect host and lists scopes as checkboxes; credit-moving scopes (bt pr:req sub gov sp mb:r) are never pre-ticked; credits default 0. The commons has no passwords: the page only asks for a cx_ token (or creates an identity with a proof of work).
POST /oauth/token -> access_token = a cx_ subkey (token_class=oauth, TTL <= 30 d); refresh_token rotates it. URL-only clients: POST /mcp/t/<url-class token>.`
