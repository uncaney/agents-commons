package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
)

// Verified-crawler lane (SPEC-v2 27.1, invariant 24.23). Two sources of truth, both outside the
// request body: the edge's verdict (X-CF-Bot / X-CF-Bot-Cat, authentic only behind X-CX-Edge ==
// EDGE_SECRET, the X-ASN rule of 3.2) and Web Bot Auth (RFC 9421 signatures by ed25519 keys read
// from bot_keys for the compiled-in BotHosts). The middleware stores the category in the context;
// the limiter (specsFor), the shed rungs (Shed) and the PoW hint read it through BotLaneFn.

const (
	BotDirMax     = 64 << 10 // Web Bot Auth directory cap, courier fetch and ack result alike
	botKeysMax    = 16       // keys kept per host
	botSkew       = 5 * time.Minute
	botHeaderMax  = 2048 // each Signature* header
	botCacheTTL   = time.Minute
	botCatMax     = 32
	botCatsMax    = 64 // distinct categories counted in memory; the rest fold into "other"
	botMaxLabels  = 4
	botMaxComps   = 32
	botMaxParams  = 16
	botKeyRefresh = "24 hours"
)

// BotHosts are the Web Bot Auth directories the lane trusts (27.1). Compiled in: request data never
// adds a host, so no attacker-chosen directory is ever fetched or looked up.
var BotHosts = []string{"chatgpt.com", "openai.com"}

type botLaneKey struct{}

// BotLaneFrom implements BotLaneFn: the category BotLaneMiddleware stored, if any.
func BotLaneFrom(ctx context.Context) (verified bool, cat string) {
	cat, verified = ctx.Value(botLaneKey{}).(string)
	return verified, cat
}

// WithBotLane marks ctx as verified-crawler traffic of category cat (middleware and tests).
func WithBotLane(ctx context.Context, cat string) context.Context {
	return context.WithValue(ctx, botLaneKey{}, cat)
}

// BotLaneSuffix is the arrivals UA-family suffix of a request: ":v" when verified (27.1 /stats).
func BotLaneSuffix(ctx context.Context) string {
	if ok, _ := BotLane(ctx); ok {
		return ":v"
	}
	return ""
}

// BotLaneMiddleware identifies verified crawlers before Handler (installed by the integration
// package as the outer wrapper): edge headers first, Web Bot Auth second, unverified otherwise.
// Verified requests carry their category in the context (BotLaneFrom), are counted per category and
// never receive a PoW hint. The first call per Deps installs BotLaneFn and the botlane janitor task
// (daily botkeys fetches, counter flush).
func (d *Deps) BotLaneMiddleware(next http.Handler) http.Handler {
	BotLaneFn = BotLaneFrom
	d.installBotLane()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cat, ok := d.botLane(r)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}
		botStats.count(cat)
		next.ServeHTTP(&botWriter{ResponseWriter: w}, r.WithContext(WithBotLane(r.Context(), cat)))
	})
}

// edgeTrusted reports whether the edge headers of r are authentic: X-CX-Edge equals EDGE_SECRET
// (constant time; an unset secret trusts nothing).
func (d *Deps) edgeTrusted(r *http.Request) bool {
	return d.Cfg.EdgeSecret != "" && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CX-Edge")), []byte(d.Cfg.EdgeSecret)) == 1
}

// botLane returns the verified category of r: the edge's verdict, else a Web Bot Auth signature.
func (d *Deps) botLane(r *http.Request) (string, bool) {
	if strings.TrimSpace(r.Header.Get("X-CF-Bot")) == "1" && d.edgeTrusted(r) {
		return botCategory(r.Header.Get("X-CF-Bot-Cat")), true
	}
	for _, h := range [...]string{"Signature-Agent", "Signature-Input", "Signature"} {
		if v := r.Header.Get(h); v == "" || len(v) > botHeaderMax {
			return "", false
		}
	}
	return d.webBotAuth(r)
}

// botCategory normalises the edge's category (cf.verified_bot_category, e.g. "Search Engine
// Crawler") to a limiter-key token: lowercase alphanumeric runs joined by '-', <= 32 bytes, "bot"
// when absent (the Free plan has no category field).
func botCategory(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		if b.Len() >= botCatMax {
			break
		}
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			if dash && b.Len() > 0 {
				b.WriteByte('-')
			}
			dash = false
			b.WriteRune(r)
			continue
		}
		dash = true
	}
	if b.Len() == 0 {
		return "bot"
	}
	return strings.TrimSuffix(b.String(), "-")
}

// botWriter drops the PoW challenge (WWW-Authenticate: PoW …) from a verified crawler's reply
// (24.23); the Bearer challenge and everything else pass through.
type botWriter struct {
	http.ResponseWriter
	wrote bool
}

func (b *botWriter) WriteHeader(c int) {
	if !b.wrote {
		b.wrote = true
		h := b.Header()
		if vs := h.Values("WWW-Authenticate"); len(vs) > 0 {
			kept := make([]string, 0, len(vs))
			for _, v := range vs {
				if !strings.HasPrefix(strings.TrimSpace(v), "PoW ") {
					kept = append(kept, v)
				}
			}
			h.Del("WWW-Authenticate")
			for _, v := range kept {
				h.Add("WWW-Authenticate", v)
			}
		}
	}
	b.ResponseWriter.WriteHeader(c)
}

func (b *botWriter) Write(p []byte) (int, error) {
	if !b.wrote {
		b.WriteHeader(http.StatusOK)
	}
	return b.ResponseWriter.Write(p)
}

func (b *botWriter) Flush() {
	if !b.wrote {
		b.WriteHeader(http.StatusOK)
	}
	if f, ok := b.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (b *botWriter) Unwrap() http.ResponseWriter { return b.ResponseWriter }

// ---- Web Bot Auth (RFC 9421 over ed25519) ----

// webBotAuth verifies the request's HTTP message signature against the keys of its Signature-Agent
// host: the signature base is rebuilt from the covered components (which must include @authority
// and signature-agent), created/expires must sit within botSkew of now, the key is matched by JWK
// kid or RFC 7638 thumbprint. Unknown hosts are ignored without any lookup. The category of a
// verified request is the directory host.
func (d *Deps) webBotAuth(r *http.Request) (string, bool) {
	host := botAgentHost(r.Header.Get("Signature-Agent"))
	if host == "" {
		return "", false
	}
	inputs, ok := parseSigInputs(r.Header.Get("Signature-Input"))
	if !ok {
		return "", false
	}
	sigs, ok := parseSigs(r.Header.Get("Signature"))
	if !ok {
		return "", false
	}
	keys := d.botKeys(r.Context(), host)
	if len(keys) == 0 {
		return "", false
	}
	now := time.Now()
	for _, in := range inputs {
		sig := sigs[in.label]
		if len(sig) != ed25519.SignatureSize || !in.valid(now) {
			continue
		}
		base, ok := signatureBase(r, in)
		if !ok {
			continue
		}
		for _, k := range keys {
			if (k.kid == in.keyid || k.thumb == in.keyid) && ed25519.Verify(k.pub, base, sig) {
				return host, true
			}
		}
	}
	return "", false
}

// botAgentHost maps a Signature-Agent value (an sf-string holding an https origin or a bare host,
// quotes optional) to a compiled-in host; "" for anything else.
func botAgentHost(v string) string {
	s := strings.TrimSpace(v)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		s = s[1 : len(s)-1]
	}
	if strings.Contains(s, "://") {
		u, err := url.Parse(s)
		if err != nil || u.Scheme != "https" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || (u.Port() != "" && u.Port() != "443") {
			return ""
		}
		s = u.Hostname()
	}
	s = strings.ToLower(strings.TrimSuffix(s, "."))
	for _, h := range BotHosts {
		if s == h {
			return h
		}
	}
	return ""
}

// botJWK is one usable directory key.
type botJWK struct {
	kid, thumb string
	pub        ed25519.PublicKey
}

type botKeyEntry struct {
	keys []botJWK
	at   time.Time
}

var botKeyCache = struct {
	sync.Mutex
	m map[string]botKeyEntry
}{m: map[string]botKeyEntry{}}

// botKeys returns the keys of a compiled-in host whose bot_keys row is ok, cached for a minute
// (only BotHosts are ever asked for, so the cache holds at most that many entries).
func (d *Deps) botKeys(ctx context.Context, host string) []botJWK {
	botKeyCache.Lock()
	e, ok := botKeyCache.m[host]
	botKeyCache.Unlock()
	if ok && time.Since(e.at) < botCacheTTL {
		return e.keys
	}
	var raw json.RawMessage
	var keys []botJWK
	switch err := d.DB.QueryRow(ctx, `SELECT jwks FROM bot_keys WHERE agent_host = $1 AND ok`, host).Scan(&raw); {
	case err == nil:
		keys, _ = parseJWKS(raw)
	case !errors.Is(err, pgx.ErrNoRows):
		return nil // transient: not cached
	}
	botKeyCache.Lock()
	botKeyCache.m[host] = botKeyEntry{keys, time.Now()}
	botKeyCache.Unlock()
	return keys
}

func botKeyForget(host string) {
	botKeyCache.Lock()
	delete(botKeyCache.m, host)
	botKeyCache.Unlock()
}

// parseJWKS keeps the Ed25519 keys of a directory (kty OKP, crv Ed25519, x = 32 bytes, kid <= 128
// chars), at most botKeysMax, and returns the compact JWKS to store; nil when none is usable.
func parseJWKS(raw []byte) ([]botJWK, json.RawMessage) {
	if len(raw) == 0 || len(raw) > BotDirMax {
		return nil, nil
	}
	var dir struct {
		Keys []struct {
			Kty string `json:"kty"`
			Crv string `json:"crv"`
			Kid string `json:"kid"`
			X   string `json:"x"`
		} `json:"keys"`
	}
	if json.Unmarshal(raw, &dir) != nil {
		return nil, nil
	}
	type jwk struct {
		Kty string `json:"kty"`
		Crv string `json:"crv"`
		Kid string `json:"kid,omitempty"`
		X   string `json:"x"`
	}
	var keys []botJWK
	var out []jwk
	for _, k := range dir.Keys {
		if k.Kty != "OKP" || k.Crv != "Ed25519" || len(k.Kid) > 128 {
			continue
		}
		x, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(k.X, "="))
		if err != nil || len(x) != ed25519.PublicKeySize {
			continue
		}
		xs := base64.RawURLEncoding.EncodeToString(x)
		th := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + xs + `"}`)) // RFC 7638 / RFC 8037
		keys = append(keys, botJWK{kid: k.Kid, thumb: base64.RawURLEncoding.EncodeToString(th[:]), pub: ed25519.PublicKey(x)})
		out = append(out, jwk{"OKP", "Ed25519", k.Kid, xs})
		if len(keys) >= botKeysMax {
			break
		}
	}
	if len(keys) == 0 {
		return nil, nil
	}
	b, _ := json.Marshal(map[string][]jwk{"keys": out})
	return keys, b
}

// BotKeysResult stores a courier `botkeys` ack (egress.ResultFn["botkeys"], wired by the
// integration package): payload {host}, result {host, jwks?, err?}. A directory with no usable key
// (missing, too large, malformed, err set) marks the host ok=false so its keys stop verifying
// until a later fetch succeeds; hosts outside BotHosts are ignored.
func BotKeysResult(ctx context.Context, q Q, payload, result json.RawMessage) error {
	var p struct {
		Host string `json:"host"`
	}
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	host := botAgentHost(p.Host)
	if host == "" {
		return nil
	}
	var res struct {
		Host string          `json:"host"`
		JWKS json.RawMessage `json:"jwks"`
		Err  string          `json:"err"`
	}
	var jwks json.RawMessage
	if len(result) > 0 && len(result) <= BotDirMax+4096 && json.Unmarshal(result, &res) == nil && res.Err == "" && (res.Host == "" || botAgentHost(res.Host) == host) {
		_, jwks = parseJWKS(res.JWKS)
	}
	defer botKeyForget(host)
	if jwks == nil {
		_, err := q.Exec(ctx, `INSERT INTO bot_keys (agent_host, jwks, fetched_at, ok) VALUES ($1, '{"keys":[]}', now(), false)
			ON CONFLICT (agent_host) DO UPDATE SET fetched_at = now(), ok = false`, host)
		return err
	}
	_, err := q.Exec(ctx, `INSERT INTO bot_keys (agent_host, jwks, fetched_at, ok) VALUES ($1, $2, now(), true)
		ON CONFLICT (agent_host) DO UPDATE SET jwks = EXCLUDED.jwks, fetched_at = now(), ok = true`, host, jwks)
	return err
}

// EnqueueBotKeys enqueues one `botkeys` outbox row per compiled-in host due for its daily fetch (no
// row, or fetched a day ago) that has no live row yet; returns how many it enqueued. Request data
// never reaches this path.
func (d *Deps) EnqueueBotKeys(ctx context.Context) (int, error) {
	n := 0
	for _, host := range BotHosts {
		var due bool
		if err := d.DB.QueryRow(ctx, `SELECT NOT EXISTS (SELECT 1 FROM bot_keys WHERE agent_host = $1 AND fetched_at > now() - $2::interval)
			AND NOT EXISTS (SELECT 1 FROM egress_outbox WHERE kind = 'botkeys' AND done_at IS NULL AND payload->>'host' = $1)`,
			host, botKeyRefresh).Scan(&due); err != nil {
			return n, err
		}
		if !due {
			continue
		}
		if err := Egress(ctx, d.DB, "botkeys", map[string]string{"host": host}); err != nil {
			if errors.Is(err, ErrOutboxFull) {
				continue
			}
			return n, err
		}
		n++
	}
	return n, nil
}

var botInstalled sync.Map // *Deps -> struct{}

// installBotLane registers the janitor task once per Deps.
func (d *Deps) installBotLane() {
	if _, dup := botInstalled.LoadOrStore(d, struct{}{}); dup || d.Janitor == nil {
		return
	}
	d.Janitor.Add("botlane", func(ctx context.Context) error {
		if err := botStats.flush(ctx, d.DB); err != nil {
			return err
		}
		_, err := d.EnqueueBotKeys(ctx)
		return err
	})
}

// ---- per-category counters ----

// botStats counts verified requests per category in memory; the janitor flushes them into
// counters (scope "bot:<cat>", kind "verified", 2-day retention) so /admin/stats can list them.
var botStats = botCounter{pending: map[string]int{}}

type botCounter struct {
	mu      sync.Mutex
	pending map[string]int
}

func (c *botCounter) count(cat string) {
	c.mu.Lock()
	if _, ok := c.pending[cat]; !ok && len(c.pending) >= botCatsMax {
		cat = "other"
	}
	c.pending[cat]++
	c.mu.Unlock()
}

func (c *botCounter) flush(ctx context.Context, q Q) error {
	c.mu.Lock()
	batch := c.pending
	c.pending = map[string]int{}
	c.mu.Unlock()
	for cat, n := range batch {
		if _, err := bump(ctx, q, "bot:"+cat, "verified", n); err != nil {
			return err
		}
	}
	return nil
}

// BotLaneStats lists the verified categories seen over the counters' window as "<cat>=<n>" lines,
// busiest first (for /admin/stats and the digest).
func BotLaneStats(ctx context.Context, q Q) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT substr(scope, 5), sum(n) FROM counters WHERE kind = 'verified' AND scope LIKE 'bot:%'
		GROUP BY 1 ORDER BY 2 DESC, 1 LIMIT $1`, botCatsMax)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var cat string
		var n int64
		if err := rows.Scan(&cat, &n); err != nil {
			return nil, err
		}
		out = append(out, cleanLine(cat, botCatMax)+"="+strconv.FormatInt(n, 10))
	}
	return out, rows.Err()
}

func init() {
	statTables["bot_categories"] = `SELECT count(DISTINCT scope) FROM counters WHERE kind = 'verified' AND scope LIKE 'bot:%'`
	statTables["bot_keys_ok"] = `SELECT count(*) FROM bot_keys WHERE ok`
}

// ---- RFC 9421 signature base over a minimal RFC 8941 reader ----

// sfItem is a bare structured-field item: 's' string, 'i' integer, 't' token, 'b' byte sequence,
// '?' boolean.
type sfItem struct {
	kind byte
	str  string
	num  int64
	raw  []byte
	flag bool
}

func (it sfItem) String() string {
	switch it.kind {
	case 's':
		return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(it.str) + `"`
	case 'i':
		return strconv.FormatInt(it.num, 10)
	case 't':
		return it.str
	case 'b':
		return ":" + base64.StdEncoding.EncodeToString(it.raw) + ":"
	}
	if it.flag {
		return "?1"
	}
	return "?0"
}

type sfParam struct {
	key string
	val sfItem
}

// serializeParams re-serialises parameters canonically (a true boolean is the bare key).
func serializeParams(ps []sfParam) string {
	var b strings.Builder
	for _, p := range ps {
		b.WriteByte(';')
		b.WriteString(p.key)
		if p.val.kind == '?' && p.val.flag {
			continue
		}
		b.WriteByte('=')
		b.WriteString(p.val.String())
	}
	return b.String()
}

type sfReader struct {
	s string
	i int
}

func (p *sfReader) eof() bool { return p.i >= len(p.s) }

func (p *sfReader) peek() byte {
	if p.eof() {
		return 0
	}
	return p.s[p.i]
}

func (p *sfReader) ws() {
	for !p.eof() && (p.s[p.i] == ' ' || p.s[p.i] == '\t') {
		p.i++
	}
}

func isLcAlpha(c byte) bool { return c >= 'a' && c <= 'z' }
func isAlpha(c byte) bool   { return isLcAlpha(c) || (c >= 'A' && c <= 'Z') }
func isDigit(c byte) bool   { return c >= '0' && c <= '9' }
func isTchar(c byte) bool {
	return isAlpha(c) || isDigit(c) || strings.IndexByte("!#$%&'*+-.^_`|~:/", c) >= 0
}

func (p *sfReader) key() (string, bool) {
	start := p.i
	if c := p.peek(); !(isLcAlpha(c) || c == '*') {
		return "", false
	}
	for !p.eof() {
		c := p.s[p.i]
		if !(isLcAlpha(c) || isDigit(c) || c == '_' || c == '-' || c == '.' || c == '*') {
			break
		}
		p.i++
	}
	return p.s[start:p.i], true
}

// str reads an sf-string (printable ASCII, \" and \\ escapes) starting at its opening quote.
func (p *sfReader) str() (string, bool) {
	if p.peek() != '"' {
		return "", false
	}
	p.i++
	var b strings.Builder
	for !p.eof() {
		c := p.s[p.i]
		p.i++
		switch {
		case c == '"':
			return b.String(), true
		case c == '\\':
			if p.eof() || (p.s[p.i] != '"' && p.s[p.i] != '\\') {
				return "", false
			}
			b.WriteByte(p.s[p.i])
			p.i++
		case c < 0x20 || c > 0x7e:
			return "", false
		default:
			b.WriteByte(c)
		}
	}
	return "", false
}

func (p *sfReader) bareItem() (sfItem, bool) {
	switch c := p.peek(); {
	case c == '"':
		s, ok := p.str()
		return sfItem{kind: 's', str: s}, ok
	case c == ':':
		p.i++
		end := strings.IndexByte(p.s[p.i:], ':')
		if end < 0 {
			return sfItem{}, false
		}
		enc := p.s[p.i : p.i+end]
		p.i += end + 1
		raw, err := base64.StdEncoding.DecodeString(enc)
		if err != nil {
			if raw, err = base64.RawStdEncoding.DecodeString(enc); err != nil {
				return sfItem{}, false
			}
		}
		return sfItem{kind: 'b', raw: raw}, true
	case c == '?':
		p.i++
		v := p.peek()
		p.i++
		if v != '0' && v != '1' {
			return sfItem{}, false
		}
		return sfItem{kind: '?', flag: v == '1'}, true
	case c == '-' || isDigit(c):
		start := p.i
		if c == '-' {
			p.i++
		}
		for !p.eof() && isDigit(p.s[p.i]) {
			p.i++
		}
		if p.peek() == '.' || p.i-start > 16 {
			return sfItem{}, false // decimals are not used by signature parameters
		}
		n, err := strconv.ParseInt(p.s[start:p.i], 10, 64)
		if err != nil {
			return sfItem{}, false
		}
		return sfItem{kind: 'i', num: n}, true
	case isAlpha(c) || c == '*':
		start := p.i
		for !p.eof() && isTchar(p.s[p.i]) {
			p.i++
		}
		return sfItem{kind: 't', str: p.s[start:p.i]}, true
	}
	return sfItem{}, false
}

// params reads *( ";" *SP key [ "=" bare-item ] ); a repeated key keeps its last value in place.
func (p *sfReader) params() ([]sfParam, bool) {
	var out []sfParam
	for p.peek() == ';' {
		p.i++
		p.ws()
		k, ok := p.key()
		if !ok {
			return nil, false
		}
		it := sfItem{kind: '?', flag: true}
		if p.peek() == '=' {
			p.i++
			if it, ok = p.bareItem(); !ok {
				return nil, false
			}
		}
		dup := false
		for i := range out {
			if out[i].key == k {
				out[i].val, dup = it, true
			}
		}
		if !dup {
			out = append(out, sfParam{k, it})
		}
		if len(out) > botMaxParams {
			return nil, false
		}
	}
	return out, true
}

// sfComp is one covered component: its identifier (an sf-string) with parameters.
type sfComp struct {
	name   string
	params []sfParam
}

func (c sfComp) id() string {
	return sfItem{kind: 's', str: c.name}.String() + serializeParams(c.params)
}

// sigInput is one Signature-Input member: label, covered components and signature parameters.
type sigInput struct {
	label                  string
	comps                  []sfComp
	params                 []sfParam
	keyid                  string
	alg                    string
	tag                    string
	created, expires       int64
	hasCreated, hasExpires bool
}

// parseSigInputs reads the Signature-Input dictionary (<= botMaxLabels inner lists).
func parseSigInputs(h string) ([]sigInput, bool) {
	p := &sfReader{s: h}
	var out []sigInput
	for {
		p.ws()
		label, ok := p.key()
		if !ok || p.peek() != '=' {
			return nil, false
		}
		p.i++
		if p.peek() != '(' {
			return nil, false
		}
		p.i++
		in := sigInput{label: label}
		for {
			p.ws()
			if p.peek() == ')' {
				p.i++
				break
			}
			name, ok := p.str()
			if !ok {
				return nil, false
			}
			ps, ok := p.params()
			if !ok {
				return nil, false
			}
			in.comps = append(in.comps, sfComp{name, ps})
			if len(in.comps) > botMaxComps {
				return nil, false
			}
		}
		if in.params, ok = p.params(); !ok {
			return nil, false
		}
		for _, prm := range in.params {
			switch prm.key {
			case "created":
				in.created, in.hasCreated = prm.val.num, prm.val.kind == 'i'
			case "expires":
				in.expires, in.hasExpires = prm.val.num, prm.val.kind == 'i'
			case "keyid":
				in.keyid = prm.val.str
			case "alg":
				in.alg = prm.val.str
			case "tag":
				in.tag = prm.val.str
			}
		}
		out = append(out, in)
		p.ws()
		if p.eof() {
			return out, true
		}
		if p.peek() != ',' || len(out) >= botMaxLabels {
			return nil, false
		}
		p.i++
	}
}

// parseSigs reads the Signature dictionary: label -> raw signature bytes.
func parseSigs(h string) (map[string][]byte, bool) {
	p := &sfReader{s: h}
	out := map[string][]byte{}
	for {
		p.ws()
		label, ok := p.key()
		if !ok || p.peek() != '=' {
			return nil, false
		}
		p.i++
		it, ok := p.bareItem()
		if !ok || it.kind != 'b' {
			return nil, false
		}
		if _, ok := p.params(); !ok {
			return nil, false
		}
		out[label] = it.raw
		p.ws()
		if p.eof() {
			return out, true
		}
		if p.peek() != ',' || len(out) >= botMaxLabels {
			return nil, false
		}
		p.i++
	}
}

// valid applies the Web Bot Auth rules: ed25519, a keyid, created within botSkew of now, expires
// (when present) after created and not past by more than botSkew, tag web-bot-auth when present,
// and coverage of @authority and signature-agent.
func (in *sigInput) valid(now time.Time) bool {
	if in.keyid == "" || !in.hasCreated || (in.alg != "" && in.alg != "ed25519") || (in.tag != "" && in.tag != "web-bot-auth") {
		return false
	}
	created := time.Unix(in.created, 0)
	if created.After(now.Add(botSkew)) || created.Before(now.Add(-botSkew)) {
		return false
	}
	if in.hasExpires && (in.expires <= in.created || time.Unix(in.expires, 0).Before(now.Add(-botSkew))) {
		return false
	}
	var auth, agent bool
	for _, c := range in.comps {
		auth = auth || c.name == "@authority"
		agent = agent || c.name == "signature-agent"
	}
	return auth && agent
}

// signatureParams is the @signature-params value: the inner list of component identifiers with
// the signature parameters, serialised canonically (RFC 9421 2.3).
func (in *sigInput) signatureParams() string {
	ids := make([]string, len(in.comps))
	for i, c := range in.comps {
		ids[i] = c.id()
	}
	return "(" + strings.Join(ids, " ") + ")" + serializeParams(in.params)
}

// signatureBase rebuilds the RFC 9421 signature base of r for one Signature-Input member; false on
// a duplicate or unsupported component or one the request does not carry.
func signatureBase(r *http.Request, in sigInput) ([]byte, bool) {
	var b strings.Builder
	seen := map[string]bool{}
	for _, c := range in.comps {
		id := c.id()
		if seen[id] {
			return nil, false
		}
		seen[id] = true
		v, ok := componentValue(r, c)
		if !ok {
			return nil, false
		}
		b.WriteString(id)
		b.WriteString(": ")
		b.WriteString(v)
		b.WriteByte('\n')
	}
	b.WriteString(`"@signature-params": `)
	b.WriteString(in.signatureParams())
	return []byte(b.String()), true
}

// componentValue resolves a derived component or a plain header field (RFC 9421 2.1-2.2). Parameters
// (sf, bs, key, req, tr, name) are not used by Web Bot Auth and make the component unsupported.
func componentValue(r *http.Request, c sfComp) (string, bool) {
	if len(c.params) > 0 {
		return "", false
	}
	switch c.name {
	case "@method":
		return r.Method, true
	case "@authority":
		return botAuthority(r), true
	case "@scheme":
		return "https", true // the public origin is https-only; signers sign the public URL
	case "@target-uri":
		return "https://" + botAuthority(r) + r.URL.RequestURI(), true
	case "@request-target":
		return r.URL.RequestURI(), true
	case "@path":
		if p := r.URL.EscapedPath(); p != "" {
			return p, true
		}
		return "/", true
	case "@query":
		return "?" + r.URL.RawQuery, true
	case "host":
		return r.Host, true
	}
	if c.name == "" || c.name[0] == '@' || c.name != strings.ToLower(c.name) {
		return "", false
	}
	vs := r.Header.Values(c.name)
	if len(vs) == 0 {
		return "", false
	}
	parts := make([]string, len(vs))
	for i, v := range vs {
		parts[i] = strings.TrimSpace(v)
	}
	return strings.Join(parts, ", "), true
}

// botAuthority is the @authority value: the lowercase host, default https port dropped.
func botAuthority(r *http.Request) string {
	h := strings.ToLower(strings.TrimSpace(r.Host))
	return strings.TrimSuffix(h, ":443")
}
