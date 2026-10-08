package core

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

const testEdgeSecret = "edge-secret-0123456789"

// newBotEnv is newWire with BotLaneMiddleware as the outer wrapper (the production shape) and a
// /lane route echoing the lane state plus a /pow route handing out the anonymous PoW challenge.
func newBotEnv(t *testing.T, edgeSecret string) *tenv {
	t.Helper()
	cfg := Config{ServerSecret: []byte("test-secret-0123456789"), AdminToken: "adm-token", PowBits: 6, DataDir: t.TempDir(), TrustCF: true,
		PublicURL: "https://agents.example", EdgeSecret: edgeSecret}
	d, err := NewDeps(context.Background(), cfg, testPool, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(d.Close)
	mux := http.NewServeMux()
	Register(mux, d)
	mux.HandleFunc("GET /lane", func(w http.ResponseWriter, r *http.Request) {
		ok, cat := BotLane(r.Context())
		OK(w, r, fmt.Sprintf("v=%v cat=%s ua=%s", ok, cat, BotLaneSuffix(r.Context())), nil)
	})
	mux.HandleFunc("GET /pow", func(w http.ResponseWriter, r *http.Request) {
		d.PoWAuthenticate(w, r)
		Fail(w, r, ErrAuth)
	})
	srv := httptest.NewServer(d.BotLaneMiddleware(d.Handler(mux)))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { BotLaneFn = nil })
	var b [2]byte
	rand.Read(b[:])
	return &tenv{d, srv, fmt.Sprintf("10.9.%d.%d", b[0], b[1])}
}

// get sends a GET with the client IP, a fixed public Host and the given header pairs.
func (e *tenv) get(t *testing.T, path, ip string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, _ := http.NewRequest("GET", e.srv.URL+path, nil)
	req.Host = "agents.example"
	req.Header.Set("CF-Connecting-IP", ip)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, strings.TrimSpace(string(b)), res.Header
}

func TestBotLaneSpoofIgnored(t *testing.T) {
	e := newBotEnv(t, testEdgeSecret)
	ip := e.ip
	for name, hdr := range map[string][]string{
		"no edge header":    {"X-CF-Bot", "1", "X-CF-Bot-Cat", "AI Crawler"},
		"wrong edge secret": {"X-CF-Bot", "1", "X-CF-Bot-Cat", "AI Crawler", "X-CX-Edge", "nope"},
		"edge says not bot": {"X-CF-Bot", "0", "X-CF-Bot-Cat", "AI Crawler", "X-CX-Edge", testEdgeSecret},
		"empty edge value":  {"X-CF-Bot", "1", "X-CX-Edge", ""},
	} {
		if st, body, _ := e.get(t, "/lane", ip, hdr...); st != 200 || body != "v=false cat= ua=" {
			t.Fatalf("%s: %d %s", name, st, body)
		}
	}
	if st, body, _ := e.get(t, "/lane", ip, "X-CF-Bot", "1", "X-CF-Bot-Cat", "AI Crawler", "X-CX-Edge", testEdgeSecret); st != 200 || body != "v=true cat=ai-crawler ua=:v" {
		t.Fatalf("verified: %d %s", st, body)
	}
	if st, body, _ := e.get(t, "/lane", ip, "X-CF-Bot", "1", "X-CX-Edge", testEdgeSecret); st != 200 || body != "v=true cat=bot ua=:v" {
		t.Fatalf("verified without category (Free plan): %d %s", st, body)
	}
	// Spoofed traffic pays from its own IP bucket: the anonymous burst (20) runs out.
	base := time.Now()
	e.d.Lim.now = func() time.Time { return base }
	denied := 0
	for i := 0; i < 25; i++ {
		if st, _, _ := e.get(t, "/lane", "10.9.250.1", "X-CF-Bot", "1", "X-CF-Bot-Cat", "Search Engine Crawler"); st == 429 {
			denied++
		}
	}
	if denied != 5 {
		t.Fatalf("spoofed requests charged a bot budget: denied=%d", denied)
	}
	// An unset EDGE_SECRET trusts nothing, whatever the client sends.
	e2 := newBotEnv(t, "")
	if st, body, _ := e2.get(t, "/lane", e2.ip, "X-CF-Bot", "1", "X-CF-Bot-Cat", "ai", "X-CX-Edge", ""); st != 200 || body != "v=false cat= ua=" {
		t.Fatalf("unset secret: %d %s", st, body)
	}
	for in, want := range map[string]string{"Search Engine Crawler": "search-engine-crawler", "Monitoring & Analytics": "monitoring-analytics",
		"": "bot", "  ": "bot", "AI_Crawler!!": "ai-crawler", strings.Repeat("abcdefghij", 5): strings.Repeat("abcdefghij", 3) + "ab"} {
		if got := botCategory(in); got != want {
			t.Fatalf("botCategory(%q) = %q want %q", in, got, want)
		}
	}
}

func TestBotLaneVerifiedCategoryBudget(t *testing.T) {
	e := newBotEnv(t, testEdgeSecret)
	ip := "10.9.251.7"
	base := time.Now()
	now := base
	e.d.Lim.now = func() time.Time { return now }
	// 15 r/s for 10 s from one IP: the verified crawler never sees a 429 (bot:<cat> 20 r/s, burst
	// 100, charged per category); an unverified client from the same IP exhausts its group bucket.
	botDenied, anonDenied := 0, 0
	for i := 0; i < 150; i++ {
		now = base.Add(time.Duration(i) * time.Second / 15)
		if st, _, h := e.get(t, "/lane", ip, "X-CF-Bot", "1", "X-CF-Bot-Cat", "Search Engine Crawler", "X-CX-Edge", testEdgeSecret); st == 429 {
			botDenied++
		} else if h.Get("RateLimit-Policy") != "100;w=5" {
			t.Fatalf("bot budget headers: %q", h.Get("RateLimit-Policy"))
		}
		if st, _, _ := e.get(t, "/lane", ip); st == 429 {
			anonDenied++
		}
	}
	if botDenied != 0 || anonDenied == 0 {
		t.Fatalf("verified denied=%d unverified denied=%d", botDenied, anonDenied)
	}
	// Another category has its own bucket; the verified lane never charged the IP group either:
	// a fresh anonymous request from a different IP in the same /24 still has its super-group budget.
	if st, _, _ := e.get(t, "/lane", ip, "X-CF-Bot", "1", "X-CF-Bot-Cat", "AI Assistant", "X-CX-Edge", testEdgeSecret); st != 200 {
		t.Fatalf("second category: %d", st)
	}
	// No PoW hint for verified traffic: the anonymous challenge disappears, the 401 stays.
	now = now.Add(time.Minute) // refill the exhausted anonymous bucket
	st, _, h := e.get(t, "/pow", ip)
	if st != 401 || !strings.Contains(strings.Join(h.Values("WWW-Authenticate"), "|"), "PoW realm=") {
		t.Fatalf("anonymous PoW hint: %d %v", st, h.Values("WWW-Authenticate"))
	}
	st, _, h = e.get(t, "/pow", ip, "X-CF-Bot", "1", "X-CF-Bot-Cat", "AI Crawler", "X-CX-Edge", testEdgeSecret)
	if st != 401 || strings.Contains(strings.Join(h.Values("WWW-Authenticate"), "|"), "PoW") {
		t.Fatalf("verified PoW hint: %d %v", st, h.Values("WWW-Authenticate"))
	}
	// Shed exemption on reads (feeds, anon-search), not on longpoll; never for writes.
	ctx := context.Background()
	cleanFlags(t, e.d, "shed:feeds", "shed:anon-search", "shed:longpoll")
	for _, k := range []string{"shed:feeds", "shed:anon-search", "shed:longpoll"} {
		if err := e.d.SetFlag(ctx, k, true, ""); err != nil {
			t.Fatal(err)
		}
	}
	bot := fakeReq(ip).WithContext(WithBotLane(context.Background(), "ai-crawler"))
	if e.d.Shed(bot, "feeds") || e.d.Shed(bot, "anon-search") || !e.d.Shed(bot, "longpoll") || !e.d.Shed(fakeReq(ip), "feeds") {
		t.Fatal("shed exemption")
	}
	// Categories are counted and flushed to counters; /admin/stats carries the counts.
	if err := botStats.flush(ctx, testPool); err != nil {
		t.Fatal(err)
	}
	lines, err := BotLaneStats(ctx, testPool)
	if err != nil {
		t.Fatal(err)
	}
	var seen bool
	for _, l := range lines {
		cat, ns, _ := strings.Cut(l, "=")
		if n, err := strconv.Atoi(ns); cat == "search-engine-crawler" && err == nil && n >= 150 {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("BotLaneStats: %v", lines)
	}
	st, body, _ := e.doH(t, "GET", "/admin/stats", "adm-token", "")
	if st != 200 || !strings.Contains(body, "bot_categories=") || !strings.Contains(body, "bot_keys_ok=") {
		t.Fatalf("/admin/stats: %d %s", st, body)
	}
}

// signer builds Web Bot Auth headers for a request the way a crawler would (RFC 9421 base written
// by hand, independently of the verifier).
type signer struct {
	priv  ed25519.PrivateKey
	keyid string
}

type sigOpts struct {
	agent, label, authority, alg, tag string
	created, expires                  int64
	comps                             []string
	extraParams                       string
}

func (s signer) headers(o sigOpts) []string {
	if o.label == "" {
		o.label = "sig1"
	}
	if o.comps == nil {
		o.comps = []string{"@authority", "signature-agent"}
	}
	ids := make([]string, len(o.comps))
	for i, c := range o.comps {
		ids[i] = `"` + c + `"`
	}
	params := fmt.Sprintf(`(%s);created=%d;keyid="%s"`, strings.Join(ids, " "), o.created, s.keyid)
	if o.alg != "" {
		params += `;alg="` + o.alg + `"`
	}
	if o.expires != 0 {
		params += fmt.Sprintf(";expires=%d", o.expires)
	}
	params += `;nonce="e8N7S2MFd/qrd6T2R3tdfAuuANngKI7LFtKYI/vowzk="`
	if o.tag != "" {
		params += `;tag="` + o.tag + `"`
	}
	params += o.extraParams
	var base strings.Builder
	for _, c := range o.comps {
		switch c {
		case "@authority":
			fmt.Fprintf(&base, "\"@authority\": %s\n", o.authority)
		case "signature-agent":
			fmt.Fprintf(&base, "\"signature-agent\": %s\n", o.agent)
		case "@method":
			base.WriteString("\"@method\": GET\n")
		case "@path":
			base.WriteString("\"@path\": /lane\n")
		}
	}
	base.WriteString(`"@signature-params": ` + params)
	sig := ed25519.Sign(s.priv, []byte(base.String()))
	return []string{"Signature-Agent", o.agent, "Signature-Input", o.label + "=" + params,
		"Signature", o.label + "=:" + base64.StdEncoding.EncodeToString(sig) + ":"}
}

func jwks(pub ed25519.PublicKey, kid string) string {
	return fmt.Sprintf(`{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"%s","x":"%s","purpose":"rag"}]}`, kid, base64.RawURLEncoding.EncodeToString(pub))
}

func thumbprint(pub ed25519.PublicKey) string {
	h := sha256.Sum256([]byte(`{"crv":"Ed25519","kty":"OKP","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}`))
	return base64.RawURLEncoding.EncodeToString(h[:])
}

func storeBotKeys(t *testing.T, host, result string) {
	t.Helper()
	payload, _ := json.Marshal(map[string]string{"host": host})
	if err := BotKeysResult(context.Background(), testPool, payload, json.RawMessage(result)); err != nil {
		t.Fatal(err)
	}
}

func resetBotKeys(t *testing.T) {
	t.Helper()
	ctx := context.Background()
	clear := func() {
		testPool.Exec(ctx, `DELETE FROM bot_keys`)
		testPool.Exec(ctx, `DELETE FROM egress_outbox WHERE kind = 'botkeys'`)
		for _, h := range BotHosts {
			botKeyForget(h)
		}
	}
	clear()
	t.Cleanup(clear)
}

func TestWebBotAuthVectors(t *testing.T) {
	resetBotKeys(t)
	e := newBotEnv(t, testEdgeSecret)
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	s := signer{priv, "k1"}
	storeBotKeys(t, "chatgpt.com", `{"host":"chatgpt.com","status":200,"jwks":`+jwks(pub, "k1")+`,"fetched":"2026-10-07T00:00:00Z"}`)
	var ok bool
	var stored string
	if err := testPool.QueryRow(ctx, `SELECT ok, jwks::text FROM bot_keys WHERE agent_host = 'chatgpt.com'`).Scan(&ok, &stored); err != nil || !ok {
		t.Fatalf("bot_keys row: ok=%v err=%v", ok, err)
	}
	if strings.Contains(stored, "purpose") || !strings.Contains(stored, `"k1"`) {
		t.Fatalf("stored jwks not compacted: %s", stored)
	}
	now := time.Now().Unix()
	good := sigOpts{agent: `"https://chatgpt.com"`, authority: "agents.example", alg: "ed25519", tag: "web-bot-auth", created: now, expires: now + 300}
	clock := time.Now()
	e.d.Lim.now = func() time.Time { return clock }
	lane := func(hdr ...string) string {
		clock = clock.Add(time.Second) // unverified vectors pay from the IP bucket: keep it refilled
		st, body, _ := e.get(t, "/lane", e.ip, hdr...)
		if st != 200 {
			t.Fatalf("lane: %d %s", st, body)
		}
		return body
	}
	verified, unverified := "v=true cat=chatgpt.com ua=:v", "v=false cat= ua="
	if got := lane(s.headers(good)...); got != verified {
		t.Fatalf("good vector: %s", got)
	}
	variants := map[string]sigOpts{
		"bare host agent":  {agent: `"chatgpt.com"`, authority: "agents.example", created: now},
		"no expires/tag":   {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now - 200},
		"more components":  {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now, expires: now + 60, tag: "web-bot-auth", comps: []string{"@method", "@authority", "@path", "signature-agent"}},
		"created at skew":  {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now - 200, expires: now - 100},
		"unknown params":   {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now, extraParams: `;foo=42;bar;baz=:AQID:`},
		"keyid thumbprint": {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now},
	}
	for name, o := range variants {
		sg := s
		if name == "keyid thumbprint" {
			sg.keyid = thumbprint(pub)
		}
		if got := lane(sg.headers(o)...); got != verified {
			t.Fatalf("%s: %s", name, got)
		}
	}
	bad := map[string]sigOpts{
		"expired":            {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now - 600, expires: now - 300},
		"future":             {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now + 600, expires: now + 900},
		"expires<=created":   {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now, expires: now},
		"other authority":    {agent: `"https://chatgpt.com"`, authority: "other.example", created: now},
		"no @authority":      {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now, comps: []string{"signature-agent"}},
		"no signature-agent": {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now, comps: []string{"@authority"}},
		"wrong alg":          {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now, alg: "rsa-pss-sha512"},
		"wrong tag":          {agent: `"https://chatgpt.com"`, authority: "agents.example", created: now, tag: "other"},
		"http origin":        {agent: `"http://chatgpt.com"`, authority: "agents.example", created: now},
		"origin with path":   {agent: `"https://chatgpt.com/x"`, authority: "agents.example", created: now},
		"lookalike host":     {agent: `"https://chatgpt.com.evil.example"`, authority: "agents.example", created: now},
	}
	for name, o := range bad {
		if got := lane(s.headers(o)...); got != unverified {
			t.Fatalf("%s accepted: %s", name, got)
		}
	}
	// Wrong key, unknown keyid, tampered signature and mismatched label.
	if got := lane(signer{priv2, "k1"}.headers(good)...); got != unverified {
		t.Fatalf("wrong key accepted: %s", got)
	}
	if got := lane(signer{priv, "k9"}.headers(good)...); got != unverified {
		t.Fatalf("unknown keyid accepted: %s", got)
	}
	hdr := s.headers(good)
	hdr[5] = "sig1=:" + base64.StdEncoding.EncodeToString(make([]byte, 64)) + ":"
	if got := lane(hdr...); got != unverified {
		t.Fatalf("zero signature accepted: %s", got)
	}
	hdr = s.headers(good)
	hdr[5] = "other" + hdr[5][4:]
	if got := lane(hdr...); got != unverified {
		t.Fatalf("label mismatch accepted: %s", got)
	}
	// Two labels: a stale proxy signature first, the crawler's second; whitespace variations.
	h1, h2 := s.headers(sigOpts{agent: `"https://chatgpt.com"`, authority: "agents.example", created: now - 900, label: "proxy"}), s.headers(good)
	if got := lane("Signature-Agent", h2[1], "Signature-Input", h1[3]+", "+h2[3], "Signature", h1[5]+" , "+h2[5]); got != verified {
		t.Fatalf("second label: %s", got)
	}
	spaced := strings.Replace(h2[3], `" "`, `"   "`, 1)
	if got := lane("Signature-Agent", h2[1], "Signature-Input", spaced, "Signature", h2[5]); got != verified {
		t.Fatalf("whitespace in inner list: %s", got)
	}
	// Malformed headers never verify (and never panic).
	for _, hs := range [][]string{
		{"Signature-Agent", `"https://chatgpt.com"`, "Signature-Input", `sig1=("@authority" "signature-agent";created=1`, "Signature", h2[5]},
		{"Signature-Agent", `"https://chatgpt.com"`, "Signature-Input", h2[3], "Signature", `sig1="not bytes"`},
		{"Signature-Agent", `"https://chatgpt.com"`, "Signature-Input", h2[3], "Signature", `sig1=:####:`},
		{"Signature-Agent", `"https://chatgpt.com"`, "Signature-Input", `sig1=("@authority" "signature-agent");created=1.5;keyid="k1"`, "Signature", h2[5]},
		{"Signature-Agent", `"https://chatgpt.com"`, "Signature-Input", `sig1=("@authority" "signature-agent");keyid="k1"`, "Signature", h2[5]},
		{"Signature-Agent", `"https://chatgpt.com"`, "Signature-Input", `sig1=("@authority" "signature-agent";sf);created=` + fmt.Sprint(now) + `;keyid="k1"`, "Signature", h2[5]},
		{"Signature-Agent", `"https://chatgpt.com"`, "Signature-Input", strings.Repeat("sig1=(", 1000), "Signature", h2[5]},
	} {
		if got := lane(hs...); got != unverified {
			t.Fatalf("malformed accepted: %v -> %s", hs[2:4], got)
		}
	}
	// A malformed directory marks the host ok=false and its keys stop verifying; the edge verdict
	// still works and a later good fetch re-enables the keys.
	storeBotKeys(t, "chatgpt.com", `{"host":"chatgpt.com","status":200,"err":"malformed directory","fetched":"2026-10-07T00:00:00Z"}`)
	if err := testPool.QueryRow(ctx, `SELECT ok FROM bot_keys WHERE agent_host = 'chatgpt.com'`).Scan(&ok); err != nil || ok {
		t.Fatalf("malformed directory: ok=%v err=%v", ok, err)
	}
	if got := lane(s.headers(good)...); got != unverified {
		t.Fatalf("disabled host accepted: %s", got)
	}
	if got := lane("X-CF-Bot", "1", "X-CF-Bot-Cat", "AI Assistant", "X-CX-Edge", testEdgeSecret); got != "v=true cat=ai-assistant ua=:v" {
		t.Fatalf("edge verdict: %s", got)
	}
	storeBotKeys(t, "chatgpt.com", `{"host":"chatgpt.com","jwks":{"keys":[{"kty":"RSA","kid":"r"},{"kty":"OKP","crv":"Ed25519","kid":"k2","x":"`+base64.RawURLEncoding.EncodeToString(pub2)+`"}]},"fetched":"x"}`)
	if got := lane(signer{priv2, "k2"}.headers(good)...); got != verified {
		t.Fatalf("re-enabled with the new key: %s", got)
	}
	if got := lane(s.headers(good)...); got != unverified {
		t.Fatalf("rotated-out key accepted: %s", got)
	}
	// Directories with no usable key or over the cap disable the host; a result for another host is ignored.
	for _, res := range []string{`{"jwks":{"keys":[]}}`, `{"jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"k","x":"AQID"}]}}`, `{"jwks":"nope"}`, ``,
		`{"jwks":{"keys":[{"kty":"OKP","crv":"Ed25519","kid":"` + strings.Repeat("k", 70000) + `","x":"` + base64.RawURLEncoding.EncodeToString(pub) + `"}]}}`} {
		storeBotKeys(t, "chatgpt.com", res)
		if err := testPool.QueryRow(ctx, `SELECT ok FROM bot_keys WHERE agent_host = 'chatgpt.com'`).Scan(&ok); err != nil || ok {
			t.Fatalf("%.60s: ok=%v err=%v", res, ok, err)
		}
	}
	storeBotKeys(t, "chatgpt.com", `{"host":"openai.com","jwks":`+jwks(pub, "k1")+`}`)
	if err := testPool.QueryRow(ctx, `SELECT ok FROM bot_keys WHERE agent_host = 'chatgpt.com'`).Scan(&ok); err != nil || ok {
		t.Fatalf("cross-host result accepted: ok=%v err=%v", ok, err)
	}
}

func TestBotLaneUnknownHostIgnored(t *testing.T) {
	resetBotKeys(t)
	e := newBotEnv(t, testEdgeSecret)
	ctx := context.Background()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s := signer{priv, "k1"}
	now := time.Now().Unix()
	for _, agent := range []string{`"https://evil.example"`, `"evil.example"`, `"https://agents.example"`, `""`, `"https://chatgpt.com@evil.example"`} {
		st, body, _ := e.get(t, "/lane", e.ip, s.headers(sigOpts{agent: agent, authority: "agents.example", created: now, expires: now + 60, tag: "web-bot-auth"})...)
		if st != 200 || body != "v=false cat= ua=" {
			t.Fatalf("%s: %d %s", agent, st, body)
		}
	}
	var n int
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM bot_keys`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("bot_keys rows after unknown hosts: %d %v", n, err)
	}
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM egress_outbox WHERE kind = 'botkeys'`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("outbox rows from request data: %d %v", n, err)
	}
	// A courier result for a host outside the list is dropped, never stored.
	storeBotKeys(t, "evil.example", `{"host":"evil.example","jwks":{"keys":[]}}`)
	if err := testPool.QueryRow(ctx, `SELECT count(*) FROM bot_keys`).Scan(&n); err != nil || n != 0 {
		t.Fatalf("unknown host stored: %d %v", n, err)
	}
	// The daily refresh enqueues the compiled-in hosts only, once, and skips hosts fetched today.
	if got, err := e.d.EnqueueBotKeys(ctx); err != nil || got != len(BotHosts) {
		t.Fatalf("enqueue: %d %v", got, err)
	}
	if got, err := e.d.EnqueueBotKeys(ctx); err != nil || got != 0 {
		t.Fatalf("duplicate enqueue: %d %v", got, err)
	}
	rows, err := testPool.Query(ctx, `SELECT payload->>'host' FROM egress_outbox WHERE kind = 'botkeys' AND done_at IS NULL ORDER BY 1`)
	if err != nil {
		t.Fatal(err)
	}
	var hosts []string
	for rows.Next() {
		var h string
		rows.Scan(&h)
		hosts = append(hosts, h)
	}
	rows.Close()
	if strings.Join(hosts, ",") != strings.Join(BotHosts, ",") {
		t.Fatalf("enqueued hosts %v", hosts)
	}
	if _, err := testPool.Exec(ctx, `UPDATE egress_outbox SET done_at = now() WHERE kind = 'botkeys'`); err != nil {
		t.Fatal(err)
	}
	storeBotKeys(t, "chatgpt.com", `{"host":"chatgpt.com","err":"not found"}`)
	if got, err := e.d.EnqueueBotKeys(ctx); err != nil || got != len(BotHosts)-1 {
		t.Fatalf("enqueue after a fetch today: %d %v", got, err)
	}
	if _, err := testPool.Exec(ctx, `UPDATE bot_keys SET fetched_at = now() - interval '25 hours'`); err != nil {
		t.Fatal(err)
	}
	if got, err := e.d.EnqueueBotKeys(ctx); err != nil || got != 1 {
		t.Fatalf("enqueue after a day: %d %v", got, err)
	}
}
