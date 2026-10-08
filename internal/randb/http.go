package randb

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/sign"
)

// Parameter caps for the deterministic draws.
const (
	maxOf    = 100_000 // largest population a /pick may permute
	maxSalt  = 128     // salt byte cap (single printable line)
	readCost = 0.2     // 3.6: reads are cheap polls
)

type svc struct {
	d   *core.Deps
	lim *rateLimiter
}

// Register mounts the beacon: the contribution endpoint, the public reads and the per-minute
// ticker (as a janitor task, so pg_try_advisory_lock gives two gateway instances one writer).
func Register(mux *http.ServeMux, d *core.Deps) {
	signerP.Store(sign.MustNew(d.Cfg))
	s := &svc{d: d, lim: newRateLimiter()}
	mux.HandleFunc("POST /v1/rand/mix", s.postMix)
	mux.HandleFunc("GET /rand", s.getLatest)
	mux.HandleFunc("GET /rand/about", s.about)
	for _, ext := range []string{".txt", ".md", ".json", ".html"} {
		mux.HandleFunc("GET /rand"+ext, s.getLatest) // wildcards cannot glue to literals: one twin each
		mux.HandleFunc("GET /rand/about"+ext, s.about)
	}
	mux.HandleFunc("GET /rand/{t}", s.getRound)
	mux.HandleFunc("GET /rand/{t}/pick", s.getPick)
	mux.HandleFunc("GET /rand/{t}/u", s.getUniform)
	mux.HandleFunc("GET /rand/{t}/coin", s.getCoin)
	mux.HandleFunc("GET /rand/{t}/mix", s.getMix)

	d.RegisterScope("POST /v1/rand/mix", "kb:w")
	for _, p := range []string{"GET /rand", "GET /rand/about", "GET /rand/{t}", "GET /rand/{t}/pick",
		"GET /rand/{t}/u", "GET /rand/{t}/coin", "GET /rand/{t}/mix"} {
		d.RegisterCost(p, readCost)
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("rand", func(context.Context) string { return llmsText })
	d.StorageClass("rand", 64<<20, `SELECT pg_total_relation_size('rand_rounds') + pg_total_relation_size('rand_mix')`)
	d.Janitor.Add("rand", func(ctx context.Context) error {
		if _, err := Advance(ctx, d.DB, d.Cfg.ServerSecret, time.Now()); err != nil {
			return err
		}
		return Janitor(ctx, d.DB)
	})
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// ensureCurrent lazily advances the beacon to the current minute so a read never lags the clock,
// even before the first janitor tick. Advance is idempotent and transactional.
func (s *svc) ensureCurrent(ctx context.Context) error {
	rd, err := latest(ctx, s.d.DB)
	if err != nil {
		return err
	}
	if rd != nil && rd.T >= minute(time.Now()) {
		return nil
	}
	_, err = Advance(ctx, s.d.DB, s.d.Cfg.ServerSecret, time.Now())
	return err
}

// --- contribution: POST /v1/rand/mix ------------------------------------------------------------

type mixIn struct {
	H   string `json:"h"`
	PoW string `json:"pow,omitempty"` // MCP only; HTTP uses the X-PoW header
}

func (s *svc) postMix(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") {
		return
	}
	var in mixIn
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.H == "" {
		in.H = r.URL.Query().Get("h")
	}
	if in.PoW != "" {
		doc.Fail(w, r, core.Bad("pow is an MCP argument; send the X-PoW header over HTTP"))
		return
	}
	h, err := parseHash(strings.TrimSpace(in.H))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	id, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if id != nil && id.Banned {
		doc.Fail(w, r, core.ErrBanned)
		return
	}
	if id == nil && r.Header.Get("X-PoW") == "" {
		s.d.PoWAuthenticate(w, r)
		doc.Fail(w, r, core.ErrAuth, doc.POST("/v1/challenge?for=w", ""), doc.POST("/v1/rand/mix", "+X-PoW"), doc.GET("/rand/about", ""))
		return
	}
	ctx := r.Context()
	if id == nil {
		if core.XPoWFn == nil {
			doc.Fail(w, r, core.E(400, "pow", "X-PoW required"))
			return
		}
		if _, _, err := core.XPoWFn(ctx, s.d.DB, r); err != nil {
			doc.Fail(w, r, err)
			return
		}
	}
	if ok, retry := s.lim.allow(s.d.IPGroup(r), time.Now()); !ok {
		w.Header().Set("Retry-After", strconv.Itoa(retry))
		doc.Fail(w, r, core.E(429, "quota", fmt.Sprintf("rand mix rate (%d/min per network)", MixPerMin)))
		return
	}
	m := minute(time.Now())
	if err := addMix(ctx, s.d.DB, m, h); err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusCreated,
		fmt.Sprintf("ok mix t=%d h=%s folds into round %d", m, hex.EncodeToString(h), m+1),
		doc.GET("/rand/"+strconv.FormatInt(m+1, 10), "next round"), doc.GET("/rand", ""))
}

// --- reads --------------------------------------------------------------------------------------

// getLatest serves GET /rand: the newest revealed round, public max-age=5.
func (s *svc) getLatest(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	if err := s.ensureCurrent(ctx); err != nil {
		doc.Fail(w, r, err)
		return
	}
	rd, err := latest(ctx, s.d.DB)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if rd == nil {
		doc.Err(w, r, 404, "notfound", "no round yet", doc.GET("/rand/about", ""))
		return
	}
	s.replyRound(w, r, rd)
}

// getRound serves GET /rand/{t}: a past/present round, or a pending future one with its commitment.
func (s *svc) getRound(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, _, err := parseT(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := s.ensureCurrent(ctx); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if t > minute(time.Now()) {
		c := commit(seed(seedKey(s.d.Cfg.ServerSecret), t))
		d := &doc.Doc{
			Head:   fmt.Sprintf("rand t=%d pending c=%s", t, hex.EncodeToString(c)),
			Fields: []doc.F{{Name: "note", Val: "c is the commitment sha256(s); when round " + strconv.FormatInt(t, 10) + " reveals, sha256(s) must equal c"}},
			Next:   []doc.Action{doc.GET("/rand/"+strconv.FormatInt(t, 10), "retry at minute "+strconv.FormatInt(t, 10)), doc.GET("/rand/about", "")},
			MaxAge: 5, Canonical: "/rand/" + strconv.FormatInt(t, 10), NoIndex: true,
		}
		doc.Reply(w, r, 200, d)
		return
	}
	rd, err := loadRound(ctx, s.d.DB, t)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if rd == nil {
		doc.Err(w, r, 404, "notfound", fmt.Sprintf("no round %d (outside the 90 d window)", t), doc.GET("/rand", ""))
		return
	}
	s.replyRound(w, r, rd)
}

// replyRound renders a revealed round: the signed statement line, its signature and the draw links.
func (s *svc) replyRound(w http.ResponseWriter, r *http.Request, rd *Round) {
	rd.CNext = commit(seed(seedKey(s.d.Cfg.ServerSecret), rd.T+1))
	ts := strconv.FormatInt(rd.T, 10)
	d := &doc.Doc{
		Head: rd.Line(),
		Fields: []doc.F{
			{Name: "sig", Val: strings.TrimPrefix(rd.Sig, "sig=")},
			{Name: "r", Val: hex.EncodeToString(rd.R)},
			{Name: "verify", Val: "r = sha256(s || mix); sha256(s) was published as c_next one round earlier"},
		},
		Next: []doc.Action{
			doc.GET("/rand/"+ts+"/pick?n=3&of=12&salt=task", "fair pick"),
			doc.GET("/rand/"+ts+"/u?max=100&salt=task", "uniform"),
			doc.GET("/rand/"+ts+"/coin?salt=task", "coin"),
			doc.GET("/rand/"+ts+"/mix", "contributions"),
			doc.GET("/rand/about", "recipe"),
		},
		MaxAge: 5, Canonical: "/rand/" + ts, NoIndex: true,
	}
	doc.Reply(w, r, 200, d)
}

// draw loads the revealed round named by {t} for /pick, /u and /coin; a future or missing round is
// an error (nothing to draw from yet).
func (s *svc) draw(w http.ResponseWriter, r *http.Request) (*Round, bool) {
	ctx := r.Context()
	t, _, err := parseT(r)
	if err != nil {
		doc.Fail(w, r, err)
		return nil, false
	}
	if err := s.ensureCurrent(ctx); err != nil {
		doc.Fail(w, r, err)
		return nil, false
	}
	if t > minute(time.Now()) {
		doc.Err(w, r, 409, "pending", fmt.Sprintf("round %d has not revealed yet", t), doc.GET("/rand/"+strconv.FormatInt(t, 10), ""))
		return nil, false
	}
	rd, err := loadRound(ctx, s.d.DB, t)
	if err != nil {
		doc.Fail(w, r, err)
		return nil, false
	}
	if rd == nil {
		doc.Err(w, r, 404, "notfound", fmt.Sprintf("no round %d (outside the 90 d window)", t), doc.GET("/rand", ""))
		return nil, false
	}
	return rd, true
}

func (s *svc) getPick(w http.ResponseWriter, r *http.Request) {
	rd, ok := s.draw(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	salt, err := cleanSalt(q.Get("salt"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	of, err := intParam(q.Get("of"), 1, maxOf)
	if err != nil {
		doc.Fail(w, r, core.Bad("of must be 1.."+strconv.Itoa(maxOf)))
		return
	}
	n, err := intParam(q.Get("n"), 1, of)
	if err != nil {
		doc.Fail(w, r, core.Bad("n must be 1..of"))
		return
	}
	idx := pick(rd.R, n, of, salt)
	cells := make([]string, len(idx))
	for i, v := range idx {
		cells[i] = strconv.Itoa(v)
	}
	ts := strconv.FormatInt(rd.T, 10)
	d := &doc.Doc{
		Head:   fmt.Sprintf("pick t=%d n=%d of=%d salt=%s => %s", rd.T, n, of, salt, strings.Join(cells, ",")),
		Fields: []doc.F{{Name: "r", Val: hex.EncodeToString(rd.R)}, {Name: "recipe", Val: "partial Fisher-Yates over [0,of) driven by HMAC-SHA256(r, \"pick\\0\"||salt||ctr)"}},
		Next:   []doc.Action{doc.GET("/rand/"+ts, "round"), doc.GET("/rand/about", "recipe")},
		MaxAge: 5, NoIndex: true, Canonical: "/rand/" + ts + "/pick",
	}
	doc.Reply(w, r, 200, d)
}

func (s *svc) getUniform(w http.ResponseWriter, r *http.Request) {
	rd, ok := s.draw(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()
	salt, err := cleanSalt(q.Get("salt"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	mx, err := intParam(q.Get("max"), 1, 1<<31-1)
	if err != nil {
		doc.Fail(w, r, core.Bad("max must be 1..2147483647"))
		return
	}
	v := uniformOf(rd.R, uint32(mx), salt)
	ts := strconv.FormatInt(rd.T, 10)
	d := &doc.Doc{
		Head:   fmt.Sprintf("u t=%d max=%d salt=%s => %d", rd.T, mx, salt, v),
		Fields: []doc.F{{Name: "r", Val: hex.EncodeToString(rd.R)}, {Name: "recipe", Val: "uniform in [0,max) by rejection over HMAC-SHA256(r, \"u\\0\"||salt||ctr)"}},
		Next:   []doc.Action{doc.GET("/rand/"+ts, "round"), doc.GET("/rand/about", "recipe")},
		MaxAge: 5, NoIndex: true, Canonical: "/rand/" + ts + "/u",
	}
	doc.Reply(w, r, 200, d)
}

func (s *svc) getCoin(w http.ResponseWriter, r *http.Request) {
	rd, ok := s.draw(w, r)
	if !ok {
		return
	}
	salt, err := cleanSalt(r.URL.Query().Get("salt"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	ts := strconv.FormatInt(rd.T, 10)
	d := &doc.Doc{
		Head:   fmt.Sprintf("coin t=%d salt=%s => %s", rd.T, salt, coin(rd.R, salt)),
		Fields: []doc.F{{Name: "r", Val: hex.EncodeToString(rd.R)}, {Name: "recipe", Val: "heads when the first bit of HMAC-SHA256(r, \"coin\\0\"||salt||ctr) draws 1"}},
		Next:   []doc.Action{doc.GET("/rand/"+ts, "round"), doc.GET("/rand/about", "recipe")},
		MaxAge: 5, NoIndex: true, Canonical: "/rand/" + ts + "/coin",
	}
	doc.Reply(w, r, 200, d)
}

// getMix lists the contribution hashes folded into round t (received in minute t-1).
func (s *svc) getMix(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	t, _, err := parseT(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	hs, err := contributions(ctx, s.d.DB, t)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	rows := make([][]string, len(hs))
	for i, h := range hs {
		rows[i] = []string{h}
	}
	ts := strconv.FormatInt(t, 10)
	d := &doc.Doc{
		Head:   fmt.Sprintf("mix t=%d n=%d (contributions received in minute %d, sorted)", t, len(hs), t-1),
		Cols:   []string{"h"},
		Rows:   rows,
		Next:   []doc.Action{doc.GET("/rand/"+ts, "round"), doc.GET("/rand/about", "recipe")},
		MaxAge: 5, NoIndex: true, Canonical: "/rand/" + ts + "/mix",
	}
	doc.Reply(w, r, 200, d)
}

// about serves GET /rand/about: the verification recipe.
func (s *svc) about(w http.ResponseWriter, r *http.Request) {
	kid := signer().KID()
	d := &doc.Doc{
		Head: "public randomness beacon: one commit-reveal round per unix minute; trust-minimised, not trustless",
		Fields: []doc.F{
			{Name: "round", Val: "every unix minute t has a round; the beacon value is r_t"},
			{Name: "seed", Val: "s_t = HMAC-SHA256(HKDF-SHA256(server_secret, info \"cx-rand-v1\"), uint64be(t)); kept secret until minute t"},
			{Name: "commit", Val: "c_t = sha256(s_t) is published one round ahead as c_next, pinning s_t before it is revealed"},
			{Name: "mix", Val: "mix_t = sha256(h0||h1||...) over the distinct contribution hashes received in minute t-1, sorted ascending by raw bytes (sha256 of the empty string when none)"},
			{Name: "value", Val: "r_t = sha256(s_t || mix_t)"},
			{Name: "statement", Val: fmt.Sprintf("rand1 t=<t> r=<hex> s=<hex> mix=<hex> n=<k> c_next=<hex> k=%d, signed Ed25519 (see /.well-known/cx-key, /verify)", kid)},
			{Name: "drbg", Val: "keystream = HMAC-SHA256(r_t, purpose||0x00||salt||uint32be(ctr)) for ctr=0,1,...; purpose in {pick,u,coin}; read as a byte stream"},
			{Name: "pick", Val: "/pick?n=&of=&salt= : partial Fisher-Yates over [0,of): for i in 0..n-1 swap i with i+uniform(of-i); returns the first n indices"},
			{Name: "uniform", Val: "uniform(bound) draws 4-byte big-endian words, rejects words >= floor(2^32/bound)*bound, returns word mod bound; /u?max= is uniform(max)"},
			{Name: "coin", Val: "/coin?salt= is heads when uniform(2)==1 else tails"},
			{Name: "contribute", Val: "POST /v1/rand/mix {\"h\":\"<64 hex>\"} adds entropy to the next round (token or X-PoW, 10/min per network)"},
			{Name: "anchor", Val: "each completed UTC day's rounds hash sha256(r_t0||r_t1||...) is stamped into the notary (GET /ts)"},
			{Name: "trust", Val: "the operator cannot bias a round after its commitment is out, but could grind s_t before committing: trust-minimised, not trustless"},
		},
		Next:      []doc.Action{doc.GET("/rand", "latest"), doc.GET("/verify", "statements"), doc.GET("/.well-known/cx-key", "key")},
		Title:     "randomness beacon: verification recipe",
		Desc:      "How agents.ekaii.fr derives and signs each minute's public random value, and how to recompute a fair pick from the revealed seed and mix.",
		Canonical: "/rand/about", MaxAge: 300,
	}
	doc.Reply(w, r, 200, d)
}

// --- parameter parsing --------------------------------------------------------------------------

// parseT reads the {t} path value (with an optional format suffix) as a unix minute.
func parseT(r *http.Request) (int64, doc.Format, error) {
	seg, f := doc.SplitSuffix(r.PathValue("t"))
	t, err := strconv.ParseInt(seg, 10, 64)
	if err != nil || t < 0 {
		return 0, f, core.Bad("t must be a non-negative unix minute")
	}
	return t, f, nil
}

// intParam parses a bounded positive integer; an empty string is the low bound.
func intParam(s string, lo, hi int) (int, error) {
	if s == "" {
		return lo, nil
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < lo || v > hi {
		return 0, core.Bad("out of range")
	}
	return v, nil
}

// cleanSalt validates the salt: <= 128 bytes, a single printable line.
func cleanSalt(s string) (string, error) {
	if len(s) > maxSalt {
		return "", core.Bad(fmt.Sprintf("salt must be <= %d bytes", maxSalt))
	}
	if !doc.OneLine(s) {
		return "", core.Bad("salt must be a single line")
	}
	for _, c := range s {
		if c < 0x20 || c == 0x7f {
			return "", core.Bad("salt must be printable")
		}
	}
	return s, nil
}
