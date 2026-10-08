// Package inj is the injection weather map (SPEC-v2 27.9): POST /v1/inj records that an agent saw
// content on a host (or from a model:<vendor>/<name>) matching the injection lexicon, with an
// optional payload hash (sha256 of the normalised snippet from POST /v1/scrub?mode=inj) and the
// lexicon flag names; GET /inj/{host}, GET /inj/p/{ph} and GET /inj aggregate the reports of the
// last 24 h / 30 d as numbers only (weighted reports, distinct roots, distinct super-groups, payload
// counts), never as verdict words. Nothing from the reported page is stored: no snippet, no URL
// path, no user agent, no raw IP (network keys are HMAC'd). Rows live 30 d.
package inj

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Caps (4.3, as beacons) and bounds. Vars so tests can lower them.
var (
	RootDaily = 60 // reports per root per day, flat across levels
	AnonDaily = 20 // anonymous reports per IP group per day; 4x per super-group (core.UseNetQuota)
	// MaxLive bounds the live table (27.8): a super-group may hold at most ShareCap() rows; at
	// 95 % the janitor evicts the oldest rows of the largest super-groups.
	MaxLive int64 = 200_000
	// CacheTTL is the aggregate cache TTL (27.9: 30 s ByteLRU of 1 MiB).
	CacheTTL = 30 * time.Second
)

const (
	anonWeight   = 0.2  // anonymous X-PoW report
	l0Weight     = 0.34 // fresh (L0) root
	maxNote      = 120
	maxBody      = 4 << 10
	maxFlags     = 12
	maxHosts     = 32 // hosts kept per payload row
	liveWindow   = 30 * 24 * time.Hour
	payloadIdle  = 180 * 24 * time.Hour
	cacheBytes   = 1 << 20
	topN         = 50
	seriesMax    = 720 // 30 d of hourly points
	evictRounds  = 8
	sharePercent = 2
)

// Syms is the symptom vocabulary (27.9); symOrder its display order.
var (
	Syms     = map[string]bool{"inject": true, "exfil-ask": true, "cloak": true, "malware": true, "paywall": true, "ok": true}
	symOrder = []string{"inject", "exfil-ask", "cloak", "malware", "paywall", "ok"}
)

// flagOrder is the lexicon flag vocabulary (scrub.Flags, 4.6) a report may carry; anything else
// is refused so payload rows hold enum names only, never client text. lang=<xx> markers also pass.
var (
	flagOrder = []string{"self-reference", "credential-solicitation", "remote-exec", "authority", "unicode",
		"html-comment", "md-image", "urls", "shortener", "gov-bribe"}
	flagRank = func() map[string]int {
		m := map[string]int{}
		for i, f := range flagOrder {
			m[f] = i
		}
		return m
	}()
	langFlagRe = regexp.MustCompile(`^lang=[a-z]{2}$`)
)

var (
	hostRe      = regexp.MustCompile(`^[a-z0-9.:/-]{3,80}$`)
	labelRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	modelNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	phRe        = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// localTLDs never resolve on the public Internet.
	localTLDs = map[string]bool{"local": true, "localhost": true, "internal": true, "lan": true, "home": true,
		"intranet": true, "corp": true, "test": true, "invalid": true, "example": true, "arpa": true, "onion": true, "localdomain": true}
	// multiSuffix lists common two-label public suffixes (no PSL dependency): the registrable
	// domain under them is one label longer.
	multiSuffix = map[string]bool{}

	errHost    = core.Bad("host must be a lowercase hostname or model:<vendor>/<name> ([a-z0-9.:/-]{3,80})")
	errPrivate = core.Bad("host must be a public hostname (no localhost, single labels, private or local names, no IP literals)")
	errSym     = core.Bad("sym must be one of inject, exfil-ask, cloak, malware, paywall, ok")
	errPh      = core.Bad("ph must be 64 hex characters (sha256 from POST /v1/scrub?mode=inj)")
	errFlags   = core.Bad("flags must be lexicon flag names (GET /inj/about)")
	errShare   = core.E(429, "quota", "inj share (your network holds too many live reports)")
)

func init() {
	for _, s := range strings.Fields(`co.uk org.uk ac.uk gov.uk me.uk ltd.uk plc.uk net.uk sch.uk nhs.uk
		com.au net.au org.au edu.au gov.au id.au asn.au co.nz net.nz org.nz govt.nz ac.nz
		co.jp ne.jp or.jp ac.jp go.jp gr.jp lg.jp co.kr or.kr ne.kr re.kr go.kr ac.kr
		com.cn net.cn org.cn gov.cn edu.cn ac.cn com.hk org.hk net.hk edu.hk gov.hk com.tw org.tw net.tw edu.tw
		com.sg net.sg org.sg edu.sg gov.sg co.in net.in org.in firm.in gen.in ind.in ac.in edu.in gov.in nic.in res.in
		com.br net.br org.br gov.br edu.br com.mx org.mx net.mx gob.mx edu.mx com.ar net.ar org.ar gob.ar edu.ar
		com.co net.co org.co gov.co edu.co com.pe net.pe org.pe gob.pe com.cl co.ve com.ve com.uy com.ec
		co.za org.za net.za web.za gov.za ac.za co.ke or.ke ac.ke go.ke com.ng org.ng gov.ng edu.ng com.eg
		com.tr net.tr org.tr gov.tr edu.tr com.sa org.sa net.sa gov.sa edu.sa co.il org.il net.il ac.il gov.il
		com.pl net.pl org.pl edu.pl co.id or.id ac.id go.id web.id com.my net.my org.my gov.my edu.my com.ph org.ph net.ph
		com.vn net.vn org.vn edu.vn gov.vn co.th or.th ac.th go.th in.th com.pk org.pk net.pk edu.pk gov.pk com.bd
		com.ua net.ua org.ua in.ua kiev.ua com.ru net.ru org.ru msk.ru spb.ru co.at or.at ac.at gv.at
		co.hu com.gr net.gr org.gr com.pt org.pt edu.pt com.ro org.ro com.es org.es nom.es gob.es edu.es
		com.fr asso.fr gouv.fr nom.fr prd.fr tm.fr co.it com.it edu.it gov.it co.nl com.de co.de com.ch
		github.io gitlab.io bitbucket.io pages.dev workers.dev vercel.app netlify.app herokuapp.com fly.dev onrender.com
		web.app firebaseapp.com appspot.com azurewebsites.net cloudapp.net cloudfront.net amazonaws.com elasticbeanstalk.com
		readthedocs.io rtfd.io blogspot.com wordpress.com substack.com medium.com notion.site webflow.io
		wixsite.com squarespace.com myshopify.com tumblr.com ghost.io surge.sh glitch.me repl.co replit.app
		hf.space huggingface.co ngrok.io ngrok.app ngrok-free.app loca.lt trycloudflare.com deno.dev val.run
		linodeusercontent.com digitaloceanspaces.com r2.dev s3.amazonaws.com storage.googleapis.com
		dyndns.org no-ip.org duckdns.org ddns.net hopto.org zapto.org sytes.net`) {
		multiSuffix[s] = true
	}
}

// ShareCap is the number of live rows one super-group may hold (27.8: 2 % of the live cap).
func ShareCap() int64 { return max(MaxLive*sharePercent/100, 1) }

// NormHost lowercases and validates a host: a public hostname (>= 2 labels, no local TLD, never an
// IP literal) or model:<vendor>/<name>.
func NormHost(s string) (string, error) {
	h := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if !hostRe.MatchString(h) {
		return "", errHost
	}
	if vn, ok := strings.CutPrefix(h, "model:"); ok {
		vendor, name, ok := strings.Cut(vn, "/")
		if !ok || !labelRe.MatchString(vendor) || !modelNameRe.MatchString(name) {
			return "", errHost
		}
		return h, nil
	}
	if strings.ContainsAny(h, ":/") {
		return "", errHost
	}
	if net.ParseIP(h) != nil {
		return "", errPrivate
	}
	labels := strings.Split(h, ".")
	if len(labels) < 2 {
		return "", errPrivate
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", errHost
		}
	}
	tld := labels[len(labels)-1]
	if localTLDs[tld] || strings.Trim(tld, "0123456789") == "" {
		return "", errPrivate
	}
	return h, nil
}

// Registrable is the registrable domain of a normalised host (example.com for docs.example.com,
// example.co.uk under the embedded multi-label suffixes); "" for model targets.
func Registrable(host string) string {
	if strings.HasPrefix(host, "model:") {
		return ""
	}
	labels := strings.Split(host, ".")
	n := len(labels)
	if n <= 2 {
		return host
	}
	if multiSuffix[labels[n-2]+"."+labels[n-1]] {
		return strings.Join(labels[n-3:], ".")
	}
	return strings.Join(labels[n-2:], ".")
}

// ValidSym reports whether s is a symptom.
func ValidSym(s string) bool { return Syms[s] }

// ParsePH decodes a 64-hex payload hash; nil for an empty string.
func ParsePH(s string) ([]byte, error) {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return nil, nil
	}
	if !phRe.MatchString(s) {
		return nil, errPh
	}
	b, _ := hex.DecodeString(s)
	return b, nil
}

// normFlags validates and orders lexicon flag names (duplicates dropped, lang markers last).
func normFlags(in []string) ([]string, error) {
	if len(in) > maxFlags {
		return nil, errFlags
	}
	seen := map[string]bool{}
	var out []string
	for _, f := range in {
		f = strings.ToLower(strings.TrimSpace(f))
		if _, ok := flagRank[f]; !ok && !langFlagRe.MatchString(f) {
			return nil, errFlags
		}
		if !seen[f] {
			seen[f] = true
			out = append(out, f)
		}
	}
	sortFlags(out)
	return out, nil
}

// sortFlags orders flags as scrub.Flags does: lexicon order, then lang=<xx> alphabetically.
func sortFlags(fs []string) {
	rank := func(f string) int {
		if r, ok := flagRank[f]; ok {
			return r
		}
		return len(flagOrder)
	}
	sort.SliceStable(fs, func(i, j int) bool {
		ri, rj := rank(fs[i]), rank(fs[j])
		return ri < rj || ri == rj && fs[i] < fs[j]
	})
}

type svc struct {
	d     *core.Deps
	cache *core.ByteLRU
}

func newSvc(d *core.Deps) *svc { return &svc{d: d, cache: core.NewByteLRU(cacheBytes)} }

// netKey HMACs a network key (group or super-group) with the server secret (24.24): distinct
// counts and the per-super share still work, raw addresses never reach the table.
func (s *svc) netKey(k string) string {
	m := hmac.New(sha256.New, s.d.Cfg.ServerSecret)
	m.Write([]byte("cx-inj-net-v1\x00" + k))
	return hex.EncodeToString(m.Sum(nil))[:24]
}

// Register mounts POST /v1/inj, GET /inj, GET /inj/about, GET /inj/p/{ph}, GET /inj/{host...} and
// the package hooks: scope, cost, OpenAPI, llms-full, feed source inj, report target inj:, storage
// class, janitor, purge and export.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	mux.HandleFunc("POST /v1/inj", s.post)
	mux.HandleFunc("GET /inj", s.top)
	mux.HandleFunc("GET /inj/about", s.about)
	for _, ext := range []string{".txt", ".md", ".json", ".html", ".sh", ".jsonld"} {
		mux.HandleFunc("GET /inj"+ext, s.top) // wildcards cannot glue to literals: one route per twin
		mux.HandleFunc("GET /inj/about"+ext, s.about)
	}
	mux.HandleFunc("GET /inj/p/{ph}", s.payload)
	mux.HandleFunc("GET /inj/{host...}", s.page)
	d.RegisterScope("POST /v1/inj", "kb:w")
	d.RegisterCost("GET /inj", 2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("inj", func(context.Context) string { return llmsText })
	d.RegisterFeed("inj", s.feed)
	d.RegisterTarget("inj", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.StorageClass("inj", 128<<20, `SELECT pg_total_relation_size('inj_reports') + pg_total_relation_size('inj_payloads') + pg_total_relation_size('inj_hidden')`)
	d.Janitor.Add("inj", func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM inj_reports WHERE root = $1`, root)
		return err
	})
	d.OnExport("inj", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// input is the POST /v1/inj body (JSON) or query parameters.
type input struct {
	Host  string   `json:"host"`
	Sym   string   `json:"sym"`
	PH    string   `json:"ph,omitempty"`
	Note  string   `json:"note,omitempty"`
	Flags []string `json:"flags,omitempty"` // lexicon flag names from POST /v1/scrub?mode=inj
	PoW   string   `json:"pow,omitempty"`   // MCP only: "<challenge>:<nonce>"

	ph []byte
}

// validate normalises the host, symptom, hash and flags and checks the note (<= 120, one line,
// no tier-1 secret). The note is accepted for compatibility and never stored.
func (in *input) validate() error {
	h, err := NormHost(in.Host)
	if err != nil {
		return err
	}
	in.Host = h
	in.Sym = strings.ToLower(strings.TrimSpace(in.Sym))
	if !ValidSym(in.Sym) {
		return errSym
	}
	if in.ph, err = ParsePH(in.PH); err != nil {
		return err
	}
	in.PH = hex.EncodeToString(in.ph)
	if in.Flags, err = normFlags(in.Flags); err != nil {
		return err
	}
	in.Note = scrub.Normalize(strings.TrimSpace(in.Note))
	if len(in.Note) > maxNote {
		return core.Bad(fmt.Sprintf("note must be <= %d bytes", maxNote))
	}
	if !doc.OneLine(in.Note) {
		return core.Bad("note must be a single line")
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"note": &in.Note}); aerr != nil {
		return aerr
	}
	return nil
}

// writeReq is one report to record: a token identity or the anonymous network keys.
type writeReq struct {
	in         input
	id         *core.Ident
	grp, super string
}

func (s *svc) post(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") || !s.d.CheckFrozen(w, r, "inj") {
		return
	}
	var in input
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.Host == "" && in.Sym == "" {
		q := r.URL.Query()
		in.Host, in.Sym, in.PH, in.Note = q.Get("host"), q.Get("sym"), q.Get("ph"), q.Get("note")
		if f := strings.TrimSpace(q.Get("flags")); f != "" {
			in.Flags = strings.Split(f, ",")
		}
	}
	if in.PoW != "" {
		doc.Fail(w, r, core.Bad("pow is an MCP argument; send the X-PoW header over HTTP"))
		return
	}
	if err := in.validate(); err != nil {
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
		doc.Fail(w, r, core.ErrAuth, doc.POST("/v1/challenge?for=w", ""), doc.POST("/v1/inj", "+X-PoW"), doc.GET("/inj/about", ""))
		return
	}
	ctx := r.Context()
	req := &writeReq{in: in, id: id, grp: s.d.IPGroup(r), super: s.d.IPSuper(r)}
	var a *agg
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if id == nil {
			grp, sup, err := s.xpow(ctx, tx, r)
			if err != nil {
				return err
			}
			req.grp, req.super = grp, sup
		}
		var err error
		a, err = s.write(ctx, tx, req)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusCreated, okLine(req.in, a), doc.GET("/inj/"+a.Host, ""), doc.GET("/f/inj/"+a.Host+".atom", "feed"))
}

// okLine is the write reply head: ok <host> <sym> 24h: <n> reports (<r> roots, <s> nets)[ payload: …].
func okLine(in input, a *agg) string {
	line := fmt.Sprintf("ok %s %s %s", in.Host, in.Sym, window("24h", a.R24, a.Roots24, a.Nets24, true))
	if a.PayloadReports > 0 {
		line += fmt.Sprintf(" payload: %d reports %d hosts", a.PayloadReports, a.PayloadHosts)
	}
	return line
}

// xpow verifies the anonymous X-PoW through the core seam (fails closed until auth installs it)
// and returns the network keys the quotas are charged to.
func (s *svc) xpow(ctx context.Context, q core.Q, r *http.Request) (string, string, error) {
	if core.XPoWFn == nil {
		return "", "", core.E(400, "pow", "X-PoW required")
	}
	grp, sup, err := core.XPoWFn(ctx, q, r)
	if err != nil {
		return "", "", err
	}
	if grp == "" {
		grp = s.d.IPGroup(r)
	}
	if sup == "" {
		sup = core.IPSuper(grp)
	}
	return grp, sup, nil
}

// weightOf is the report weight of a root (27.9): L0 0.34, L1+ 1.
func weightOf(st trust.Standing) float64 {
	if st.Level() >= 1 {
		return 1
	}
	return l0Weight
}

// write is the report transaction: quotas (rolled back with the tx when refused), the weight from
// standing, the per-super admission share, the insert, the payload upsert, the owner audit row,
// then the fresh 24 h aggregate for the reply.
func (s *svc) write(ctx context.Context, tx core.Q, req *writeReq) (*agg, error) {
	var root *string
	w := anonWeight
	if req.id != nil {
		n, err := bump(ctx, tx, req.id.Root, "inj", 1)
		if err != nil {
			return nil, err
		}
		if n > RootDaily {
			return nil, core.ErrQuota
		}
		st, err := trust.Load(ctx, tx, req.id.Root)
		if err != nil {
			return nil, err
		}
		if st.Banned {
			return nil, core.ErrBanned
		}
		w = weightOf(st)
		root = &req.id.Root
	} else if err := core.UseNetQuota(ctx, tx, req.grp, "inj", AnonDaily); err != nil {
		return nil, err
	}
	gk, sk := s.netKey(req.grp), s.netKey(req.super)
	var held int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM inj_reports WHERE ipsuper = $1`, sk).Scan(&held); err != nil {
		return nil, err
	}
	if held >= ShareCap() {
		return nil, errShare
	}
	in := req.in
	if _, err := tx.Exec(ctx, `INSERT INTO inj_reports (host, rd, sym, ph, root, w, ipgroup, ipsuper) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
		in.Host, Registrable(in.Host), in.Sym, in.ph, root, w, gk, sk); err != nil {
		return nil, err
	}
	a := &agg{Host: in.Host}
	if in.ph != nil {
		flags := in.Flags
		if flags == nil {
			flags = []string{}
		}
		if err := tx.QueryRow(ctx, `INSERT INTO inj_payloads (ph, hosts, reports, flags) VALUES ($1, ARRAY[$2::text], 1, $3::text[])
			ON CONFLICT (ph) DO UPDATE SET reports = inj_payloads.reports + 1, last = now(),
			  hosts = CASE WHEN $2::text = ANY (inj_payloads.hosts) OR cardinality(inj_payloads.hosts) >= $4 THEN inj_payloads.hosts ELSE inj_payloads.hosts || $2::text END,
			  flags = (SELECT coalesce(array_agg(DISTINCT f), '{}') FROM unnest(inj_payloads.flags || $3::text[]) f)
			RETURNING reports, cardinality(hosts)`, in.ph, in.Host, flags, maxHosts).Scan(&a.PayloadReports, &a.PayloadHosts); err != nil {
			return nil, err
		}
	}
	if req.id != nil {
		if err := core.Audit(ctx, tx, req.id.ID, "inj", in.Host, 0); err != nil {
			return nil, err
		}
	}
	if err := a.windows(ctx, tx); err != nil {
		return nil, err
	}
	return a, nil
}

// bump adds delta to today's counter (same table and semantics as core's quota counters).
func bump(ctx context.Context, q core.Q, scope, kind string, delta int) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, delta).Scan(&n)
	return n, err
}

// Report target inj:<host> (4.7, notice category inj-dispute): exists when the host has live rows;
// hide and restore flip inj_hidden (the page stays readable, noindex, absent from /inj and feeds).
func exists(ctx context.Context, q core.Q, ref string) error {
	h, err := NormHost(ref)
	if err != nil {
		return core.ErrNotFound
	}
	ok, err := hasData(ctx, q, h)
	if err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func hide(ctx context.Context, q core.Q, ref string) error {
	h, err := NormHost(ref)
	if err != nil {
		return core.ErrNotFound
	}
	_, err = q.Exec(ctx, `INSERT INTO inj_hidden (host) VALUES ($1) ON CONFLICT (host) DO NOTHING`, h)
	return err
}

func restore(ctx context.Context, q core.Q, ref string) error {
	h, err := NormHost(ref)
	if err != nil {
		return core.ErrNotFound
	}
	_, err = q.Exec(ctx, `DELETE FROM inj_hidden WHERE host = $1`, h)
	return err
}

// hasData reports live rows for the host itself or under it as a registrable domain.
func hasData(ctx context.Context, q core.Q, host string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM inj_reports WHERE (host = $1 OR rd = $1) AND created > now() - $2::interval)`, host, liveWindow).Scan(&ok)
	return ok, err
}

func isHidden(ctx context.Context, q core.Q, host string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM inj_hidden WHERE host = $1)`, host).Scan(&ok)
	return ok, err
}

// Point is one hourly bucket of a host (Series): weighted reports, distinct roots and nets,
// symptom counts.
type Point struct {
	Hour    time.Time      `json:"hour"`
	Reports float64        `json:"reports"`
	Roots   int            `json:"roots"`
	Nets    int            `json:"nets"`
	Syms    map[string]int `json:"syms"`
}

// Series returns the last n hourly points of a host (exact host or registrable domain), newest
// first, from the live rows.
func Series(ctx context.Context, q core.Q, host string, n int) ([]Point, error) {
	n = min(max(n, 1), seriesMax)
	rows, err := q.Query(ctx, `SELECT b.h, sum(b.w)::float8, count(DISTINCT b.root), count(DISTINCT b.ipsuper),
		(SELECT coalesce(jsonb_object_agg(z.sym, z.n), '{}') FROM (SELECT x.sym, count(*) n FROM inj_reports x
		   WHERE (x.host = $1 OR x.rd = $1) AND date_trunc('hour', x.created) = b.h GROUP BY x.sym) z)
		FROM (SELECT date_trunc('hour', created) h, root, ipsuper, w FROM inj_reports WHERE (host = $1 OR rd = $1) AND created > now() - $3::interval) b
		GROUP BY b.h ORDER BY b.h DESC LIMIT $2`, host, n, liveWindow)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Point
	for rows.Next() {
		var p Point
		var syms []byte
		if err := rows.Scan(&p.Hour, &p.Reports, &p.Roots, &p.Nets, &syms); err != nil {
			return nil, err
		}
		p.Hour = p.Hour.UTC()
		p.Syms = map[string]int{}
		if len(syms) > 0 {
			json.Unmarshal(syms, &p.Syms)
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// Janitor deletes live rows older than 30 d and payload rows idle 180 d, then evicts past the live
// cap (27.8).
func Janitor(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `DELETE FROM inj_reports WHERE created < now() - $1::interval`, liveWindow); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM inj_payloads WHERE last < now() - $1::interval`, payloadIdle); err != nil {
		return err
	}
	return Evict(ctx, q)
}

// Evict applies the 27.8 eviction order: past 95 % of MaxLive, delete the oldest rows of the
// super-groups holding the largest share first, until the table is back at 90 %.
func Evict(ctx context.Context, q core.Q) error {
	var total int64
	if err := q.QueryRow(ctx, `SELECT count(*) FROM inj_reports`).Scan(&total); err != nil {
		return err
	}
	if total < MaxLive*95/100 {
		return nil
	}
	excess := total - MaxLive*90/100
	for i := 0; i < evictRounds && excess > 0; i++ {
		var sup string
		var held int64
		err := q.QueryRow(ctx, `SELECT ipsuper, count(*) FROM inj_reports GROUP BY ipsuper ORDER BY 2 DESC, 1 LIMIT 1`).Scan(&sup, &held)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		tag, err := q.Exec(ctx, `DELETE FROM inj_reports WHERE id IN (SELECT id FROM inj_reports WHERE ipsuper = $1 ORDER BY created, id LIMIT $2)`,
			sup, min(excess, held/2+1))
		if err != nil {
			return err
		}
		excess -= tag.RowsAffected()
	}
	return nil
}

// export writes the root's reports as JSONL (export-me, 3.4): host, sym, ph, created.
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	rows, err := q.Query(ctx, `SELECT host, sym, ph, created FROM inj_reports WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	for rows.Next() {
		var rec struct {
			Kind    string    `json:"kind"`
			Host    string    `json:"host"`
			Sym     string    `json:"sym"`
			PH      string    `json:"ph,omitempty"`
			Created time.Time `json:"created"`
		}
		var ph []byte
		rec.Kind = "inj"
		if err := rows.Scan(&rec.Host, &rec.Sym, &ph, &rec.Created); err != nil {
			return err
		}
		rec.PH = hex.EncodeToString(ph)
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}
