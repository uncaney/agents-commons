// Package pagecost is the web token-cost map (SPEC-v2 27.9): agents report what a URL cost them to
// read (POST /v1/pc {url, tokens, bytes, fmt, alt}); GET /pc?u=<url>, GET /pc/{uh} and GET
// /pc/h/{host} show crowd medians per page and per host plus a cheaper twin (alt) once two distinct
// super-groups confirmed it. Only canonical URLs are kept (no query, fragment, userinfo, private
// host or capability-looking segment); a reporter is a root id or an HMAC'd network key; medians
// run over one sample per super-group with anonymous samples at half weight; rows idle 180 d are
// deleted; nothing is exported.
package pagecost

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// Caps and bounds. Vars so tests can lower them.
var (
	RootDaily = 100 // samples per root per day (27.9)
	AnonDaily = 30  // anonymous samples per IP group per day; 4x per super-group (core.UseNetQuota)
	VoteDaily = 100 // altok/altbad votes per root per day
	CacheTTL  = 30 * time.Second
	IdleTTL   = 180 * 24 * time.Hour
)

const (
	anonWeight = 0.5
	maxSamples = 32 // samples kept per uh
	maxBody    = 4 << 10
	maxTokens  = 50_000_000
	maxBytes   = int64(1) << 32
	altOKMin   = 2 // distinct super-groups (other than the proposer's) before an alt shows
	cacheBytes = 256 << 10
	topN       = 10
)

var (
	// Fmts is the sample format vocabulary; fmtOrder its display order.
	Fmts     = map[string]bool{"html": true, "md": true, "txt": true, "json": true, "pdf": true}
	fmtOrder = []string{"html", "md", "txt", "json", "pdf"}
	uhRe     = regexp.MustCompile(`^[0-9a-f]{16}(?:[0-9a-f]{48})?$`)

	errTokens = core.Bad("tokens must be 1..50000000")
	errBytes  = core.Bad("bytes must be 0..4294967296")
	errFmt    = core.Bad("fmt must be one of html, md, txt, json, pdf")
	errUH     = core.Bad("uh must be 16 (or 64) hex characters")
	errNoAlt  = core.E(404, "notfound", "no alt proposed for this page")
)

type svc struct {
	d     *core.Deps
	cache *core.ByteLRU
}

func newSvc(d *core.Deps) *svc { return &svc{d: d, cache: core.NewByteLRU(cacheBytes)} }

// netKey HMACs a network key (group or super-group) with the server secret (24.24): distinct
// counts and collapses still work, raw addresses never reach the table.
func (s *svc) netKey(k string) string {
	m := hmac.New(sha256.New, s.d.Cfg.ServerSecret)
	m.Write([]byte("cx-pagecost-net-v1\x00" + k))
	return hex.EncodeToString(m.Sum(nil))[:24]
}

// superKey is the HMAC'd super-group of a token root (its registration network); a root without
// one collapses with itself only.
func (s *svc) superKey(st trust.Standing, root string) string {
	if st.Super == "" {
		return s.netKey("root:" + root)
	}
	return s.netKey(st.Super)
}

var exts = []string{".txt", ".md", ".json", ".html", ".sh", ".jsonld"}

// Register mounts POST /v1/pc, POST /v1/pc/{uh}/altok|altbad, GET /pc, GET /pc/about, GET
// /pc/h/{host}, GET /pc/{uh} and the package hooks: scopes, OpenAPI, llms-full, storage class,
// janitor and purge. Nothing is exported or fed (27.9).
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	mux.HandleFunc("POST /v1/pc", s.post)
	mux.HandleFunc("POST /v1/pc/{uh}/altok", s.vote(true))
	mux.HandleFunc("POST /v1/pc/{uh}/altbad", s.vote(false))
	mux.HandleFunc("GET /pc", s.lookup)
	mux.HandleFunc("GET /pc/about", s.about)
	for _, ext := range exts {
		mux.HandleFunc("GET /pc"+ext, s.lookup) // wildcards cannot glue to literals: one route per twin
		mux.HandleFunc("GET /pc/about"+ext, s.about)
	}
	mux.HandleFunc("GET /pc/h/{host}", s.host)
	mux.HandleFunc("GET /pc/{uh}", s.page)
	d.RegisterScope("POST /v1/pc", "w")
	d.RegisterScope("POST /v1/pc/{uh}/altok", "w")
	d.RegisterScope("POST /v1/pc/{uh}/altbad", "w")
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("pagecost", func(context.Context) string { return llmsText })
	d.StorageClass("pagecost", 64<<20, `SELECT pg_total_relation_size('pagecost') + pg_total_relation_size('pagecost_samples') + pg_total_relation_size('pagecost_alt_votes')`)
	d.Janitor.Add("pagecost", func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error { return Purge(ctx, d.DB, root) })
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// input is the POST /v1/pc body (JSON) or query parameters.
type input struct {
	URL    string `json:"url"`
	Tokens int    `json:"tokens"`
	Bytes  int64  `json:"bytes,omitempty"`
	Fmt    string `json:"fmt,omitempty"`
	Alt    string `json:"alt,omitempty"` // cheaper twin on the same registrable domain
	PoW    string `json:"pow,omitempty"` // MCP only: "<challenge>:<nonce>"

	page Page
}

// validate canonicalises url and alt and range-checks the numbers; fmt defaults to html.
func (in *input) validate() error {
	p, err := Canon(in.URL)
	if err != nil {
		return err
	}
	in.page, in.URL = p, p.URL
	if in.Tokens < 1 || in.Tokens > maxTokens {
		return errTokens
	}
	if in.Bytes < 0 || in.Bytes > maxBytes {
		return errBytes
	}
	in.Fmt = strings.ToLower(strings.TrimSpace(in.Fmt))
	if in.Fmt == "" {
		in.Fmt = "html"
	}
	if !Fmts[in.Fmt] {
		return errFmt
	}
	in.Alt = strings.TrimSpace(in.Alt)
	if in.Alt != "" {
		alt, err := CanonAlt(p, in.Alt)
		if err != nil {
			return err
		}
		in.Alt = alt.URL
	}
	return nil
}

// fromQuery fills an empty input from ?url=|u=&tokens=&bytes=&fmt=&alt=.
func (in *input) fromQuery(r *http.Request) {
	q := r.URL.Query()
	in.URL = q.Get("url")
	if in.URL == "" {
		in.URL = q.Get("u")
	}
	in.Tokens, _ = strconv.Atoi(q.Get("tokens"))
	in.Bytes, _ = strconv.ParseInt(q.Get("bytes"), 10, 64)
	in.Fmt, in.Alt = q.Get("fmt"), q.Get("alt")
}

// writeReq is one sample to record: a token identity or the anonymous network keys.
type writeReq struct {
	in         input
	id         *core.Ident
	grp, super string
}

func (s *svc) post(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") || !s.d.CheckFrozen(w, r, "pagecost") {
		return
	}
	var in input
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.URL == "" && in.Tokens == 0 {
		in.fromQuery(r)
	}
	if in.PoW != "" {
		doc.Fail(w, r, core.Bad("pow is an MCP argument; send the X-PoW header over HTTP"))
		return
	}
	if err := in.validate(); err != nil {
		doc.Fail(w, r, err, doc.GET("/pc/about", ""))
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
		doc.Fail(w, r, core.ErrAuth, doc.POST("/v1/challenge?for=w", ""), doc.POST("/v1/pc", "+X-PoW"), doc.GET("/pc/about", ""))
		return
	}
	ctx := r.Context()
	req := &writeReq{in: in, id: id, grp: s.d.IPGroup(r), super: s.d.IPSuper(r)}
	var row *Row
	var alt string
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if id == nil {
			grp, sup, err := s.xpow(ctx, tx, r)
			if err != nil {
				return err
			}
			req.grp, req.super = grp, sup
		}
		var err error
		row, alt, err = s.write(ctx, tx, req)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusCreated, okLine(row, alt), doc.GET("/pc/"+row.Short(), ""), doc.GET("/pc/h/"+row.Host, "host"))
}

// okLine is the write reply head: ok uh=<16 hex> n=5 tok~8.2k[ alt=set|ok|kept|noted].
func okLine(row *Row, alt string) string {
	line := fmt.Sprintf("ok uh=%s n=%d tok~%s", row.Short(), row.N, kfmt(int64(row.TokP50)))
	if alt != "" {
		line += " alt=" + alt
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

// write is the sample transaction: quotas (rolled back with the tx when refused), the reporter key
// and weight, the row upsert (locked), the daily sample upsert, the per-uh trim, the alt proposal
// or implicit confirmation, the aggregate recompute and the owner audit row. The second result
// names what happened to alt: set, ok (confirmed), kept (another alt stands), noted (anonymous).
func (s *svc) write(ctx context.Context, tx core.Q, req *writeReq) (*Row, string, error) {
	var who, sup string
	w := anonWeight
	if req.id != nil {
		n, err := bump(ctx, tx, req.id.Root, "pc", 1)
		if err != nil {
			return nil, "", err
		}
		if n > RootDaily {
			return nil, "", core.ErrQuota
		}
		st, err := trust.Load(ctx, tx, req.id.Root)
		if err != nil {
			return nil, "", err
		}
		if st.Banned {
			return nil, "", core.ErrBanned
		}
		who, sup, w = req.id.Root, s.superKey(st, req.id.Root), 1
	} else {
		if err := core.UseNetQuota(ctx, tx, req.grp, "pc", AnonDaily); err != nil {
			return nil, "", err
		}
		who, sup = "n:"+s.netKey(req.grp), s.netKey(req.super)
	}
	in, p := req.in, req.in.page
	if _, err := tx.Exec(ctx, `INSERT INTO pagecost (uh, url, host, rd, path) VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (uh) DO UPDATE SET last = now()`, p.UH, p.URL, p.Host, Registrable(p.Host), p.Path); err != nil {
		return nil, "", err
	}
	var alt string
	var okW, badW float64
	if err := tx.QueryRow(ctx, `SELECT alt, alt_ok_w, alt_bad_w FROM pagecost WHERE uh = $1 FOR UPDATE`, p.UH).Scan(&alt, &okW, &badW); err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO pagecost_samples (uh, who, sup, w, tok, bytes, fmt) VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (uh, who, day) DO UPDATE SET sup = EXCLUDED.sup, w = EXCLUDED.w, tok = EXCLUDED.tok, bytes = EXCLUDED.bytes, fmt = EXCLUDED.fmt, created = now()`,
		p.UH, who, sup, w, in.Tokens, in.Bytes, in.Fmt); err != nil {
		return nil, "", err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM pagecost_samples s USING (SELECT who, day FROM pagecost_samples WHERE uh = $1 ORDER BY created DESC, who OFFSET $2) o
		WHERE s.uh = $1 AND s.who = o.who AND s.day = o.day`, p.UH, maxSamples); err != nil {
		return nil, "", err
	}
	status := ""
	if in.Alt != "" {
		switch {
		case alt == "" || (alt != in.Alt && badW > okW):
			if _, err := tx.Exec(ctx, `UPDATE pagecost SET alt = $2, alt_sup = $3, alt_ok_w = 0, alt_bad_w = 0 WHERE uh = $1`, p.UH, in.Alt, sup); err != nil {
				return nil, "", err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM pagecost_alt_votes WHERE uh = $1`, p.UH); err != nil {
				return nil, "", err
			}
			status = "set"
		case alt == in.Alt && req.id != nil:
			if err := castVote(ctx, tx, p.UH, who, sup, true); err != nil {
				return nil, "", err
			}
			status = "ok"
		case alt == in.Alt:
			status = "noted"
		default:
			status = "kept"
		}
	}
	row, err := recompute(ctx, tx, p.UH)
	if err != nil {
		return nil, "", err
	}
	if row == nil {
		return nil, "", errors.New("pagecost: row vanished")
	}
	if req.id != nil {
		if err := core.Audit(ctx, tx, req.id.ID, "pc", p.Display(), in.Tokens); err != nil {
			return nil, "", err
		}
	}
	return row, status, nil
}

// castVote records one root's altok/altbad on the current alt (one vote per root, the last wins).
func castVote(ctx context.Context, q core.Q, uh []byte, who, sup string, ok bool) error {
	_, err := q.Exec(ctx, `INSERT INTO pagecost_alt_votes (uh, who, sup, ok) VALUES ($1, $2, $3, $4)
		ON CONFLICT (uh, who) DO UPDATE SET ok = EXCLUDED.ok, sup = EXCLUDED.sup, created = now()`, uh, who, sup, ok)
	return err
}

// vote serves POST /v1/pc/{uh}/altok and /altbad (token): the voter's super-group counts once;
// votes from the proposer's super-group never confirm (27.9: distinct super-groups).
func (s *svc) vote(ok bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		noStore(w)
		if !s.d.CheckFrozen(w, r, "write") || !s.d.CheckFrozen(w, r, "pagecost") {
			return
		}
		uh, err := parseUH(r.PathValue("uh"))
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		id, err := s.d.Auth(r)
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		if id.Banned {
			doc.Fail(w, r, core.ErrBanned)
			return
		}
		ctx := r.Context()
		var row *Row
		err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			var err error
			row, err = s.castVote(ctx, tx, id, uh, ok)
			return err
		})
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		doc.Tail(w, r, voteLine(row), doc.GET("/pc/"+row.Short(), ""), doc.GET("/pc/h/"+row.Host, "host"))
	}
}

// castVote is the vote transaction: quota, standing, the row (must carry an alt), the vote, recompute.
func (s *svc) castVote(ctx context.Context, tx core.Q, id *core.Ident, uh []byte, ok bool) (*Row, error) {
	n, err := bump(ctx, tx, id.Root, "pcv", 1)
	if err != nil {
		return nil, err
	}
	if n > VoteDaily {
		return nil, core.ErrQuota
	}
	st, err := trust.Load(ctx, tx, id.Root)
	if err != nil {
		return nil, err
	}
	if st.Banned {
		return nil, core.ErrBanned
	}
	row, err := loadUH(ctx, tx, uh, true)
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, core.ErrNotFound
	}
	if row.Alt == "" {
		return nil, errNoAlt
	}
	if err := castVote(ctx, tx, row.UH, id.Root, s.superKey(st, id.Root), ok); err != nil {
		return nil, err
	}
	if err := core.Audit(ctx, tx, id.ID, "pcv", row.Display(), 0); err != nil {
		return nil, err
	}
	return recompute(ctx, tx, row.UH)
}

// voteLine is the vote reply head: ok alt ok=<n> bad=<n> [visible].
func voteLine(row *Row) string {
	line := fmt.Sprintf("ok alt ok=%d bad=%d", int(row.AltOK), int(row.AltBad))
	if row.AltVisible() {
		line += " visible"
	}
	return line
}

// bump adds delta to today's counter (same table and semantics as core's quota counters).
func bump(ctx context.Context, q core.Q, scope, kind string, delta int) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, delta).Scan(&n)
	return n, err
}

// parseUH decodes a 16-hex (prefix) or 64-hex uh; a format suffix is stripped first.
func parseUH(seg string) ([]byte, error) {
	seg, _ = doc.SplitSuffix(seg)
	seg = strings.ToLower(strings.TrimSpace(seg))
	if !uhRe.MatchString(seg) {
		return nil, errUH
	}
	b, _ := hex.DecodeString(seg)
	return b, nil
}

// sample is one collapsed sample (the latest of its super-group) used by the medians.
type sample struct {
	w     float64
	tok   int
	bytes int64
	fmt   string
}

// recompute rebuilds a row's aggregates from its samples: n = distinct reporters; medians, min,
// max and the modal fmt over one sample per super-group (the latest), weighted (anonymous 0.5);
// alt_ok_w = distinct confirming super-groups other than the proposer's, alt_bad_w = distinct
// contesting super-groups. A row left without samples is deleted (nil result).
func recompute(ctx context.Context, q core.Q, uh []byte) (*Row, error) {
	rows, err := q.Query(ctx, `SELECT who, sup, w, tok, bytes, fmt FROM pagecost_samples WHERE uh = $1 ORDER BY created DESC, who`, uh)
	if err != nil {
		return nil, err
	}
	whos, sups := map[string]bool{}, map[string]bool{}
	var col []sample
	for rows.Next() {
		var who, sup string
		var sm sample
		if err := rows.Scan(&who, &sup, &sm.w, &sm.tok, &sm.bytes, &sm.fmt); err != nil {
			rows.Close()
			return nil, err
		}
		whos[who] = true
		if !sups[sup] {
			sups[sup] = true
			col = append(col, sm)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(col) == 0 {
		_, err := q.Exec(ctx, `DELETE FROM pagecost WHERE uh = $1`, uh)
		return nil, err
	}
	tokMin, tokMax := col[0].tok, col[0].tok
	fmtW := map[string]float64{}
	for _, sm := range col {
		tokMin, tokMax = min(tokMin, sm.tok), max(tokMax, sm.tok)
		fmtW[sm.fmt] += sm.w
	}
	best := col[0].fmt
	for _, f := range fmtOrder {
		if fmtW[f] > fmtW[best] {
			best = f
		}
	}
	tokP50 := wmedian(col, func(sm sample) int64 { return int64(sm.tok) })
	bytesP50 := wmedian(col, func(sm sample) int64 { return sm.bytes })
	var altSup string
	if err := q.QueryRow(ctx, `SELECT alt_sup FROM pagecost WHERE uh = $1`, uh).Scan(&altSup); err != nil {
		return nil, err
	}
	var okN, badN int
	if err := q.QueryRow(ctx, `SELECT count(DISTINCT sup) FILTER (WHERE ok AND sup <> $2), count(DISTINCT sup) FILTER (WHERE NOT ok)
		FROM pagecost_alt_votes WHERE uh = $1`, uh, altSup).Scan(&okN, &badN); err != nil {
		return nil, err
	}
	return scanRow(q.QueryRow(ctx, `UPDATE pagecost SET n = $2, tok_p50 = $3, tok_min = $4, tok_max = $5, bytes_p50 = $6, fmt = $7,
		alt_ok_w = $8, alt_bad_w = $9, last = now() WHERE uh = $1 RETURNING `+rowCols,
		uh, len(whos), tokP50, tokMin, tokMax, bytesP50, best, float64(okN), float64(badN)))
}

// wmedian is the weighted median of val over the samples: the smallest value whose cumulative
// weight reaches half the total.
func wmedian(col []sample, val func(sample) int64) int64 {
	type wv struct {
		v int64
		w float64
	}
	xs := make([]wv, len(col))
	total := 0.0
	for i, sm := range col {
		xs[i] = wv{val(sm), sm.w}
		total += sm.w
	}
	sort.Slice(xs, func(i, j int) bool { return xs[i].v < xs[j].v })
	cum := 0.0
	for _, x := range xs {
		cum += x.w
		if cum >= total/2-1e-9 {
			return x.v
		}
	}
	return xs[len(xs)-1].v
}

// Janitor deletes rows idle for IdleTTL (samples and votes cascade) and samples older than IdleTTL.
func Janitor(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `DELETE FROM pagecost WHERE last < now() - $1::interval`, IdleTTL); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `DELETE FROM pagecost_samples WHERE created < now() - $1::interval`, IdleTTL)
	return err
}

// Purge deletes a root's samples and votes (24.15) and recomputes the rows it touched; rows left
// without samples disappear.
func Purge(ctx context.Context, q core.Q, root string) error {
	rows, err := q.Query(ctx, `DELETE FROM pagecost_samples WHERE who = $1 RETURNING uh`, root)
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	var uhs [][]byte
	for rows.Next() {
		var uh []byte
		if err := rows.Scan(&uh); err != nil {
			rows.Close()
			return err
		}
		if k := string(uh); !seen[k] {
			seen[k] = true
			uhs = append(uhs, uh)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM pagecost_alt_votes WHERE who = $1`, root); err != nil {
		return err
	}
	for _, uh := range uhs {
		if _, err := recompute(ctx, q, uh); err != nil {
			return err
		}
	}
	return nil
}
