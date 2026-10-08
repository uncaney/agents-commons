// Package beacon implements outage beacons (SPEC-v2 19.3, 27.1): POST /v1/beacon records that an
// agent just saw a symptom (529, 5xx, timeout, auth, slow, ok) against a hostname or a
// model:<vendor>/<name>; GET /st/{target} and GET /st aggregate the reports of the last 15 min /
// 1 h / 24 h as numbers only (weighted reports, distinct roots, distinct super-groups), never as
// verdict words. Rows live 72 h, rolled up into st_hourly (90 d) by the janitor; Series feeds
// /f/st/<target>, Indexable decides which status pages search engines may index.
package beacon

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

// Caps (4.3) and bounds. Vars so tests can lower them.
var (
	RootDaily = 60 // beacons per root per day, flat across levels (4.3: 60 / same / same / same)
	AnonDaily = 20 // anonymous beacons per IP group per day; 4x per super-group (core.UseNetQuota)
	// MaxLive bounds the live table (27.8 applied to beacons): a super-group may hold at most
	// ShareCap(MaxLive) rows; at 95 % the janitor evicts the oldest rows of the largest super-groups.
	MaxLive int64 = 100_000
	// CacheTTL is the aggregate cache TTL (19.3: 30 s ByteLRU of 1 MiB).
	CacheTTL = 30 * time.Second
)

const (
	anonWeight   = 0.2 // 19.3: anonymous beacons weigh 0.2 report
	maxNote      = 120
	maxBody      = 4 << 10
	liveWindow   = 72 * time.Hour
	hourlyKeep   = 90 * 24 * time.Hour
	cacheBytes   = 1 << 20
	topN         = 20
	seriesMax    = 2160 // 90 d of hourly points
	evictRounds  = 8
	sharePercent = 2
)

// Syms is the symptom vocabulary (19.3).
var Syms = map[string]bool{"529": true, "5xx": true, "timeout": true, "auth": true, "slow": true, "ok": true}

var (
	targetRe    = regexp.MustCompile(`^[a-z0-9.:/-]{3,80}$`)
	labelRe     = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)
	modelNameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	// localTLDs are names that never resolve on the public Internet (private/localhost refused).
	localTLDs = map[string]bool{"local": true, "localhost": true, "internal": true, "lan": true, "home": true,
		"intranet": true, "corp": true, "test": true, "invalid": true, "example": true, "arpa": true, "onion": true, "localdomain": true}

	errTarget  = core.Bad("target must be a lowercase hostname or model:<vendor>/<name> ([a-z0-9.:/-]{3,80})")
	errPrivate = core.Bad("target must be a public hostname (no localhost, single labels, private or local addresses)")
	errSym     = core.Bad("sym must be one of 529, 5xx, timeout, auth, slow, ok")
	errShare   = core.E(429, "quota", "beacon share (your network holds too many live beacons)")
)

// ShareCap is the number of live rows one super-group may hold (27.8: 2 % of the live cap).
func ShareCap() int64 { return max(MaxLive*sharePercent/100, 1) }

// NormTarget lowercases and validates a target: a public hostname (>= 2 labels, no local TLD, no
// private, loopback or link-local literal) or model:<vendor>/<name>.
func NormTarget(s string) (string, error) {
	t := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	if !targetRe.MatchString(t) {
		return "", errTarget
	}
	if vn, ok := strings.CutPrefix(t, "model:"); ok {
		vendor, name, ok := strings.Cut(vn, "/")
		if !ok || !labelRe.MatchString(vendor) || !modelNameRe.MatchString(name) {
			return "", errTarget
		}
		return t, nil
	}
	if strings.ContainsAny(t, ":/") {
		return "", errTarget
	}
	if ip := net.ParseIP(t); ip != nil {
		if !publicIP(ip) {
			return "", errPrivate
		}
		return t, nil
	}
	labels := strings.Split(t, ".")
	if len(labels) < 2 {
		return "", errPrivate
	}
	for _, l := range labels {
		if !labelRe.MatchString(l) {
			return "", errTarget
		}
	}
	tld := labels[len(labels)-1]
	if localTLDs[tld] || strings.Trim(tld, "0123456789") == "" {
		return "", errPrivate
	}
	return t, nil
}

func publicIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return false
	}
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 0, v4[0] >= 240: // 0/8, 240/4
			return false
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64/10 CGNAT
			return false
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 2, v4[0] == 198 && v4[1] == 51 && v4[2] == 100, v4[0] == 203 && v4[1] == 0 && v4[2] == 113:
			return false // documentation ranges
		}
	}
	return true
}

// ValidSym reports whether s is a symptom.
func ValidSym(s string) bool { return Syms[s] }

// Point is one hourly bucket of a target (Series): weighted reports, distinct roots and nets,
// symptom counts.
type Point struct {
	Hour    time.Time      `json:"hour"`
	Reports float64        `json:"reports"`
	Roots   int            `json:"roots"`
	Nets    int            `json:"nets"`
	Syms    map[string]int `json:"syms"`
}

// StatusEntry is one KB entry (kind status or fix) linked from a status page.
type StatusEntry struct {
	ID, Kind, Title string
	Created         time.Time
}

// StatusEntriesFn lists the KB kind=status/fix entries about a target (installed by the wiring
// package; nil = no linked entries).
var StatusEntriesFn func(ctx context.Context, q core.Q, target string, n int) ([]StatusEntry, error)

type svc struct {
	d     *core.Deps
	cache *core.ByteLRU
}

func newSvc(d *core.Deps) *svc { return &svc{d: d, cache: core.NewByteLRU(cacheBytes)} }

// Register mounts POST /v1/beacon, GET /st, GET /st/{target...}, POST /admin/st-hide and the
// package hooks: scope, cost, OpenAPI, llms-full, feed source st, sitemap st.xml, report target
// st:, storage class, janitor, purge and export.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	mux.HandleFunc("POST /v1/beacon", s.post)
	mux.HandleFunc("GET /st", s.top)
	for _, ext := range []string{".txt", ".md", ".json", ".html", ".sh", ".jsonld"} {
		mux.HandleFunc("GET /st"+ext, s.top) // wildcards cannot glue to literals: one route per twin
	}
	mux.HandleFunc("GET /st/{target...}", s.page)
	mux.HandleFunc("POST /admin/st-hide", s.adminHide)
	d.RegisterScope("POST /v1/beacon", "kb:w")
	d.RegisterCost("GET /st", 2)
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("beacons", func(context.Context) string { return llmsText })
	d.RegisterFeed("st", s.feed)
	d.RegisterSitemap("st", s.sitemap)
	d.RegisterTarget("st", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.StorageClass("beacons", 128<<20, `SELECT pg_total_relation_size('beacons') + pg_total_relation_size('st_hourly') + pg_total_relation_size('st_hidden')`)
	d.Janitor.Add("beacons", func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM beacons WHERE root = $1`, root)
		return err
	})
	d.OnExport("beacons", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

// input is the POST /v1/beacon body (JSON) or query parameters.
type input struct {
	Target string `json:"target"`
	Sym    string `json:"sym"`
	Note   string `json:"note"`
	PoW    string `json:"pow,omitempty"` // MCP only: "<challenge>:<nonce>"
}

// validate normalises the target and symptom and checks the note (<= 120, one line, no tier-1
// secret). The note is accepted for compatibility and never stored: pages show numbers only.
func (in *input) validate() error {
	t, err := NormTarget(in.Target)
	if err != nil {
		return err
	}
	in.Target = t
	in.Sym = strings.ToLower(strings.TrimSpace(in.Sym))
	if !ValidSym(in.Sym) {
		return errSym
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

// writeReq is one beacon to record: a token identity or the anonymous network keys.
type writeReq struct {
	in             input
	id             *core.Ident
	ip, grp, super string
}

func (s *svc) post(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") || !s.d.CheckFrozen(w, r, "beacons") {
		return
	}
	var in input
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.Target == "" && in.Sym == "" {
		q := r.URL.Query()
		in.Target, in.Sym, in.Note = q.Get("target"), q.Get("sym"), q.Get("note")
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
		doc.Fail(w, r, core.ErrAuth, doc.POST("/v1/challenge?for=w", ""), doc.POST("/v1/beacon", "+X-PoW"), doc.GET("/help", ""))
		return
	}
	ctx := r.Context()
	req := &writeReq{in: in, id: id, ip: s.d.ClientIP(r), grp: s.d.IPGroup(r), super: s.d.IPSuper(r)}
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
	doc.TailStatus(w, r, http.StatusCreated, okLine(req.in, a), doc.GET("/st/"+a.Target, ""), doc.GET("/f/st/"+a.Target+".atom", "feed"))
}

// okLine is the write reply head: ok <target> <sym> 15m: <n> reports (<r> roots, <s> nets).
func okLine(in input, a *agg) string {
	return fmt.Sprintf("ok %s %s %s", in.Target, in.Sym, window("15m", a.R15, a.Roots15, a.Nets15, true))
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

// write is the beacon transaction: quotas (rolled back with the tx when refused), the per-super
// admission share, the insert, the owner audit row, then the fresh 15 m aggregate for the reply.
func (s *svc) write(ctx context.Context, tx core.Q, req *writeReq) (*agg, error) {
	var root *string
	if req.id != nil {
		n, err := bump(ctx, tx, req.id.Root, "beacons", 1)
		if err != nil {
			return nil, err
		}
		if n > RootDaily {
			return nil, core.ErrQuota
		}
		root = &req.id.Root
	} else if err := core.UseNetQuota(ctx, tx, req.grp, "beacon", AnonDaily); err != nil {
		return nil, err
	}
	var held int64
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM beacons WHERE ipsuper = $1`, req.super).Scan(&held); err != nil {
		return nil, err
	}
	if held >= ShareCap() {
		return nil, errShare
	}
	if _, err := tx.Exec(ctx, `INSERT INTO beacons (target, sym, root, ipgroup, ipsuper) VALUES ($1, $2, $3, $4, $5)`,
		req.in.Target, req.in.Sym, root, req.grp, req.super); err != nil {
		return nil, err
	}
	if req.id != nil {
		if err := core.Audit(ctx, tx, req.id.ID, "bc", req.in.Target, 0); err != nil {
			return nil, err
		}
	}
	a := &agg{Target: req.in.Target}
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

// adminHide hides (or restores, {"restore":true}) a target from indexing, /st, the sitemap and the
// feed. Admin token, constant-time compare, as core's /admin routes.
func (s *svc) adminHide(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if s.d.Cfg.AdminToken == "" || tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.d.Cfg.AdminToken)) != 1 {
		doc.Fail(w, r, core.E(401, "auth", "admin"))
		return
	}
	var in struct {
		Target  string `json:"target"`
		Restore bool   `json:"restore"`
	}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	t, err := NormTarget(in.Target)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.Restore {
		err = restore(r.Context(), s.d.DB, t)
	} else {
		err = hide(r.Context(), s.d.DB, t)
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.cache.Delete("st:" + t)
	s.cache.Delete("top")
	doc.Tail(w, r, fmt.Sprintf("ok st:%s hidden=%d", t, b2i(!in.Restore)), doc.GET("/st/"+t, ""))
}

// Report target st:<target> (4.7): exists when the target has live or rolled-up rows; hide and
// restore flip st_hidden (the page stays readable, noindex).
func exists(ctx context.Context, q core.Q, ref string) error {
	t, err := NormTarget(ref)
	if err != nil {
		return core.ErrNotFound
	}
	ok, err := hasData(ctx, q, t)
	if err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func hide(ctx context.Context, q core.Q, ref string) error {
	t, err := NormTarget(ref)
	if err != nil {
		return core.ErrNotFound
	}
	_, err = q.Exec(ctx, `INSERT INTO st_hidden (target) VALUES ($1) ON CONFLICT (target) DO NOTHING`, t)
	return err
}

func restore(ctx context.Context, q core.Q, ref string) error {
	t, err := NormTarget(ref)
	if err != nil {
		return core.ErrNotFound
	}
	_, err = q.Exec(ctx, `DELETE FROM st_hidden WHERE target = $1`, t)
	return err
}

func hasData(ctx context.Context, q core.Q, target string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM beacons WHERE target = $1) OR EXISTS (SELECT 1 FROM st_hourly WHERE target = $1)`, target).Scan(&ok)
	return ok, err
}

func isHidden(ctx context.Context, q core.Q, target string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM st_hidden WHERE target = $1)`, target).Scan(&ok)
	return ok, err
}

// Series returns the last n hourly points of a target, newest first. Every hour is aggregated
// from the live rows (72 h) and read from st_hourly (90 d); when both hold a bucket the one with
// more reports wins, so the bucket straddling the 72 h boundary and hours thinned by eviction
// keep their complete counts.
func Series(ctx context.Context, q core.Q, target string, n int) ([]Point, error) {
	n = min(max(n, 1), seriesMax)
	rows, err := q.Query(ctx, `WITH live AS (
		SELECT b.h, sum(b.w)::float8 AS reports, count(DISTINCT b.root) AS roots, count(DISTINCT b.ipsuper) AS nets,
		  (SELECT coalesce(jsonb_object_agg(z.sym, z.n), '{}') FROM (SELECT x.sym, count(*) n FROM beacons x
		     WHERE x.target = $1 AND date_trunc('hour', x.created) = b.h GROUP BY x.sym) z) AS syms
		FROM (SELECT date_trunc('hour', created) h, root, ipsuper, CASE WHEN root IS NULL THEN $3::numeric ELSE 1 END w
		      FROM beacons WHERE target = $1) b
		GROUP BY b.h)
		SELECT DISTINCT ON (h) h, reports, roots, nets, syms FROM (
		  SELECT 0 AS src, h, reports, roots, nets, syms FROM live
		  UNION ALL
		  SELECT 1, hour, reports::float8, roots, nets, syms FROM st_hourly WHERE target = $1) u
		ORDER BY h DESC, reports DESC, src LIMIT $2`, target, n, anonWeight)
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

// Indexable (27.1): the target has >= 7 distinct days with >= 5 distinct super-groups in the last
// 30 d (exact daily counts from live rows, busiest-hour counts from st_hourly), passes
// core.Reserved and the lexicon (score < 2, as trust.Indexable) and is not hidden.
func Indexable(ctx context.Context, q core.Q, target string) (bool, error) {
	if core.Reserved(target) {
		return false, nil
	}
	if score, _, _ := scrub.Flags(target); score >= 2 {
		return false, nil
	}
	hidden, err := isHidden(ctx, q, target)
	if err != nil || hidden {
		return false, err
	}
	var days int
	err = q.QueryRow(ctx, `SELECT count(*) FROM (
		SELECT date_trunc('day', created) d FROM beacons WHERE target = $1 AND created > now() - interval '30 days'
		  GROUP BY 1 HAVING count(DISTINCT ipsuper) >= 5
		UNION
		SELECT DISTINCT date_trunc('day', hour) FROM st_hourly WHERE target = $1 AND hour > now() - interval '30 days' AND nets >= 5) x`, target).Scan(&days)
	return days >= 7, err
}

// lastHour is the newest hour bucket of a target with reports (dateModified, sitemap lastmod).
func lastHour(ctx context.Context, q core.Q, target string) (time.Time, error) {
	var t *time.Time
	err := q.QueryRow(ctx, `SELECT greatest((SELECT date_trunc('hour', max(created)) FROM beacons WHERE target = $1),
		(SELECT max(hour) FROM st_hourly WHERE target = $1 AND reports > 0))`, target).Scan(&t)
	if err != nil || t == nil {
		return time.Time{}, err
	}
	return t.UTC(), nil
}

// Janitor rolls complete hours up into st_hourly (never lowering a stored bucket), deletes live
// rows older than 72 h, drops st_hourly beyond 90 d, then evicts past the live cap (27.8).
func Janitor(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `INSERT INTO st_hourly (target, hour, reports, roots, nets, syms)
		SELECT b.target, b.h, sum(b.w)::real, count(DISTINCT b.root), count(DISTINCT b.ipsuper),
		  (SELECT coalesce(jsonb_object_agg(z.sym, z.n), '{}') FROM (SELECT x.sym, count(*) n FROM beacons x
		     WHERE x.target = b.target AND date_trunc('hour', x.created) = b.h GROUP BY x.sym) z)
		FROM (SELECT target, date_trunc('hour', created) h, root, ipsuper, CASE WHEN root IS NULL THEN $1::numeric ELSE 1 END w
		      FROM beacons WHERE created < date_trunc('hour', now())) b
		GROUP BY b.target, b.h
		ON CONFLICT (target, hour) DO UPDATE SET
		  reports = greatest(st_hourly.reports, EXCLUDED.reports), roots = greatest(st_hourly.roots, EXCLUDED.roots),
		  nets = greatest(st_hourly.nets, EXCLUDED.nets),
		  syms = CASE WHEN EXCLUDED.reports >= st_hourly.reports THEN EXCLUDED.syms ELSE st_hourly.syms END`, anonWeight); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM beacons WHERE created < now() - $1::interval`, liveWindow); err != nil {
		return err
	}
	if _, err := q.Exec(ctx, `DELETE FROM st_hourly WHERE hour < now() - $1::interval`, hourlyKeep); err != nil {
		return err
	}
	return Evict(ctx, q)
}

// Evict applies the 27.8 eviction order to beacons: past 95 % of MaxLive, delete the oldest rows
// of the super-groups holding the largest share first, until the table is back at 90 %.
func Evict(ctx context.Context, q core.Q) error {
	var total int64
	if err := q.QueryRow(ctx, `SELECT count(*) FROM beacons`).Scan(&total); err != nil {
		return err
	}
	if total < MaxLive*95/100 {
		return nil
	}
	excess := total - MaxLive*90/100
	for i := 0; i < evictRounds && excess > 0; i++ {
		var sup string
		var held int64
		err := q.QueryRow(ctx, `SELECT ipsuper, count(*) FROM beacons GROUP BY ipsuper ORDER BY 2 DESC, 1 LIMIT 1`).Scan(&sup, &held)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		tag, err := q.Exec(ctx, `DELETE FROM beacons WHERE id IN (SELECT id FROM beacons WHERE ipsuper = $1 ORDER BY created, id LIMIT $2)`,
			sup, min(excess, held/2+1))
		if err != nil {
			return err
		}
		excess -= tag.RowsAffected()
	}
	return nil
}

// export writes the root's beacons as JSONL (export-me, 3.4).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	rows, err := q.Query(ctx, `SELECT target, sym, created FROM beacons WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	for rows.Next() {
		var rec struct {
			Kind    string    `json:"kind"`
			Target  string    `json:"target"`
			Sym     string    `json:"sym"`
			Created time.Time `json:"created"`
		}
		rec.Kind = "beacon"
		if err := rows.Scan(&rec.Target, &rec.Sym, &rec.Created); err != nil {
			return err
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
