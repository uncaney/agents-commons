// Package tripwire implements tripwire URLs (SPEC-v2 27.9): an agent mints /y/<secret> (POST /v1/tw,
// or anonymously PUT /y/<secret> with X-PoW) and plants it where nobody should look: a config
// file, a prompt, a private repo. Any GET, HEAD or POST of the URL (with or without a path suffix)
// answers 200 with an empty body (a 1x1 PNG when the path ends .png) and records a hit: existence,
// time, the UA class from a fixed prefix table and the HMAC'd network of the caller. Nothing
// attacker-controlled is stored: no suffix, query, UA string, referer or IP. The first hit mails
// the owner (mail.SendSys), appends a root-scoped event and optionally publishes through
// PublishFn. Unknown, expired and hidden secrets answer one identical 404. Reads: GET /v1/tw/{id}
// (owner) or GET /y/<secret>/.hits with the read key.
package tripwire

import (
	"bytes"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"image"
	"image/png"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/mail"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Caps and bounds (4.3, 27.9). Vars so tests can lower them.
var (
	AnonDaily = 10 // anonymous mints per IP group per day; 4x per super-group (core.UseNetQuota)
	HitCap    = 50 // stored hit rows per tripwire; the hits counter keeps counting past it
)

const (
	tokenTTL    = 30 * 24 * time.Hour
	maxTTL      = 180 * 24 * time.Hour
	anonTTL     = 7 * 24 * time.Hour
	maxNote     = 120
	maxBody     = 4 << 10
	triggerCost = 0.2
	readHeader  = "X-Tripwire-Read"
	capKind     = "tripwires" // trust.Cap row: live tripwires L0 20 / L1+ 200
)

var (
	secretRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
	rkeyRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{16,64}$`)
	// topicRe is the shape check of on_hit.ps; swarm.ParseName validates fully when PublishFn runs.
	topicRe = regexp.MustCompile(`^[~a-z][A-Za-z0-9:._-]{1,127}$`)

	errSecret = core.Bad("secret must be 22-64 chars of [A-Za-z0-9_-] (24 random bytes, base64url)")
	errRKey   = core.Bad(readHeader + " must be 16-64 chars of [A-Za-z0-9_-]")
	errTopic  = core.Bad("on_hit.ps must be a topic name (g:<name> | ~<name> | a:<root>.<name> | s:<slug>.<name>)")
	errLive   = core.E(429, "quota", "live tripwires cap reached (expire or wait)")
	errMiss   = errors.New("tripwire: miss")
)

// PublishFn publishes the first-hit notice to the on_hit.ps topic as the owner root (the wiring
// package points it at swarm.Publish); nil = no publish.
var PublishFn func(ctx context.Context, q core.Q, topic, root, text string) error

// png1x1 is the transparent pixel served when the path ends .png.
var png1x1 = func() []byte {
	var b bytes.Buffer
	png.Encode(&b, image.NewNRGBA(image.Rect(0, 0, 1, 1)))
	return b.Bytes()
}()

type svc struct{ d *core.Deps }

// Register mounts POST /v1/tw, GET /v1/tw/{id}, PUT /y/{secret}, the triggers GET|HEAD|POST
// /y/{secret}[/{rest...}] (cost 0.2) and the package hooks: scopes, OpenAPI, llms-full, report
// target y:, storage class, janitor, purge, export, resume.
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d}
	mux.HandleFunc("POST /v1/tw", s.create)
	mux.HandleFunc("GET /v1/tw/{id}", s.get)
	mux.HandleFunc("PUT /y/{secret}", s.put)
	for _, p := range []string{"GET /y/{secret}", "POST /y/{secret}", "GET /y/{secret}/{rest...}", "POST /y/{secret}/{rest...}"} {
		mux.HandleFunc(p, s.trip)
		d.RegisterCost(p, triggerCost)
	}
	d.RegisterScope("POST /v1/tw", "w")
	d.RegisterScope("GET /v1/tw/{id}", "w")
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("tripwires", func(context.Context) string { return llmsText })
	d.RegisterTarget("y", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.StorageClass(capKind, 64<<20, `SELECT pg_total_relation_size('tripwires') + pg_total_relation_size('tripwire_hits')`)
	d.Janitor.Add(capKind, func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM tripwires WHERE root = $1`, root)
		return err
	})
	d.OnExport(capKind, func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.OnResume(func(ctx context.Context, root string) []string { return resume(ctx, d.DB, root) })
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func randB64(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// netKey is HMAC(day key, super-group)[:16] with day key = HKDF(server secret, "tripwire|date"):
// the same network collapses within a day, nothing links days or recovers the prefix.
func (s *svc) netKey(super string, t time.Time) []byte {
	k, err := hkdf.Key(sha256.New, s.d.Cfg.ServerSecret, nil, "tripwire|"+t.UTC().Format("2006-01-02"), 32)
	if err != nil {
		k = make([]byte, 32)
	}
	m := hmac.New(sha256.New, k)
	m.Write([]byte(super))
	return m.Sum(nil)[:16]
}

// netHex is the 4-hex rendering of a stored network key (net=a1b2).
func netHex(h []byte) string {
	if len(h) < 2 {
		return "0000"
	}
	return hex.EncodeToString(h[:2])
}

// input is the mint body of POST /v1/tw (and the optional body of PUT /y/{secret}).
type input struct {
	Note  string `json:"note"`
	TTLH  int    `json:"ttl_h"`
	OnHit onHit  `json:"on_hit"`
}

type onHit struct {
	PS string `json:"ps,omitempty"`
}

// validate checks the note (<= 120 bytes, one line, no tier-1 secret), the ttl and the on_hit
// topic shape; anonymous mints ignore ttl and on_hit.
func (in *input) validate(anon bool) error {
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
	if in.TTLH < 0 {
		return core.Bad("ttl_h must be >= 0")
	}
	if anon {
		in.TTLH, in.OnHit = 0, onHit{}
		return nil
	}
	if in.OnHit.PS != "" && !topicRe.MatchString(in.OnHit.PS) {
		return errTopic
	}
	return nil
}

// ttl is the lifetime of a mint: anonymous 7 d; token ttl_h (default 30 d) clamped to 180 d.
func (in *input) ttl(anon bool) time.Duration {
	if anon {
		return anonTTL
	}
	if in.TTLH == 0 {
		return tokenTTL
	}
	return min(time.Duration(in.TTLH)*time.Hour, maxTTL)
}

// mintReq is one tripwire to create: the secret and read key (server-made or client-chosen), the
// owner identity or the anonymous network keys.
type mintReq struct {
	in           input
	secret, rkey string
	id           *core.Ident
	grp          string
}

type minted struct {
	ID      string
	Secret  string
	RKey    string
	Expires time.Time
}

// line is the mint reply head: ok y… url=<base>/y/<secret> read=<rkey>, then expires: <date>.
func (m minted) line() string {
	return fmt.Sprintf("ok %s url=%s/y/%s read=%s\nexpires: %s", m.ID, doc.Base(), m.Secret, m.RKey, core.Date(m.Expires))
}

// mint is the create transaction: the live cap (token) or the anonymous network quota, the
// insert, the owner audit row.
func (s *svc) mint(ctx context.Context, tx core.Q, req *mintReq) (minted, error) {
	anon := req.id == nil
	root := ""
	if !anon {
		root = req.id.Root
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM tripwires WHERE root = $1 AND expires_at > now()`, root).Scan(&live); err != nil {
			return minted{}, err
		}
		if live >= trust.Cap(capKind, core.Level(ctx, tx, root)) {
			return minted{}, errLive
		}
	} else if err := core.UseNetQuota(ctx, tx, req.grp, "tripwire", AnonDaily); err != nil {
		return minted{}, err
	}
	m := minted{ID: core.NewID('y'), Secret: req.secret, RKey: req.rkey, Expires: time.Now().Add(req.in.ttl(anon))}
	if m.Secret == "" {
		m.Secret = randB64(24)
	}
	if m.RKey == "" {
		m.RKey = randB64(18)
	}
	oh, _ := json.Marshal(req.in.OnHit)
	if _, err := tx.Exec(ctx, `INSERT INTO tripwires (id, h, rh, root, note, expires_at, on_hit) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		m.ID, hash(m.Secret), hash(m.RKey), root, req.in.Note, m.Expires, oh); err != nil {
		if core.IsUniqueViolation(err) {
			return minted{}, core.ErrDup
		}
		return minted{}, err
	}
	if !anon {
		if err := core.Audit(ctx, tx, req.id.ID, "tw", m.ID, 0); err != nil {
			return minted{}, err
		}
	}
	return m, nil
}

// create serves POST /v1/tw (token): mints a server-made secret and read key.
func (s *svc) create(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") || !s.d.CheckFrozen(w, r, capKind) {
		return
	}
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in input
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := in.validate(false); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var m minted
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		var err error
		m, err = s.mint(r.Context(), tx, &mintReq{in: in, id: id})
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.TailStatus(w, r, http.StatusCreated, m.line(), doc.GET("/v1/tw/"+m.ID, ""), doc.GET("/y/"+m.Secret+"/.hits", "+"+readHeader))
}

// put serves PUT /y/{secret}: a client-chosen secret with the read key in X-Tripwire-Read;
// anonymous with X-PoW (7 d, 10/day per network) or with a token (owned, as POST /v1/tw).
func (s *svc) put(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	if !s.d.CheckFrozen(w, r, "write") || !s.d.CheckFrozen(w, r, capKind) {
		return
	}
	secret, rkey := r.PathValue("secret"), strings.TrimSpace(r.Header.Get(readHeader))
	switch {
	case !secretRe.MatchString(secret):
		doc.Fail(w, r, errSecret)
		return
	case !rkeyRe.MatchString(rkey):
		doc.Fail(w, r, errRKey)
		return
	}
	var in input
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if in.Note == "" {
		in.Note = r.URL.Query().Get("note")
	}
	if in.TTLH == 0 {
		in.TTLH, _ = strconv.Atoi(r.URL.Query().Get("ttl_h"))
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
		doc.Fail(w, r, core.ErrAuth, doc.POST("/v1/challenge?for=w", ""), doc.Action{Method: "PUT", Path: "/y/" + secret, Hint: "+X-PoW +" + readHeader}, doc.GET("/help", ""))
		return
	}
	if err := in.validate(id == nil); err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	req := &mintReq{in: in, secret: secret, rkey: rkey, id: id}
	var m minted
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if id == nil {
			// The proof is consumed inside the tx so a refused quota does not burn the challenge.
			if core.XPoWFn == nil {
				return core.E(400, "pow", "X-PoW required")
			}
			grp, _, err := core.XPoWFn(ctx, tx, r)
			if err != nil {
				return err
			}
			if grp == "" {
				grp = s.d.IPGroup(r)
			}
			req.grp = grp
		}
		var err error
		m, err = s.mint(ctx, tx, req)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	next := []doc.Action{doc.GET("/y/"+secret+"/.hits", "+"+readHeader)}
	if id != nil {
		next = append(next, doc.GET("/v1/tw/"+m.ID, ""))
	}
	doc.TailStatus(w, r, http.StatusCreated, m.line(), next...)
}

// notFound is the one 404 every miss answers (unknown, expired, hidden, malformed), always in the
// text format so the body is byte-identical whatever the suffix.
func notFound(w http.ResponseWriter, r *http.Request) {
	doc.ReplyAs(w, r, http.StatusNotFound, doc.Error("notfound", "not found", doc.GET("/help", "")), doc.Txt)
}

// trip serves GET|HEAD|POST /y/{secret} and /y/{secret}/{rest...}: GET /y/{secret}/.hits with a
// valid X-Tripwire-Read is the anonymous read; everything else is a hit (a wrong read key too).
func (s *svc) trip(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	secret, rest := r.PathValue("secret"), r.PathValue("rest")
	if !secretRe.MatchString(secret) {
		notFound(w, r)
		return
	}
	ctx, h := r.Context(), hash(secret)
	if rest == ".hits" && r.Method != http.MethodPost {
		if rk := strings.TrimSpace(r.Header.Get(readHeader)); rk != "" {
			v, err := s.view(ctx, `h = $1 AND rh = $2`, h, hash(rk))
			if err == nil {
				s.reply(w, r, v, "/y/"+secret+"/.hits")
				return
			}
			if !errors.Is(err, errMiss) {
				doc.Fail(w, r, err)
				return
			}
		}
	}
	first, err := s.hit(ctx, h, UAClass(r.UserAgent()), s.d.IPSuper(r))
	if errors.Is(err, errMiss) {
		notFound(w, r)
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if first != nil {
		s.notify(ctx, first)
	}
	if strings.HasSuffix(r.URL.Path, ".png") {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", strconv.Itoa(len(png1x1)))
		w.WriteHeader(http.StatusOK)
		w.Write(png1x1)
		return
	}
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(http.StatusOK)
}

// firstHit carries what the first-hit notices need; nothing in it comes from the caller but the
// UA class (fixed vocabulary) and the HMAC'd network key.
type firstHit struct {
	id, root, note, topic, ua string
	net                       []byte
	at                        time.Time
}

// hit records one hit in its own transaction: the counters on the tripwire row (its lock
// serialises concurrent hits), a hit row while fewer than HitCap exist. Returns the first-hit
// notice data when this hit was the first; errMiss for unknown, expired or hidden secrets.
func (s *svc) hit(ctx context.Context, h []byte, ua, super string) (*firstHit, error) {
	var fh *firstHit
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var id, root, note string
		var hits int
		var oh onHit
		var at time.Time
		err := tx.QueryRow(ctx, `UPDATE tripwires SET hits = hits + 1, first_hit = coalesce(first_hit, now()), last_hit = now()
			WHERE h = $1 AND expires_at > now() AND NOT hidden RETURNING id, root, note, hits, on_hit, last_hit`, h).
			Scan(&id, &root, &note, &hits, &oh, &at)
		if errors.Is(err, pgx.ErrNoRows) {
			return errMiss
		}
		if err != nil {
			return err
		}
		net := s.netKey(super, at)
		if _, err := tx.Exec(ctx, `INSERT INTO tripwire_hits (id, at, ua_class, super_h) SELECT $1, $2, $3, $4
			WHERE (SELECT count(*) FROM tripwire_hits WHERE id = $1) < $5 ON CONFLICT DO NOTHING`, id, at, ua, net, HitCap); err != nil {
			return err
		}
		if hits == 1 {
			fh = &firstHit{id: id, root: root, note: note, topic: oh.PS, ua: ua, net: net, at: at}
		}
		return nil
	})
	return fh, err
}

// notify runs the first-hit notices after the hit is committed, best effort (a failed notice
// never changes the 200 the caller sees): mail.SendSys to the owner, a root-scoped event, the
// optional publish. Anonymous tripwires have no owner and get none.
func (s *svc) notify(ctx context.Context, f *firstHit) {
	if f.root == "" {
		return
	}
	when := f.at.UTC().Format("2006-01-02T15:04Z")
	short := fmt.Sprintf("tripwire %s tripped %s ua=%s net=%s", f.id, when, f.ua, netHex(f.net))
	text := short + "\nread: GET /v1/tw/" + f.id
	if f.note != "" {
		text += "\nnote: " + doc.SafeLine(f.note)
	}
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if err := mail.SendSys(ctx, tx, f.root, "tripwire "+f.id+" tripped", text); err != nil {
			return err
		}
		return core.Event(ctx, tx, "tw", f.id, f.root, "tripwire "+f.id+" tripped")
	})
	if err != nil {
		s.d.Log.Warn("tripwire notify", "id", f.id, "err", err)
	}
	if f.topic != "" && PublishFn != nil {
		if err := PublishFn(ctx, s.d.DB, f.topic, f.root, short); err != nil {
			s.d.Log.Warn("tripwire publish", "id", f.id, "err", err)
		}
	}
}

// view is what a read shows: the tripwire's counters and its stored hit rows.
type view struct {
	ID, Note       string
	Root           string
	Hits           int
	Created        time.Time
	Expires        time.Time
	First, Last    time.Time
	Hidden         bool
	Rows           []hitRow
	Topic          string
	LiveCap, Lives int
}

type hitRow struct {
	At  time.Time
	UA  string
	Net []byte
}

// view loads one tripwire by a WHERE clause over the owner's or the reader's proof; errMiss when
// no live row matches.
func (s *svc) view(ctx context.Context, where string, args ...any) (*view, error) {
	v := &view{}
	var first, last *time.Time
	var oh onHit
	err := s.d.DB.QueryRow(ctx, `SELECT id, root, note, hits, created, expires_at, first_hit, last_hit, on_hit, hidden
		FROM tripwires WHERE `+where+` AND expires_at > now()`, args...).
		Scan(&v.ID, &v.Root, &v.Note, &v.Hits, &v.Created, &v.Expires, &first, &last, &oh, &v.Hidden)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errMiss
	}
	if err != nil {
		return nil, err
	}
	if first != nil {
		v.First = *first
	}
	if last != nil {
		v.Last = *last
	}
	v.Topic = oh.PS
	rows, err := s.d.DB.Query(ctx, `SELECT at, ua_class, super_h FROM tripwire_hits WHERE id = $1 ORDER BY at`, v.ID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var h hitRow
		if err := rows.Scan(&h.At, &h.UA, &h.Net); err != nil {
			return nil, err
		}
		v.Rows = append(v.Rows, h)
	}
	return v, rows.Err()
}

var hitCols = []string{"at", "ua", "net"}

// head is the read head line: hits=3 first=<date> last=<date>.
func (v *view) head() string {
	s := fmt.Sprintf("hits=%d first=%s last=%s", v.Hits, core.Date(v.First), core.Date(v.Last))
	if v.Hidden {
		s += " hidden"
	}
	return s
}

func (v *view) fields() []doc.F {
	fs := []doc.F{{Name: "id", Val: v.ID}, {Name: "expires", Val: core.Date(v.Expires)}}
	if v.Note != "" {
		fs = append(fs, doc.F{Name: "note", Val: doc.SafeLine(v.Note)})
	}
	if v.Topic != "" {
		fs = append(fs, doc.F{Name: "on_hit", Val: "ps " + doc.SafeLine(v.Topic)})
	}
	return fs
}

// rows renders the hit rows: <time> <ua class> net=<4 hex>.
func (v *view) rows() [][]string {
	out := make([][]string, 0, len(v.Rows))
	for _, h := range v.Rows {
		out = append(out, []string{h.At.UTC().Format("2006-01-02T15:04Z"), h.UA, "net=" + netHex(h.Net)})
	}
	return out
}

// Text is the compact text rendering (ops twg, tests): head, fields, rows.
func (v *view) Text() string {
	var b strings.Builder
	b.WriteString(v.head() + "\n")
	for _, f := range v.fields() {
		b.WriteString(f.Name + ": " + f.Val + "\n")
	}
	for _, r := range v.rows() {
		b.WriteString(strings.Join(r, " ") + "\n")
	}
	return b.String()
}

func (s *svc) reply(w http.ResponseWriter, r *http.Request, v *view, canonical string) {
	d := &doc.Doc{Head: v.head(), Fields: v.fields(), Cols: hitCols, Rows: v.rows(),
		Title: "tripwire " + v.ID, Desc: "hits of one tripwire URL: time, UA class, HMAC'd network", Canonical: canonical,
		NoIndex: true, MaxAge: -1}
	if v.Root != "" {
		d.Next = []doc.Action{doc.GET("/v1/tw/"+v.ID+".json", ""), doc.GET("/v1/me/resume", "")}
	}
	w.Header().Set("X-Robots-Tag", "noindex, nofollow")
	doc.Reply(w, r, http.StatusOK, d)
}

// get serves GET /v1/tw/{id} (owner): the counters and hit rows of one tripwire.
func (s *svc) get(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	id, err := s.d.Auth(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	seg, _ := doc.SplitSuffix(r.PathValue("id"))
	if !core.ValidIDPrefix(seg, 'y') {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	v, err := s.view(r.Context(), `id = $1 AND root = $2`, seg, id.Root)
	if errors.Is(err, errMiss) {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.reply(w, r, v, "/v1/tw/"+seg)
}

// Report target y:<id> (4.7): exists while the row lives; hide makes the URL answer the unknown
// 404 and record nothing; restore reopens it.
func exists(ctx context.Context, q core.Q, ref string) error {
	if !core.ValidIDPrefix(ref, 'y') {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM tripwires WHERE id = $1)`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func hide(ctx context.Context, q core.Q, ref string) error { return setHidden(ctx, q, ref, true) }

func restore(ctx context.Context, q core.Q, ref string) error { return setHidden(ctx, q, ref, false) }

func setHidden(ctx context.Context, q core.Q, ref string, on bool) error {
	if !core.ValidIDPrefix(ref, 'y') {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `UPDATE tripwires SET hidden = $2 WHERE id = $1`, ref, on)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return nil
}

// Janitor deletes expired tripwires (their hit rows cascade).
func Janitor(ctx context.Context, q core.Q) error {
	_, err := q.Exec(ctx, `DELETE FROM tripwires WHERE expires_at < now()`)
	return err
}

// export writes the root's tripwires as JSONL (export-me, 3.4): counters only, never a secret.
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	rows, err := q.Query(ctx, `SELECT id, note, created, expires_at, hits, first_hit, last_hit FROM tripwires WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	for rows.Next() {
		var rec struct {
			Kind    string     `json:"kind"`
			ID      string     `json:"id"`
			Note    string     `json:"note,omitempty"`
			Created time.Time  `json:"created"`
			Expires time.Time  `json:"expires"`
			Hits    int        `json:"hits"`
			First   *time.Time `json:"first_hit,omitempty"`
			Last    *time.Time `json:"last_hit,omitempty"`
		}
		rec.Kind = "tripwire"
		if err := rows.Scan(&rec.ID, &rec.Note, &rec.Created, &rec.Expires, &rec.Hits, &rec.First, &rec.Last); err != nil {
			return err
		}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}

// resume adds "tripwires: <live> live (<n> tripped)" to GET /v1/me/resume when the root has any.
func resume(ctx context.Context, q core.Q, root string) []string {
	var live, tripped int
	if err := q.QueryRow(ctx, `SELECT count(*), count(*) FILTER (WHERE hits > 0) FROM tripwires WHERE root = $1 AND expires_at > now()`, root).Scan(&live, &tripped); err != nil || live == 0 {
		return nil
	}
	return []string{fmt.Sprintf("tripwires: %d live (%d tripped)", live, tripped)}
}
