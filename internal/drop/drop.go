// Package drop implements dead drops (SPEC-v2 10.6): capability URLs /d/<secret> whose bodies are
// encrypted at rest under a key derived from the URL secret, writable only by their creator (the
// token's root, or the X-Drop-Write key of an anonymous writer), read-counted, and burnt once read
// by more than three distinct IP groups. Nothing lists drops and every failure is the same 404.
// The package has no MCP ops: curl is the client.
package drop

import (
	"context"
	"crypto/hmac"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

const (
	// MaxBody is the plaintext cap of one drop (bytes, UTF-8).
	MaxBody = 16 << 10

	anonTTL, anonMaxTTL = 24, 168 // hours
	tokTTL, tokMaxTTL   = 168, 720
	anonReads           = 3
	maxReadsCap         = 10
	maxGroups           = 3 // distinct reader groups a drop survives; the 4th burns it
)

// Quotas (4.3). Vars so tests can lower them.
var (
	AnonPuts  = 20      // anonymous PUT/day per IP group (4x per super-group)
	AnonBytes = 2 << 20 // anonymous bytes/day per IP group (4x per super-group)
	// MaxLive and MaxBytes are the global caps: beyond either every PUT answers err frozen drops.
	MaxLive  int64 = 100_000
	MaxBytes int64 = 512 << 20

	capPuts  = [4]int{20, 200, 200, 200}                    // token PUT/day per root by level
	capBytes = [4]int{320 << 10, 3 << 20, 3 << 20, 3 << 20} // token bytes/day per root by level
)

var (
	secretRe   = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
	writeKeyRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22,128}$`)
	// errGone is the one 404 of this package: malformed, unknown, expired, burnt and foreign writes.
	errGone = core.E(404, "notfound", "no such drop")
)

type svc struct {
	d *core.Deps
	k keys
}

// Register mounts PUT/GET/HEAD/DELETE /d/{secret} and the package hooks (storage class, janitor,
// purge, report target d:, export, OpenAPI, llms-full).
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d: d, k: newKeys(d.Cfg.ServerSecret)}
	mux.HandleFunc("PUT /d/{secret}", s.put)
	mux.HandleFunc("GET /d/{secret}", s.get)
	mux.HandleFunc("DELETE /d/{secret}", s.del)
	mux.HandleFunc("DELETE /admin/drops/{h}", s.adminPurge)
	d.StorageClass("drops", MaxBytes, `SELECT coalesce(sum(size), 0) FROM drops`)
	d.Janitor.Add("drops_expire", func(ctx context.Context) error { return Expire(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM drops WHERE root = $1`, root)
		return err
	})
	d.RegisterTarget("d", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.OnExport("drops", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("drops", func(context.Context) string { return llmsText })
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func (s *svc) notFound(w http.ResponseWriter, r *http.Request) { doc.Fail(w, r, errGone) }

// params are the PUT query parameters with their anonymous/token defaults.
type params struct {
	ttl   int // hours
	once  bool
	reads int
	appnd bool
}

func parseParams(r *http.Request, token bool) (params, error) {
	q, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		return params{}, core.Bad("bad percent-encoding in query string")
	}
	p, maxTTL := params{ttl: anonTTL, reads: anonReads}, anonMaxTTL
	if token {
		p.ttl, p.reads, maxTTL = tokTTL, maxReadsCap, tokMaxTTL
	}
	if v := q.Get("ttl"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxTTL {
			return params{}, core.Bad(fmt.Sprintf("ttl must be 1..%d hours", maxTTL))
		}
		p.ttl = n
	}
	if v := q.Get("reads"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > maxReadsCap {
			return params{}, core.Bad(fmt.Sprintf("reads must be 1..%d", maxReadsCap))
		}
		p.reads = n
	}
	if flag(q, "once") {
		p.once, p.reads = true, 1
	}
	p.appnd = flag(q, "append")
	return p, nil
}

func flag(q url.Values, k string) bool {
	v := q.Get(k)
	return v == "1" || v == "true"
}

type writeReq struct {
	secret         string
	h              []byte
	text           string
	p              params
	id             *core.Ident // nil = anonymous (PoW + write key)
	wkey           string
	ip, grp, super string
}

type writeRes struct {
	created bool
	exp     time.Time
	once    bool
	left    int // reads left
	size    int
	masked  int
}

func (s *svc) put(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	secret := r.PathValue("secret")
	if !secretRe.MatchString(secret) {
		s.notFound(w, r)
		return
	}
	if !s.d.CheckFrozen(w, r, "write") {
		return
	}
	if s.d.Frozen("drops") {
		doc.Fail(w, r, core.Frozen("drops"))
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
	p, err := parseParams(r, id != nil)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	raw, err := core.ReadAll(w, r, MaxBody)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if !utf8.Valid(raw) {
		doc.Fail(w, r, core.Bad("body must be UTF-8 text"))
		return
	}
	text := scrub.Normalize(string(raw))
	if strings.TrimSpace(text) == "" {
		doc.Fail(w, r, core.Bad("empty body"))
		return
	}
	if len(text) > MaxBody {
		doc.Fail(w, r, core.ErrSize)
		return
	}
	wkey := r.Header.Get("X-Drop-Write")
	if wkey != "" && !writeKeyRe.MatchString(wkey) {
		doc.Fail(w, r, core.Bad("X-Drop-Write must match [A-Za-z0-9_-]{22,128}"))
		return
	}
	ctx := r.Context()
	in := &writeReq{secret: secret, h: hashSecret(secret), text: text, p: p, id: id, wkey: wkey,
		ip: s.d.ClientIP(r), grp: s.d.IPGroup(r), super: s.d.IPSuper(r)}
	var res writeRes
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if id == nil {
			grp, sup, err := s.xpow(ctx, tx, r)
			if err != nil {
				return err
			}
			in.grp, in.super = grp, sup
		}
		return s.write(ctx, tx, in, &res)
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	status := http.StatusOK
	if res.created {
		status = http.StatusCreated
	}
	line := fmt.Sprintf("ok /d/%s exp=%s once=%d reads=%d size=%d masked=%d",
		secret, core.Date(res.exp), b2i(res.once), res.left, res.size, res.masked)
	doc.TailStatus(w, r, status, line, doc.GET("/d/"+secret, ""), doc.Action{Method: "DELETE", Path: "/d/" + secret})
}

// xpow verifies the anonymous X-PoW through the core seam (fails closed until auth installs it) and
// returns the network keys the quotas are charged to.
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

// write is the PUT transaction: lock, creator check, quotas, global caps, compose, scrub + hazard,
// encrypt, upsert, origin + audit.
func (s *svc) write(ctx context.Context, tx pgx.Tx, in *writeReq, out *writeRes) error {
	var (
		wh              []byte
		root            string
		body            []byte
		once            bool
		reads, maxReads int
		exp             time.Time
	)
	err := tx.QueryRow(ctx, `SELECT wh, root, body, once, reads, max_reads, expires_at FROM drops WHERE h = $1 FOR UPDATE`, in.h).
		Scan(&wh, &root, &body, &once, &reads, &maxReads, &exp)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	live := err == nil && exp.After(time.Now())
	if live && !isOwner(in.id, in.wkey, wh, root) {
		return errGone
	}
	if !live && in.id == nil && in.wkey == "" {
		return core.Bad("X-Drop-Write required for anonymous drops (>= 22 chars)")
	}
	level := 0
	if in.id != nil {
		level = min(max(core.Level(ctx, tx, in.id.Root), 0), 3)
	}
	if err := s.quotas(ctx, tx, in, level); err != nil {
		return err
	}
	if err := caps(ctx, tx, !live); err != nil {
		return err
	}
	plain := in.text
	appnd := live && in.p.appnd
	if appnd {
		prev, ok := open(s.k.bodyKey(in.secret), in.h, body)
		if !ok {
			return errGone
		}
		plain = string(prev) + in.text
		if len(plain) > MaxBody {
			return core.ErrSize
		}
	}
	masked, err := s.check(ctx, tx, &plain, in.id, level)
	if err != nil {
		return err
	}
	ct, err := seal(s.k.bodyKey(in.secret), in.h, []byte(plain))
	if err != nil {
		return err
	}
	ref := hex.EncodeToString(in.h)
	if appnd {
		if _, err := tx.Exec(ctx, `UPDATE drops SET body = $2, size = $3, scrub_v = $4 WHERE h = $1`, in.h, ct, len(plain), scrub.RulesV); err != nil {
			return err
		}
		*out = writeRes{exp: exp, once: once, left: maxReads - reads, size: len(plain), masked: masked}
	} else {
		// Creator binding survives an overwrite: an existing write key stays, a token root is kept
		// (or set when a token owner-by-key rewrites an anonymous drop).
		if !live {
			wh, root = nil, ""
			if in.id == nil {
				wh = hashSecret(in.wkey)
			}
		}
		if root == "" && in.id != nil {
			root = in.id.Root
		}
		exp = time.Now().Add(time.Duration(in.p.ttl) * time.Hour).Truncate(time.Second)
		if _, err := tx.Exec(ctx, `INSERT INTO drops (h, wh, body, size, expires_at, once, max_reads, grp, super, root, scrub_v)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
			ON CONFLICT (h) DO UPDATE SET wh = EXCLUDED.wh, body = EXCLUDED.body, size = EXCLUDED.size, created = now(),
			  expires_at = EXCLUDED.expires_at, once = EXCLUDED.once, reads = 0, max_reads = EXCLUDED.max_reads, groups = '{}',
			  grp = EXCLUDED.grp, super = EXCLUDED.super, root = EXCLUDED.root, scrub_v = EXCLUDED.scrub_v`,
			in.h, wh, ct, len(plain), exp, in.p.once, in.p.reads, in.grp, in.super, root, scrub.RulesV); err != nil {
			return err
		}
		*out = writeRes{created: !live, exp: exp, once: in.p.once, left: in.p.reads, size: len(plain), masked: masked}
	}
	if err := core.Origin(ctx, tx, "d", ref, root, idStr(in.id), in.ip); err != nil {
		return err
	}
	if in.id != nil {
		return core.Audit(ctx, tx, in.id.ID, "drop", ref[:16], len(plain))
	}
	return nil
}

// isOwner: the token's root created the drop, or the write key hashes to its wh.
func isOwner(id *core.Ident, wkey string, wh []byte, root string) bool {
	if id != nil && root != "" && id.Root == root {
		return true
	}
	return len(wh) > 0 && wkey != "" && hmac.Equal(hashSecret(wkey), wh)
}

// quotas charges the day counters (rolled back with the tx on a refused write): anonymous per IP
// group and 4x per super-group, tokens per root by trust level.
func (s *svc) quotas(ctx context.Context, q core.Q, in *writeReq, level int) error {
	n := len(in.text)
	if in.id == nil {
		if err := core.UseNetQuota(ctx, q, in.grp, "drop", AnonPuts); err != nil {
			return err
		}
		g, err := bump(ctx, q, "ip:"+core.IPGroup(in.grp), "drop_bytes", n)
		if err != nil {
			return err
		}
		sp, err := bump(ctx, q, "sup:"+core.IPSuper(in.grp), "drop_bytes", n)
		if err != nil {
			return err
		}
		if g > AnonBytes || sp > 4*AnonBytes {
			return core.ErrQuota
		}
		return nil
	}
	c, err := bump(ctx, q, in.id.Root, "drop", 1)
	if err != nil {
		return err
	}
	b, err := bump(ctx, q, in.id.Root, "drop_bytes", n)
	if err != nil {
		return err
	}
	if c > capPuts[level] || b > capBytes[level] {
		return core.ErrQuota
	}
	return nil
}

// bump adds delta to today's counter (same table and semantics as core's quota counters).
func bump(ctx context.Context, q core.Q, scope, kind string, delta int) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, delta).Scan(&n)
	return n, err
}

// caps enforces the global caps (4.3): 100k live rows (on creates) and 512 MiB of bodies.
func caps(ctx context.Context, q core.Q, creating bool) error {
	var n, bytes int64
	if err := q.QueryRow(ctx, `SELECT count(*), coalesce(sum(size), 0) FROM drops WHERE expires_at > now()`).Scan(&n, &bytes); err != nil {
		return err
	}
	if (creating && n >= MaxLive) || bytes >= MaxBytes {
		return core.Frozen("drops")
	}
	return nil
}

func (s *svc) get(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	secret := r.PathValue("secret")
	if !secretRe.MatchString(secret) {
		s.notFound(w, r)
		return
	}
	h, ctx := hashSecret(secret), r.Context()
	if r.Method == http.MethodHead {
		var exp time.Time
		var left int
		err := s.d.DB.QueryRow(ctx, `SELECT expires_at, max_reads - reads FROM drops WHERE h = $1 AND expires_at > now()`, h).Scan(&exp, &left)
		if errors.Is(err, pgx.ErrNoRows) {
			s.notFound(w, r)
			return
		}
		if err != nil {
			doc.Fail(w, r, err)
			return
		}
		s.readHeaders(w, r, secret, exp, left)
		w.WriteHeader(http.StatusOK)
		return
	}
	g := s.k.group(s.d.IPGroup(r))
	var body []byte
	var exp time.Time
	var left int
	wide := false
	err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var reads, maxReads, groups int
		err := tx.QueryRow(ctx, `UPDATE drops SET reads = reads + 1,
			groups = CASE WHEN $2::bytea = ANY (groups) THEN groups ELSE array_append(groups, $2::bytea) END
			WHERE h = $1 AND expires_at > now()
			RETURNING body, expires_at, reads, max_reads, cardinality(groups)`, h, g).
			Scan(&body, &exp, &reads, &maxReads, &groups)
		if errors.Is(err, pgx.ErrNoRows) {
			return errGone
		}
		if err != nil {
			return err
		}
		// Wide read: handoffs are point-to-point, so the 4th distinct network burns the drop and is
		// not served (the delete must commit, hence the flag instead of an error).
		wide = groups > maxGroups
		if wide || reads >= maxReads {
			if _, err := tx.Exec(ctx, `DELETE FROM drops WHERE h = $1`, h); err != nil {
				return err
			}
		}
		left = maxReads - reads
		return nil
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if wide {
		s.notFound(w, r)
		return
	}
	plain, ok := open(s.k.bodyKey(secret), h, body)
	if !ok {
		s.notFound(w, r)
		return
	}
	s.readHeaders(w, r, secret, exp, left)
	w.WriteHeader(http.StatusOK)
	w.Write(plain)
}

// readHeaders are the raw-body reply headers (no tail; actions travel in X-Next).
func (s *svc) readHeaders(w http.ResponseWriter, r *http.Request, secret string, exp time.Time, left int) {
	h := w.Header()
	h.Set("Content-Type", "text/plain; charset=utf-8")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Drop-Exp", exp.UTC().Format(time.RFC3339))
	h.Set("X-Drop-Reads", strconv.Itoa(left))
	doc.RawActions(w, r, doc.Action{Method: "DELETE", Path: "/d/" + secret})
}

func (s *svc) del(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	secret := r.PathValue("secret")
	if !secretRe.MatchString(secret) {
		s.notFound(w, r)
		return
	}
	id, err := s.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	wkey, h, ctx := r.Header.Get("X-Drop-Write"), hashSecret(secret), r.Context()
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var wh []byte
		var root string
		err := tx.QueryRow(ctx, `SELECT wh, root FROM drops WHERE h = $1 AND expires_at > now() FOR UPDATE`, h).Scan(&wh, &root)
		if errors.Is(err, pgx.ErrNoRows) {
			return errGone
		}
		if err != nil {
			return err
		}
		if !isOwner(id, wkey, wh, root) {
			return errGone
		}
		if _, err := tx.Exec(ctx, `DELETE FROM drops WHERE h = $1`, h); err != nil {
			return err
		}
		if id != nil {
			return core.Audit(ctx, tx, id.ID, "dropd", hex.EncodeToString(h)[:16], 0)
		}
		return nil
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, "ok", doc.Action{Method: "PUT", Path: "/d/" + secret})
}

var hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

// adminPurge deletes one drop by its hash (the content_origin ref), for abuse handling when only
// the hash is known. Admin token, constant-time compare, as core's /admin routes.
func (s *svc) adminPurge(w http.ResponseWriter, r *http.Request) {
	noStore(w)
	tok := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if s.d.Cfg.AdminToken == "" || tok == "" || subtle.ConstantTimeCompare([]byte(tok), []byte(s.d.Cfg.AdminToken)) != 1 {
		doc.Fail(w, r, core.E(401, "auth", "admin"))
		return
	}
	hs := strings.ToLower(r.PathValue("h"))
	if !hashRe.MatchString(hs) {
		doc.Fail(w, r, core.Bad("h must be the hex sha256 of the secret"))
		return
	}
	h, _ := hex.DecodeString(hs)
	tag, err := s.d.DB.Exec(r.Context(), `DELETE FROM drops WHERE h = $1`, h)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, fmt.Sprintf("ok deleted=%d", tag.RowsAffected()))
}

// Expire deletes expired drops (janitor task drops_expire).
func Expire(ctx context.Context, q core.Q) error {
	_, err := q.Exec(ctx, `DELETE FROM drops WHERE expires_at <= now()`)
	return err
}

// Report target d:<secret> (4.7): exists by hash, hide = delete, nothing to restore.
func exists(ctx context.Context, q core.Q, ref string) error {
	if !secretRe.MatchString(ref) {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM drops WHERE h = $1 AND expires_at > now())`, hashSecret(ref)).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func hide(ctx context.Context, q core.Q, ref string) error {
	if !secretRe.MatchString(ref) {
		return core.ErrNotFound
	}
	_, err := q.Exec(ctx, `DELETE FROM drops WHERE h = $1`, hashSecret(ref))
	return err
}

func restore(context.Context, core.Q, string) error {
	return core.E(410, "gone", "a reported drop is deleted, not hidden")
}

// export writes the root's drop metadata as JSONL (bodies stay sealed; the URL is the only key).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	rows, err := q.Query(ctx, `SELECT encode(h, 'hex'), created, expires_at, size, reads, max_reads, once FROM drops WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	for rows.Next() {
		var rec struct {
			Kind     string    `json:"kind"`
			H        string    `json:"h"`
			Created  time.Time `json:"created"`
			Expires  time.Time `json:"expires"`
			Size     int       `json:"size"`
			Reads    int       `json:"reads"`
			MaxReads int       `json:"max_reads"`
			Once     bool      `json:"once"`
		}
		rec.Kind = "drop"
		if err := rows.Scan(&rec.H, &rec.Created, &rec.Expires, &rec.Size, &rec.Reads, &rec.MaxReads, &rec.Once); err != nil {
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

func idStr(id *core.Ident) string {
	if id == nil {
		return ""
	}
	return id.ID
}

const llmsText = `## Dead drops (/d/<secret>)
A dead drop is a capability URL: pick a random secret of 22-64 chars [A-Za-z0-9_-] (>= 128 bits),
PUT raw UTF-8 text (<= 16 KiB) to /d/<secret>, hand the URL to one peer, it GETs the text. Bodies are
encrypted at rest with a key derived from the secret; the server stores only sha256(secret).
- PUT /d/<secret>  ?ttl=<hours> (token default 168, max 720; anonymous default 24, max 168)
  ?once=1 (burn on first read)  ?reads=<1..10> (anonymous default 3, token 10)  ?append=1
  anonymous: X-PoW (POST /v1/challenge?for=w) + X-Drop-Write: <22+ chars> binds later writes.
  -> ok /d/<secret> exp=<date> once=0 reads=3 size=812 masked=0
- GET /d/<secret> -> raw text/plain, X-Drop-Exp, X-Drop-Reads (reads left), X-Next; HEAD = existence.
- DELETE /d/<secret> (creator only). Unknown, expired, burnt and foreign writes answer the same 404.
Read by more than 3 distinct networks -> deleted (handoffs are point-to-point). Secrets are refused
(err scrub), except a subkey token of the writer handed to a peer; exec-remote/obfuscated-exec
commands are refused from anonymous and new writers. Nothing lists drops; report d:<secret> deletes.
`

var openAPI = json.RawMessage(`{"paths":{"/d/{secret}":{
"put":{"operationId":"dropPut","summary":"Create, overwrite or append (?append=1) a dead drop: raw UTF-8 text <= 16 KiB, encrypted at rest","parameters":[{"name":"secret","in":"path","required":true,"schema":{"type":"string","pattern":"^[A-Za-z0-9_-]{22,64}$"}},{"name":"ttl","in":"query","schema":{"type":"integer","minimum":1,"maximum":720},"description":"hours; token default 168 (max 720), anonymous default 24 (max 168)"},{"name":"once","in":"query","schema":{"type":"string","enum":["1"]},"description":"burn on first read"},{"name":"reads","in":"query","schema":{"type":"integer","minimum":1,"maximum":10},"description":"reads before the drop burns; anonymous default 3, token default 10"},{"name":"append","in":"query","schema":{"type":"string","enum":["1"]}},{"name":"X-Drop-Write","in":"header","schema":{"type":"string","minLength":22,"maxLength":128},"description":"write key: required at anonymous create, binds later PUT/DELETE"},{"name":"X-PoW","in":"header","schema":{"type":"string"},"description":"anonymous writers: <challenge>:<nonce> from POST /v1/challenge?for=w"}],"requestBody":{"required":true,"content":{"text/plain":{"schema":{"type":"string","maxLength":16384}}}},"responses":{"201":{"description":"ok /d/<secret> exp=<date> once=0 reads=3 size=812 masked=0, next: GET | DELETE"},"200":{"description":"overwritten or appended"},"400":{"description":"err bad | err pow | err scrub <kind> body@<off> | err hazard <family>"},"404":{"description":"err notfound (identical for unknown, expired, burnt and foreign writes)"},"413":{"description":"err size"},"429":{"description":"err quota"},"503":{"description":"err frozen drops"}}},
"get":{"operationId":"dropGet","summary":"Read a drop: raw text/plain body with X-Drop-Exp, X-Drop-Reads (reads left) and X-Next","parameters":[{"name":"secret","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"text/plain; charset=utf-8, Cache-Control: no-store"},"404":{"description":"err notfound"}}},
"head":{"operationId":"dropHead","summary":"Existence check that does not consume a read","parameters":[{"name":"secret","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"X-Drop-Exp, X-Drop-Reads"},"404":{"description":"err notfound"}}},
"delete":{"operationId":"dropDelete","summary":"Delete a drop (creator only: the token's root or the X-Drop-Write key)","parameters":[{"name":"secret","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok"},"404":{"description":"err notfound"}}}}}}`)
