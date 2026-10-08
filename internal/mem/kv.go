package mem

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	"ekaii.fr/commons/internal/trust"
)

// nspace is a parsed KV namespace (10.3): a:<root> own, s:<slug> space, g:<name> public read,
// x:<rv> rendezvous peers, r:<room> room members. "me" is the caller's own namespace.
type nspace struct {
	raw  string
	kind byte
	name string
}

const nsHelp = "namespace must be me, a:<root>, s:<slug>, g:<name>, x:<rv id> or r:<room id>"

func parseNS(raw, root string) (nspace, error) {
	if raw == "me" {
		if root == "" {
			return nspace{}, core.ErrAuth
		}
		raw = "a:" + root
	}
	if len(raw) < 3 || raw[1] != ':' || len(raw) > 72 {
		return nspace{}, core.Bad(nsHelp)
	}
	ns := nspace{raw: raw, kind: raw[0], name: raw[2:]}
	ok := false
	switch ns.kind {
	case 'a', 'x', 'r':
		ok = core.ValidID(ns.name)
	case 's':
		ok = slugRe.MatchString(ns.name)
	case 'g':
		ok = gNameRe.MatchString(ns.name)
	}
	if !ok {
		return nspace{}, core.Bad(nsHelp)
	}
	return ns, nil
}

// nsAccess enforces who may read or write a namespace (root "" = anonymous). g: writes need the
// current fence of lock g:kv.<name> through FenceCheckFn; s:/x:/r: need the membership seams.
// Every seam is nil-safe and refuses when unset; a non-member of a room gets the room's 404.
func nsAccess(ctx context.Context, q core.Q, ns nspace, root string, write bool, fence int64) error {
	if ns.kind == 'g' && !write {
		return nil
	}
	if root == "" {
		return core.ErrAuth
	}
	switch ns.kind {
	case 'a':
		if ns.name != root {
			return core.ErrForbid
		}
	case 'g':
		if FenceCheckFn == nil {
			return core.E(409, "fenced", "lock g:kv."+ns.name+" fence required")
		}
		return FenceCheckFn(ctx, q, "g:kv."+ns.name, fence)
	case 's':
		if MemberFn == nil {
			return core.E(403, "auth", "space members only")
		}
		ok, err := MemberFn(ctx, q, ns.name, root)
		if err != nil {
			return err
		}
		if !ok {
			return core.E(403, "auth", "space members only")
		}
	case 'x':
		if RendezvousFn == nil {
			return core.E(403, "auth", "rendezvous peers only")
		}
		ok, err := RendezvousFn(ctx, q, ns.name, root)
		if err != nil {
			return err
		}
		if !ok {
			return core.E(403, "auth", "rendezvous peers only")
		}
	case 'r':
		ok, err := roomMember(ctx, q, ns.name, root)
		if err != nil {
			return err
		}
		if !ok {
			return core.ErrNotFound
		}
	}
	return nil
}

// kvScopeOK checks a scoped token against the namespace (3.5): reads pass with kv:r or a matching
// kv:<ns-glob>, writes need the glob.
func kvScopeOK(id *core.Ident, ns nspace, write bool) error {
	if id == nil || id.Scopes == nil {
		return nil
	}
	if !write && core.ScopeAllowed(id.Scopes, "kv:r") {
		return nil
	}
	if core.ScopeAllowed(id.Scopes, "kv:"+ns.raw) {
		return nil
	}
	return core.E(403, "scope", "kv:"+ns.raw)
}

// kvRow is one KV row.
type kvRow struct {
	NS, K        string
	V            []byte
	Ver, Fence   int64
	Exp, Updated time.Time
	Root         string
	Sealed       bool
	Hidden       bool
}

const kvCols = `ns, k, v, ver, fence, expires_at, root, updated, sealed, hidden`

func scanKV(row interface{ Scan(dest ...any) error }) (*kvRow, error) {
	var x kvRow
	if err := row.Scan(&x.NS, &x.K, &x.V, &x.Ver, &x.Fence, &x.Exp, &x.Root, &x.Updated, &x.Sealed, &x.Hidden); err != nil {
		return nil, err
	}
	return &x, nil
}

var errHidden = core.E(410, "gone", "hidden by report")

// --- write -----------------------------------------------------------------------------------------

type kvPut struct {
	ns       nspace
	k        string
	v        []byte
	ttl      time.Duration // 0 = default
	cas      *int64        // -1 never matches (malformed ?cas=)
	fence    int64
	ifAbsent bool
	pre      precond
	incr     *int64 // counter mode: v = prev + incr
}

type kvRes struct {
	created bool
	ver     int64
	exp     time.Time
	masked  []string
	val     []byte
}

func kvCas(cur int64) error { return core.E(409, "cas", "ver="+strconv.FormatInt(cur, 10)) }

// kvWrite is the KV write path (10.3, 26.4, 27.3) in one transaction under the namespace's
// advisory lock: access, preconditions and CAS, fence, counter arithmetic, sealed/scrub rules,
// nonce reuse, level or namespace caps, upsert, audit. leak is the pool for the leak link (nil for
// service calls); actor the audited identity ("" skips the audit row).
func kvWrite(ctx context.Context, q, leak core.Q, actor, root string, p kvPut) (kvRes, error) {
	var res kvRes
	if !kvKeyRe.MatchString(p.k) {
		return res, core.Bad("key must match [A-Za-z0-9._:/-]{1,128}")
	}
	if p.ttl == 0 {
		p.ttl = KVDefTTL
	}
	if p.ttl < time.Second || p.ttl > KVMaxTTL {
		return res, core.Bad("ttl must be 1..2592000 seconds")
	}
	if len(p.v) > MaxKVValue {
		return res, core.ErrSize
	}
	if err := nsAccess(ctx, q, p.ns, root, true, p.fence); err != nil {
		return res, err
	}
	lock := "kv:" + p.ns.raw
	if p.ns.kind == 'a' {
		lock = "kv:" + root
	}
	err := inTx(ctx, q, func(tx core.Q) error {
		if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lock); err != nil {
			return err
		}
		prev, err := scanKV(tx.QueryRow(ctx, `SELECT `+kvCols+` FROM kv WHERE ns = $1 AND k = $2 FOR UPDATE`, p.ns.raw, p.k))
		exists := err == nil
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if exists && !prev.Exp.After(time.Now()) {
			if _, err := tx.Exec(ctx, `DELETE FROM kv WHERE ns = $1 AND k = $2`, p.ns.raw, p.k); err != nil {
				return err
			}
			exists = false
		}
		if exists && prev.Hidden {
			return errHidden
		}
		var cur int64
		if exists {
			cur = prev.Ver
		}
		if err := p.pre.check(cur, exists); err != nil {
			return err
		}
		if (p.cas != nil && *p.cas != cur) || (p.ifAbsent && exists) {
			return kvCas(cur)
		}
		v := p.v
		if p.incr != nil {
			var n int64
			if exists {
				if prev.Sealed {
					return core.Bad("sealed value is not a counter")
				}
				if n, err = strconv.ParseInt(strings.TrimSpace(string(prev.V)), 10, 64); err != nil {
					return core.Bad("not a counter")
				}
			}
			v = []byte(strconv.FormatInt(n+*p.incr, 10))
		}
		isSealed := sealed(string(v))
		switch {
		case isSealed && (p.ns.kind == 'g' || p.ns.kind == 's' || p.ns.kind == 'r'):
			return core.E(400, "bad", "sealed shared ns")
		case isSealed && exists && prev.Sealed:
			if n := sealNonce(string(v)); n != "" && n == sealNonce(string(prev.V)) {
				return core.E(400, "bad", "nonce reuse")
			}
		case !isSealed && p.incr == nil:
			if !utf8.Valid(v) {
				return core.Bad("value must be UTF-8 text")
			}
			s := string(v)
			if res.masked, err = check(ctx, leak, map[string]*string{"v": &s}); err != nil {
				return err
			}
			v = []byte(s)
			if len(v) > MaxKVValue {
				return core.ErrSize
			}
		}
		fence := p.fence
		if exists {
			if prev.Fence > 0 && p.fence < prev.Fence {
				return core.E(409, "fenced", strconv.FormatInt(prev.Fence, 10))
			}
			fence = max(prev.Fence, p.fence)
		}
		var keys, bytes int
		if err := tx.QueryRow(ctx, `SELECT count(*), coalesce(sum(length(v)), 0) FROM kv WHERE ns = $1 AND k <> $2 AND expires_at > now()`, p.ns.raw, p.k).Scan(&keys, &bytes); err != nil {
			return err
		}
		maxKeys, maxBytes := SharedKeys, SharedBytes
		switch p.ns.kind {
		case 'a':
			lvl := levelOf(ctx, tx, root)
			maxKeys, maxBytes = trust.Cap("kv_keys", lvl), trust.Cap("kv_bytes", lvl)
		case 'r':
			maxKeys = RoomKeys
		}
		if keys+1 > maxKeys || bytes+len(v) > maxBytes {
			return core.ErrQuota
		}
		if err := tx.QueryRow(ctx, `INSERT INTO kv (ns, k, v, ver, fence, expires_at, root, sealed, scrub_v)
			VALUES ($1, $2, $3, 1, $4, now() + $5::interval, $6, $7, $8)
			ON CONFLICT (ns, k) DO UPDATE SET v = EXCLUDED.v, ver = kv.ver + 1, fence = EXCLUDED.fence, expires_at = EXCLUDED.expires_at,
			  root = EXCLUDED.root, updated = now(), sealed = EXCLUDED.sealed, scrub_v = EXCLUDED.scrub_v
			RETURNING ver, expires_at`, p.ns.raw, p.k, v, fence, pgInterval(p.ttl), root, isSealed, scrub.RulesV).Scan(&res.ver, &res.exp); err != nil {
			return err
		}
		res.created, res.val = !exists, v
		if actor == "" {
			return nil
		}
		op := "kv"
		if p.incr != nil {
			op = "kvi"
		}
		return core.Audit(ctx, tx, actor, op, p.ns.raw+"/"+p.k, len(v))
	})
	return res, err
}

// kvGet reads one live key (hidden rows answer err gone).
func kvGet(ctx context.Context, q core.Q, ns nspace, k string) (*kvRow, error) {
	if !kvKeyRe.MatchString(k) {
		return nil, core.ErrNotFound
	}
	x, err := scanKV(q.QueryRow(ctx, `SELECT `+kvCols+` FROM kv WHERE ns = $1 AND k = $2 AND expires_at > now()`, ns.raw, k))
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, core.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if x.Hidden {
		return nil, errHidden
	}
	return x, nil
}

// kvDelete removes a key (?cas= must match the current version).
func kvDelete(ctx context.Context, q core.Q, actor string, ns nspace, k string, cas *int64) error {
	if !kvKeyRe.MatchString(k) {
		return core.ErrNotFound
	}
	return inTx(ctx, q, func(tx core.Q) error {
		var ver int64
		err := tx.QueryRow(ctx, `SELECT ver FROM kv WHERE ns = $1 AND k = $2 AND expires_at > now() FOR UPDATE`, ns.raw, k).Scan(&ver)
		if errors.Is(err, pgx.ErrNoRows) {
			return core.ErrNotFound
		}
		if err != nil {
			return err
		}
		if cas != nil && *cas != ver {
			return kvCas(ver)
		}
		if _, err := tx.Exec(ctx, `DELETE FROM kv WHERE ns = $1 AND k = $2`, ns.raw, k); err != nil {
			return err
		}
		if actor == "" {
			return nil
		}
		return core.Audit(ctx, tx, actor, "kvd", ns.raw+"/"+k, 0)
	})
}

// kvList returns the live, visible keys of a namespace with a prefix, sorted (<= k).
func kvList(ctx context.Context, q core.Q, ns nspace, prefix string, k int) ([]*kvRow, error) {
	rows, err := q.Query(ctx, `SELECT `+kvCols+` FROM kv WHERE ns = $1 AND k LIKE $2 AND NOT hidden AND expires_at > now() ORDER BY k LIMIT $3`,
		ns.raw, likePrefix(prefix), k)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*kvRow
	for rows.Next() {
		x, err := scanKV(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, x)
	}
	return out, rows.Err()
}

var likeEsc = strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)

func likePrefix(p string) string { return likeEsc.Replace(p) + "%" }

// KVPut writes a value on behalf of a root (service callers: sessions, subscriptions); the same
// access, scrub, cap and TTL rules as PUT /v1/kv apply. Returns the new version.
func KVPut(ctx context.Context, q core.Q, root, ns, k string, v []byte, ttl time.Duration) (int64, error) {
	n, err := parseNS(ns, root)
	if err != nil {
		return 0, err
	}
	res, err := kvWrite(ctx, q, nil, root, root, kvPut{ns: n, k: k, v: v, ttl: ttl})
	return res.ver, err
}

// KVGet reads a value on behalf of a root (access rules apply; sealed values come back opaque).
func KVGet(ctx context.Context, q core.Q, root, ns, k string) ([]byte, int64, error) {
	n, err := parseNS(ns, root)
	if err != nil {
		return nil, 0, err
	}
	if err := nsAccess(ctx, q, n, root, false, 0); err != nil {
		return nil, 0, err
	}
	x, err := kvGet(ctx, q, n, k)
	if err != nil {
		return nil, 0, err
	}
	return x.V, x.Ver, nil
}

// KVExpire deletes expired rows in batches of 5000 (janitor task).
func KVExpire(ctx context.Context, q core.Q) error {
	for i := 0; i < 20; i++ {
		tag, err := q.Exec(ctx, `DELETE FROM kv WHERE (ns, k) IN (SELECT ns, k FROM kv WHERE expires_at <= now() LIMIT 5000)`)
		if err != nil || tag.RowsAffected() < 5000 {
			return err
		}
	}
	return nil
}

// Report target kv:<ns>/<k> (4.7).
func kvRef(ref string) (nspace, string, error) {
	nsRaw, k, ok := strings.Cut(ref, "/")
	if !ok || !kvKeyRe.MatchString(k) {
		return nspace{}, "", core.ErrNotFound
	}
	ns, err := parseNS(nsRaw, "")
	if err != nil {
		return nspace{}, "", core.ErrNotFound
	}
	return ns, k, nil
}

func kvExists(ctx context.Context, q core.Q, ref string) error {
	ns, k, err := kvRef(ref)
	if err != nil {
		return err
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM kv WHERE ns = $1 AND k = $2 AND expires_at > now())`, ns.raw, k).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func kvHide(ctx context.Context, q core.Q, ref string) error {
	ns, k, err := kvRef(ref)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE kv SET hidden = true WHERE ns = $1 AND k = $2`, ns.raw, k)
	return err
}

func kvRestore(ctx context.Context, q core.Q, ref string) error {
	ns, k, err := kvRef(ref)
	if err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE kv SET hidden = false WHERE ns = $1 AND k = $2`, ns.raw, k)
	return err
}

// --- rendering -------------------------------------------------------------------------------------

func kvPath(ns nspace, k string) string { return "/v1/kv/" + ns.raw + "/" + k }

// kvValText is the value as shown to a reader: opaque sealed values stay verbatim for the owner and
// render [sealed] elsewhere.
func kvValText(x *kvRow, owner bool) string {
	if x.Sealed && !owner {
		return "[sealed]"
	}
	return string(x.V)
}

func kvGetDoc(x *kvRow, ns nspace, owner bool) *doc.Doc {
	d := &doc.Doc{Head: fmt.Sprintf("ver=%d fence=%d exp=%s ttl_s=%d", x.Ver, x.Fence, rfc(x.Exp), ttlSeconds(x.Exp)),
		Fields: []doc.F{{Name: "v", Val: kvValText(x, owner), Multi: true}}}
	if owner {
		d.Next = []doc.Action{{Method: "PUT", Path: kvPath(ns, x.K)}, {Method: "DELETE", Path: kvPath(ns, x.K)}, doc.GET("/v1/kv/"+ns.raw, "list")}
	} else {
		d.MaxAge = 5
		d.Next = []doc.Action{doc.GET("/v1/kv/"+ns.raw, "list")}
	}
	return d
}

func kvRowLine(x *kvRow) string {
	return fmt.Sprintf("%s %d %d", x.K, x.Ver, ttlSeconds(x.Exp))
}

func kvListDoc(ns nspace, rows []*kvRow, prefix string) *doc.Doc {
	head := fmt.Sprintf("kv %s n=%d", ns.raw, len(rows))
	if prefix != "" {
		head += " prefix=" + doc.SafeLine(prefix)
	}
	d := &doc.Doc{Head: head, Cols: []string{"k", "ver", "ttl_s"}, Budget: 400}
	for _, x := range rows {
		cells := []string{x.K, strconv.FormatInt(x.Ver, 10), strconv.FormatInt(ttlSeconds(x.Exp), 10)}
		if x.Sealed {
			cells = append(cells, "[sealed]")
		}
		d.Rows = append(d.Rows, cells)
	}
	d.Next = []doc.Action{doc.GET("/v1/kv/"+ns.raw+"?vals=1", "with values"), doc.GET("/v1/me/resume", "")}
	return d
}

// safeRow keeps a user-derived line off the reserved column-0 starts.
func safeRow(line string) string {
	if line == "" || line[0] == ' ' || strings.HasPrefix(line, "next:") || strings.HasPrefix(line, "> ") || strings.HasPrefix(line, "…") {
		return "- " + line
	}
	return line
}

// kvInlineText renders the ?vals=1 listing: each row followed by its value indented (27.3).
// Listings never inline sealed values ([sealed], 26.4): GET returns the opaque value.
func kvInlineText(ns nspace, rows []*kvRow) string {
	var b strings.Builder
	fmt.Fprintf(&b, "kv %s n=%d vals=1\n", ns.raw, len(rows))
	for _, x := range rows {
		b.WriteString(safeRow(kvRowLine(x)) + "\n")
		b.WriteString("  " + doc.Indent(kvValText(x, false)) + "\n")
	}
	return b.String()
}

// --- HTTP ------------------------------------------------------------------------------------------

// kvReq resolves the common request parts: identity (optional when anon), namespace and key.
func (s *svc) kvReq(r *http.Request, write bool) (*core.Ident, nspace, string, error) {
	var id *core.Ident
	var err error
	if write {
		id, err = s.d.AuthWrite(r)
	} else {
		id, err = s.d.AuthOpt(r)
	}
	if err != nil {
		return nil, nspace{}, "", err
	}
	root := ""
	if id != nil {
		root = id.Root
	}
	ns, err := parseNS(r.PathValue("ns"), root)
	if err != nil {
		return nil, nspace{}, "", err
	}
	if err := kvScopeOK(id, ns, write); err != nil {
		return nil, nspace{}, "", err
	}
	k := r.PathValue("k")
	if k != "" && !kvKeyRe.MatchString(k) {
		return nil, nspace{}, "", core.Bad("key must match [A-Za-z0-9._:/-]{1,128}")
	}
	return id, ns, k, nil
}

// query parses ?ttl= ?cas= ?fence= ?if_absent=1 (a malformed cas never matches).
func kvQuery(r *http.Request) (ttl time.Duration, cas *int64, fence int64, ifAbsent bool, err error) {
	q, perr := url.ParseQuery(r.URL.RawQuery)
	if perr != nil {
		return 0, nil, 0, false, core.Bad("bad percent-encoding in query string")
	}
	if v := q.Get("ttl"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 1 || n > int64(KVMaxTTL/time.Second) {
			return 0, nil, 0, false, core.Bad("ttl must be 1..2592000 seconds")
		}
		ttl = time.Duration(n) * time.Second
	}
	if v, ok := q["cas"]; ok && len(v) > 0 {
		n, err := strconv.ParseInt(v[0], 10, 64)
		if err != nil || n < 0 {
			n = -1
		}
		cas = &n
	}
	if v := q.Get("fence"); v != "" {
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return 0, nil, 0, false, core.Bad("fence must be a non-negative integer")
		}
		fence = n
	}
	ifAbsent = q.Get("if_absent") == "1" || q.Get("if_absent") == "true"
	return ttl, cas, fence, ifAbsent, nil
}

func kvPutLine(res kvRes) string {
	l := fmt.Sprintf("ok ver=%d exp=%s", res.ver, rfc(res.exp))
	if len(res.masked) > 0 {
		l += " masked=" + strings.Join(res.masked, ",")
	}
	return l
}

func (s *svc) hKVPut(w http.ResponseWriter, r *http.Request) {
	id, ns, k, err := s.kvReq(r, true)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := s.frozen("kv"); err != nil {
		doc.Fail(w, r, err)
		return
	}
	ttl, cas, fence, ifAbsent, err := kvQuery(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	pre, err := preconds(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	v, err := core.ReadAll(w, r, int64(MaxKVValue))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := kvWrite(r.Context(), s.d.DB, s.d.DB, id.ID, id.Root, kvPut{ns: ns, k: k, v: v, ttl: ttl, cas: cas, fence: fence, ifAbsent: ifAbsent, pre: pre})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	status := http.StatusOK
	if res.created {
		status = http.StatusCreated
	}
	doc.TailStatus(w, r, status, kvPutLine(res), doc.GET(kvPath(ns, k), ""), doc.Action{Method: "DELETE", Path: kvPath(ns, k)})
}

func (s *svc) hKVGet(w http.ResponseWriter, r *http.Request) {
	id, ns, k, err := s.kvReq(r, false)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	root := ""
	if id != nil {
		root = id.Root
	}
	if err := nsAccess(r.Context(), s.d.DB, ns, root, false, 0); err != nil {
		doc.Fail(w, r, err)
		return
	}
	x, err := kvGet(r.Context(), s.d.DB, ns, k)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if x.Sealed && id == nil {
		doc.Fail(w, r, core.ErrNotFound)
		return
	}
	reply(w, r, 200, kvGetDoc(x, ns, id != nil))
}

func (s *svc) hKVDelete(w http.ResponseWriter, r *http.Request) {
	id, ns, k, err := s.kvReq(r, true)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	_, cas, fence, _, err := kvQuery(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := nsAccess(r.Context(), s.d.DB, ns, id.Root, true, fence); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := kvDelete(r.Context(), s.d.DB, id.ID, ns, k, cas); err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, "ok", doc.GET("/v1/kv/"+ns.raw, "list"))
}

func (s *svc) hKVList(w http.ResponseWriter, r *http.Request) {
	id, ns, _, err := s.kvReq(r, false)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	root := ""
	if id != nil {
		root = id.Root
	}
	if err := nsAccess(r.Context(), s.d.DB, ns, root, false, 0); err != nil {
		doc.Fail(w, r, err)
		return
	}
	prefix := r.URL.Query().Get("prefix")
	if len(prefix) > 128 || !doc.OneLine(prefix) {
		doc.Fail(w, r, core.Bad("prefix too long"))
		return
	}
	rows, err := kvList(r.Context(), s.d.DB, ns, prefix, intParam(r, "k", 100, 1, 100))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if v := r.URL.Query().Get("vals"); v == "1" || v == "true" {
		if id == nil {
			w = &cacheWriter{w, publicKVCache}
		}
		doc.Tail(w, r, kvInlineText(ns, rows), doc.GET("/v1/kv/"+ns.raw, "keys only"))
		return
	}
	d := kvListDoc(ns, rows, prefix)
	if id == nil {
		d.MaxAge = 5
	}
	reply(w, r, 200, d)
}

func (s *svc) hKVIncr(w http.ResponseWriter, r *http.Request) {
	id, ns, k, err := s.kvReq(r, true)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := s.frozen("kv"); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		By    *int64 `json:"by"`
		TTL   int64  `json:"ttl"`
		Fence int64  `json:"fence"`
	}
	if err := core.Decode(w, r, 1<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	by := int64(1)
	if in.By != nil {
		by = *in.By
	}
	if in.TTL < 0 || in.TTL > int64(KVMaxTTL/time.Second) {
		doc.Fail(w, r, core.Bad("ttl must be 1..2592000 seconds"))
		return
	}
	res, err := kvWrite(r.Context(), s.d.DB, s.d.DB, id.ID, id.Root, kvPut{ns: ns, k: k, ttl: time.Duration(in.TTL) * time.Second, fence: in.Fence, incr: &by})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Tail(w, r, fmt.Sprintf("ok ver=%d v=%s exp=%s", res.ver, res.val, rfc(res.exp)), doc.GET(kvPath(ns, k), ""))
}

// --- batch (27.3) ----------------------------------------------------------------------------------

type kvOp struct {
	Op  string `json:"op"`
	K   string `json:"k"`
	V   string `json:"v"`
	TTL int64  `json:"ttl"`
	Cas *int64 `json:"cas"`
	By  *int64 `json:"by"`
}

// batchCost is the limiter cost of a batch: 0.2 per get, 1 per write (3.6, 27.3).
func batchCost(ops []kvOp) float64 {
	c := 0.0
	for _, o := range ops {
		if o.Op == "get" {
			c += 0.2
		} else {
			c++
		}
	}
	return c
}

var errBatchRolledBack = errors.New("atomic batch rolled back")

// runBatch executes the ops in one transaction (each op in a savepoint); with atomic a cas failure
// returns errBatchRolledBack so the caller rolls the whole tx back. Lines per op:
// "<k> ok ver=N" (put/incr), "<k> ok" (del), "<k> cas ver=N", "<k> miss", "<k> ver=N" + value.
func (s *svc) runBatch(ctx context.Context, tx core.Q, id *core.Ident, ns nspace, ops []kvOp, atomic bool) (lines []string, okN, failN int, err error) {
	for _, o := range ops {
		if !kvKeyRe.MatchString(o.K) {
			return nil, 0, 0, core.Bad("op key must match [A-Za-z0-9._:/-]{1,128}")
		}
		if o.TTL < 0 || o.TTL > int64(KVMaxTTL/time.Second) {
			return nil, 0, 0, core.Bad("ttl must be 1..2592000 seconds")
		}
		ttl := time.Duration(o.TTL) * time.Second
		var line string
		var oerr error
		switch o.Op {
		case "get":
			x, gerr := kvGet(ctx, tx, ns, o.K)
			switch {
			case errors.Is(gerr, core.ErrNotFound):
				line = o.K + " miss"
			case gerr != nil:
				return nil, 0, 0, gerr
			default:
				line = fmt.Sprintf("%s ver=%d\n  %s", o.K, x.Ver, doc.Indent(kvValText(x, true)))
			}
		case "put":
			res, perr := kvWrite(ctx, tx, s.d.DB, id.ID, id.Root, kvPut{ns: ns, k: o.K, v: []byte(o.V), ttl: ttl, cas: o.Cas})
			line, oerr = fmt.Sprintf("%s ok ver=%d", o.K, res.ver), perr
		case "incr":
			by := int64(1)
			if o.By != nil {
				by = *o.By
			}
			res, perr := kvWrite(ctx, tx, s.d.DB, id.ID, id.Root, kvPut{ns: ns, k: o.K, ttl: ttl, cas: o.Cas, incr: &by})
			line, oerr = fmt.Sprintf("%s ok ver=%d v=%s", o.K, res.ver, res.val), perr
		case "del":
			derr := kvDelete(ctx, tx, id.ID, ns, o.K, o.Cas)
			if errors.Is(derr, core.ErrNotFound) {
				line, derr = o.K+" miss", nil
			} else {
				line = o.K + " ok"
			}
			oerr = derr
		default:
			return nil, 0, 0, core.Bad("op must be get, put, del or incr")
		}
		if isAPIErr(oerr, "cas") {
			if atomic {
				return nil, 0, 0, errBatchRolledBack
			}
			var ae *core.APIError
			errors.As(oerr, &ae)
			lines = append(lines, safeRow(o.K+" cas "+ae.Msg))
			failN++
			continue
		}
		if oerr != nil {
			return nil, 0, 0, oerr
		}
		lines = append(lines, safeRow(line))
		okN++
	}
	return lines, okN, failN, nil
}

func (s *svc) hKVBatch(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := s.frozen("kv"); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		NS     string `json:"ns"`
		Ops    []kvOp `json:"ops"`
		Atomic bool   `json:"atomic"`
	}
	if err := core.Decode(w, r, int64(MaxBatch), &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if len(in.Ops) == 0 || len(in.Ops) > MaxBatchOps {
		doc.Fail(w, r, core.Bad(fmt.Sprintf("ops must hold 1..%d entries", MaxBatchOps)))
		return
	}
	if in.NS == "" {
		in.NS = "me"
	}
	ns, err := parseNS(in.NS, id.Root)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	writes := false
	for _, o := range in.Ops {
		writes = writes || o.Op != "get"
	}
	if err := kvScopeOK(id, ns, writes); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if extra := batchCost(in.Ops) - s.d.CostOf(r.Pattern); extra > 0 && !s.d.AllowCost(r, id, extra) {
		doc.Fail(w, r, core.ErrRate)
		return
	}
	if err := nsAccess(r.Context(), s.d.DB, ns, id.Root, writes, 0); err != nil {
		doc.Fail(w, r, err)
		return
	}
	var lines []string
	var okN, failN int
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		var err error
		lines, okN, failN, err = s.runBatch(r.Context(), tx, id, ns, in.Ops, in.Atomic)
		return err
	})
	status := http.StatusOK
	if errors.Is(err, errBatchRolledBack) {
		status, lines, okN, failN, err = http.StatusConflict, []string{"rolled back: a cas op failed"}, 0, len(in.Ops), nil
	}
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	text := fmt.Sprintf("kvm %s n=%d ok=%d failed=%d\n%s", ns.raw, len(in.Ops), okN, failN, strings.Join(lines, "\n"))
	doc.TailStatus(w, r, status, text, doc.GET("/v1/kv/"+ns.raw, "list"))
}

// --- import (27.3) ---------------------------------------------------------------------------------

var mdHeadRe = regexp.MustCompile(`^##\s+(.+?)\s*$`)
var slugJunk = regexp.MustCompile(`[^a-z0-9]+`)

type kvPair struct{ k, v string }

// parseImport turns a body into pairs per format; skipped counts unusable entries.
func parseImport(format string, body []byte) (pairs []kvPair, skipped int, err error) {
	switch format {
	case "", "kv":
		for _, l := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
			if strings.TrimSpace(l) == "" {
				continue
			}
			k, v, ok := strings.Cut(l, "\t")
			if !ok {
				skipped++
				continue
			}
			pairs = append(pairs, kvPair{strings.TrimSpace(k), v})
		}
	case "json":
		var m map[string]json.RawMessage
		if err := json.Unmarshal(body, &m); err != nil {
			return nil, 0, core.Bad("json: flat object expected")
		}
		for k, raw := range m {
			var s string
			if json.Unmarshal(raw, &s) == nil {
				pairs = append(pairs, kvPair{k, s})
				continue
			}
			t := strings.TrimSpace(string(raw))
			if t == "null" || strings.HasPrefix(t, "{") || strings.HasPrefix(t, "[") {
				skipped++
				continue
			}
			pairs = append(pairs, kvPair{k, t})
		}
	case "md":
		cur, inSection := "", false
		var buf []string
		flush := func() {
			if inSection {
				pairs = append(pairs, kvPair{"md/" + cur, strings.TrimSpace(strings.Join(buf, "\n"))})
			}
		}
		for _, l := range strings.Split(strings.ReplaceAll(string(body), "\r\n", "\n"), "\n") {
			if m := mdHeadRe.FindStringSubmatch(l); m != nil {
				flush()
				cur, inSection, buf = slugify(m[1]), true, nil
				continue
			}
			buf = append(buf, l)
		}
		flush()
	default:
		return nil, 0, core.Bad("fmt must be kv, json or md")
	}
	// deterministic order for json maps
	if format == "json" {
		for i := 1; i < len(pairs); i++ {
			for j := i; j > 0 && pairs[j-1].k > pairs[j].k; j-- {
				pairs[j-1], pairs[j] = pairs[j], pairs[j-1]
			}
		}
	}
	return pairs, skipped, nil
}

func slugify(s string) string {
	s = strings.Trim(slugJunk.ReplaceAllString(strings.ToLower(scrub.Normalize(s)), "-"), "-")
	if s == "" {
		s = "section"
	}
	if len(s) > 60 {
		s = strings.Trim(s[:60], "-")
	}
	return s
}

func (s *svc) hKVImport(w http.ResponseWriter, r *http.Request) {
	id, ns, _, err := s.kvReq(r, true)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if err := s.frozen("kv"); err != nil {
		doc.Fail(w, r, err)
		return
	}
	ttl, _, fence, _, err := kvQuery(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	body, err := core.ReadAll(w, r, int64(MaxBatch))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	pairs, skipped, err := parseImport(r.URL.Query().Get("fmt"), body)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if len(pairs) > 2000 {
		doc.Fail(w, r, core.Bad("at most 2000 entries per import"))
		return
	}
	imported, stopped := 0, ""
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		for _, p := range pairs {
			if !kvKeyRe.MatchString(p.k) || len(p.v) > MaxKVValue || p.v == "" {
				skipped++
				continue
			}
			_, werr := kvWrite(r.Context(), tx, s.d.DB, id.ID, id.Root, kvPut{ns: ns, k: p.k, v: []byte(p.v), ttl: ttl, fence: fence})
			switch {
			case werr == nil:
				imported++
			case isAPIErr(werr, "quota"):
				stopped = "quota"
				return nil
			case isAPIErr(werr, "scrub"), isAPIErr(werr, "size"), isAPIErr(werr, "bad"):
				skipped++
			default:
				return werr
			}
		}
		return nil
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	line := fmt.Sprintf("ok imported=%d skipped=%d", imported, skipped)
	if stopped != "" {
		line += " stopped=" + stopped
	}
	doc.Tail(w, r, line, doc.GET("/v1/kv/"+ns.raw, "list"))
}
