package keys

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/sign"
)

type handlers struct{ s *svc }

func jsonBytes(v any) []byte {
	b, _ := json.Marshal(v)
	return append(b, '\n')
}

// --- directory ----------------------------------------------------------------------------------

// put is PUT /v1/keys (3.2, 3.7): raw canonical || sigs (cap 16 KiB). With a current bundle the
// request must carry X-Cx-Sig under the stored rk and the bundle must be seq+1; without one the
// legacy contested-publish path applies (seq 1 over the bearer, pending 24 h).
func (h *handlers) put(w http.ResponseWriter, r *http.Request) {
	s, d := h.s, h.s.d
	id, err := d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	raw, err := readBody(w, r, e2e.BundleCap)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	b, err := parseBundle(raw, id.ID, time.Now().Unix())
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	prev, found, err := Bundle(ctx, d.DB, id.ID)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if found {
		if _, err := s.verifySig(ctx, id, r, raw); err != nil {
			core.Fail(w, r, err)
			return
		}
	}
	var res *PubResult
	err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if err := core.UseQuota(ctx, tx, id, "keys", PubPerDay); err != nil {
			return err
		}
		var err error
		if found {
			res, err = publishNext(ctx, tx, id, b, raw, prev)
		} else {
			res, err = legacyPublish(ctx, tx, id, b, raw)
		}
		return err
	})
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if res.Pending || res.Contested {
		if _, err := s.signHead(ctx); err != nil { // kinds 2 and 3: head at once
			d.Log.Warn("keys: head after pending publish", "err", err)
		}
	}
	if res.Contested {
		core.Fail(w, r, ErrContested)
		return
	}
	hd := s.head.Load()
	text := fmt.Sprintf("ok seq=%d leaf=%d bundle=%s head=%s", res.Seq, res.Leaf, hex.EncodeToString(res.RawHash), headHex(hd))
	j := map[string]any{"ok": true, "seq": res.Seq, "leaf": res.Leaf, "bundle": hex.EncodeToString(res.RawHash), "head": headHex(hd)}
	status := 200
	if res.Pending {
		status = 202
		text += " pending=1 until=" + res.Until.UTC().Format(time.RFC3339)
		j["pending"], j["until"] = true, res.Until.Unix()
	}
	s.reply(w, r, status, text, j)
}

func headHex(h *Head) string {
	if h == nil {
		return hex.EncodeToString(e2e.EmptyRoot())[:16]
	}
	return hex.EncodeToString(h.Root)[:16]
}

// getOwn is GET /v1/keys: the caller's own bundle.
func (h *handlers) getOwn(w http.ResponseWriter, r *http.Request) {
	id, err := h.s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	h.serveDir(w, r, id.ID)
}

// get is GET /v1/keys/{id}[?leaf=<idx>] (anonymous, 5/s per IP group).
func (h *handlers) get(w http.ResponseWriter, r *http.Request) {
	seg := r.PathValue("id")
	if i := strings.IndexByte(seg, '.'); i > 0 {
		seg = seg[:i]
	}
	if !core.ValidID(seg) {
		core.Fail(w, r, core.Bad("id must be a 7-char id"))
		return
	}
	if !h.anonOK(w, r) {
		return
	}
	if v := r.URL.Query().Get("leaf"); v != "" {
		leaf, err := strconv.ParseUint(v, 10, 62)
		if err != nil {
			core.Fail(w, r, core.Bad("leaf must be an integer"))
			return
		}
		b, err := AtLeaf(r.Context(), h.s.d.DB, seg, leaf)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		h.s.reply(w, r, 200, h.s.dirText(b), h.s.dirJSON(b))
		return
	}
	h.serveDir(w, r, seg)
}

// anonOK applies the anonymous directory rate (token holders are governed by the request budget).
func (h *handlers) anonOK(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("Authorization") != "" {
		return true
	}
	if !h.s.d.Lim.Allow("keysdir:"+h.s.d.IPGroup(r), dirRate, dirBurst) {
		core.Fail(w, r, core.ErrRate)
		return false
	}
	return true
}

func (h *handlers) serveDir(w http.ResponseWriter, r *http.Request, id string) {
	b, err := Lookup(r.Context(), h.s.d.DB, id)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.s.reply(w, r, 200, h.s.dirText(b), h.s.dirJSON(b))
}

// dirText renders the 3.2 directory lines: the facts, then the raw bundle (b64url).
func (s *svc) dirText(b *Record) string {
	cs := "1"
	if b.HasCS2() {
		cs = "1,2"
	}
	lk, pend := 0, 0
	if b.Flags&e2e.FlagLKOK != 0 {
		lk = 1
	}
	if b.State == "pending" {
		pend = 1
	}
	hd := s.head.Load()
	var size uint64
	if hd != nil {
		size = hd.Size
	}
	line := fmt.Sprintf("id=%s seq=%d iat=%s ik=%s rk=%s ak=%s cs=%s ek=%d+%d lk_ok=%d pol=%d fp=%s leaf=%d size=%d head=%s pending=%d",
		b.ID, b.Seq, core.Date(time.Unix(int64(b.IAT), 0)), b64(b.IK), b64(b.RK), b64(b.AK), cs, b.E0, b.NEK(), lk, b.MailPolicy,
		hex.EncodeToString(b.Fingerprint()), b.LeafIdx(), size, headHex(hd), pend)
	if pend == 1 && !b.PendingUntil.IsZero() {
		line += " until=" + b.PendingUntil.UTC().Format(time.RFC3339)
	}
	return line + "\n" + b64(b.Raw) + "\n"
}

func (s *svc) dirJSON(b *Record) map[string]any {
	cs := []int{1}
	if b.HasCS2() {
		cs = []int{1, 2}
	}
	hd := s.head.Load()
	var size uint64
	if hd != nil {
		size = hd.Size
	}
	m := map[string]any{"id": b.ID, "seq": b.Seq, "iat": b.IAT, "exp": b.Exp, "ik": b64(b.IK), "rk": b64(b.RK), "ak": b64(b.AK),
		"cs": cs, "e0": b.E0, "n_ek": b.NEK(), "lk_ok": b.Flags&e2e.FlagLKOK != 0, "pol": b.MailPolicy, "fp": hex.EncodeToString(b.Fingerprint()),
		"fp_digits": e2e.FPDigits(b.Fingerprint()), "leaf": b.LeafIdx(), "size": size, "head": headHex(hd), "pending": b.State == "pending",
		"raw": b64(b.Raw), "hash": hex.EncodeToString(b.Hash)}
	if !b.PendingUntil.IsZero() && b.State == "pending" {
		m["until"] = b.PendingUntil.Unix()
	}
	return m
}

// hist is GET /v1/keys/{id}/hist: every (seq, leaf, iat, fp, state) ever logged for the id.
func (h *handlers) hist(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !core.ValidID(id) {
		core.Fail(w, r, core.Bad("id must be a 7-char id"))
		return
	}
	if !h.anonOK(w, r) {
		return
	}
	rows, err := h.s.d.DB.Query(r.Context(), `SELECT seq, coalesce(leaf, -1), coalesce(pending_leaf, -1), iat, ik, state FROM key_bundles WHERE id = $1 ORDER BY seq`, id)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	defer rows.Close()
	var b strings.Builder
	var js []map[string]any
	for rows.Next() {
		var seq int
		var leaf, pleaf int64
		var iat time.Time
		var ik []byte
		var state string
		if err := rows.Scan(&seq, &leaf, &pleaf, &iat, &ik, &state); err != nil {
			core.Fail(w, r, err)
			return
		}
		if leaf < 0 {
			leaf = pleaf
		}
		fp := hex.EncodeToString(e2e.Fingerprint(ik))
		fmt.Fprintf(&b, "seq=%d leaf=%d iat=%d fp=%s state=%s\n", seq, leaf, iat.Unix(), fp, state)
		js = append(js, map[string]any{"seq": seq, "leaf": leaf, "iat": iat.Unix(), "fp": fp, "state": state})
	}
	if err := rows.Err(); err != nil {
		core.Fail(w, r, err)
		return
	}
	if len(js) == 0 {
		core.Fail(w, r, ErrNoKeys)
		return
	}
	h.s.reply(w, r, 200, b.String(), map[string]any{"id": id, "hist": js})
}

// server is GET /v1/keys/server (3.6): root, online key, certificate, witness keys, mirror. A
// convenience to be checked against the mirror, never a trust root.
func (h *handlers) server(w http.ResponseWriter, r *http.Request) {
	s := h.s
	c := s.sk.cert.Load()
	var b strings.Builder
	fmt.Fprintf(&b, "root=%s online=%s cert=%s exp=%d", b64(s.sk.trustRoot()), b64(s.sk.pub), b64(c.Raw), c.Exp)
	j := map[string]any{"root": b64(s.sk.trustRoot()), "online": b64(s.sk.pub), "cert": b64(c.Raw), "exp": c.Exp, "seq": c.Seq,
		"self_certified": s.sk.rootPub == nil, "mirror": s.sk.mirror}
	wit := map[string]string{}
	for _, name := range s.sk.wnames {
		fmt.Fprintf(&b, " %s=%s", name, b64(s.sk.witness[name]))
		wit[name] = b64(s.sk.witness[name])
	}
	j["witness"] = wit
	fmt.Fprintf(&b, " mirror=%s", s.sk.mirror)
	if s.sk.rootPub == nil {
		b.WriteString(" self=1")
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	s.reply(w, r, 200, b.String(), j)
}

// --- log ----------------------------------------------------------------------------------------

// sthText renders the head at size (0 = latest) with its cosignatures.
func (s *svc) sthText(ctx context.Context, size uint64) (string, map[string]any, error) {
	var h *Head
	var err error
	if size == 0 {
		h, err = s.latestHead(ctx, s.d.DB)
		if errors.Is(err, pgx.ErrNoRows) {
			h, err = s.signHead(ctx)
		}
	} else {
		h, err = s.headAt(ctx, s.d.DB, size)
		if errors.Is(err, pgx.ErrNoRows) {
			return "", nil, core.E(404, "notfound", "no head at this size")
		}
	}
	if err != nil {
		return "", nil, err
	}
	cos, err := s.cosigns(ctx, s.d.DB, h.Size)
	if err != nil {
		return "", nil, err
	}
	cert := s.sk.cert.Load().Raw
	var b strings.Builder
	b.WriteString(h.Line(cert) + "\n")
	var cj []map[string]any
	for _, c := range cos {
		b.WriteString(c.Line() + "\n")
		cj = append(cj, map[string]any{"id": c.Signer, "at": c.HeadAt.Unix(), "sig": b64(c.Sig)})
	}
	j := map[string]any{"size": h.Size, "root": hex.EncodeToString(h.Root), "at": h.At.Unix(), "sig": b64(h.Sig), "cert": b64(cert), "cosign": cj}
	return b.String(), j, nil
}

func (h *handlers) sth(w http.ResponseWriter, r *http.Request) {
	var size uint64
	if v := r.URL.Query().Get("size"); v != "" {
		n, err := strconv.ParseUint(v, 10, 62)
		if err != nil || n == 0 {
			core.Fail(w, r, core.Bad("size must be a positive integer"))
			return
		}
		size = n
	}
	text, j, err := h.s.sthText(r.Context(), size)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.s.reply(w, r, 200, text, j)
}

func queryU64(r *http.Request, name string, def uint64) (uint64, error) {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def, nil
	}
	n, err := strconv.ParseUint(v, 10, 62)
	if err != nil {
		return 0, core.Bad(name + " must be a non-negative integer")
	}
	return n, nil
}

// incl is GET /v1/log/incl?leaf=<idx>&size=<n> -> `idx=<i> leaf=<hex> path=<hex,...>` (size defaults to the latest head).
func (h *handlers) incl(w http.ResponseWriter, r *http.Request) {
	s := h.s
	ctx := r.Context()
	leaf, err := queryU64(r, "leaf", 0)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if r.URL.Query().Get("leaf") == "" {
		core.Fail(w, r, core.Bad("leaf required"))
		return
	}
	var def uint64
	if hd := s.head.Load(); hd != nil {
		def = hd.Size
	}
	size, err := queryU64(r, "size", def)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	cur, err := LogSize(ctx, s.d.DB)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if size == 0 || size > cur || leaf >= size {
		core.Fail(w, r, core.Bad(fmt.Sprintf("need leaf < size <= %d", cur)))
		return
	}
	var lh []byte
	if err := s.d.DB.QueryRow(ctx, `SELECT leaf FROM klog WHERE idx = $1`, int64(leaf)).Scan(&lh); err != nil {
		core.Fail(w, r, err)
		return
	}
	path, err := InclusionPath(ctx, s.d.DB, leaf, size)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	s.reply(w, r, 200, fmt.Sprintf("idx=%d leaf=%s path=%s size=%d", leaf, hex.EncodeToString(lh), e2e.EncodePath(path), size),
		map[string]any{"idx": leaf, "leaf": hex.EncodeToString(lh), "path": strings.Split(e2e.EncodePath(path), ","), "size": size})
}

// cons is GET /v1/log/cons?from=<a>&to=<b> -> `path=<hex,...>` (to defaults to the latest head).
func (h *handlers) cons(w http.ResponseWriter, r *http.Request) {
	s := h.s
	ctx := r.Context()
	from, err := queryU64(r, "from", 0)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var def uint64
	if hd := s.head.Load(); hd != nil {
		def = hd.Size
	}
	to, err := queryU64(r, "to", def)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	cur, err := LogSize(ctx, s.d.DB)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if from == 0 || from > to || to > cur {
		core.Fail(w, r, core.Bad(fmt.Sprintf("need 1 <= from <= to <= %d", cur)))
		return
	}
	path, err := ConsistencyPath(ctx, s.d.DB, from, to)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=3600")
	enc := e2e.EncodePath(path)
	var parts []string
	if enc != "" {
		parts = strings.Split(enc, ",")
	}
	s.reply(w, r, 200, fmt.Sprintf("path=%s from=%d to=%d", enc, from, to), map[string]any{"path": parts, "from": from, "to": to})
}

// logDelta is GET /v1/log?from=<idx>&n=<=500 -> `<idx> <kind> <id> <item_hash> <leaf>` lines.
func (h *handlers) logDelta(w http.ResponseWriter, r *http.Request) {
	from, err := queryU64(r, "from", 0)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	n, err := queryU64(r, "n", maxLogLines)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	es, err := Entries(r.Context(), h.s.d.DB, from, int(min(n, maxLogLines)))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	text := deltaLines(es)
	if len(es) == int(min(n, maxLogLines)) && len(es) > 0 {
		text += fmt.Sprintf("next=%d\n", es[len(es)-1].Idx+1)
	}
	w.Header().Set("Cache-Control", "no-store")
	h.s.reply(w, r, 200, text, map[string]any{"from": from, "rows": entriesJSON(es)})
}

// logID is GET /v1/log/id/{id} -> `<idx> <kind> <seq> <item_hash> <at>` for every leaf of the id.
func (h *handlers) logID(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if !core.ValidID(id) {
		core.Fail(w, r, core.Bad("id must be a 7-char id"))
		return
	}
	es, err := EntriesFor(r.Context(), h.s.d.DB, id)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	h.s.reply(w, r, 200, idLines(es), map[string]any{"id": id, "rows": entriesJSON(es)})
}

// cosign is POST /v1/log/cosign {size, sig[, w]} (3.4, D8): a configured witness (w names its key)
// or an established root (token + X-Cx-Sig, its ik, one per hour) cosigns the head at size.
func (h *handlers) cosign(w http.ResponseWriter, r *http.Request) {
	s := h.s
	if r.Header.Get("Authorization") == "" {
		h.witnessCosign(w, r)
		return
	}
	RequireSigMax(maxCosignBody, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id, err := s.d.Auth(r)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		var in struct {
			Size uint64 `json:"size"`
			Sig  string `json:"sig"`
			W    string `json:"w"`
		}
		if err := core.Decode(w, r, maxCosignBody, &in); err != nil {
			core.Fail(w, r, err)
			return
		}
		if id.ID != id.Root {
			core.Fail(w, r, core.E(403, "auth", "roots cosign, not sub-keys"))
			return
		}
		if !id.Established() {
			core.Fail(w, r, core.E(403, "auth", "established roots only"))
			return
		}
		sig, err := decodeB64(in.Sig)
		if err != nil || len(sig) != 64 {
			core.Fail(w, r, core.Bad("sig must be a base64 Ed25519 signature"))
			return
		}
		ctx := r.Context()
		b, found, err := Bundle(ctx, s.d.DB, id.ID)
		if err != nil || !found {
			core.Fail(w, r, core.E(403, "sig", "no key published"))
			return
		}
		var recent int
		if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM kcosign WHERE signer = $1 AND at > now() - $2::interval`, id.ID, cosignEvery.String()).Scan(&recent); err != nil {
			core.Fail(w, r, err)
			return
		}
		if recent > 0 {
			w.Header().Set("Retry-After", "3600")
			core.Fail(w, r, core.E(429, "quota", "cosign: 1 per hour"))
			return
		}
		hd, err := s.addCosign(ctx, s.d.DB, in.Size, id.ID, b.IK, sig)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		s.reply(w, r, 200, fmt.Sprintf("ok size=%d root=%s", hd.Size, hex.EncodeToString(hd.Root)), map[string]any{"ok": true, "size": hd.Size, "root": hex.EncodeToString(hd.Root)})
	})).ServeHTTP(w, r)
}

// witnessCosign stores a witness signature (no token: the signature under a configured witness key is the credential).
func (h *handlers) witnessCosign(w http.ResponseWriter, r *http.Request) {
	s := h.s
	if !s.d.Lim.Allow("kcosign:"+s.d.IPGroup(r), 1, 10) {
		core.Fail(w, r, core.ErrRate)
		return
	}
	var in struct {
		Size uint64 `json:"size"`
		Sig  string `json:"sig"`
		W    string `json:"w"`
	}
	if err := core.Decode(w, r, maxCosignBody, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	pk, ok := s.sk.witness[in.W]
	if !ok {
		core.Fail(w, r, core.E(401, "auth", "token required, or w must name a configured witness"))
		return
	}
	sig, err := decodeB64(in.Sig)
	if err != nil || len(sig) != 64 {
		core.Fail(w, r, core.Bad("sig must be a base64 Ed25519 signature"))
		return
	}
	hd, err := s.addCosign(r.Context(), s.d.DB, in.Size, in.W, pk, sig)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	s.reply(w, r, 200, fmt.Sprintf("ok size=%d root=%s", hd.Size, hex.EncodeToString(hd.Root)), map[string]any{"ok": true, "size": hd.Size, "root": hex.EncodeToString(hd.Root)})
}

// --- policy, pk1, admin -------------------------------------------------------------------------

// policy is GET /v1/policy (9.4): the stored JSON pack, signed, hash in X-Cx-Policy.
func (h *handlers) policy(w http.ResponseWriter, r *http.Request) {
	p, err := h.s.currentPolicy(r.Context())
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("X-Cx-Policy", fmt.Sprintf("v=%d hash=%s leaf=%d", p.V, hex.EncodeToString(p.Hash), p.Leaf))
	h.s.signed(w, r, 200, p.Body, "application/json")
}

// pkLines renders `pk1 id=<id> ik=<b64> n=<seq> t=<unix> k=<kid>` + sig= (26.6), cached 60 s.
func (s *svc) pkLines(ctx context.Context, id string) (string, error) {
	if v, ok := s.pk.Get("pk:" + id); ok {
		return string(v), nil
	}
	b, err := Lookup(ctx, s.d.DB, id)
	if err != nil {
		return "", err
	}
	if b.State == "pending" {
		return "", core.E(404, "notfound", "keys pending, not current")
	}
	line := sign.Canonical(TypePK, sign.KV{K: "id", V: b.ID}, sign.KV{K: "ik", V: b64(b.IK)}, sign.KV{K: "n", V: strconv.FormatUint(uint64(b.Seq), 10)},
		sign.KV{K: "t", V: strconv.FormatInt(b.Published.Unix(), 10)}, sign.KV{K: "k", V: strconv.Itoa(s.signer.KID())})
	text := line + "\n" + s.signer.Sign(TypePK, line) + "\n"
	s.pk.Put("pk:"+id, []byte(text), pkTTL)
	return text, nil
}

func (h *handlers) pk(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if i := strings.IndexByte(id, '.'); i > 0 {
		id = id[:i]
	}
	if !core.ValidID(id) {
		core.Fail(w, r, core.Bad("id must be a 7-char id"))
		return
	}
	if !h.anonOK(w, r) {
		return
	}
	text, err := h.s.pkLines(r.Context(), id)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=60")
	line, sig, _ := strings.Cut(strings.TrimSuffix(text, "\n"), "\n")
	h.s.reply(w, r, 200, text, map[string]any{"statement": line, "sig": sig})
}

// onlineKey is POST /admin/online-key {cert} (3.6): installs a root-signed online certificate.
func (h *handlers) onlineKey(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cert string `json:"cert"`
	}
	if err := core.Decode(w, r, maxAdminBody, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	raw, err := decodeB64(in.Cert)
	if err != nil {
		core.Fail(w, r, core.Bad("cert must be base64"))
		return
	}
	core.AdminArg(r, "seq")
	c, err := h.s.installCert(r.Context(), raw)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, fmt.Sprintf("ok seq=%d exp=%d", c.Seq, c.Exp), map[string]any{"ok": true, "seq": c.Seq, "exp": c.Exp})
}
