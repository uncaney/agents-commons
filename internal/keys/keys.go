// Package keys is the key directory and transparency log of the sealed lane (SECURITY-E2EE-v2
// 3.2-3.8, 9.3, 9.4; SPEC-v2 26.1, 26.6): bundles born inside registration, PUT/GET /v1/keys, the
// RFC 6962 key log with signed heads, inclusion and consistency proofs and cosignatures, the
// X-Cx-Sig request-signing middleware with single-use nonces, the server online key with signed
// replies, the policy pack, signed pk1 lines stamped into the notary, and the 24 h ?all=1 refusal
// after a key change. The server stores public keys, hashes and signatures only.
package keys

import (
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/sign"
)

// Log kinds (E2EE 3.3).
const (
	KindBundle     = 1
	KindTombstone  = 2
	KindPending    = 3
	KindSuccession = 4
	KindPolicy     = 5
	KindState      = 6
	KindAdmin      = 7
	KindAnchor     = 8
)

const (
	// PendingWindow is the veto window of a legacy first publish and of an ik rotation (3.2, 3.7).
	PendingWindow = 24 * time.Hour
	// HeadEvery is the signed-head cadence (3.3).
	HeadEvery = 10 * time.Minute
	// KeyChangeEvery bounds key changes (ik or rk) to one per 24 h per root (26.6).
	KeyChangeEvery = 24 * time.Hour
	// PubPerDay is the daily bundle publication cap per root (weekly republish is the norm).
	PubPerDay = 24
	// DefaultSigBody is the body cap RequireSig applies when the route gives none.
	DefaultSigBody = 256 << 10
	// CertLen is the online certificate wire length: online_pk 32 | nbf u64 | exp u64 | seq u32 | sig 64.
	CertLen = 32 + 8 + 8 + 4 + 64
	// CertMaxTTL is the longest root-signed certificate accepted (30 d plus a day of slack).
	CertMaxTTL = 31 * 24 * time.Hour
	// SelfCertTTL is the lifetime of a self-certified online key (wave 1); re-issued by the janitor.
	SelfCertTTL = 30 * 24 * time.Hour

	nonceTTL      = 2 * e2e.ReqSkew * time.Second
	pkTTL         = 60 * time.Second
	dirRate       = 5.0 // anonymous GET /v1/keys/{id}: 5/s per IP group
	dirBurst      = 10
	cosignEvery   = time.Hour
	maxCosignBody = 2 << 10
	maxAdminBody  = 4 << 10
	maxLogLines   = 500
	nodeCacheMax  = 8 << 20
	pkCacheMax    = 1 << 20
	onlineInfo    = "cx-online-v1" // HKDF info of the SERVER_SECRET fallback (dev and tests)
	witnessMax    = 8
)

// Statement type of GET /v1/pk/{id} (26.6, signed by the server statement key).
const TypePK = "pk1"

func init() { sign.RegisterTypes(TypePK) }

var (
	ErrNoKeys    = core.E(404, "notfound", "no keys published")
	ErrContested = core.E(409, "keys", "contested")
	ErrRevoked   = core.E(410, "revoked", "keys revoked")
	ErrNotReady  = core.E(503, "keys", "key directory not ready")
)

// svc is the package service: deps, the statement signer, the server keys and the caches.
type svc struct {
	d      *core.Deps
	signer *sign.Signer
	sk     *serverKeys
	pk     *core.ByteLRU
	head   atomic.Pointer[Head]
	policy atomic.Pointer[policyPack]
}

// cur is the service installed by Register; the package-level seams read it (nil = not ready).
var cur atomic.Pointer[svc]

// nodeCache holds immutable perfect-subtree nodes of the key log (shared by every svc).
var nodeCache = core.NewByteLRU(nodeCacheMax)

// serverKeys are the three key roles of 3.6 as the gateway sees them: its online key, the root
// public key (nil = self-certified, wave 1), the current certificate and the witness public keys.
type serverKeys struct {
	online  ed25519.PrivateKey
	pub     []byte
	rootPub []byte
	cert    atomic.Pointer[Cert]
	witness map[string][]byte
	wnames  []string
	mirror  string
}

// Cert is a parsed online certificate (3.6): root_sk-signed {online_pk, nbf, exp, seq}.
type Cert struct {
	Raw    []byte
	Online []byte
	NBF    uint64
	Exp    uint64
	Seq    uint32
	Sig    []byte
}

// EncodeCert renders the wire form; ParseCert reads it (shape only, see Verify).
func EncodeCert(online []byte, nbf, exp uint64, seq uint32, sig []byte) []byte {
	out := make([]byte, 0, CertLen)
	out = append(out, online...)
	out = append(out, e2e.U64(nbf)...)
	out = append(out, e2e.U64(exp)...)
	out = append(out, e2e.U32(seq)...)
	return append(out, sig...)
}

func ParseCert(raw []byte) (*Cert, error) {
	if len(raw) != CertLen {
		return nil, errors.New("keys: certificate length")
	}
	c := &Cert{Raw: raw, Online: raw[:32], Sig: raw[52:]}
	c.NBF = beU64(raw[32:40])
	c.Exp = beU64(raw[40:48])
	c.Seq = uint32(raw[48])<<24 | uint32(raw[49])<<16 | uint32(raw[50])<<8 | uint32(raw[51])
	return c, nil
}

func beU64(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		v = v<<8 | uint64(c)
	}
	return v
}

// Verify checks the certificate over online under rootPub at time now.
func (c *Cert) Verify(rootPub, online []byte, now int64) error {
	switch {
	case !e2e.Verify(rootPub, e2e.CertBytes(c.Online, c.NBF, c.Exp, c.Seq), c.Sig):
		return errors.New("keys: certificate signature")
	case !equal(c.Online, online):
		return errors.New("keys: certificate names another online key")
	case int64(c.NBF) > now+e2e.IATSkew:
		return errors.New("keys: certificate not yet valid")
	case int64(c.Exp) <= now:
		return errors.New("keys: certificate expired")
	case c.Exp-c.NBF > uint64(CertMaxTTL/time.Second):
		return errors.New("keys: certificate lifetime above 30 d")
	}
	return nil
}

func equal(a, b []byte) bool { return len(a) == len(b) && sha256.Sum256(a) == sha256.Sum256(b) }

// selfCert signs a certificate for the online key with the online key itself (wave 1 posture).
func (k *serverKeys) selfCert(now time.Time) *Cert {
	nbf, exp := uint64(now.Unix()), uint64(now.Add(SelfCertTTL).Unix())
	sig := e2e.Sign(k.online, e2e.CertBytes(k.pub, nbf, exp, 0))
	c, _ := ParseCert(EncodeCert(k.pub, nbf, exp, 0, sig))
	return c
}

// trustRoot is the key certificates are verified against: the root public key, or the online key
// itself while self-certified.
func (k *serverKeys) trustRoot() []byte {
	if k.rootPub != nil {
		return k.rootPub
	}
	return k.pub
}

// loadServerKeys reads the key material of 9.3 from the environment: SERVER_SIGN_KEY_FILE (an
// Ed25519 seed, generated on first boot when the file is missing), SERVER_ROOT_PUB, WITNESS_PUBS,
// MIRROR_URL. Without a key file the online key is derived from SERVER_SECRET (dev and tests).
func loadServerKeys(cfg core.Config, log *slog.Logger) (*serverKeys, error) {
	seed, err := loadOnlineSeed(cfg, log)
	if err != nil {
		return nil, err
	}
	k := &serverKeys{online: ed25519.NewKeyFromSeed(seed), witness: map[string][]byte{}, mirror: cfg.MirrorURL}
	k.pub = k.online.Public().(ed25519.PublicKey)
	if v := strings.TrimSpace(os.Getenv("SERVER_ROOT_PUB")); v != "" {
		pub, err := decodeB64(v)
		if err != nil || len(pub) != 32 {
			return nil, errors.New("keys: SERVER_ROOT_PUB must be a base64 Ed25519 public key")
		}
		k.rootPub = pub
	}
	for i, f := range strings.FieldsFunc(os.Getenv("WITNESS_PUBS"), func(r rune) bool { return r == ',' || r == ';' || r == ' ' || r == '\n' || r == '\t' }) {
		name, val, ok := strings.Cut(f, ":")
		if !ok {
			name, val = "w"+strconv.Itoa(i+1), f
		}
		pub, err := decodeB64(val)
		if err != nil || len(pub) != 32 || len(name) == 0 || len(name) > 16 || !sign.ValidType(name) {
			return nil, errors.New("keys: WITNESS_PUBS must be [name:]<base64 Ed25519 public key> entries")
		}
		if len(k.witness) >= witnessMax {
			return nil, errors.New("keys: too many WITNESS_PUBS")
		}
		k.witness[name] = pub
		k.wnames = append(k.wnames, name)
	}
	sort.Strings(k.wnames)
	k.cert.Store(k.selfCert(time.Now()))
	return k, nil
}

func loadOnlineSeed(cfg core.Config, log *slog.Logger) ([]byte, error) {
	if p := os.Getenv("SERVER_SIGN_KEY_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if errors.Is(err, os.ErrNotExist) {
			seed := make([]byte, ed25519.SeedSize)
			rand.Read(seed)
			if err := os.WriteFile(p, []byte(base64.RawURLEncoding.EncodeToString(seed)+"\n"), 0o600); err != nil {
				return nil, fmt.Errorf("keys: SERVER_SIGN_KEY_FILE: %w", err)
			}
			log.Info("keys: generated online key", "file", p)
			return seed, nil
		}
		if err != nil {
			return nil, fmt.Errorf("keys: SERVER_SIGN_KEY_FILE: %w", err)
		}
		return parseSeed(b)
	}
	if v := strings.TrimSpace(os.Getenv("SERVER_SIGN_KEY")); v != "" {
		return parseSeed([]byte(v))
	}
	if len(cfg.ServerSecret) == 0 {
		return nil, errors.New("keys: SERVER_SIGN_KEY_FILE or SERVER_SECRET required")
	}
	log.Warn("keys: online key derived from SERVER_SECRET; set SERVER_SIGN_KEY_FILE in production")
	return hkdf.Key(sha256.New, cfg.ServerSecret, nil, onlineInfo, ed25519.SeedSize)
}

// parseSeed accepts a raw 32-byte seed, 64 hex chars or base64 (url or std, padded or not).
func parseSeed(b []byte) ([]byte, error) {
	if len(b) == ed25519.SeedSize {
		return b, nil
	}
	s := strings.TrimSpace(string(b))
	if h, err := hex.DecodeString(s); err == nil && len(h) == ed25519.SeedSize {
		return h, nil
	}
	if d, err := decodeB64(s); err == nil && len(d) == ed25519.SeedSize {
		return d, nil
	}
	return nil, errors.New("keys: online key seed must be 32 bytes (raw, hex or base64)")
}

// decodeB64 reads base64url or standard base64, padded or not.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func newSvc(d *core.Deps) (*svc, error) {
	sk, err := loadServerKeys(d.Cfg, d.Log)
	if err != nil {
		return nil, err
	}
	signer, err := sign.New(d.Cfg)
	if err != nil {
		return nil, err
	}
	return &svc{d: d, signer: signer, sk: sk, pk: core.NewByteLRU(pkCacheMax)}, nil
}

// Register loads the server keys (fatal on a bad configuration), installs the package service,
// mounts every route (all LogMinimal: no per-write IP on the sealed lane, D3(b)), and registers
// scopes, costs, the OpenAPI fragment, the llms-full section, the storage class, the janitor tasks
// (heads every 10 min, nonce expiry, pending publications, policy pack) and the purge hook.
func Register(mux *http.ServeMux, d *core.Deps) {
	s, err := newSvc(d)
	if err != nil {
		panic(err)
	}
	cur.Store(s)
	bctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	s.boot(bctx)
	cancel()
	h := &handlers{s}
	mux.Handle("PUT /v1/keys", s.wrap(h.put))
	mux.Handle("GET /v1/keys", s.wrap(h.getOwn))
	mux.Handle("GET /v1/keys/server", s.wrap(h.server))
	mux.Handle("GET /v1/keys/{id}", s.wrap(h.get))
	mux.Handle("GET /v1/keys/{id}/hist", s.wrap(h.hist))
	mux.Handle("GET /v1/log", s.wrap(h.logDelta))
	mux.Handle("GET /v1/log/sth", s.wrap(h.sth))
	mux.Handle("GET /v1/log/incl", s.wrap(h.incl))
	mux.Handle("GET /v1/log/cons", s.wrap(h.cons))
	mux.Handle("GET /v1/log/id/{id}", s.wrap(h.logID))
	mux.Handle("POST /v1/log/cosign", s.wrap(h.cosign))
	mux.Handle("GET /v1/policy", s.wrap(h.policy))
	mux.Handle("GET /v1/pk/{id}", s.wrap(h.pk))
	mux.HandleFunc("POST /admin/online-key", d.AdminOnly(h.onlineKey))
	d.RegisterScope("PUT /v1/keys", "keys")
	d.RegisterScope("GET /v1/keys", "me:r")
	d.RegisterScope("POST /v1/log/cosign", "keys")
	for _, p := range []string{"GET /v1/log/sth", "GET /v1/log/incl", "GET /v1/log/cons", "GET /v1/pk/{id}", "GET /v1/keys/server"} {
		d.RegisterCost(p, 0.2)
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("keys", func(context.Context) string { return llmsText })
	d.StorageClass("keys", 256<<20, `SELECT pg_total_relation_size('key_bundles') + pg_total_relation_size('klog') + pg_total_relation_size('knodes') + pg_total_relation_size('ksth')`)
	d.Janitor.Add("keys_sth", s.janitorHead)
	d.Janitor.Add("keys_nonces", func(ctx context.Context) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM req_nonces WHERE exp < now()`)
		return err
	})
	d.Janitor.Add("keys_pending", s.promotePending)
	d.Janitor.Add("keys_policy", func(ctx context.Context) error { return s.ensurePolicy(ctx) })
	d.OnPurge(s.purge)
}

// boot loads the operator certificate, makes sure a head and a policy pack exist. Failures are
// logged: the janitor retries every tick.
func (s *svc) boot(ctx context.Context) {
	if err := s.loadCert(ctx); err != nil {
		s.d.Log.Warn("keys: certificate", "err", err)
	}
	if _, err := s.latestHead(ctx, s.d.DB); errors.Is(err, pgx.ErrNoRows) {
		if _, err := s.signHead(ctx); err != nil {
			s.d.Log.Warn("keys: initial head", "err", err)
		}
	} else if err != nil {
		s.d.Log.Warn("keys: head", "err", err)
	}
	if err := s.ensurePolicy(ctx); err != nil {
		s.d.Log.Warn("keys: policy pack", "err", err)
	}
}

// loadCert installs the newest valid operator certificate for this online key: from server_keys
// (pushed through POST /admin/online-key), else SERVER_ONLINE_CERT_FILE; otherwise the self-signed
// certificate stays (wave 1).
func (s *svc) loadCert(ctx context.Context) error {
	if s.sk.rootPub == nil {
		return nil
	}
	now := time.Now().Unix()
	rows, err := s.d.DB.Query(ctx, `SELECT cert FROM server_keys WHERE online_pub = $1 AND exp > now() ORDER BY seq DESC LIMIT 5`, s.sk.pub)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		if c, err := ParseCert(raw); err == nil && c.Verify(s.sk.rootPub, s.sk.pub, now) == nil {
			s.sk.cert.Store(c)
			return nil
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if p := os.Getenv("SERVER_ONLINE_CERT_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		raw, err := decodeB64(string(b))
		if err != nil {
			return errors.New("keys: SERVER_ONLINE_CERT_FILE is not base64")
		}
		c, err := ParseCert(raw)
		if err != nil {
			return err
		}
		if err := c.Verify(s.sk.rootPub, s.sk.pub, now); err != nil {
			return err
		}
		s.sk.cert.Store(c)
	}
	return nil
}

// installCert verifies and stores a root-signed certificate (POST /admin/online-key).
func (s *svc) installCert(ctx context.Context, raw []byte) (*Cert, error) {
	if s.sk.rootPub == nil {
		return nil, core.Bad("SERVER_ROOT_PUB unset: the online key is self-certified")
	}
	c, err := ParseCert(raw)
	if err != nil {
		return nil, core.Bad(err.Error())
	}
	if err := c.Verify(s.sk.rootPub, s.sk.pub, time.Now().Unix()); err != nil {
		return nil, core.Bad(err.Error())
	}
	tag, err := s.d.DB.Exec(ctx, `INSERT INTO server_keys (seq, online_pub, cert, nbf, exp) VALUES ($1, $2, $3, to_timestamp($4), to_timestamp($5))
		ON CONFLICT (seq) DO NOTHING`, int64(c.Seq), c.Online, c.Raw, int64(c.NBF), int64(c.Exp))
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, core.E(409, "dup", "certificate seq already installed")
	}
	if old := s.sk.cert.Load(); old == nil || old.Seq < c.Seq || old.Online == nil {
		s.sk.cert.Store(c)
	}
	return c, nil
}

// janitorHead signs a head every HeadEvery (and refreshes an expiring self-certificate).
func (s *svc) janitorHead(ctx context.Context) error {
	if c := s.sk.cert.Load(); s.sk.rootPub == nil && c != nil && time.Until(time.Unix(int64(c.Exp), 0)) < 24*time.Hour {
		s.sk.cert.Store(s.sk.selfCert(time.Now()))
	}
	h, err := s.latestHead(ctx, s.d.DB)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if h != nil && time.Since(h.At) < HeadEvery {
		s.head.Store(h)
		return nil
	}
	_, err = s.signHead(ctx)
	return err
}

// purge tombstones every bundle of the root's tree (kind 2 leaves), drops its nonces and signs a head.
func (s *svc) purge(ctx context.Context, root string) error {
	rows, err := s.d.DB.Query(ctx, `SELECT DISTINCT id FROM key_bundles WHERE root = $1 AND state IN ('current', 'pending')`, root)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, id := range ids {
		if err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error { _, err := Tombstone(ctx, tx, id); return err }); err != nil {
			return err
		}
	}
	if _, err := s.d.DB.Exec(ctx, `DELETE FROM req_nonces WHERE id IN (SELECT id FROM identities WHERE root = $1)`, root); err != nil {
		return err
	}
	if len(ids) > 0 {
		_, err = s.signHead(ctx)
	}
	return err
}

// --- request context flags and response headers --------------------------------------------------

type logMinKey struct{}

// WithLogMinimal marks a request context as sealed-lane traffic: the request log keeps the route
// and status but no client IP, and no content_origin row is ever written (E2EE 8.2, D3(b)).
func WithLogMinimal(ctx context.Context) context.Context {
	return context.WithValue(ctx, logMinKey{}, true)
}

// IsLogMinimal reports the WithLogMinimal flag.
func IsLogMinimal(ctx context.Context) bool {
	v, _ := ctx.Value(logMinKey{}).(bool)
	return v
}

// LogMinimalHeader is the response header the sealed routes set so the request logger (core.Handler)
// can honour LogMinimal without a context round trip.
const LogMinimalHeader = "X-Cx-Log"

// LogMinimal wraps a sealed-lane handler: context flag, X-Cx-Log: minimal, X-Now and CX-STH.
func LogMinimal(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(LogMinimalHeader, "minimal")
		if s := cur.Load(); s != nil {
			s.hdr(w)
		} else {
			w.Header().Set("X-Now", strconv.FormatInt(time.Now().Unix(), 10))
		}
		h.ServeHTTP(w, r.WithContext(WithLogMinimal(r.Context())))
	})
}

// Gossip adds X-Now and CX-STH (the latest head, 3.3) to every response of h; the gateway wraps /v1.
func Gossip(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s := cur.Load(); s != nil {
			s.hdr(w)
		} else {
			w.Header().Set("X-Now", strconv.FormatInt(time.Now().Unix(), 10))
		}
		h.ServeHTTP(w, r)
	})
}

func (s *svc) wrap(fn http.HandlerFunc) http.Handler { return LogMinimal(fn) }

// hdr sets X-Now (3.5) and CX-STH (3.3) on a response.
func (s *svc) hdr(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Now", strconv.FormatInt(time.Now().Unix(), 10))
	if hd := s.head.Load(); hd != nil {
		h.Set("CX-STH", e2e.GossipHeader(hd.Size, hd.Root))
	}
}

// SignServer returns the X-Cx-Sig-Server value for a reply body served at path (3.6): the scrub
// package and the client-delivery routes call it; empty until Register ran.
func SignServer(path string, body []byte) string {
	s := cur.Load()
	if s == nil {
		return ""
	}
	return e2e.SignResp(s.sk.online, path, uint64(time.Now().Unix()), body)
}

// OnlinePub is the server's online public key (nil until Register ran).
func OnlinePub() []byte {
	if s := cur.Load(); s != nil {
		return append([]byte(nil), s.sk.pub...)
	}
	return nil
}

// signed writes body with X-Cx-Sig-Server over the exact bytes written.
func (s *svc) signed(w http.ResponseWriter, r *http.Request, status int, body []byte, ct string) {
	w.Header().Set("X-Cx-Sig-Server", e2e.SignResp(s.sk.online, r.URL.Path, uint64(time.Now().Unix()), body))
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(status)
	w.Write(body)
}

// reply writes text (or j when JSON is wanted) as a signed reply.
func (s *svc) reply(w http.ResponseWriter, r *http.Request, status int, text string, j any) {
	if j != nil && core.WantJSON(r) {
		s.signed(w, r, status, jsonBytes(j), "application/json")
		return
	}
	if !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	s.signed(w, r, status, []byte(text), "text/plain; charset=utf-8")
}

func readBody(w http.ResponseWriter, r *http.Request, max int64) ([]byte, error) {
	b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, max))
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) {
			return nil, core.ErrSize
		}
		return nil, core.Bad("read: " + err.Error())
	}
	return b, nil
}
