// Package group is the Delivery Service for cxg1 sealed groups (SECURITY-E2EE-v2 5; SPEC-v2 26).
// The server is exactly an MLS Delivery Service: it holds the roster (visible by design, 5.5), gives
// a total order to opaque rows whose 85-byte headers are cleartext AAD, enforces the epoch CAS and
// the roster rules, signs a relay receipt per write, and never holds a key, a plaintext, or a
// ciphertext key. Every write is behind keys.RequireSig; every read and write is roster-checked.
// Server-originated removals are the lawful lever (5.5). Content is zero-knowledge; the roster,
// counters, epochs and franking commitments are not.
package group

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
	"ekaii.fr/commons/internal/sign"
)

// Tunables (9.3 budgets, 5.5 quotas). Overridable by env in loadEnv.
var (
	MaxBytes     int64 = 256 << 20       // the 'groups' storage class budget
	GroupBytes   int64 = 4 << 20         // live bytes per group (5.5)
	RowCap             = e2e.GroupRowCap // 16 KiB per non-commit row
	CommitRowCap       = e2e.CommitCap   // 64 KiB per commit
	TTL                = 30 * 24 * time.Hour
	IdleExpiry         = 90 * 24 * time.Hour // idle group expiry (storage class 'groups')
	EvidenceTTL        = 90 * 24 * time.Hour // x_evidence equivalent (D6)
	TombTTL            = 365 * 24 * time.Hour

	GMsgPerDay     = 2000
	GBytesPerDay   = 4 << 20
	GCreatePerDay  = 10
	GWelcomePerDay = 200
	PullMax        = 100
	WaitHold       = 85 * time.Second
	LockTTLMax     = 3600
)

// svc is the package service: deps and the online statement signer (receipts, server proposals,
// reputation attestations). The online key here is the sign.Signer, as in the sealed mailbox.
type svc struct {
	d      *core.Deps
	signer *sign.Signer
}

// cur is the installed service (nil until Register ran; ops answer err group).
var cur atomic.Pointer[svc]

// Routes lists every pattern Register mounted (route-table test).
var Routes []string

// Register mounts the Delivery Service: every write behind keys.RequireSig, every read behind
// keys.LogMinimal and roster-checked inside the handler; the scopes, costs, OpenAPI, llms section,
// the report target g:, the 'groups' storage class, the janitor, the purge hook (server-originated
// removals), the resume and me lines. keys.Register must run in the same process.
func Register(mux *http.ServeMux, d *core.Deps) {
	signer, err := sign.New(d.Cfg)
	if err != nil {
		panic(err)
	}
	s := &svc{d: d, signer: signer}
	loadEnv()
	cur.Store(s)
	Routes = Routes[:0]
	mount := func(pat string, h http.Handler) {
		Routes = append(Routes, pat)
		mux.Handle(pat, h)
	}
	read := func(fn http.HandlerFunc) http.Handler { return keys.LogMinimal(fn) }
	write := func(max int64, fn http.HandlerFunc) http.Handler { return keys.RequireSigMax(max, fn) }

	mount("POST /v1/g", write(int64(CommitRowCap)+4096, s.create))
	mount("GET /v1/g", read(s.list))
	mount("GET /v1/g/inv", read(s.invites))
	mount("GET /v1/me/attest", read(s.attest))
	mount("GET /v1/g/{gid}", read(s.info))
	mount("GET /v1/g/{gid}/me", read(s.meInfo))
	mount("POST /v1/g/{gid}/m", write(int64(RowCap), s.postApp))
	mount("POST /v1/g/{gid}/c", write(int64(CommitRowCap), s.postCommit))
	mount("POST /v1/g/{gid}/p", write(int64(RowCap), s.postProposal))
	mount("POST /v1/g/{gid}/w", write(int64(RowCap), s.postWelcome))
	mount("GET /v1/g/{gid}/m", read(s.pull))
	mount("GET /v1/g/{gid}/wait", read(s.wait))
	mount("POST /v1/g/{gid}/leave", write(1<<10, s.leave))
	mount("POST /v1/g/{gid}/remove", write(1<<10, s.remove))
	mount("DELETE /v1/g/{gid}", write(1<<10, s.del))
	mount("PUT /v1/g/{gid}/state", write(e2e.StateCap, s.statePut))
	mount("GET /v1/g/{gid}/state", read(s.stateGet))
	mount("PUT /v1/g/{gid}/snapshot", write(e2e.StateCap, s.snapshotPut))
	mount("GET /v1/g/{gid}/snapshot", read(s.snapshotGet))
	mount("POST /v1/g/{gid}/lock", write(1<<10, s.lock))
	mount("POST /v1/g/{gid}/barrier", write(1<<10, s.barrier))
	mount("POST /v1/g/{gid}/lead", write(1<<10, s.lead))
	mount("POST /v1/g/{gid}/report", write(8<<10, s.report))

	for pat, scope := range map[string]string{
		"POST /v1/g": "g:w", "GET /v1/g": "*", "GET /v1/g/inv": "*", "GET /v1/me/attest": "*",
		"GET /v1/g/{gid}": "g:r", "GET /v1/g/{gid}/me": "g:r",
		"POST /v1/g/{gid}/m": "g:w", "POST /v1/g/{gid}/c": "g:w", "POST /v1/g/{gid}/p": "g:w", "POST /v1/g/{gid}/w": "g:w",
		"GET /v1/g/{gid}/m": "g:r", "GET /v1/g/{gid}/wait": "g:r",
		"POST /v1/g/{gid}/leave": "g:w", "POST /v1/g/{gid}/remove": "g:w", "DELETE /v1/g/{gid}": "g:w",
		"PUT /v1/g/{gid}/state": "g:w", "GET /v1/g/{gid}/state": "g:r",
		"PUT /v1/g/{gid}/snapshot": "g:w", "GET /v1/g/{gid}/snapshot": "g:r",
		"POST /v1/g/{gid}/lock": "g:w", "POST /v1/g/{gid}/barrier": "g:w", "POST /v1/g/{gid}/lead": "g:w",
		"POST /v1/g/{gid}/report": "g:w",
	} {
		d.RegisterScope(pat, scope)
	}
	for _, p := range []string{"GET /v1/g", "GET /v1/g/inv", "GET /v1/g/{gid}", "GET /v1/g/{gid}/me",
		"GET /v1/g/{gid}/m", "GET /v1/g/{gid}/wait", "GET /v1/g/{gid}/state", "GET /v1/g/{gid}/snapshot", "GET /v1/me/attest"} {
		d.RegisterCost(p, 0.2)
	}
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("groups", func(context.Context) string { return llmsText })
	d.RegisterTarget("g", core.Target{Exists: exists, Hide: hide, Restore: restore})
	d.StorageClass("groups", MaxBytes,
		`SELECT pg_total_relation_size('grp') + pg_total_relation_size('grp_rows') + pg_total_relation_size('grp_state') + pg_total_relation_size('grp_snapshots')`)
	d.Janitor.Add("groups", func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error { return s.purge(ctx, root) })
	d.OnResume(func(ctx context.Context, root string) []string { return resumeLines(ctx, d.DB, root) })
	d.MeExtra(func(ctx context.Context, id *core.Ident) []string { return meLines(ctx, d.DB, id) })
}

func loadEnv() {
	if v := strings.TrimSpace(os.Getenv("GROUP_MAX_BYTES")); v != "" {
		if n, err := core.ParseBytes(v); err == nil && n > 0 {
			MaxBytes = n
		}
	}
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func decodeB64(s string) ([]byte, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	return base64.RawURLEncoding.Strict().DecodeString(s)
}

var (
	errNotReady   = core.E(503, "group", "the delivery service is starting")
	errNotMember  = core.E(403, "roster", "not a member of this group")
	errNoGroup    = core.E(404, "notfound", "no such group")
	errFrozen     = core.Frozen("mail")
	errBadRow     = core.Bad("row: not a valid cxg1 row for this group")
	errStaleEpoch = func(cur int64) *core.APIError { return core.E(409, "stale", "epoch="+strconv.FormatInt(cur, 10)) }
	errBadIdx     = core.E(403, "roster", "hdr.idx is not the sender's roster idx")
)

func ready() (*svc, error) {
	if s := cur.Load(); s != nil {
		return s, nil
	}
	return nil, errNotReady
}

// grpRow is a group's grp row (metadata only).
type grpRow struct {
	id          string
	cs          int16
	maxN        int
	ttlD        int
	epoch       int64
	lastSeq     int64
	bytes       int64
	creatorRoot string
	pending     int
	frozen      bool
	created     time.Time
	idle        time.Time
}

func loadGroup(ctx context.Context, q core.Q, gid string) (*grpRow, error) {
	g := &grpRow{}
	err := q.QueryRow(ctx, `SELECT id, cs, max_n, ttl_d, epoch, last_seq, bytes, creator_root, pending, frozen, created, idle
		FROM grp WHERE id = $1`, gid).
		Scan(&g.id, &g.cs, &g.maxN, &g.ttlD, &g.epoch, &g.lastSeq, &g.bytes, &g.creatorRoot, &g.pending, &g.frozen, &g.created, &g.idle)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNoGroup
	}
	return g, err
}

// member is one grp_members row.
type member struct {
	idx        int
	id, root   string
	leaf       int64
	ik         []byte
	role       int16
	sinceEpoch int64
}

// memberOf returns the caller's roster entry, or errNotMember when the caller's identity is not a
// current member (roster-checked reads and writes, 5.4).
func memberOf(ctx context.Context, q core.Q, gid, id string) (*member, error) {
	m := &member{}
	err := q.QueryRow(ctx, `SELECT idx, id, root, leaf, ik, role, since_epoch FROM grp_members WHERE gid = $1 AND id = $2`, gid, id).
		Scan(&m.idx, &m.id, &m.root, &m.leaf, &m.ik, &m.role, &m.sinceEpoch)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, errNotMember
	}
	return m, err
}

func roster(ctx context.Context, q core.Q, gid string) ([]member, error) {
	rows, err := q.Query(ctx, `SELECT idx, id, root, leaf, ik, role, since_epoch FROM grp_members WHERE gid = $1 ORDER BY idx`, gid)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []member
	for rows.Next() {
		var m member
		if err := rows.Scan(&m.idx, &m.id, &m.root, &m.leaf, &m.ik, &m.role, &m.sinceEpoch); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// authMember authenticates the caller and checks it is a current member of gid. Used by every
// roster-checked read (writes already carry the verified identity from keys.RequireSig).
func (s *svc) authMember(r *http.Request) (*core.Ident, *grpRow, *member, error) {
	id, err := s.d.Auth(r)
	if err != nil {
		return nil, nil, nil, err
	}
	gid := r.PathValue("gid")
	if !core.ValidIDPrefix(gid, 'g') {
		return nil, nil, nil, core.Bad("gid must be a group id (g…)")
	}
	g, err := loadGroup(r.Context(), s.d.DB, gid)
	if err != nil {
		return nil, nil, nil, err
	}
	m, err := memberOf(r.Context(), s.d.DB, gid, id.ID)
	if err != nil {
		return nil, nil, nil, err
	}
	return id, g, m, nil
}

// info is GET /v1/g/{gid}: the group line then one roster line per member (roster-checked).
func (s *svc) info(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, g, _, err := s.authMember(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	ms, err := roster(r.Context(), s.d.DB, g.id)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "g=%s epoch=%d n=%d bytes=%d ttl=%d pending=%d\n", g.id, g.epoch, len(ms), g.bytes, g.ttlD, g.pending)
	for _, m := range ms {
		role := "member"
		if m.role == 1 {
			role = "admin"
		}
		fmt.Fprintf(&b, "%d %s %s %d %s e%d\n", m.idx, m.id, fp16(m.ik), m.leaf, role, m.sinceEpoch)
	}
	core.Text(w, r, 200, b.String(), nil)
}

// meInfo is GET /v1/g/{gid}/me: the caller's idx, its next gen (stateless senders fetch it here),
// the current epoch and the pending count.
func (s *svc) meInfo(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	_, g, m, err := s.authMember(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	gen, err := nextGen(r.Context(), s.d.DB, g.id, m.idx)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, fmt.Sprintf("idx=%d gen=%d epoch=%d pending=%d", m.idx, gen, g.epoch, g.pending),
		map[string]any{"idx": m.idx, "gen": gen, "epoch": g.epoch, "pending": g.pending})
}

// list is GET /v1/g: one line per group the caller belongs to.
func (s *svc) list(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	rows, err := s.d.DB.Query(r.Context(), `SELECT g.id, g.epoch, (SELECT count(*) FROM grp_members mm WHERE mm.gid = g.id), g.last_seq, g.created
		FROM grp g JOIN grp_members m ON m.gid = g.id WHERE m.id = $1 ORDER BY g.created DESC`, id.ID)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	defer rows.Close()
	var b strings.Builder
	for rows.Next() {
		var gid string
		var epoch, n, last int64
		var created time.Time
		if err := rows.Scan(&gid, &epoch, &n, &last, &created); err != nil {
			core.Fail(w, r, err)
			return
		}
		fmt.Fprintf(&b, "%s epoch=%d n=%d last=%d %s\n", gid, epoch, n, last, created.UTC().Format("2006-01-02"))
	}
	if err := rows.Err(); err != nil {
		core.Fail(w, r, err)
		return
	}
	core.Text(w, r, 200, b.String(), nil)
}

func nextGen(ctx context.Context, q core.Q, gid string, idx int) (int64, error) {
	var gen *int64
	if err := q.QueryRow(ctx, `SELECT max(gen) FROM grp_rows WHERE gid = $1 AND idx = $2`, gid, idx).Scan(&gen); err != nil {
		return 0, err
	}
	if gen == nil {
		return 1, nil
	}
	return *gen + 1, nil
}

func fp16(ik []byte) string { return b64(e2e.Sum([]byte("fp"), ik))[:16] }
