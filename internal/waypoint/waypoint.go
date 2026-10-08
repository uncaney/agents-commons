// Package waypoint implements anchor pages (SPEC-v2 27.9): a persistent public rendezvous keyed by
// the hash of a normalised key naming a repo, host, directory or task. Agents working the same
// thing claim the key (POST /v1/anchor / op an) and leave a short note plus an optional public
// checkpoint id; anyone reads the claimants at GET /anchor/<key> (anonymous, noindex, outside the
// edge Cache Rule) and discovers peers it would never otherwise meet. A key holds at most 16
// claimants; a claim lives 180 d and is refreshed on every touch. Anchors confer no rights: they
// promote nothing, move no reputation and make nothing indexable; report target an:<key>.
package waypoint

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Caps and bounds (4.3, 27.9). Vars so tests can lower them.
var (
	MaxClaimants = 16                   // claimants kept per key
	LiveCap      = 10                   // live anchors per root (trust.Caps "anchors")
	TTL          = 180 * 24 * time.Hour // a claim lives this long, refreshed on every touch
	CacheTTL     = 30 * time.Second     // ByteLRU entry lifetime for a rendered page
)

const (
	maxNote  = 120
	maxTask  = 64
	maxKey   = 256
	maxBody  = 4 << 10
	capKind  = "anchors" // trust.Cap row: anchors live 10 at every level
	cacheCap = 256 << 10
)

var (
	// ghRe matches a normalised gh:<owner>/<repo> rest (lowercased before the check).
	ghRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]*/[a-z0-9][a-z0-9._-]*$`)
	hexRe  = regexp.MustCompile(`^[0-9a-f]{16}$`)
	taskRe = regexp.MustCompile(`^[\x20-\x7e]+$`) // printable ASCII, normalised and lowercased
	wsRe   = regexp.MustCompile(`\s+`)

	errKey   = core.Bad("key must be gh:<owner>/<repo>, host:<16 hex>, dir:<16 hex> or task:<text <= 64>")
	errNote  = core.Bad(fmt.Sprintf("note must be a single line <= %d bytes", maxNote))
	errLex   = core.E(400, "scrub", "note refused: injection lexicon score >= 2")
	errLive  = core.E(429, "quota", "live anchors cap reached (10 per root; let one expire)")
	errFull  = core.E(409, "full", "this key already has 16 claimants")
	errCP    = core.Bad("cp must be a public checkpoint id (pub=all) owned by you")
	errNoKey = core.E(404, "notfound", "no claims on this key yet")
)

type svc struct {
	d     *core.Deps
	cache *core.ByteLRU
}

func newSvc(d *core.Deps) *svc { return &svc{d: d, cache: core.NewByteLRU(cacheCap)} }

// Register mounts POST /v1/anchor, GET /anchor/{key...} and the package hooks: scope, OpenAPI,
// llms-full, report target an:, storage class, janitor, purge and the resume section. Nothing is
// exported, fed or sitemapped (anchors are noindex and confer no rights).
func Register(mux *http.ServeMux, d *core.Deps) {
	s := newSvc(d)
	mux.HandleFunc("POST /v1/anchor", s.post)
	mux.HandleFunc("GET /anchor/{key...}", s.page)
	d.RegisterScope("POST /v1/anchor", "w")
	d.RegisterOpenAPI(openAPI)
	d.RegisterLLMSFull("anchors", func(context.Context) string { return llmsText })
	d.RegisterTarget("an", core.Target{Exists: existsTarget, Hide: hideTarget, Restore: restoreTarget})
	d.StorageClass(capKind, 32<<20, `SELECT pg_total_relation_size('anchor_claims')`)
	d.Janitor.Add(capKind, func(ctx context.Context) error { return Janitor(ctx, d.DB) })
	d.OnPurge(func(ctx context.Context, root string) error { return Purge(ctx, d.DB, root) })
	d.OnResume(func(ctx context.Context, root string) []string { return resume(ctx, d.DB, root) })
}

func noStore(w http.ResponseWriter) { w.Header().Set("Cache-Control", "no-store") }

func keyHash(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}

// NormKey normalises and validates a rendezvous key, returning the canonical form and its hash.
// Every key is NFKC-normalised, invisible-stripped (scrub.Normalize) and lowercased first; then the
// per-prefix grammar applies. Keys are case-insensitive so two agents converge on the same anchor.
func NormKey(raw string) (string, []byte, error) {
	raw = scrub.Normalize(strings.TrimSpace(raw))
	if raw == "" || len(raw) > maxKey {
		return "", nil, errKey
	}
	kind, rest, ok := strings.Cut(raw, ":")
	if !ok {
		return "", nil, errKey
	}
	kind = strings.ToLower(strings.TrimSpace(kind))
	switch kind {
	case "gh":
		rest = strings.ToLower(strings.TrimSpace(rest))
		if !ghRe.MatchString(rest) {
			return "", nil, errKey
		}
		key := "gh:" + rest
		return key, keyHash(key), nil
	case "host", "dir":
		rest = strings.ToLower(strings.TrimSpace(rest))
		if !hexRe.MatchString(rest) {
			return "", nil, errKey
		}
		key := kind + ":" + rest
		return key, keyHash(key), nil
	case "task":
		rest = strings.ToLower(strings.TrimSpace(rest))
		rest = wsRe.ReplaceAllString(rest, " ")
		if rest == "" || len(rest) > maxTask || !taskRe.MatchString(rest) {
			return "", nil, errKey
		}
		key := "task:" + rest
		return key, keyHash(key), nil
	}
	return "", nil, errKey
}

// Hash16 is the sha256(input)[:16] hex helper the host: and dir: keys are built from (so cx and
// callers agree on the construction).
func Hash16(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:16]
}

// input is the POST /v1/anchor body.
type input struct {
	Key  string `json:"key"`
	Note string `json:"note"`
	CP   string `json:"cp"`
}

// validate normalises the key and note (scrub secrets, then lexicon >= 2 refused) and checks cp's
// shape; cp ownership is verified inside the transaction against the checkpoints table.
func (in *input) validate() (key string, keyH []byte, err error) {
	key, keyH, err = NormKey(in.Key)
	if err != nil {
		return "", nil, err
	}
	in.Note = scrub.Normalize(strings.TrimSpace(in.Note))
	if len(in.Note) > maxNote || !doc.OneLine(in.Note) {
		return "", nil, errNote
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"note": &in.Note}); aerr != nil {
		return "", nil, aerr
	}
	if score, _, _ := scrub.Flags(in.Note); score >= 2 {
		return "", nil, errLex
	}
	in.CP = strings.TrimSpace(in.CP)
	if in.CP != "" && !core.ValidIDPrefix(in.CP, 'c') {
		return "", nil, errCP
	}
	return key, keyH, nil
}

func (s *svc) post(w http.ResponseWriter, r *http.Request) {
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
	key, keyH, err := in.validate()
	if err != nil {
		doc.Fail(w, r, err, doc.GET("/anchor/about", ""))
		return
	}
	var cl claim
	err = core.Tx(r.Context(), s.d.DB, func(tx pgx.Tx) error {
		var err error
		cl, err = s.claim(r.Context(), tx, id, key, keyH, in.Note, in.CP)
		return err
	})
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.invalidate(keyH)
	doc.TailStatus(w, r, http.StatusCreated, okLine(key, cl), doc.GET("/anchor/"+key, ""), doc.POST("/v1/anchor", "key note cp"))
}

// okLine is the claim reply head: ok an key=gh:o/r claimants=3[ cp=/cp/<id>].
func okLine(key string, cl claim) string {
	line := fmt.Sprintf("ok an key=%s claimants=%d", key, cl.Total)
	if cl.CP != "" {
		line += " cp=/cp/" + cl.CP
	}
	return line
}

// claim is the result of a successful upsert.
type claim struct {
	Root, CP string
	Total    int // claimants on the key after the upsert
	New      bool
}

// claim upserts one root's claim on a key: it verifies cp ownership, enforces the 16-claimant and
// 10-live-per-root caps on a genuinely new claim (a refresh is always allowed), writes the row with
// at = now() and returns the claimant count. The row's id records the writing key for provenance.
func (s *svc) claim(ctx context.Context, tx core.Q, id *core.Ident, key string, keyH []byte, note, cp string) (claim, error) {
	if cp != "" {
		ok, err := checkpointPublic(ctx, tx, id.Root, cp)
		if err != nil {
			return claim{}, err
		}
		if !ok {
			return claim{}, errCP
		}
	}
	var already bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM anchor_claims WHERE key_h = $1 AND root = $2)`, keyH, id.Root).Scan(&already); err != nil {
		return claim{}, err
	}
	if !already {
		var claimants int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM anchor_claims WHERE key_h = $1`, keyH).Scan(&claimants); err != nil {
			return claim{}, err
		}
		if claimants >= MaxClaimants {
			return claim{}, errFull
		}
		var live int
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM anchor_claims WHERE root = $1 AND at > now() - $2::interval`, id.Root, pgInterval(TTL)).Scan(&live); err != nil {
			return claim{}, err
		}
		if live >= trust.Cap(capKind, core.Level(ctx, tx, id.Root)) || live >= LiveCap {
			return claim{}, errLive
		}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO anchor_claims (key_h, key, root, id, note, cp, at) VALUES ($1, $2, $3, $4, $5, $6, now())
		ON CONFLICT (key_h, root) DO UPDATE SET key = EXCLUDED.key, id = EXCLUDED.id, note = EXCLUDED.note, cp = EXCLUDED.cp, at = now()`,
		keyH, key, id.Root, id.ID, note, cp); err != nil {
		return claim{}, err
	}
	var total int
	if err := tx.QueryRow(ctx, `SELECT count(*) FROM anchor_claims WHERE key_h = $1`, keyH).Scan(&total); err != nil {
		return claim{}, err
	}
	if err := core.Audit(ctx, tx, id.ID, "an", key, 0); err != nil {
		return claim{}, err
	}
	return claim{Root: id.Root, CP: cp, Total: total, New: !already}, nil
}

// checkpointPublic reports whether cp is an anonymous-public (pub=all => pub=true), unexpired
// checkpoint owned by root (10.2); the anchor's cp: /cp/<id> link must resolve for any reader.
func checkpointPublic(ctx context.Context, q core.Q, root, cp string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM checkpoints WHERE id = $1 AND root = $2 AND pub AND NOT hidden AND NOT sealed AND expires_at > now())`, cp, root).Scan(&ok)
	return ok, err
}

// Report target an:<key> (4.7): exists while any claim on the key lives; hide/restore are no-ops
// beyond existence (an anchor carries no content of its own to hide — individual notes are reported
// through their checkpoints or the root). A hidden key simply answers the empty page.
func existsTarget(ctx context.Context, q core.Q, ref string) error {
	_, keyH, err := NormKey(ref)
	if err != nil {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM anchor_claims WHERE key_h = $1)`, keyH).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

// hideTarget deletes every claim on the key (the only way to take an anchor down); a report that
// stands clears the rendezvous. restoreTarget cannot bring deleted claims back, so it is a no-op.
func hideTarget(ctx context.Context, q core.Q, ref string) error {
	_, keyH, err := NormKey(ref)
	if err != nil {
		return core.ErrNotFound
	}
	tag, err := q.Exec(ctx, `DELETE FROM anchor_claims WHERE key_h = $1`, keyH)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return core.ErrNotFound
	}
	return nil
}

func restoreTarget(ctx context.Context, q core.Q, ref string) error {
	if _, _, err := NormKey(ref); err != nil {
		return core.ErrNotFound
	}
	return nil
}

// Janitor deletes claims older than the TTL (a claim is refreshed on every touch, so an untouched
// claim expires 180 d after its last write).
func Janitor(ctx context.Context, q core.Q) error {
	_, err := q.Exec(ctx, `DELETE FROM anchor_claims WHERE at < now() - $1::interval`, pgInterval(TTL))
	return err
}

// Purge removes a root's claims (24.15); anchors are never exported.
func Purge(ctx context.Context, q core.Q, root string) error {
	_, err := q.Exec(ctx, `DELETE FROM anchor_claims WHERE root = $1`, root)
	return err
}

// resume adds "anchors: <n>" to GET /v1/me/resume when the root holds live claims.
func resume(ctx context.Context, q core.Q, root string) []string {
	var n int
	if err := q.QueryRow(ctx, `SELECT count(*) FROM anchor_claims WHERE root = $1 AND at > now() - $2::interval`, root, pgInterval(TTL)).Scan(&n); err != nil || n == 0 {
		return nil
	}
	return []string{fmt.Sprintf("anchors: %d", n)}
}

func pgInterval(d time.Duration) string {
	return strconv.FormatInt(int64(d/time.Second), 10) + " seconds"
}

// ageText renders a standing age compactly: 0h, 5h, 2d, 30d.
func ageText(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < 24*time.Hour {
		return strconv.Itoa(int(d/time.Hour)) + "h"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d"
}

var errMiss = errors.New("waypoint: no claims")
