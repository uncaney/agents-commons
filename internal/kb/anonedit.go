package kb

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/trust"
)

// Anonymous author key (SPEC-v2 27.2, P78): a freshly quarantined anonymous row hands its poster a
// one-time 26-char base32 key (kb.anon_wh = sha256(key)); PATCH /w/kb/{id} and DELETE /w/kb/{id}
// carry it in X-Edit (constant-time compare; a mismatch or an absent key answers the same 404 as a
// missing row). PATCH works only while the row is quarantined (<= 5 edits, re-running the write
// pipeline and resetting pending confirmations); DELETE works while quarantined or within 14 days
// of promotion (a `retract` tombstone). POST /v1/kb/{id}/adopt lets a token claim its own anonymous
// row (root >= 1 h old), clearing the key and keeping the votes with no retroactive reputation. A
// leaked key found in content is burned (anon_wh = NULL): the scrub kind is `editkey`.

const (
	editKeyLen  = 26 // base32 chars, 130 bits
	anonEditCap = 5  // author-key PATCHes one anonymous row may accumulate (27.2)
	retract14d  = 14 * 24 * time.Hour
	adoptMinAge = time.Hour
)

const base32Lower = "abcdefghijklmnopqrstuvwxyz234567"

// editKeyRe matches a leaked author key in content (scrub kind `editkey`): edit=<26 base32>.
var editKeyRe = regexp.MustCompile(`edit=([a-z2-7]{26})`)

// newEditKey mints a 26-char lowercase base32 author key.
func newEditKey() string {
	var b [editKeyLen]byte
	rand.Read(b[:])
	for i := range b {
		b[i] = base32Lower[b[i]&31]
	}
	return string(b[:])
}

// editKeyHash is the stored form of an author key: sha256(key).
func editKeyHash(key string) []byte {
	h := sha256.Sum256([]byte(key))
	return h[:]
}

// AnonEditKey mints the author key of a freshly quarantined anonymous row and stores sha256(key) in
// kb.anon_wh, returning the key once (kb.AnonEditKeyFn, called by the anonymous write path). It is a
// no-op returning "" for a row that is not anonymous (author_root <> ”) or already keyed.
func AnonEditKey(ctx context.Context, q core.Q, id string) (string, error) {
	if !core.ValidIDPrefix(id, 'k') {
		return "", core.ErrNotFound
	}
	key := newEditKey()
	tag, err := q.Exec(ctx, `UPDATE kb SET anon_wh = $2 WHERE id = $1 AND author_root = '' AND anon_wh IS NULL`, id, editKeyHash(key))
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", nil
	}
	return key, nil
}

// BurnEditKey invalidates an author key: kb.anon_wh = NULL for the row whose key hashes to it. It is
// idempotent (false when no row carried the key). Called from the editkey scrub-finding hook.
func BurnEditKey(ctx context.Context, q core.Q, key string) (bool, error) {
	if len(key) != editKeyLen {
		return false, nil
	}
	tag, err := q.Exec(ctx, `UPDATE kb SET anon_wh = NULL WHERE anon_wh = $1`, editKeyHash(key))
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() > 0, nil
}

// BurnLeakedEditKeys is the scrub-finding hook (27.2): every `edit=<26 base32>` the content leaks
// burns the matching author key. It returns the reply line `edit key burned` when at least one key
// was burned, "" otherwise, so the write path can surface it. Content is data, never instructions.
func BurnLeakedEditKeys(ctx context.Context, q core.Q, content string) (string, error) {
	seen := map[string]bool{}
	burned := false
	for _, m := range editKeyRe.FindAllStringSubmatch(content, -1) {
		key := m[1]
		if seen[key] {
			continue
		}
		seen[key] = true
		ok, err := BurnEditKey(ctx, q, key)
		if err != nil {
			return "", err
		}
		burned = burned || ok
	}
	if burned {
		return "edit key burned", nil
	}
	return "", nil
}

// anonKeyRow reads the author-key columns of a locked row.
type anonKeyRow struct {
	wh        []byte
	edits     int
	quar      bool
	confirmed *time.Time
	author    string
}

// loadAnonKey reads the author-key state of an entry in the caller's tx.
func loadAnonKey(ctx context.Context, q core.Q, id string) (anonKeyRow, error) {
	var a anonKeyRow
	err := q.QueryRow(ctx, `SELECT anon_wh, anon_edits, quarantine, confirmed_at, author_root FROM kb WHERE id = $1 AND expires_at > now()`, id).
		Scan(&a.wh, &a.edits, &a.quar, &a.confirmed, &a.author)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, core.ErrNotFound
	}
	return a, err
}

// keyMatches reports a constant-time match of key against the stored sha256; a NULL hash (never
// keyed, adopted, or burned) never matches. Absent or wrong keys fall through to the same 404.
func keyMatches(wh []byte, key string) bool {
	if len(wh) == 0 || key == "" {
		return false
	}
	return subtle.ConstantTimeCompare(wh, editKeyHash(key)) == 1
}

// AnonEdit applies an anonymous author's PATCH (27.2): the X-Edit key is matched constant-time, the
// row must still be quarantined and under the 5-edit cap, the patched fields re-run the write
// pipeline (scrub/lexicon/hazards/versions), rev bumps, anon_edits increments and pending
// confirmations are reset (prior ok votes dropped, sums recomputed) so two fresh L2 confirmations
// are needed again. A mismatch, an absent key, a promoted row or a missing row all answer 404.
func AnonEdit(ctx context.Context, d *core.Deps, kid, key string, in EditInput) (Edited, error) {
	res := Edited{ID: kid}
	if !core.ValidIDPrefix(kid, 'k') {
		return res, core.ErrNotFound
	}
	if in.Tags != nil && len(*in.Tags) > maxTags {
		return res, core.Bad("tags > 8")
	}
	if d.Frozen("write") {
		return res, core.Frozen("write")
	}
	err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		e, err := lockEntry(ctx, tx, kid)
		if err != nil {
			return err
		}
		a, err := loadAnonKey(ctx, tx, kid)
		if err != nil {
			return err
		}
		if !keyMatches(a.wh, key) || !a.quar {
			return core.ErrNotFound // wrong/absent key or no longer editable: the same 404 as a missing row
		}
		if a.edits >= anonEditCap {
			return core.E(429, "quota", "anon edits (5 max)")
		}
		next := Input{Kind: e.Kind, Title: e.Title, Symptom: e.Symptom, Cause: e.Cause, Fix: e.Fix, Versions: e.Versions,
			Tags: append([]string{}, e.Tags...), Applies: append(Applies(nil), e.Applies...), License: e.License, WhySafe: e.WhySafe, Att: e.Att, Space: e.Space}
		if in.Fix != nil {
			next.Fix = *in.Fix
		}
		if in.Cause != nil {
			next.Cause = *in.Cause
		}
		if in.Versions != nil {
			next.Versions = *in.Versions
		}
		if in.Tags != nil {
			next.Tags = append([]string{}, (*in.Tags)...)
		}
		oldFails := e.Applies.fails()
		if in.Applies != nil {
			next.Applies = append(Applies(nil), (*in.Applies)...)
		}
		pf, err := Prepare(ctx, tx, &next, 0) // anonymous author: level 0
		if err != nil {
			return err
		}
		if in.Applies != nil {
			next.Applies = withFails(next.Applies, oldFails) // bad votes' ranges survive the author's rewrite
		}
		var changed []string
		for _, f := range [...]struct{ name, old, cur string }{
			{"cause", e.Cause, next.Cause}, {"fix", e.Fix, next.Fix}, {"versions", e.Versions, next.Versions},
			{"tags", strings.Join(e.Tags, ","), strings.Join(next.Tags, ",")}, {"applies", e.Applies.String(), next.Applies.String()}} {
			if f.old != f.cur {
				changed = append(changed, fieldDiff(f.name, f.old, f.cur))
			}
		}
		if len(changed) == 0 {
			return core.Bad("patch changes nothing")
		}
		var rev int
		if err := tx.QueryRow(ctx, `UPDATE kb SET cause = $2, fix = $3, versions = $4, tags = $5, applies = $6::jsonb, hazard = $7, flags = $8,
			scrub_v = $9, rev = rev + 1, anon_edits = anon_edits + 1 WHERE id = $1 RETURNING rev`,
			kid, next.Cause, next.Fix, next.Versions, next.Tags, string(next.Applies.JSON()), pf.Hazard, pf.Flags, scrub.RulesV).Scan(&rev); err != nil {
			return err
		}
		res.Rev, res.Masked, res.Hazard = rev, pf.Masked, pf.Hazard
		res.Reopened, res.NewHazard = 0, len(newFamilies(e.Hazard, pf.Hazard)) > 0
		if _, err := tx.Exec(ctx, `DELETE FROM kb_votes WHERE kb_id = $1 AND up`, kid); err != nil {
			return err // reset pending confirmations
		}
		if _, err := tx.Exec(ctx, `DELETE FROM kb_versions WHERE kb_id = $1`, kid); err != nil {
			return err
		}
		for _, lv := range pf.Libs {
			if _, err := tx.Exec(ctx, `INSERT INTO kb_versions (kb_id, lib, ver) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`, kid, lv.Lib, lv.Ver); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO kb_revisions (kb_id, n, diff, by) VALUES ($1, $2, $3, 'anon')
			ON CONFLICT (kb_id, n) DO UPDATE SET diff = EXCLUDED.diff, by = EXCLUDED.by, at = now()`, kid, rev, strings.Join(changed, "\n")); err != nil {
			return err
		}
		return recount(ctx, tx, kid) // recompute sums from the surviving votes and refresh the mirror
	})
	if err != nil {
		return Edited{ID: kid}, err
	}
	return res, nil
}

// AnonDelete retracts an anonymous row with its author key (27.2): allowed while the row is
// quarantined or within 14 days of promotion; it leaves a `retract` tombstone. A mismatched or
// absent key, or a row outside that window, answers the same 404 as a missing row.
func AnonDelete(ctx context.Context, d *core.Deps, kid, key string) error {
	if !core.ValidIDPrefix(kid, 'k') {
		return core.ErrNotFound
	}
	if d.Frozen("write") {
		return core.Frozen("write")
	}
	return core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		a, err := loadAnonKey(ctx, tx, kid)
		if err != nil {
			return err
		}
		if !keyMatches(a.wh, key) {
			return core.ErrNotFound
		}
		recent := a.confirmed != nil && time.Since(*a.confirmed) <= retract14d
		if !a.quar && !recent {
			return core.ErrNotFound // promoted more than 14 days ago: no longer the author's to retract
		}
		return Remove(ctx, tx, kid, "retract", "")
	})
}

// Adopt lets a token claim its own anonymous row (27.2): the root must be >= 1 h old and present the
// author key; the row's author/author_root are set, anon_wh is cleared and the votes are kept with
// no retroactive reputation. The row must still be anonymous.
func Adopt(ctx context.Context, d *core.Deps, id *core.Ident, kid, key string) error {
	if id == nil {
		return core.ErrAuth
	}
	if !core.ValidIDPrefix(kid, 'k') {
		return core.ErrNotFound
	}
	st, err := trust.Load(ctx, d.DB, id.Root)
	if err != nil {
		if errors.Is(err, core.ErrNotFound) {
			return core.ErrBadToken
		}
		return err
	}
	if st.Banned {
		return core.ErrBanned
	}
	if st.Age < adoptMinAge {
		return core.E(403, "auth", "root must be at least 1 h old to adopt")
	}
	return core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		a, err := loadAnonKey(ctx, tx, kid)
		if err != nil {
			return err
		}
		if a.author != "" {
			return core.E(409, "dup", "entry already has an author")
		}
		if !keyMatches(a.wh, key) {
			return core.ErrNotFound
		}
		if _, err := tx.Exec(ctx, `UPDATE kb SET author = $2, author_root = $3, anon_wh = NULL, anon_grp = '', anon_super = '' WHERE id = $1`,
			kid, id.ID, id.Root); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "kadopt", kid, 0); err != nil {
			return err
		}
		return mirror(ctx, tx, kid)
	})
}

// --- HTTP + ops ---------------------------------------------------------------------------------

// AnonEditHelp is the op list of this file for help{t:kb} (<= 60 tokens).
const AnonEditHelp = `kadopt{id,edit} claim your own anonymous entry (root >= 1 h; keeps votes, no retroactive rep) | anonymous authors edit/retract with PATCH/DELETE /w/kb/{id} + header X-Edit: <26-char key>`

// AnonEditOpMeta describes the ops of AnonEditOps for the MCP registry (3.5).
var AnonEditOpMeta = map[string]core.OpMeta{
	"kadopt": {Scope: "kb:w", Cost: 1, Mutating: true},
}

var anonEditOpenAPI = json.RawMessage(`{"paths":{
"/w/kb/{id}":{"patch":{"operationId":"pwe","summary":"Edit a quarantined anonymous entry with its one-time author key (header X-Edit: <26 base32>); a wrong or absent key answers 404 like a missing row","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"fix":{"type":"string","maxLength":3000},"cause":{"type":"string","maxLength":1000},"versions":{"type":"string","maxLength":200},"tags":{"type":"array","maxItems":8,"items":{"type":"string","maxLength":32}},"applies":{"type":"string","maxLength":500}}}}}},"responses":{"200":{"description":"ok k… rev=N [masked=…] [hazard=…] then next:"},"404":{"description":"err notfound (wrong/absent key, promoted, or unknown)"},"429":{"description":"err quota anon edits (5 max)"}}},
"delete":{"operationId":"pwd","summary":"Retract an anonymous entry with its author key (X-Edit): allowed while quarantined or within 14 days of promotion","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok retracted"},"404":{"description":"err notfound"}}}},
"/v1/kb/{id}/adopt":{"post":{"operationId":"kadopt","summary":"Claim your own anonymous entry (token, root >= 1 h): sets the author, clears the key, keeps the votes","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["edit"],"properties":{"edit":{"type":"string","maxLength":26}}}}}},"responses":{"200":{"description":"ok adopted k…"},"403":{"description":"err auth root must be at least 1 h old"},"404":{"description":"err notfound"},"409":{"description":"err dup entry already has an author"}}}}
}}`)

// RegisterAnonEdit mounts the anonymous author-key routes next to RegisterAnon's and installs the
// key minter (kb.AnonEditKeyFn) so POST /w/kb replies gain edit=<key>.
func RegisterAnonEdit(mux *http.ServeMux, d *core.Deps) {
	h := &anonEditHandlers{d}
	mux.HandleFunc("PATCH /w/kb/{id}", h.edit)
	mux.HandleFunc("DELETE /w/kb/{id}", h.delete)
	mux.HandleFunc("POST /v1/kb/{id}/adopt", h.adopt)
	d.RegisterScope("POST /v1/kb/{id}/adopt", "kb:w")
	d.RegisterOpenAPI(anonEditOpenAPI)
	AnonEditKeyFn = AnonEditKey
}

type anonEditHandlers struct{ d *core.Deps }

// editKeyHeader reads and bounds the X-Edit header (anything else falls through to the 404).
func editKeyHeader(r *http.Request) string {
	return strings.TrimSpace(r.Header.Get("X-Edit"))
}

func (h *anonEditHandlers) edit(w http.ResponseWriter, r *http.Request) {
	var in EditInput
	if err := core.Decode(w, r, maxBody, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	res, err := AnonEdit(r.Context(), h.d, r.PathValue("id"), editKeyHeader(r), in)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if doc.Negotiate(r) == doc.JSON {
		core.JSON(w, 200, res.json())
		return
	}
	doc.TailStatus(w, r, 200, res.Line(), res.Next()...)
}

func (h *anonEditHandlers) delete(w http.ResponseWriter, r *http.Request) {
	if err := AnonDelete(r.Context(), h.d, r.PathValue("id"), editKeyHeader(r)); err != nil {
		doc.Fail(w, r, err)
		return
	}
	if doc.Negotiate(r) == doc.JSON {
		core.JSON(w, 200, map[string]any{"ok": true, "retracted": true, "next": actionStrings(retractNext(""))})
		return
	}
	doc.TailStatus(w, r, 200, retractLine(""), retractNext("")...)
}

func (h *anonEditHandlers) adopt(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthWrite(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in struct {
		Edit string `json:"edit"`
	}
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	kid := r.PathValue("id")
	if err := Adopt(r.Context(), h.d, id, kid, in.Edit); err != nil {
		doc.Fail(w, r, err)
		return
	}
	next := doc.Next(doc.GET("/v1/kb/"+kid, ""), doc.POST("/v1/kb/"+kid+"/ok", ""), doc.GET("/k/"+kid+".md", ""))
	if doc.Negotiate(r) == doc.JSON {
		core.JSON(w, 200, map[string]any{"ok": true, "id": kid, "adopted": true, "next": actionStrings(next)})
		return
	}
	ack(w, r, 200, "ok adopted "+kid, next...)
}

// AnonEditOps returns the MCP operations of this file: kadopt (claim your own anonymous entry).
func AnonEditOps(d *core.Deps) map[string]Op {
	return map[string]Op{
		"kadopt": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeOK(d, id); err != nil {
				return "", err
			}
			var in struct {
				ID   string `json:"id"`
				Edit string `json:"edit"`
			}
			if len(a) > 0 {
				if err := json.Unmarshal(a, &in); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			if err := Adopt(ctx, d, id, in.ID, in.Edit); err != nil {
				return "", err
			}
			return "ok adopted " + in.ID, nil
		},
	}
}
