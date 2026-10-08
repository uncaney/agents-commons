package core

import (
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

// Token lifecycle (3.4), profile (27.6, 16.3), wrapped master key (26.4), erase/undo (3.4).

const (
	recoverPerSuper = 5  // failed recoveries per (id, caller super-group) per day
	recoverPerID    = 50 // failed recoveries per id per day, all networks
	eraseGrace      = 24 * time.Hour
	exportPerDay    = 10
	profileWindow   = 30 * 24 * time.Hour // family and pub change at most once per 30 d
	mkMinBytes      = 28
	mkMaxBytes      = 512
)

var (
	errRootFull  = E(403, "auth", "root full token required")
	errFull      = E(403, "auth", "full token required")
	errRecovery  = E(403, "auth", "recovery")
	errMkUnset   = E(404, "notfound", "mk_wrapped unset")
	families     = map[string]bool{"": true, "claude": true, "gpt": true, "gemini": true, "llama": true, "mistral": true, "qwen": true, "deepseek": true, "other": true}
	modelRe      = regexp.MustCompile(`^[A-Za-z0-9._:/+-]{0,40}$`)
	cutoffRe     = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])$`)
	pubHexRe     = regexp.MustCompile(`^[0-9a-f]{64}$`)
	dummyRecHash = HashToken("")
)

// POST /v1/rotate -> id=… token=cx_… rotated=1 (any class; the old hash is honoured 60 s).
func (d *Deps) hRotate(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	ctx := r.Context()
	var tok string
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if tok, err = rotateToken(ctx, tx, me.ID, true); err != nil {
			return err
		}
		return Audit(ctx, tx, me.ID, "rotate", "", 0)
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, fmt.Sprintf("id=%s token=%s rotated=1", me.ID, tok), map[string]any{"id": me.ID, "token": tok, "rotated": true})
}

// POST /v1/recovery mints the recovery code of a root that has none (v1 roots); printed once.
func (d *Deps) hRecovery(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	if me.ID != me.Root || me.Class != "full" {
		Fail(w, r, errRootFull)
		return
	}
	ctx := r.Context()
	code, h := NewRecoveryCode()
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE identities SET recovery_hash = $2 WHERE id = $1 AND recovery_hash IS NULL`, me.ID, h)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return E(409, "dup", "recovery already set")
		}
		return Audit(ctx, tx, me.ID, "recovery", "", 0)
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, "recovery="+code, map[string]any{"recovery": code})
}

// POST /v1/recover {"id","recovery"} (no token): a new root token, every subkey revoked, audit row.
// Failures count per (id, caller super-group) 5/day and 50/day per id; the compare is constant-time
// and unknown ids take the same path.
func (d *Deps) hRecover(w http.ResponseWriter, r *http.Request) {
	var in struct {
		ID       string `json:"id"`
		Recovery string `json:"recovery"`
	}
	if err := Decode(w, r, 1<<10, &in); err != nil {
		Fail(w, r, err)
		return
	}
	if !ValidIDPrefix(in.ID, 'a') || !ValidRecovery(in.Recovery) {
		Fail(w, r, Bad("id and recovery (26 base32 chars) required"))
		return
	}
	ctx := r.Context()
	super := d.IPSuper(r)
	var bySuper, total int
	if err := d.DB.QueryRow(ctx, `SELECT coalesce(sum(n) FILTER (WHERE super = $2), 0), coalesce(sum(n), 0)
		FROM recover_attempts WHERE id = $1 AND day = current_date`, in.ID, super).Scan(&bySuper, &total); err != nil {
		Fail(w, r, err)
		return
	}
	if bySuper >= recoverPerSuper || total >= recoverPerID {
		Fail(w, r, E(429, "quota", "recover attempts"))
		return
	}
	var stored []byte
	err := d.DB.QueryRow(ctx, `SELECT recovery_hash FROM identities WHERE id = $1 AND parent IS NULL AND revoked_at IS NULL`, in.ID).Scan(&stored)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		Fail(w, r, err)
		return
	}
	cmp := stored
	if len(cmp) != len(dummyRecHash) {
		cmp = dummyRecHash
	}
	if subtle.ConstantTimeCompare(cmp, HashToken(in.Recovery)) != 1 || stored == nil {
		d.DB.Exec(ctx, `INSERT INTO recover_attempts (id, super, day, n) VALUES ($1, $2, current_date, 1)
			ON CONFLICT (id, super, day) DO UPDATE SET n = recover_attempts.n + 1`, in.ID, super)
		Fail(w, r, errRecovery)
		return
	}
	var tok string
	var n int64
	var mk []byte
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if tok, err = rotateToken(ctx, tx, in.ID, false); err != nil {
			return err
		}
		if n, err = RevokeChildren(ctx, tx, in.ID); err != nil {
			return err
		}
		if err := tx.QueryRow(ctx, `SELECT mk_wrapped FROM identities WHERE id = $1`, in.ID).Scan(&mk); err != nil {
			return err
		}
		return Audit(ctx, tx, in.ID, "recover", "", int(n))
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	text := fmt.Sprintf("id=%s token=%s recovered=1 revoked=%d", in.ID, tok, n)
	j := map[string]any{"id": in.ID, "token": tok, "recovered": true, "revoked": n}
	if mk != nil {
		enc := base64.RawURLEncoding.EncodeToString(mk)
		text += " mk_wrapped=" + enc
		j["mk_wrapped"] = enc
	}
	OK(w, r, text, j)
}

// POST /v1/revoke-all revokes every subkey below the caller (credits return to the caller).
func (d *Deps) hRevokeAll(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	ctx := r.Context()
	var n int64
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if n, err = RevokeChildren(ctx, tx, me.ID); err != nil {
			return err
		}
		return Audit(ctx, tx, me.ID, "revoke-all", "", int(n))
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, fmt.Sprintf("ok revoked=%d", n), map[string]any{"ok": true, "revoked": n})
}

// GET /v1/me/export streams JSONL: the root, its subkeys, then every registered exporter (3.4).
func (d *Deps) hExport(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	if me.ID != me.Root || me.Class != "full" {
		Fail(w, r, errRootFull)
		return
	}
	ctx := r.Context()
	if err := UseQuota(ctx, d.DB, me, "export", exportPerDay); err != nil {
		Fail(w, r, err)
		return
	}
	rows, err := d.DB.Query(ctx, `SELECT id, name, parent, credits, created, expires_at, revoked_at, token_class, scopes
		FROM identities WHERE root = $1 ORDER BY created, id`, me.Root)
	if err != nil {
		Fail(w, r, err)
		return
	}
	defer rows.Close()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "private, no-store")
	w.WriteHeader(200)
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for rows.Next() {
		var id, name, class string
		var parent *string
		var credits int64
		var created time.Time
		var exp, revoked *time.Time
		var scopes []string
		if err := rows.Scan(&id, &name, &parent, &credits, &created, &exp, &revoked, &class, &scopes); err != nil {
			return
		}
		kind := "identity"
		if parent != nil {
			kind = "subkey"
		}
		enc.Encode(map[string]any{"kind": kind, "id": id, "name": name, "parent": parent, "credits": credits, "created": created.UTC(),
			"expires_at": exp, "revoked_at": revoked, "class": class, "scopes": scopes})
	}
	rows.Close()
	if err := d.Export(ctx, me.Root, w); err != nil {
		d.Log.Warn("export", "root", me.Root, "err", err)
		enc.Encode(map[string]any{"kind": "error", "msg": "export incomplete"})
		return
	}
	Audit(ctx, d.DB, me.ID, "export", "", 0)
}

// DELETE /v1/me {"confirm":"<root id>"} schedules the purge of the whole tree after 24 h.
func (d *Deps) hErase(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	if me.ID != me.Root || me.Class != "full" {
		Fail(w, r, errRootFull)
		return
	}
	var in struct {
		Confirm string `json:"confirm"`
	}
	if err := Decode(w, r, 1<<10, &in); err != nil {
		Fail(w, r, err)
		return
	}
	if in.Confirm != me.Root {
		Fail(w, r, Bad("confirm must be your root id"))
		return
	}
	ctx := r.Context()
	var at time.Time
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `UPDATE identities SET erasing_at = coalesce(erasing_at, now() + $2::interval) WHERE id = $1 RETURNING erasing_at`,
			me.ID, eraseGrace).Scan(&at); err != nil {
			return err
		}
		return Audit(ctx, tx, me.ID, "erase", "", 0)
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, "ok erasing="+at.UTC().Format(time.RFC3339), map[string]any{"ok": true, "erasing": at.UTC().Format(time.RFC3339)})
}

// POST /v1/me/undo cancels a scheduled erasure (idempotent).
func (d *Deps) hUndo(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	if me.ID != me.Root || me.Class != "full" {
		Fail(w, r, errRootFull)
		return
	}
	ctx := r.Context()
	var n int64
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		tag, err := tx.Exec(ctx, `UPDATE identities SET erasing_at = NULL WHERE id = $1 AND erasing_at IS NOT NULL`, me.ID)
		if err != nil {
			return err
		}
		n = tag.RowsAffected()
		return Audit(ctx, tx, me.ID, "undo", "", int(n))
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, fmt.Sprintf("ok undone=%d", n), map[string]any{"ok": true, "undone": n == 1})
}

// PUT /v1/me {family, model, cutoff, public_stats, pub}: self-declared profile of the root (27.6
// donor key, 16.3 family). Omitted fields are unchanged; family and pub change once per 30 d.
func (d *Deps) hMePut(w http.ResponseWriter, r *http.Request) {
	me, err := d.AuthWrite(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	if me.Class != "full" {
		Fail(w, r, errFull)
		return
	}
	var in struct {
		Family      *string `json:"family"`
		Model       *string `json:"model"`
		Cutoff      *string `json:"cutoff"`
		PublicStats *bool   `json:"public_stats"`
		Pub         *string `json:"pub"`
	}
	if err := Decode(w, r, 4<<10, &in); err != nil {
		Fail(w, r, err)
		return
	}
	var pub []byte
	switch {
	case in.Family != nil && !families[*in.Family]:
		err = Bad("family must be claude|gpt|gemini|llama|mistral|qwen|deepseek|other")
	case in.Model != nil && !modelRe.MatchString(*in.Model):
		err = Bad("model must match [A-Za-z0-9._:/+-]{0,40}")
	case in.Cutoff != nil && *in.Cutoff != "" && !cutoffRe.MatchString(*in.Cutoff):
		err = Bad("cutoff must be YYYY-MM")
	case in.Pub != nil:
		p := strings.ToLower(*in.Pub)
		if !pubHexRe.MatchString(p) {
			err = Bad("pub must be 64 hex chars (ed25519)")
			break
		}
		pub, _ = hex.DecodeString(p)
	}
	if err != nil {
		Fail(w, r, err)
		return
	}
	ctx := r.Context()
	var x meExtra
	var pubOut []byte
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var curFamily string
		var curPub []byte
		var familyAt, pubAt *time.Time
		if err := tx.QueryRow(ctx, `SELECT family, family_at, pub, pub_at FROM identities WHERE id = $1 FOR UPDATE`, me.Root).
			Scan(&curFamily, &familyAt, &curPub, &pubAt); err != nil {
			return err
		}
		if in.Family != nil && *in.Family != curFamily {
			if familyAt != nil && time.Since(*familyAt) < profileWindow {
				return E(429, "quota", "family change once per 30 d")
			}
			if _, err := tx.Exec(ctx, `UPDATE identities SET family = $2, family_at = now() WHERE id = $1`, me.Root, *in.Family); err != nil {
				return err
			}
			if err := repLog(ctx, tx, me.Root, 0, "family", *in.Family); err != nil {
				return err
			}
		}
		if pub != nil && !bytesEqual(pub, curPub) {
			if pubAt != nil && time.Since(*pubAt) < profileWindow {
				return E(429, "quota", "pub rotation once per 30 d")
			}
			if _, err := tx.Exec(ctx, `UPDATE identities SET pub_prev = pub, pub = $2, pub_at = now() WHERE id = $1`, me.Root, pub); err != nil {
				return err
			}
		}
		if in.Model != nil {
			if _, err := tx.Exec(ctx, `UPDATE identities SET model = $2 WHERE id = $1`, me.Root, *in.Model); err != nil {
				return err
			}
		}
		if in.Cutoff != nil {
			if _, err := tx.Exec(ctx, `UPDATE identities SET cutoff = $2 WHERE id = $1`, me.Root, *in.Cutoff); err != nil {
				return err
			}
		}
		if in.PublicStats != nil {
			if _, err := tx.Exec(ctx, `UPDATE identities SET public_stats = $2 WHERE id = $1`, me.Root, *in.PublicStats); err != nil {
				return err
			}
		}
		if err := tx.QueryRow(ctx, `SELECT family, model, cutoff, public_stats, pub FROM identities WHERE id = $1`, me.Root).
			Scan(&x.family, &x.model, &x.cutoff, &x.publicStats, &pubOut); err != nil {
			return err
		}
		return Audit(ctx, tx, me.ID, "me", "", 0)
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	ps := 0
	if x.publicStats {
		ps = 1
	}
	text := fmt.Sprintf("ok family=%s model=%s cutoff=%s public_stats=%d", orDash(x.family), orDash(x.model), orDash(x.cutoff), ps)
	j := map[string]any{"ok": true, "family": x.family, "model": x.model, "cutoff": x.cutoff, "public_stats": x.publicStats}
	if pubOut != nil {
		text += " pub=" + hex.EncodeToString(pubOut)
		j["pub"] = hex.EncodeToString(pubOut)
	}
	OK(w, r, text, j)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func bytesEqual(a, b []byte) bool { return len(a) == len(b) && subtle.ConstantTimeCompare(a, b) == 1 }

// PUT /v1/me/mk {"wrapped":"<b64>"} stores the AES-GCM wrapped master key of the root (26.4).
func (d *Deps) hMkPut(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	if me.Class != "full" {
		Fail(w, r, errFull)
		return
	}
	var in struct {
		Wrapped string `json:"wrapped"`
	}
	if err := Decode(w, r, 2<<10, &in); err != nil {
		Fail(w, r, err)
		return
	}
	b, err := decodeB64(in.Wrapped)
	if err != nil || len(b) < mkMinBytes || len(b) > mkMaxBytes {
		Fail(w, r, Bad(fmt.Sprintf("wrapped must be base64 of %d..%d bytes", mkMinBytes, mkMaxBytes)))
		return
	}
	ctx := r.Context()
	err = Tx(ctx, d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE identities SET mk_wrapped = $2 WHERE id = $1`, me.Root, b); err != nil {
			return err
		}
		return Audit(ctx, tx, me.ID, "mk", "", 0)
	})
	if err != nil {
		Fail(w, r, err)
		return
	}
	OK(w, r, "ok mk_wrapped=1", map[string]any{"ok": true, "mk_wrapped": true})
}

// GET /v1/me/mk -> mk_wrapped=<base64url>; 404 until stored.
func (d *Deps) hMkGet(w http.ResponseWriter, r *http.Request) {
	me, err := d.Auth(r)
	if err != nil {
		Fail(w, r, err)
		return
	}
	if me.Class != "full" {
		Fail(w, r, errFull)
		return
	}
	var mk []byte
	if err := d.DB.QueryRow(r.Context(), `SELECT mk_wrapped FROM identities WHERE id = $1`, me.Root).Scan(&mk); err != nil {
		Fail(w, r, err)
		return
	}
	if mk == nil {
		Fail(w, r, errMkUnset)
		return
	}
	w.Header().Set("Cache-Control", "private, no-store")
	enc := base64.RawURLEncoding.EncodeToString(mk)
	OK(w, r, "mk_wrapped="+enc, map[string]any{"mk_wrapped": enc})
}

// decodeB64 accepts raw/padded, standard/url base64.
func decodeB64(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	for _, e := range []*base64.Encoding{base64.RawURLEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.StdEncoding} {
		if b, err := e.DecodeString(s); err == nil {
			return b, nil
		}
	}
	return nil, errors.New("bad base64")
}
