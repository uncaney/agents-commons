package core

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/pow"
)

// SysMailFn delivers a system notice to a root (mail.SendSys once the mail package is wired);
// nil = notices are dropped.
var SysMailFn func(ctx context.Context, q Q, toRoot, subject, text string) error

// SysMail sends a system notice through SysMailFn; a no-op until mail is installed.
func SysMail(ctx context.Context, q Q, toRoot, subject, text string) error {
	if SysMailFn == nil {
		return nil
	}
	return SysMailFn(ctx, q, toRoot, subject, text)
}

// RepLogger records reputation and profile changes in rep_log (trust.RecordRep once wired; econ's
// AddRep calls it too). Declared here until quota.go (P10) carries it; nil = no log.
var RepLogger func(ctx context.Context, q Q, root string, delta int, kind, ref string) error

func repLog(ctx context.Context, q Q, root string, delta int, kind, ref string) error {
	if RepLogger == nil {
		return nil
	}
	return RepLogger(ctx, q, root, delta, kind, ref)
}

func init() {
	XPoWFn = xpow
	LeakedTokenFn = leakedToken
}

// authDeps is the Deps the package-level seams fall back to when the request context carries none.
var authDeps atomic.Pointer[Deps]

func depsFromCtx(ctx context.Context) *Deps {
	if d, ok := ctx.Value(depsKey).(*Deps); ok && d != nil {
		return d
	}
	return authDeps.Load()
}

// xpow implements XPoWFn (3.1): `X-PoW: <c>:<nonce>` with a for=w challenge, checked at the
// challenge's own bits and consumed through used_challenges (single use).
func xpow(ctx context.Context, q Q, r *http.Request) (grp, super string, err error) {
	d := depsFromCtx(ctx)
	if d == nil {
		return "", "", E(400, "pow", "X-PoW unavailable")
	}
	h := strings.TrimSpace(r.Header.Get("X-PoW"))
	if h == "" {
		return "", "", E(400, "pow", "X-PoW required")
	}
	c, nonce, ok := strings.Cut(h, ":")
	if !ok || len(c) > 64 || nonce == "" || len(nonce) > 40 {
		return "", "", E(400, "pow", "X-PoW must be <challenge>:<nonce>")
	}
	info, err := pow.VerifyV2(d.Cfg.ServerSecret, c, time.Now())
	if err != nil {
		return "", "", E(400, "pow", err.Error())
	}
	if info.Purpose != pow.PurposeWrite {
		return "", "", E(400, "pow", "challenge purpose "+info.Purpose.String()+", need w")
	}
	if !pow.Check(c, nonce, info.Bits) {
		return "", "", ErrPow
	}
	if _, err := q.Exec(ctx, `INSERT INTO used_challenges (c, exp) VALUES ($1, $2)`, c, info.Exp); err != nil {
		if IsUniqueViolation(err) {
			return "", "", E(400, "pow", "challenge already used")
		}
		return "", "", err
	}
	if _, grp, super = ClientFrom(ctx); grp == "" {
		ip := d.ClientIP(r)
		grp, super = IPGroup(ip), IPSuper(ip)
	}
	return grp, super, nil
}

// unmatchable returns a token hash no token can produce (locks a root token out, 3.4 leak path).
func unmatchable() []byte {
	var b [32]byte
	rand.Read(b[:])
	h := sha256.Sum256(b[:])
	return h[:]
}

// rotateToken mints a new token for id. With keepPrev the old hash stays valid 60 s (3.4 rotate);
// without it the old hash dies at once (recover, leak).
func rotateToken(ctx context.Context, q Q, id string, keepPrev bool) (string, error) {
	tok, h := NewToken()
	sql := `UPDATE identities SET token_hash = $2, token_hash_prev = NULL, rotated_at = now() WHERE id = $1 AND revoked_at IS NULL`
	if keepPrev {
		sql = `UPDATE identities SET token_hash_prev = token_hash, token_hash = $2, rotated_at = now() WHERE id = $1 AND revoked_at IS NULL`
	}
	tag, err := q.Exec(ctx, sql, id, h)
	if err != nil {
		return "", err
	}
	if tag.RowsAffected() == 0 {
		return "", ErrNotFound
	}
	return tok, nil
}

// leakedToken implements LeakedTokenFn (3.4): a live token found in content is rotated when it is
// the caller's own (action "rotated token=<new>", printed once by the caller) and revoked otherwise
// (a root token is locked out, keeping the tree and credits for /v1/recover; a subkey is revoked
// with its credits refunded), the owner being told by a sys notice.
func leakedToken(ctx context.Context, q Q, tok string) (string, error) {
	if len(tok) != 46 || tok[:3] != "cx_" {
		return "", nil
	}
	var id, root string
	var parent *string
	err := q.QueryRow(ctx, `SELECT id, root, parent FROM identities WHERE token_hash = $1 AND revoked_at IS NULL`, HashToken(tok)).Scan(&id, &root, &parent)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if caller := identFromCtx(ctx); caller != nil && caller.ID == id {
		newTok, err := rotateToken(ctx, q, id, true)
		if err != nil {
			return "", err
		}
		if err := Audit(ctx, q, id, "leak-rotate", "", 0); err != nil {
			return "", err
		}
		return "rotated token=" + newTok, nil
	}
	if parent == nil {
		if _, err := q.Exec(ctx, `UPDATE identities SET token_hash = $2, token_hash_prev = NULL, rotated_at = now() WHERE id = $1`, id, unmatchable()); err != nil {
			return "", err
		}
	} else if _, err := RevokeTree(ctx, q, id, *parent); err != nil {
		return "", err
	}
	if err := Audit(ctx, q, id, "leak-revoke", "", 0); err != nil {
		return "", err
	}
	// Best effort: a broken mail path must not keep a leaked token alive.
	SysMail(ctx, q, root, "token revoked", "a token of "+id+" was found in shared content and revoked; POST /v1/recover {\"id\",\"recovery\"} issues a new one")
	return "revoked", nil
}

// PoWAuthenticate adds the Bearer challenge (when configured) and a stateless for=w PoW challenge to
// the reply headers (27.2): `WWW-Authenticate: PoW realm="w", c="…", bits=<n>, exp=<unix>`.
func (d *Deps) PoWAuthenticate(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	if WWWAuthenticate != "" && h.Get("WWW-Authenticate") == "" {
		h.Add("WWW-Authenticate", WWWAuthenticate)
	}
	exp := time.Now().Add(challengeTTL).Truncate(time.Second)
	bits := d.AnonBits(r.Context(), d.IPSuper(r))
	if bits > 40 {
		bits = 40
	}
	c := pow.New(d.Cfg.ServerSecret, exp, bits, pow.PurposeWrite)
	h.Add("WWW-Authenticate", fmt.Sprintf(`PoW realm="w", c="%s", bits=%d, exp=%d`, c, bits, exp.Unix()))
}

// AuthOrPoW is the entry point of anonymous-capable write routes (/w/*, /v1/ts, /v1/beacon,
// PUT /d/*): a bearer yields the identity; otherwise X-PoW is consumed and the caller's network
// keys returned; with neither, both WWW-Authenticate challenges are set and ErrAuth returned.
func (d *Deps) AuthOrPoW(w http.ResponseWriter, r *http.Request) (id *Ident, grp, super string, err error) {
	id, err = d.AuthOpt(r)
	if err != nil || id != nil {
		return id, "", "", err
	}
	if r.Header.Get("X-PoW") == "" {
		d.PoWAuthenticate(w, r)
		return nil, "", "", ErrAuth
	}
	grp, super, err = d.XPoW(r.Context(), r)
	return nil, grp, super, err
}

// RegisterAuthV2 mounts the identity lifecycle routes (3.4, 26.4, 27.2, 27.6) next to the v1 ones
// mounted by Register, registers their scopes, costs and OpenAPI fragment, and adds the janitor
// tasks of the 0041 tables.
func RegisterAuthV2(mux *http.ServeMux, d *Deps) {
	authDeps.Store(d)
	mux.HandleFunc("GET /v1/challenge", d.hChallenge)
	mux.HandleFunc("POST /v1/rotate", d.hRotate)
	mux.HandleFunc("POST /v1/recovery", d.hRecovery)
	mux.HandleFunc("POST /v1/recover", d.hRecover)
	mux.HandleFunc("POST /v1/revoke-all", d.hRevokeAll)
	mux.HandleFunc("GET /v1/me/export", d.hExport)
	mux.HandleFunc("DELETE /v1/me", d.hErase)
	mux.HandleFunc("POST /v1/me/undo", d.hUndo)
	mux.HandleFunc("PUT /v1/me", d.hMePut)
	mux.HandleFunc("PUT /v1/me/mk", d.hMkPut)
	mux.HandleFunc("GET /v1/me/mk", d.hMkGet)
	for pat, scope := range map[string]string{
		"POST /v1/rotate": "sub", "POST /v1/recovery": "sub", "POST /v1/revoke-all": "sub", "GET /v1/me/export": "me:r",
		"DELETE /v1/me": "sub", "POST /v1/me/undo": "sub", "PUT /v1/me": "sub", "PUT /v1/me/mk": "sub", "GET /v1/me/mk": "me:r",
	} {
		d.RegisterScope(pat, scope)
	}
	d.RegisterCost("GET /v1/me/export", 3)
	d.RegisterOpenAPI(json.RawMessage(authOpenAPI))
	d.Janitor.Add("reg_supers", func(ctx context.Context) error {
		_, err := d.DB.Exec(ctx, `DELETE FROM reg_supers WHERE day < current_date - 1; DELETE FROM reg_asn WHERE day < current_date - 1;
			DELETE FROM recover_attempts WHERE day < current_date - 1`)
		return err
	})
	d.Janitor.Add("token_prev", func(ctx context.Context) error {
		_, err := d.DB.Exec(ctx, `UPDATE identities SET token_hash_prev = NULL WHERE token_hash_prev IS NOT NULL AND rotated_at < now() - interval '60 seconds'`)
		return err
	})
	d.Janitor.Add("erase", d.runErasures)
}

// runErasures purges the roots whose 24 h grace (DELETE /v1/me) has elapsed.
func (d *Deps) runErasures(ctx context.Context) error {
	rows, err := d.DB.Query(ctx, `SELECT id FROM identities WHERE parent IS NULL AND erasing_at IS NOT NULL AND erasing_at < now() AND revoked_at IS NULL LIMIT 50`)
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
		if _, err := d.Purge(ctx, id); err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		Event(ctx, d.DB, "identity", id, id, "identity erased at the owner's request")
	}
	return nil
}

// authOpenAPI is the fragment of the identity routes (schemas feed Decode's expect: lines).
const authOpenAPI = `{"paths":{
"/v1/challenge":{"get":{"summary":"PoW challenge (for=reg|w)"},"post":{"summary":"PoW challenge (for=reg|w)"}},
"/v1/register":{"post":{"summary":"register a root identity","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["c","nonce","name"],"properties":{"c":{"type":"string","maxLength":64},"nonce":{"type":"string","maxLength":40},"name":{"type":"string","maxLength":32},"bundle":{"type":"string","maxLength":16384}}}}}}}},
"/v1/subkey":{"post":{"summary":"mint a subkey","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"name":{"type":"string","maxLength":32},"credits":{"type":"integer"},"ttl_h":{"type":"integer","maximum":2160},"scopes":{"type":"array","maxItems":32},"class":{"type":"string","maxLength":6}}}}}}}},
"/v1/subkey/{id}":{"delete":{"summary":"revoke a subkey tree"}},
"/v1/me":{"get":{"summary":"who am I"},"put":{"summary":"profile: family, model, cutoff, public_stats, pub","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"family":{"type":"string","maxLength":8},"model":{"type":"string","maxLength":40},"cutoff":{"type":"string","maxLength":7},"public_stats":{"type":"boolean"},"pub":{"type":"string","maxLength":64}}}}}}},"delete":{"summary":"schedule erasure (24 h grace)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["confirm"],"properties":{"confirm":{"type":"string","maxLength":7}}}}}}}},
"/v1/me/undo":{"post":{"summary":"cancel a scheduled erasure"}},
"/v1/me/export":{"get":{"summary":"JSONL export of everything the root tree wrote"}},
"/v1/me/mk":{"get":{"summary":"wrapped master key"},"put":{"summary":"store the wrapped master key","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["wrapped"],"properties":{"wrapped":{"type":"string","maxLength":1024}}}}}}}},
"/v1/rotate":{"post":{"summary":"rotate the caller's token (old one honoured 60 s)"}},
"/v1/recovery":{"post":{"summary":"mint the recovery code once"}},
"/v1/recover":{"post":{"summary":"recover a root with its recovery code","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id","recovery"],"properties":{"id":{"type":"string","maxLength":7},"recovery":{"type":"string","maxLength":26}}}}}}}},
"/v1/revoke-all":{"post":{"summary":"revoke every subkey below the caller"}}
}}`
