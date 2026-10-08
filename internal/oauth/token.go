package oauth

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// token implements POST /oauth/token (RFC 6749 4.1.3 / 6, OAuth 2.1): form or JSON body, public
// clients (client_id only), grants authorization_code (PKCE S256 mandatory) and refresh_token.
// Replies are JSON with Cache-Control no-store whatever the Accept header says.
func (s *svc) token(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	noStore(w)
	if err := core.UseNetQuota(ctx, s.d.DB, s.d.ClientIP(r), "oauth:token", TokenDaily); err != nil {
		writeOAuthErr(w, r, err)
		return
	}
	for _, what := range []string{"write", "oauth"} {
		if s.d.Frozen(what) {
			writeOAuthErr(w, r, core.Frozen(what))
			return
		}
	}
	v, err := bodyValues(w, r)
	if err != nil {
		writeOAuthErr(w, r, err)
		return
	}
	var out map[string]any
	switch v.Get("grant_type") {
	case "authorization_code":
		out, err = s.grantCode(ctx, v)
	case "refresh_token":
		out, err = s.grantRefresh(ctx, v)
	case "":
		err = oerr("invalid_request", "grant_type required")
	default:
		err = oerr("unsupported_grant_type", "authorization_code or refresh_token")
	}
	if err != nil {
		writeOAuthErr(w, r, err)
		return
	}
	core.JSON(w, 200, out)
}

// bodyValues reads a form-encoded (RFC) or JSON (convenience) body into url.Values.
func bodyValues(w http.ResponseWriter, r *http.Request) (url.Values, error) {
	body, err := core.ReadAll(w, r, maxBody)
	if err != nil {
		return nil, err
	}
	ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
	trim := bytes.TrimSpace(body)
	if ct == "application/json" || (ct == "" && len(trim) > 0 && trim[0] == '{') {
		var m map[string]any
		if err := json.Unmarshal(trim, &m); err != nil {
			return nil, oerr("invalid_request", "body must be form-encoded or a JSON object")
		}
		v := url.Values{}
		for k, x := range m {
			if str, ok := x.(string); ok {
				v.Set(k, str)
			}
		}
		return v, nil
	}
	v, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, oerr("invalid_request", "bad form body")
	}
	return v, nil
}

type codeRow struct {
	client, redirect, pkce, ident, root string
	scopes                              []string
	ttl                                 int
	credits                             int64
}

// grantCode exchanges a code. The code is consumed by its first presentation, right or wrong
// (a wrong verifier voids it, OAuth 2.1 7.6); the subkey is minted only after every check passes.
func (s *svc) grantCode(ctx context.Context, v url.Values) (map[string]any, error) {
	code, verifier, client, redirect := v.Get("code"), v.Get("code_verifier"), v.Get("client_id"), v.Get("redirect_uri")
	switch {
	case code == "" || len(code) > 128:
		return nil, oerr("invalid_request", "code required")
	case !validPKCEString(verifier):
		return nil, oerr("invalid_request", "code_verifier required: 43..128 chars of [A-Za-z0-9._~-]")
	case client == "" || len(client) > maxClientID:
		return nil, oerr("invalid_client", "client_id required")
	case len(redirect) > maxRedirectLen:
		return nil, oerr("invalid_request", "redirect_uri too long")
	}
	var c codeRow
	err := s.d.DB.QueryRow(ctx, `UPDATE oauth_codes SET used_at = now() WHERE code_hash = $1 AND used_at IS NULL AND exp > now()
		RETURNING client_id, redirect, pkce, ident, root, scopes, ttl_s, credits`, hash(code)).
		Scan(&c.client, &c.redirect, &c.pkce, &c.ident, &c.root, &c.scopes, &c.ttl, &c.credits)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, s.codeReplay(ctx, code)
	}
	if err != nil {
		return nil, err
	}
	switch {
	case subtle.ConstantTimeCompare([]byte(c.client), []byte(client)) != 1:
		return nil, oerr("invalid_client", "client_id does not match the code; the code is now void")
	case redirect != "" && redirect != c.redirect:
		return nil, oerr("invalid_grant", "redirect_uri does not match the authorization request; the code is now void")
	case !pkceOK(c.pkce, verifier):
		return nil, oerr("invalid_grant", "PKCE verification failed; the code is now void")
	}
	return s.mint(ctx, &c, code)
}

// codeReplay answers a code that did not consume: unknown or expired -> invalid_grant; already
// used -> the subkey it minted is revoked too (a replayed code means it leaked, OAuth 2.1 4.1.2).
func (s *svc) codeReplay(ctx context.Context, code string) error {
	var sub *string
	var ident string
	err := s.d.DB.QueryRow(ctx, `SELECT sub, ident FROM oauth_codes WHERE code_hash = $1 AND used_at IS NOT NULL`, hash(code)).Scan(&sub, &ident)
	if errors.Is(err, pgx.ErrNoRows) {
		return oerr("invalid_grant", "unknown or expired code")
	}
	if err != nil {
		return err
	}
	if sub == nil {
		return oerr("invalid_grant", "code already used")
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := core.RevokeTree(ctx, tx, *sub, ident); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM oauth_refresh WHERE ident = $1`, *sub); err != nil {
			return err
		}
		return core.Audit(ctx, tx, ident, "oauth-replay", *sub, 0)
	})
	if err != nil {
		return err
	}
	return oerr("invalid_grant", "code already used; the token it minted has been revoked")
}

func pkceOK(challenge, verifier string) bool {
	sum := sha256.Sum256([]byte(verifier))
	return subtle.ConstantTimeCompare([]byte(enc.EncodeToString(sum[:])), []byte(challenge)) == 1
}

// mint creates the oauth subkey under the consenting identity with the granted scopes, lifetime
// and credits, plus the first refresh token; the code row remembers the subkey for replay handling.
func (s *svc) mint(ctx context.Context, c *codeRow, code string) (map[string]any, error) {
	parent, err := loadIdent(ctx, s.d.DB, c.ident)
	if err != nil {
		return nil, err
	}
	exp := time.Now().Add(time.Duration(c.ttl) * time.Second).Truncate(time.Second)
	if !parent.Exp.IsZero() && parent.Exp.Before(exp) {
		exp = parent.Exp
	}
	var subID, tok, rt string
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var err error
		subID, tok, err = core.CreateSubkeyV2(ctx, tx, parent, core.SubkeyOpts{Name: subName(hostOf(c.redirect)), Credits: c.credits, Exp: exp, Scopes: c.scopes, Class: "oauth"})
		if err != nil {
			return err
		}
		if rt, err = s.newRefresh(ctx, tx, c.client, subID, parent.Root, c.ttl); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE oauth_codes SET sub = $2 WHERE code_hash = $1`, hash(code), subID); err != nil {
			return err
		}
		return core.Audit(ctx, tx, parent.ID, "oauth-mint", subID, int(c.credits))
	})
	if err != nil {
		return nil, grantErr(err)
	}
	return tokenReply(tok, rt, exp, c.scopes), nil
}

// grantErr turns a minting failure (credits, subkey cap, scope) into invalid_grant.
func grantErr(err error) error {
	var ae *core.APIError
	if errors.As(err, &ae) && ae.Status < 500 {
		return oerr("invalid_grant", ae.Error())
	}
	return err
}

func tokenReply(tok, rt string, exp time.Time, scopes []string) map[string]any {
	return map[string]any{"access_token": tok, "token_type": "Bearer", "expires_in": max(int64(time.Until(exp).Seconds()), 1),
		"refresh_token": rt, "scope": strings.Join(scopes, " ")}
}

// newRefresh stores a fresh refresh token (hash only) living ttl seconds like the access token.
func (s *svc) newRefresh(ctx context.Context, q core.Q, client, sub, root string, ttl int) (string, error) {
	rt := randToken(codeBytes)
	_, err := q.Exec(ctx, `INSERT INTO oauth_refresh (rt_hash, client_id, ident, root, ttl_s, exp) VALUES ($1, $2, $3, $4, $5, $6)`,
		hash(rt), client, sub, root, ttl, time.Now().Add(time.Duration(ttl)*time.Second))
	return rt, err
}

// loadIdent builds the Ident of a live identity by id (the consenting parent at exchange time).
func loadIdent(ctx context.Context, q core.Q, id string) (*core.Ident, error) {
	var ident core.Ident
	var parent *string
	var expT *time.Time
	err := q.QueryRow(ctx, `SELECT i.id, i.name, i.root, i.parent, i.credits, i.expires_at, i.scopes, i.token_class, r.rep, r.created, r.seed, i.earned
		FROM identities i JOIN identities r ON r.id = i.root
		WHERE i.id = $1 AND i.revoked_at IS NULL AND r.revoked_at IS NULL AND (i.expires_at IS NULL OR i.expires_at > now())`, id).
		Scan(&ident.ID, &ident.Name, &ident.Root, &parent, &ident.Credits, &expT, &ident.Scopes, &ident.Class, &ident.Rep, &ident.Created, &ident.Seed, &ident.Earned)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, oerr("invalid_grant", "the consenting identity is gone")
	}
	if err != nil {
		return nil, err
	}
	if parent != nil {
		ident.Parent = *parent
	}
	if expT != nil {
		ident.Exp = *expT
	}
	if ident.Class == "" {
		ident.Class = "full"
	}
	if ident.Banned = ident.Rep <= -10; ident.Banned {
		return nil, oerr("invalid_grant", "identity banned")
	}
	return &ident, nil
}

type refreshRow struct {
	client, ident, root string
	ttl                 int
}

// grantRefresh rotates: the presented refresh token is consumed, the oauth subkey gets a new
// cx_ token (old hash honoured 60 s like POST /v1/rotate) and a lifetime of ttl again (never past
// its parent's), and a new refresh token is issued. Reuse of a consumed token revokes the family.
func (s *svc) grantRefresh(ctx context.Context, v url.Values) (map[string]any, error) {
	rt, client := v.Get("refresh_token"), v.Get("client_id")
	switch {
	case rt == "" || len(rt) > 128:
		return nil, oerr("invalid_request", "refresh_token required")
	case client == "" || len(client) > maxClientID:
		return nil, oerr("invalid_client", "client_id required")
	}
	var row refreshRow
	err := s.d.DB.QueryRow(ctx, `UPDATE oauth_refresh SET used_at = now() WHERE rt_hash = $1 AND used_at IS NULL AND exp > now()
		RETURNING client_id, ident, root, ttl_s`, hash(rt)).Scan(&row.client, &row.ident, &row.root, &row.ttl)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, s.refreshReplay(ctx, rt)
	}
	if err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare([]byte(row.client), []byte(client)) != 1 {
		return nil, oerr("invalid_client", "client_id does not match; the refresh_token is now void")
	}
	want := time.Now().Add(time.Duration(row.ttl) * time.Second).Truncate(time.Second)
	var newTok, newRT string
	var scopes []string
	var exp time.Time
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		tok, h := core.NewToken()
		err := tx.QueryRow(ctx, `UPDATE identities i SET token_hash_prev = token_hash, token_hash = $2, rotated_at = now(),
			expires_at = LEAST($3::timestamptz, coalesce((SELECT p.expires_at FROM identities p WHERE p.id = i.parent), 'infinity'::timestamptz))
			WHERE i.id = $1 AND i.revoked_at IS NULL AND i.token_class = 'oauth' RETURNING expires_at, scopes`, row.ident, h, want).Scan(&exp, &scopes)
		if errors.Is(err, pgx.ErrNoRows) {
			return oerr("invalid_grant", "token revoked")
		}
		if err != nil {
			return err
		}
		newTok = tok
		if newRT, err = s.newRefresh(ctx, tx, row.client, row.ident, row.root, row.ttl); err != nil {
			return err
		}
		return core.Audit(ctx, tx, row.ident, "oauth-refresh", "", 0)
	})
	if err != nil {
		return nil, err
	}
	return tokenReply(newTok, newRT, exp, scopes), nil
}

// refreshReplay answers a refresh token that did not consume: unknown or expired -> invalid_grant;
// already rotated -> two parties hold it, so the subkey and its refresh family are revoked
// (OAuth 2.1 4.3.1 refresh token rotation).
func (s *svc) refreshReplay(ctx context.Context, rt string) error {
	var ident string
	err := s.d.DB.QueryRow(ctx, `SELECT ident FROM oauth_refresh WHERE rt_hash = $1 AND used_at IS NOT NULL`, hash(rt)).Scan(&ident)
	if errors.Is(err, pgx.ErrNoRows) {
		return oerr("invalid_grant", "unknown or expired refresh_token")
	}
	if err != nil {
		return err
	}
	err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		var parent string
		if err := tx.QueryRow(ctx, `SELECT coalesce(parent, root) FROM identities WHERE id = $1`, ident).Scan(&parent); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if _, err := core.RevokeTree(ctx, tx, ident, parent); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `DELETE FROM oauth_refresh WHERE ident = $1`, ident); err != nil {
			return err
		}
		return core.Audit(ctx, tx, parent, "oauth-replay", ident, 0)
	})
	if err != nil {
		return err
	}
	return oerr("invalid_grant", "refresh_token already used; the token it belonged to has been revoked")
}
