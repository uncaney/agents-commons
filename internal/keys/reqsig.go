package keys

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strconv"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
)

// Request signing (E2EE 3.5): X-Cx-Sig: v1,<ts>,<nonce b64url 16>,<sig b64url 64> with
// sig = Ed25519(rk, "cx1/req" || 0x00 || METHOD || 0x0a || path?query || 0x0a || u64(ts) || nonce || sha256(body)).
// The identity comes from the bearer, rk from its current bundle (pending never counts), |now-ts|
// <= 300 s, the nonce is single-use (req_nonces), the body is hashed through the route's cap. Every
// reply carries X-Now so a skewed client re-signs with an offset.

type sigKey struct{}

// SigFrom returns the verified request signature RequireSig stored in the context (the sealed
// mailbox keeps it as send_sig).
func SigFrom(ctx context.Context) (*e2e.ReqSig, bool) {
	s, ok := ctx.Value(sigKey{}).(*e2e.ReqSig)
	return s, ok
}

// RequireSig wraps a sealed-lane write: bearer auth (banned and write-freeze refused), X-Cx-Sig
// verified against the caller's current rk with a single-use nonce, body re-readable by h, LogMinimal.
func RequireSig(h http.Handler) http.Handler { return RequireSigMax(DefaultSigBody, h) }

// RequireSigMax is RequireSig with the route's body cap.
func RequireSigMax(max int64, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s := cur.Load()
		w.Header().Set(LogMinimalHeader, "minimal")
		if s == nil {
			w.Header().Set("X-Now", strconv.FormatInt(time.Now().Unix(), 10))
			core.Fail(w, r, ErrNotReady)
			return
		}
		s.hdr(w)
		id, err := s.d.AuthWrite(r)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		body, err := readBody(w, r, max)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		sig, err := s.verifySig(r.Context(), id, r, body)
		if err != nil {
			core.Fail(w, r, err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		r.ContentLength = int64(len(body))
		ctx := context.WithValue(WithLogMinimal(r.Context()), sigKey{}, sig)
		h.ServeHTTP(w, r.WithContext(ctx))
	})
}

// verifySig checks X-Cx-Sig of r (whose body bytes are body) for id and burns the nonce.
func (s *svc) verifySig(ctx context.Context, id *core.Ident, r *http.Request, body []byte) (*e2e.ReqSig, error) {
	header := r.Header.Get("X-Cx-Sig")
	if header == "" {
		return nil, core.E(401, "sig", "X-Cx-Sig required")
	}
	b, found, err := Bundle(ctx, s.d.DB, id.ID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, core.E(403, "sig", "no key published for "+id.ID)
	}
	now := time.Now().Unix()
	rs, err := e2e.VerifyReq(b.RK, r.Method, r.URL.RequestURI(), header, body, now)
	switch {
	case errors.Is(err, e2e.ErrSkew):
		return nil, core.E(401, "skew", "now="+strconv.FormatInt(now, 10))
	case errors.Is(err, e2e.ErrSig):
		return nil, core.E(401, "sig", "X-Cx-Sig must be v1,<ts>,<nonce>,<sig>")
	case err != nil:
		return nil, core.E(401, "sig", "invalid")
	}
	tag, err := s.d.DB.Exec(ctx, `INSERT INTO req_nonces (id, nonce, exp) VALUES ($1, $2, to_timestamp($3)) ON CONFLICT DO NOTHING`,
		id.ID, rs.Nonce, int64(rs.TS)+int64(nonceTTL/time.Second))
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, core.E(409, "sig", "nonce replayed")
	}
	return rs, nil
}
