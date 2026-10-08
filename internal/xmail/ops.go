package xmail

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/e2e"
	"ekaii.fr/commons/internal/keys"
)

func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

// verifyOpSig checks the request signature an op carries as if the client had done
// `POST /v1/x/<to>` with the envelope as body (3.5): the caller's current rk, the skew window and a
// single-use nonce in req_nonces.
func verifyOpSig(ctx context.Context, q core.Q, id *core.Ident, to, header string, body []byte) (*e2e.ReqSig, error) {
	if header == "" {
		return nil, core.E(401, "sig", "sig required: X-Cx-Sig value over POST /v1/x/<to> with the envelope as body")
	}
	b, found, err := keys.Bundle(ctx, q, id.ID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, core.E(403, "sig", "no key published for "+id.ID)
	}
	now := time.Now().Unix()
	rs, err := e2e.VerifyReq(b.RK, "POST", "/v1/x/"+to, header, body, now)
	switch {
	case errors.Is(err, e2e.ErrSkew):
		return nil, core.E(401, "skew", "now="+strconv.FormatInt(now, 10))
	case err != nil:
		return nil, core.E(401, "sig", "invalid")
	}
	tag, err := q.Exec(ctx, `INSERT INTO req_nonces (id, nonce, exp) VALUES ($1, $2, to_timestamp($3)) ON CONFLICT DO NOTHING`,
		id.ID, rs.Nonce, int64(rs.TS)+2*e2e.ReqSkew)
	if err != nil {
		return nil, err
	}
	if tag.RowsAffected() == 0 {
		return nil, core.E(409, "sig", "nonce replayed")
	}
	return rs, nil
}

// Ops are the raw relay ops the remote /mcp exposes (26.2): xraw relays one sealed envelope, xpull
// lists envelope metadata. Sealing, opening, acks and policy stay in cx mcp (plaintext never
// reaches the gateway).
func Ops(d *core.Deps) map[string]Op {
	ready := func() (*svc, error) {
		if s := cur.Load(); s != nil {
			return s, nil
		}
		return nil, errNotReady
	}
	return map[string]Op{
		"xraw": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			s, err := ready()
			if err != nil {
				return "", err
			}
			switch {
			case id == nil:
				return "", core.ErrAuth
			case id.Banned:
				return "", core.ErrBanned
			case d.Frozen("write"):
				return "", core.Frozen("write")
			}
			var in struct {
				To     string `json:"to"`
				Env    string `json:"env"`
				Sig    string `json:"sig"`
				Stamp  string `json:"stamp"`
				ScrubV string `json:"scrub_v"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if !core.ValidIDPrefix(in.To, 'a') {
				return "", core.Bad("to must be an identity id")
			}
			if len(in.Env) > 4*e2e.MailCap/3+4 {
				return "", errSizeBucket
			}
			env, err := decodeB64(in.Env)
			if err != nil {
				return "", core.Bad("env must be the base64url envelope bytes")
			}
			sig, err := verifyOpSig(ctx, d.DB, id, in.To, in.Sig, env)
			if err != nil {
				return "", err
			}
			_, grp, _ := core.ClientFrom(ctx)
			res, err := s.relay(ctx, id, &sendIn{to: in.To, stamp: in.Stamp, scrubV: in.ScrubV, env: env, sig: sig, group: grp})
			if err != nil {
				return "", err
			}
			return res.Text(), nil
		},
		"xpull": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			s, err := ready()
			if err != nil {
				return "", err
			}
			if id == nil {
				return "", core.ErrAuth
			}
			var in struct {
				After int64  `json:"after"`
				K     int    `json:"k"`
				Wait  int    `json:"wait"`
				Dev   string `json:"dev"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			switch {
			case in.After < 0:
				return "", core.Bad("after must be a sequence number")
			case in.K < 0 || in.K > MaxK:
				return "", core.Bad("k must be 1.." + strconv.Itoa(MaxK))
			case in.Wait < 0 || in.Wait > MaxWait:
				return "", core.Bad("wait must be 0.." + strconv.Itoa(MaxWait))
			case in.Dev != "" && !devRe.MatchString(in.Dev):
				return "", core.Bad("dev must match [A-Za-z0-9._-]{1,32}")
			}
			_, grp, _ := core.ClientFrom(ctx)
			res, err := s.read(ctx, id, pullParams{after: in.After, k: in.K, wait: in.Wait, dev: in.Dev}, grp)
			if err != nil {
				return "", err
			}
			return res.Text(), nil
		},
	}
}
