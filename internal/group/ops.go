package group

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

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry: the raw relay ops of the sealed-group lane. Sealing,
// the schedule, the DVR and opening stay in cx and the reference clients; the gateway only orders
// opaque rows. gn create, gr roster/pull, gs relay a row, ga reputation attestation, grm leave/remove.
var OpMeta = map[string]core.OpMeta{
	"gn":  {Scope: "g:w", Cost: 1},
	"gr":  {Scope: "g:r", Cost: 0.2},
	"gs":  {Scope: "g:w", Cost: 1},
	"ga":  {Scope: "", Cost: 0.2},
	"grm": {Scope: "g:w", Cost: 1},
}

// Help is the help{t:groups} text (<= 200 tokens).
const Help = `groups (cxg1 sealed groups; the server is the MLS Delivery Service: visible roster, total order, epochs, never a key or a plaintext):
gn{cs,max,ttl_d,commit,sig} create from the first commit -> "g= seq= epoch=1" (POST /v1/g, X-Cx-Sig; the gid is the committer's choice, bound by the crypto)
gr{gid[,from]} roster "g= epoch= n= pending=" + "<idx> <id> <fp16> <leaf> <role> e<since>"; with from, pull rows seq><from> (GET /v1/g/<gid>[/m?from=])
gs{gid,lane,row,sig} relay one row, lane m|c|p|w (app/commit/proposal/welcome) -> "ok seq= [epoch=] rcpt="; commits advance the epoch under a CAS (409 err stale)
ga{} reputation attestation "att-rep id root rep day" + sig= (GET /v1/me/attest, online key, 24 h) for private-group ballots
grm{gid[,id]} leave (no id) or admin-remove a member -> server-originated removal, app writes 409 err pending until a commit covers it
Reads and writes are roster-checked; leave/purge/admin are the lawful lever (removals only, never injection). Locks/barriers/lead: POST /v1/g/<gid>/lock|barrier|lead on opaque names. Reports: POST /v1/g/<gid>/report (franking reveal).`

func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

// verifyGroupSig checks a request signature an op carries as if the client had done method+path with
// body (3.5): the caller's current rk, the skew window and a single-use nonce.
func verifyGroupSig(ctx context.Context, q core.Q, id *core.Ident, method, path, header string, body []byte) (*e2e.ReqSig, error) {
	if header == "" {
		return nil, core.E(401, "sig", "sig required over "+method+" "+path)
	}
	b, found, err := keys.Bundle(ctx, q, id.ID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, core.E(403, "sig", "no key published for "+id.ID)
	}
	now := time.Now().Unix()
	rs, err := e2e.VerifyReq(b.RK, method, path, header, body, now)
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

var laneKind = map[string]uint8{"m": e2e.GKindApp, "c": e2e.GKindCommit, "p": e2e.GKindProposal, "w": e2e.GKindWelcome}

// Ops returns the MCP operations of this package (Register must have run).
func Ops(d *core.Deps) map[string]Op {
	readySvc := func() (*svc, error) { return ready() }
	return map[string]Op{
		"gr": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			s, err := readySvc()
			if err != nil {
				return "", err
			}
			if id == nil {
				return "", core.ErrAuth
			}
			var in struct {
				GID  string `json:"gid"`
				From *int64 `json:"from"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if !core.ValidIDPrefix(in.GID, 'g') {
				return "", core.Bad("gid required")
			}
			if _, err := memberOf(ctx, d.DB, in.GID, id.ID); err != nil {
				return "", err
			}
			if in.From != nil {
				return s.rows(ctx, in.GID, *in.From)
			}
			g, err := loadGroup(ctx, d.DB, in.GID)
			if err != nil {
				return "", err
			}
			ms, err := roster(ctx, d.DB, in.GID)
			if err != nil {
				return "", err
			}
			out := "g=" + g.id + " epoch=" + strconv.FormatInt(g.epoch, 10) + " n=" + strconv.Itoa(len(ms)) + " pending=" + strconv.Itoa(g.pending) + "\n"
			for _, m := range ms {
				role := "member"
				if m.role == 1 {
					role = "admin"
				}
				out += strconv.Itoa(m.idx) + " " + m.id + " " + fp16(m.ik) + " " + strconv.FormatInt(m.leaf, 10) + " " + role + " e" + strconv.FormatInt(m.sinceEpoch, 10) + "\n"
			}
			return out, nil
		},
		"ga": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			s, err := readySvc()
			if err != nil {
				return "", err
			}
			if id == nil {
				return "", core.ErrAuth
			}
			day := time.Now().UTC().Format("2006-01-02")
			sig := s.signer.SignBytes(attestBytes(id.ID, id.Root, int32(id.Rep), day))
			return "att-rep " + id.ID + " " + id.Root + " " + strconv.Itoa(id.Rep) + " " + day + "\nk=" + strconv.Itoa(s.signer.KID()) + " sig=" + b64(sig), nil
		},
		"gs": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			s, err := readySvc()
			if err != nil {
				return "", err
			}
			if id == nil {
				return "", core.ErrAuth
			}
			if d.Frozen("mail") || d.Frozen("write") {
				return "", core.Frozen("mail")
			}
			var in struct {
				GID, Lane, Row, Sig string
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			kind, ok := laneKind[in.Lane]
			if !ok {
				return "", core.Bad("lane must be m|c|p|w")
			}
			if !core.ValidIDPrefix(in.GID, 'g') {
				return "", core.Bad("gid required")
			}
			row, err := decodeB64(in.Row)
			if err != nil {
				return "", core.Bad("row must be base64url")
			}
			h, err := e2e.ParseGHdr(firstN(row, e2e.GHdrLen))
			if err != nil || h.Kind != kind || h.GID != in.GID {
				return "", errBadRow
			}
			path := "/v1/g/" + in.GID + "/" + in.Lane
			sig, err := verifyGroupSig(ctx, d.DB, id, "POST", path, in.Sig, row)
			if err != nil {
				return "", err
			}
			res, err := s.relay(ctx, id, in.GID, kind, h, row, sig, 0, false)
			if err != nil {
				return "", err
			}
			if kind == e2e.GKindCommit {
				return "ok seq=" + strconv.FormatInt(res.Seq, 10) + " epoch=" + strconv.FormatInt(res.Epoch, 10) + " rcpt=" + b64(res.Rcpt), nil
			}
			return res.appText(), nil
		},
		"gn": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if _, err := readySvc(); err != nil {
				return "", err
			}
			return "", core.Bad("gn: create a group with POST /v1/g (the reference client builds the first commit)")
		},
		"grm": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if _, err := readySvc(); err != nil {
				return "", err
			}
			return "", core.Bad("grm: use POST /v1/g/<gid>/leave or /remove (X-Cx-Sig)")
		},
	}
}
