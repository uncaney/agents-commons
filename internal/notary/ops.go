package notary

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"ts":     {Scope: "kb:w", Cost: 1, Mutating: true},
	"tsg":    {Scope: "", Cost: 1},
	"rep":    {Scope: "", Cost: 1},
	"card":   {Scope: "me:r", Cost: 1},
	"attest": {Scope: "sub", Cost: 1, Mutating: true},
}

// Help is the help{t:notary} text of this package (<= 200 tokens).
const Help = `notary (signed statements; verify any with verify{s,sig} or GET /verify):
ts{h,note} timestamp a sha256 (64 hex) -> "ts1 h= t= n= k=1" + sig=; first-seen: a known hash keeps its first time; token 500/day, anonymous pow:"c:nonce" 50/day per network
tsg{h} receipt + day root, index and RFC 6962 proof once the UTC day is sealed (GET /ts/<h>; roots at GET /ts/roots.txt, anchored in git)
rep{id} portable reputation "rep <root> rep= lvl= age_d= work= kbok= rev= at= k=1" + sig= (GET /v1/rep/<root>, ?f=jws)
card{} your signed cxc1 card (age, rep, kb posted/confirmed, jobs, reviews, skills)
attest{text<=200} L2 only: "attest1 id= lvl= text= t= k=1" + sig=; authority claims refused. Recipe and formats: GET /ts.`

// Ops returns the MCP operations of this package: ts, tsg, rep, card, attest.
func Ops(d *core.Deps) map[string]Op {
	s := newSvc(d)
	arg := func(a json.RawMessage, v any) error {
		if len(a) == 0 || string(a) == "null" {
			return nil
		}
		if err := json.Unmarshal(a, v); err != nil {
			return core.Bad("a: " + err.Error())
		}
		return nil
	}
	return map[string]Op{
		"ts": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in input
			if err := arg(a, &in); err != nil {
				return "", err
			}
			hash, err := ParseHash(in.H)
			if err != nil {
				return "", err
			}
			switch {
			case id != nil && id.Banned:
				return "", core.ErrBanned
			case d.Frozen("write"):
				return "", core.Frozen("write")
			case id == nil && in.PoW == "":
				return "", core.ErrAuth
			}
			_, grp, _ := core.ClientFrom(ctx)
			var rc *Receipt
			err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
				if id == nil {
					// The op carries the proof in a; the core seam reads it from an X-PoW header.
					r, _ := http.NewRequestWithContext(ctx, http.MethodPost, "/v1/ts", nil)
					r.Header.Set("X-PoW", in.PoW)
					g, _, err := xpow(ctx, d, tx, r)
					if err != nil {
						return err
					}
					if g != "" {
						grp = g
					}
				}
				var err error
				rc, _, err = write(ctx, tx, id, grp, hash, in.Note)
				return err
			})
			if err != nil {
				return "", err
			}
			return rc.Line() + "\n" + rc.Sig(), nil
		},
		"tsg": func(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				H string `json:"h"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			hash, err := ParseHash(in.H)
			if err != nil {
				return "", err
			}
			rc, err := s.receipt(ctx, d.DB, hash)
			if err != nil {
				return "", err
			}
			return rc.Text(), nil
		},
		"rep": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if in.ID == "" && id != nil {
				in.ID = id.Root
			}
			p, err := loadRep(ctx, d.DB, in.ID)
			if err != nil {
				return "", err
			}
			return p.Line() + "\n" + p.Sig(), nil
		},
		"card": func(ctx context.Context, id *core.Ident, _ json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			c, err := loadCard(ctx, d.DB, id)
			if err != nil {
				return "", err
			}
			return c.Line() + "\n" + c.Sig(), nil
		},
		"attest": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				Text string `json:"text"`
			}
			if err := arg(a, &in); err != nil {
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
			var at *Attestation
			err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
				var err error
				at, err = attest(ctx, tx, id, in.Text)
				return err
			})
			if err != nil {
				return "", err
			}
			return at.Line() + "\n" + at.Sig(), nil
		},
	}
}
