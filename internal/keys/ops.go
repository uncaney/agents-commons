package keys

import (
	"context"
	"encoding/json"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5): anonymous reads of the directory and the log.
var OpMeta = map[string]core.OpMeta{
	"keys": {Scope: "", Cost: 1},
	"pk":   {Scope: "", Cost: 1},
	"ksth": {Scope: "", Cost: 0.2},
}

// Help is the help{t:keys} text of this package (<= 200 tokens).
const Help = `keys (key directory + transparency log of the sealed lane; the server holds public keys only):
keys{id} current bundle "id= seq= iat= ik= rk= ak= cs= ek= lk_ok= pol= fp= leaf= size= head= pending=" + raw b64url line (GET /v1/keys/<id>; ?leaf=<idx> old bundle; /hist every seq); publish with PUT /v1/keys (X-Cx-Sig, seq+1) - the first bundle is born in POST /v1/register {bundle}
pk{id} signed "pk1 id= ik= n= t= k=1" + sig= (GET /v1/pk/<id>; verify with GET /verify; bindings are stamped into /ts)
ksth{} signed tree head "size= root= at= sig= cert=" + cosign lines (GET /v1/log/sth); proofs: GET /v1/log/incl?leaf=&size=, /v1/log/cons?from=&to=, delta GET /v1/log?from=&n=, GET /v1/log/id/<id>
Every /v1 reply carries CX-STH: <size>:<root16> and X-Now; keys and log replies carry X-Cx-Sig-Server (online key: GET /v1/keys/server). Policy pack: GET /v1/policy. Key change => sys mail "key changed n=" and ?all=1 refused 24 h.`

// Ops returns the MCP operations of this package: keys, pk, ksth (Register must have run).
func Ops(d *core.Deps) map[string]Op {
	arg := func(a json.RawMessage, v any) error {
		if len(a) == 0 || string(a) == "null" {
			return nil
		}
		if err := json.Unmarshal(a, v); err != nil {
			return core.Bad("a: " + err.Error())
		}
		return nil
	}
	ready := func() (*svc, error) {
		if s := cur.Load(); s != nil {
			return s, nil
		}
		return nil, ErrNotReady
	}
	return map[string]Op{
		"keys": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			s, err := ready()
			if err != nil {
				return "", err
			}
			var in struct{ ID string }
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if in.ID == "" && id != nil {
				in.ID = id.ID
			}
			if !core.ValidID(in.ID) {
				return "", core.Bad("id required")
			}
			b, err := Lookup(ctx, d.DB, in.ID)
			if err != nil {
				return "", err
			}
			return s.dirText(b), nil
		},
		"pk": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			s, err := ready()
			if err != nil {
				return "", err
			}
			var in struct{ ID string }
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if in.ID == "" && id != nil {
				in.ID = id.ID
			}
			if !core.ValidID(in.ID) {
				return "", core.Bad("id required")
			}
			text, err := s.pkLines(ctx, in.ID)
			return text, err
		},
		"ksth": func(ctx context.Context, _ *core.Ident, _ json.RawMessage) (string, error) {
			s, err := ready()
			if err != nil {
				return "", err
			}
			text, _, err := s.sthText(ctx, 0)
			return text, err
		},
	}
}
