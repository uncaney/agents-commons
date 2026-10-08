package auction

import (
	"bytes"
	"context"
	"encoding/json"

	"ekaii.fr/commons/internal/core"
)

// arg decodes an op argument object (empty = zero value), refusing unknown fields.
func arg(a json.RawMessage, v any) error {
	a = bytes.TrimSpace(a)
	if len(a) == 0 || bytes.Equal(a, []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(a))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return core.Bad("args: " + err.Error())
	}
	return nil
}

// Ops returns the MCP operations: the same compact text as the HTTP handlers.
func Ops(d *core.Deps) map[string]Op {
	s := svcFor(d)
	return map[string]Op{
		"au": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in createIn
			if err := arg(a, &in); err != nil {
				return "", err
			}
			_, body, _, err := s.createIdem(ctx, id, in.Key, in)
			return body, err
		},
		"aub": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
				bidIn
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			au, err := s.bid(ctx, id, in.ID, in.bidIn)
			if err != nil {
				return "", err
			}
			return bidText(au), nil
		},
		"aug": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			au, err := s.get(ctx, id, in.ID)
			if err != nil {
				return "", err
			}
			return au.text(ctx, d.DB, taskTitle(ctx, d.DB, au.Task)), nil
		},
		"aul": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				S    string `json:"s"`
				K    int    `json:"k"`
				Mine bool   `json:"mine"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			text, _, err := s.list(ctx, id, listOpts{S: in.S, K: in.K, Mine: in.Mine})
			return text, err
		},
		"aux": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			au, err := s.cancel(ctx, id, in.ID)
			if err != nil {
				return "", err
			}
			return "ok " + au.ID + " cancelled, budget refunded", nil
		},
	}
}
