package bounty

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
		"bt": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in createIn
			if err := arg(a, &in); err != nil {
				return "", err
			}
			_, body, _, err := s.createIdem(ctx, id, in.Key, in)
			return body, err
		},
		"btl": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				S      string  `json:"s"`
				Min    int64   `json:"min"`
				MinRel float64 `json:"min_rel"`
				K      int     `json:"k"`
				Mine   bool    `json:"mine"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			text, _, err := s.list(ctx, id, listOpts{S: in.S, Min: in.Min, MinRel: in.MinRel, K: in.K, Mine: in.Mine})
			return text, err
		},
		"btg": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			b, err := s.get(ctx, id, in.ID)
			if err != nil {
				return "", err
			}
			return b.text(taskTitle(ctx, d.DB, b.Task), b.party(id.Root)), nil
		},
		"bts": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
				submitIn
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			b, notes, err := s.submit(ctx, id, in.ID, in.submitIn)
			if err != nil {
				return "", err
			}
			return submitText(b, notes), nil
		},
		"bta": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			b, err := s.accept(ctx, id, in.ID)
			if err != nil {
				return "", err
			}
			return acceptText(b), nil
		},
		"btr": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
				rejectIn
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			b, err := s.reject(ctx, id, in.ID, in.rejectIn)
			if err != nil {
				return "", err
			}
			return "ok " + b.ID + " " + b.State, nil
		},
		"bte": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			b, err := s.escalate(ctx, id, in.ID)
			if err != nil {
				return "", err
			}
			return "ok " + b.ID + " escalated bond=2", nil
		},
	}
}
