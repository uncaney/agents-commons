package pay

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

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
		"ag": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in createIn
			if err := arg(a, &in); err != nil {
				return "", err
			}
			_, body, _, err := s.createIdem(ctx, id, in.Key, in)
			return body, err
		},
		"aga": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			ag, err := s.accept(ctx, id, in.ID)
			if err != nil {
				return "", err
			}
			return "ok " + ag.ID + " open", nil
		},
		"agc": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
				chargeIn
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			ag, replay, err := s.charge(ctx, id, in.ID, in.chargeIn)
			if err != nil {
				return "", err
			}
			text := chargeText(ag, in.chargeIn)
			if replay {
				text += "\nidem=replay"
			}
			return text, nil
		},
		"agx": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			ag, err := s.close(ctx, id, in.ID)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("ok %s closed, %dcr refunded", ag.ID, ag.remainder()), nil
		},
		"agg": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID   string `json:"id"`
				Role string `json:"role"`
				S    string `json:"s"`
				K    int    `json:"k"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if in.ID == "" {
				text, _, err := s.list(ctx, id, listOpts{Role: in.Role, State: in.S, K: in.K})
				return text, err
			}
			if id == nil {
				return "", core.ErrAuth
			}
			ag, err := load(ctx, d.DB, in.ID, false)
			if err != nil {
				return "", err
			}
			if !ag.party(id.Root) {
				return "", core.E(403, "auth", "payer or payee only")
			}
			return ag.text(ctx, d.DB), nil
		},
		"tip": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in tipIn
			if err := arg(a, &in); err != nil {
				return "", err
			}
			_, body, err := s.tipIdem(ctx, id, in)
			return body, err
		},
	}
}
