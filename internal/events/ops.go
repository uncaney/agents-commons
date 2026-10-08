package events

import (
	"context"
	"encoding/json"
	"strconv"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation: compact text result, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

// kindsArg accepts kinds as a JSON array of strings or as the HTTP comma string.
func kindsArg(raw json.RawMessage) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []string
	if json.Unmarshal(raw, &list) == nil {
		return normList(list, MaxKinds, kindRe, "kind")
	}
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return nil, core.Bad("kinds must be a list or a comma string")
	}
	return parseKinds(s)
}

// Ops are the MCP ops ev, watch and unwatch (same text as the HTTP replies, without the tail).
func Ops(d *core.Deps) map[string]Op {
	h := &handlers{d}
	return map[string]Op{
		"ev": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				After *int64          `json:"after"`
				Kinds json.RawMessage `json:"kinds"`
				W     string          `json:"w"`
				Wait  int             `json:"wait"`
				K     int             `json:"k"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			p := evParams{latest: in.After == nil, w: in.W, wait: in.Wait, k: in.K}
			if in.After != nil {
				if *in.After < 0 {
					return "", core.Bad("after must be a sequence number")
				}
				p.after = *in.After
			}
			var err error
			if p.kinds, err = kindsArg(in.Kinds); err != nil {
				return "", err
			}
			if p.w != "" && !core.ValidIDPrefix(p.w, 'w') {
				return "", core.ErrNotFound
			}
			if p.wait < 0 || p.wait > MaxWait {
				return "", core.Bad("wait must be 0.." + strconv.Itoa(MaxWait))
			}
			if p.k < 0 || p.k > MaxK {
				return "", core.Bad("k must be 1.." + strconv.Itoa(MaxK))
			}
			_, grp, _ := core.ClientFrom(ctx)
			res, err := h.read(ctx, id, p, grp)
			if err != nil {
				return "", err
			}
			return Text(res.rows, res.next, res.retry), nil
		},
		"watch": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeOK(d, id); err != nil {
				return "", err
			}
			var in WatchIn
			if err := arg(a, &in); err != nil {
				return "", err
			}
			var wt *Watch
			err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
				var err error
				wt, err = Create(ctx, tx, id, in)
				return err
			})
			if err != nil {
				return "", err
			}
			return wt.text("ok", false), nil
		},
		"unwatch": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeOK(d, id); err != nil {
				return "", err
			}
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error { return Delete(ctx, tx, id, in.ID) }); err != nil {
				return "", err
			}
			return "ok", nil
		},
	}
}

// writeOK mirrors core.AuthWrite for ops: token, not banned, no write freeze.
func writeOK(d *core.Deps, id *core.Ident) error {
	switch {
	case id == nil:
		return core.ErrAuth
	case id.Banned:
		return core.ErrBanned
	case d.Frozen("write"):
		return core.Frozen("write")
	}
	return nil
}
