package mail

import (
	"context"
	"encoding/json"
	"strconv"

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

// Ops are the MCP ops mb, mbx, mbg, mbd, mbset and mbblock: the HTTP replies without the tail.
func Ops(d *core.Deps) map[string]Op {
	s := &svc{d}
	return map[string]Op{
		"mb": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := s.writeOK(id); err != nil {
				return "", err
			}
			var in struct {
				To      string `json:"to"`
				Text    string `json:"text"`
				Subject string `json:"subject"`
				Re      string `json:"re"`
				Key     string `json:"key"`
				PoW     string `json:"pow"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if in.To == "" {
				return "", core.Bad("to required")
			}
			ip, _, _ := core.ClientFrom(ctx)
			m := &Msg{Subject: in.Subject, Text: in.Text, Re: in.Re, PoW: in.PoW, IP: ip}
			_, body, _, err := s.sendOp(ctx, id, in.To, sendIn{Text: in.Text, Subject: in.Subject, Re: in.Re}, m, in.Key)
			return body, err
		},
		"mbx": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in struct {
				Box   string          `json:"box"`
				After json.RawMessage `json:"after"`
				K     int             `json:"k"`
				Wait  int             `json:"wait"`
				All   bool            `json:"all"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			p := pullParams{box: in.Box, k: in.K, wait: in.Wait, all: in.All}
			if len(in.After) > 0 && string(in.After) != "null" {
				var n int64
				var str string
				switch {
				case json.Unmarshal(in.After, &n) == nil:
					p.after = strconv.FormatInt(n, 10)
				case json.Unmarshal(in.After, &str) == nil:
					p.after = str
				default:
					return "", core.Bad("after must be a number or a cursor")
				}
			}
			if p.k < 0 || p.k > MaxK {
				return "", core.Bad("k must be 1.." + strconv.Itoa(MaxK))
			}
			if p.wait < 0 || p.wait > MaxWait {
				return "", core.Bad("wait must be 0.." + strconv.Itoa(MaxWait))
			}
			_, grp, _ := core.ClientFrom(ctx)
			res, err := s.read(ctx, id, p, grp)
			if err != nil {
				return "", err
			}
			return res.Text(), nil
		},
		"mbg": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			e, text, err := s.getOp(ctx, id, in.ID)
			if err != nil {
				return "", err
			}
			return getText(e, text), nil
		},
		"mbd": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := s.writeOK(id); err != nil {
				return "", err
			}
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if err := s.ackOp(ctx, id, in.ID); err != nil {
				return "", err
			}
			return "ok", nil
		},
		"mbset": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := s.writeOK(id); err != nil {
				return "", err
			}
			var in struct {
				Box string `json:"box"`
				setIn
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			return s.setOp(ctx, id, in.Box, in.setIn)
		},
		"mbblock": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := s.writeOK(id); err != nil {
				return "", err
			}
			var in struct {
				From string `json:"from"`
				Del  bool   `json:"del"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			return s.blockOp(ctx, id, in.From, in.Del)
		},
	}
}
