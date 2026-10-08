package subs

import (
	"context"
	"encoding/json"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Help is the help{t:subs} text (<= 200 tokens).
const Help = `subs; server-side subscriptions: a topic feeds a sink, exactly-once.
sub{topic,sink,to?,filter?,mode?,hop_max?,ttl_h?,max_credits_day?} -> ok u… lag=0
 sink: wq:<name> queue | mb:me mailbox (mode each|digest) | kv:<ns>/<k> latest | fn:<svc>@<ver> reactive function
 fn writes its output to to: topic:<name> | mail:me | kv:<ns>/<k>, header hop=<n+1>; hop>=hop_max never fires again; via=sub messages are never re-matched
 filter: prefix:<text> | re:<RE2 <=64>
subg list | unsub{id} remove | subresume{id} clear errors and resume a paused sub
caps: 20 subs/root (L0 5), 200/topic, 200 firings/day/root, 2000/h global; refusals pause after 100, out-of-credits pauses.`

// Ops returns the MCP operations of this package.
func Ops(d *core.Deps) map[string]Op {
	s := svc(d)
	return map[string]Op{
		"sub": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in CreateIn
			if err := arg(a, &in); err != nil {
				return "", err
			}
			sub, err := s.Create(ctx, id, in)
			if err != nil {
				return "", err
			}
			return "ok " + sub.ID + " lag=0", nil
		},
		"subg": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			subs, err := s.List(ctx, id.Root)
			if err != nil {
				return "", err
			}
			var b strings.Builder
			b.WriteString("subs=" + itoa(int64(len(subs))))
			for _, sub := range subs {
				b.WriteString("\n" + sub.line())
			}
			return b.String(), nil
		},
		"unsub": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if err := s.Delete(ctx, id, in.ID); err != nil {
				return "", err
			}
			return "ok", nil
		},
		"subresume": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			sub, err := s.Resume(ctx, id, in.ID)
			if err != nil {
				return "", err
			}
			return "ok " + sub.ID + " resumed", nil
		},
	}
}

func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}
