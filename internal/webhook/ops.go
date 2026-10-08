package webhook

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Help is the help{t:webhooks} text (<= 200 tokens).
const Help = `webhooks (by pull, no egress) + inbound sinks.
Outbound: hk{url,fmt,kinds[],tags[],q} register (<=10/root, L1+) -> ok h… secret=whsec_… (shown once); fmt standard|slack|discord|ntfy|a2a; filter is a 19.1 watch. hkg list. hko{id,after,k<=20,wait<=85,f} pull signed envelopes (f=json|curl, curl lines are shell-safe) then POST /v1/hook/<id>/ack {upto}. unhook{id}. Deliver each envelope with YOUR OWN egress; the gateway never calls your url. Private feed GET /f/h/<url-token>.atom.
Inbound: inhook{kind,sink,target,filter} (kind github|gitlab|generic, sink ps|mb|wq, <=5/root) -> ok i… url=/in/i… secret=… Point a provider webhook at /in/i…; a valid HMAC signature publishes one scrubbed line into the sink. inhookg list, uninhook{id}. 60 events/h per hook, 600/day per root; 100 bad signatures disable it.`

// OpMeta describes the ops for the MCP registry (scope hook).
var OpMeta = map[string]core.OpMeta{
	"hk":       {Scope: "hook", Cost: 1, Mutating: true},
	"hkg":      {Scope: "hook", Cost: 0.2},
	"hko":      {Scope: "hook", Cost: 0.2},
	"hkack":    {Scope: "hook", Cost: 1, Mutating: true},
	"unhook":   {Scope: "hook", Cost: 1, Mutating: true},
	"inhook":   {Scope: "hook", Cost: 1, Mutating: true},
	"inhookg":  {Scope: "hook", Cost: 0.2},
	"uninhook": {Scope: "hook", Cost: 1, Mutating: true},
}

func arg(a json.RawMessage, v any) error {
	if len(a) == 0 {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("args: " + err.Error())
	}
	return nil
}

// Ops returns the MCP operations of this package.
func Ops(d *core.Deps) map[string]Op {
	h := &handlers{d}
	return map[string]Op{
		"hk": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in CreateIn
			if err := arg(a, &in); err != nil {
				return "", err
			}
			var hk *Hook
			var secret string
			err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
				var e error
				hk, secret, e = Create(ctx, tx, id, in)
				return e
			})
			if err != nil {
				return "", err
			}
			return "ok " + hk.ID + " secret=" + secret, nil
		},
		"hkg": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			hks, err := List(ctx, d.DB, id.Root)
			if err != nil {
				return "", err
			}
			var b strings.Builder
			fmt.Fprintf(&b, "hooks n=%d/%d", len(hks), MaxHooks)
			for _, x := range hks {
				fmt.Fprintf(&b, "\n%s %s %s kinds=%s tags=%s", x.ID, x.Fmt, maskURL(x.URL), dash(x.Kinds), dash(x.Tags))
			}
			return b.String(), nil
		},
		"hko": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in struct {
				ID    string `json:"id"`
				After int64  `json:"after"`
				K     int    `json:"k"`
				Wait  int    `json:"wait"`
				F     string `json:"f"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			hk, err := Get(ctx, d.DB, id.Root, in.ID)
			if err != nil {
				return "", err
			}
			k := in.K
			if k < 1 || k > MaxOutK {
				k = MaxOutK
			}
			wait := in.Wait
			if wait < 0 || wait > MaxWait {
				wait = 0
			}
			out, err := h.pollWait(ctx, id, hk.ID, in.After, k, wait)
			if err != nil {
				return "", err
			}
			last := in.After
			for _, o := range out {
				last = max(last, o.ID)
			}
			var b strings.Builder
			if strings.ToLower(in.F) == "curl" {
				for _, o := range out {
					var e Envelope
					if json.Unmarshal(o.Envelope, &e) == nil {
						b.WriteString(e.curlLine())
						b.WriteByte('\n')
					}
				}
			} else {
				js, _ := json.Marshal(out)
				b.Write(js)
				b.WriteByte('\n')
			}
			fmt.Fprintf(&b, "next: POST /v1/hook/%s/ack {\"upto\":%d}", hk.ID, last)
			return b.String(), nil
		},
		"hkack": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in struct {
				ID   string `json:"id"`
				Upto int64  `json:"upto"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			hk, err := Get(ctx, d.DB, id.Root, in.ID)
			if err != nil {
				return "", err
			}
			tag, err := d.DB.Exec(ctx, `UPDATE hook_out SET acked = true WHERE hook = $1 AND id <= $2 AND NOT acked`, hk.ID, in.Upto)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("ok acked=%d", tag.RowsAffected()), nil
		},
		"unhook": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
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
		"inhook": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in InCreateIn
			if err := arg(a, &in); err != nil {
				return "", err
			}
			var hk *InHook
			var secret string
			err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
				var e error
				hk, secret, e = InCreate(ctx, tx, id, in)
				return e
			})
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("ok %s url=/in/%s secret=%s", hk.ID, hk.ID, secret), nil
		},
		"inhookg": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			hks, err := InList(ctx, d.DB, id.Root)
			if err != nil {
				return "", err
			}
			var b strings.Builder
			fmt.Fprintf(&b, "inhooks n=%d/%d", len(hks), MaxInHooks)
			for _, x := range hks {
				fmt.Fprintf(&b, "\n%s %s %s:%s n=%d bad=%d disabled=%v", x.ID, x.Kind, x.Sink, x.Target, x.N, x.Bad, x.Disabled)
			}
			return b.String(), nil
		},
		"uninhook": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error { return InDelete(ctx, tx, id, in.ID) }); err != nil {
				return "", err
			}
			return "ok", nil
		},
	}
}
