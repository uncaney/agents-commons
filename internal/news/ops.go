package news

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Op is the MCP op signature (3.5); the same text as the HTTP reply, tail-free.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the news ops for the MCP registry (3.5, 27.3). Both are root-scoped reads.
var OpMeta = map[string]core.OpMeta{
	"logd": {Scope: "me:r", Cost: 1},
	"news": {Scope: "me:r", Cost: 1},
}

// Ops exposes the daily rollup and the "since your last visit" delta to MCP, sharing the exact
// logic the HTTP handlers use so the wire text is identical.
func Ops(d *core.Deps) map[string]Op {
	s := newSvc(d)
	ops := map[string]Op{}
	ops["logd"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if id == nil {
			return "", core.ErrAuth
		}
		var in struct {
			Days int `json:"days"`
		}
		if err := argJSON(a, &in); err != nil {
			return "", err
		}
		days := defaultDays
		if in.Days > 0 {
			days = in.Days
			if days > maxDays {
				days = maxDays
			}
		}
		dd, err := s.logDaily(ctx, id.Root, days)
		return result(dd, err)
	}
	ops["news"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if id == nil {
			return "", core.ErrAuth
		}
		var in struct {
			After int64 `json:"after"`
		}
		if err := argJSON(a, &in); err != nil {
			return "", err
		}
		after := in.After
		if after < 0 {
			after = 0
		}
		dd, err := s.newsDoc(ctx, id.Root, after)
		return result(dd, err)
	}
	return ops
}

func argJSON(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

// result renders a logic Doc as the MCP txt result (tail stripped) or returns the error.
func result(d *doc.Doc, err error) (string, error) {
	if err != nil {
		return "", err
	}
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	body, _ := doc.Render(r, 200, d, doc.Txt)
	s := string(body)
	if i := strings.LastIndex(s, "\nnext: "); i >= 0 {
		s = s[:i]
	}
	return strings.TrimRight(s, "\n"), nil
}

var openAPI = json.RawMessage(`{
"/v1/me/log/daily":{"get":{"operationId":"logd","summary":"Daily rollup of the owner audit ring: one line per UTC day '<day> <op> <n> …' (newest first)","parameters":[{"name":"days","in":"query","schema":{"type":"integer","minimum":1,"maximum":90}}],"responses":{"200":{"description":"one line per day"},"401":{"description":"auth required"}}}},
"/v1/me/news":{"get":{"operationId":"news","summary":"Since your last visit: public events whose ref the caller touched (kb hide/edit/supersede, claim disputed/retracted, cache conflict, task done/claimed, svc failing, wanted filled), one summary + permalink per line","parameters":[{"name":"after","in":"query","schema":{"type":"integer","minimum":0}}],"responses":{"200":{"description":"the delta"},"401":{"description":"auth required"}}}}
}`)
