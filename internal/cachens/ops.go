package cachens

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(a)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

// text renders a Doc as the MCP result: txt without the tail.
func text(d *doc.Doc) string {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	body, _ := doc.Render(r, 200, d, doc.Txt)
	s := string(body)
	if i := strings.LastIndex(s, "\nnext: "); i >= 0 {
		s = s[:i+1]
	}
	return strings.TrimRight(s, "\n")
}

// Ops are the MCP ops of the cache namespaces (27.3): ckey (pure derivation), cnear (near-miss),
// cns (declare/update a recipe) and cnsg (read a recipe). They mirror the HTTP replies, tail-free.
func Ops(d *core.Deps) map[string]Op {
	s := newSvc(d)
	return map[string]Op{
		"ckey": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				NS string `json:"ns"`
				In string `json:"in"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			res, err := deriveKey(in.NS, in.In)
			if err != nil {
				return "", err
			}
			return text(keyDoc(res)), nil
		},
		"cnear": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				NS string `json:"ns"`
				In string `json:"in"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			lines, v, err := s.near(ctx, id, strings.ToLower(in.NS), in.In)
			if err != nil {
				return "", err
			}
			head := "near " + nsVer(strings.ToLower(in.NS), v) + " n=" + strconv.Itoa(len(lines))
			out := []string{head}
			for _, l := range lines {
				out = append(out, l.Line())
			}
			return strings.Join(out, "\n"), nil
		},
		"cns": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := s.writeOK(id); err != nil {
				return "", err
			}
			var in struct {
				NS string `json:"ns"`
				putReq
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			rc, err := s.put(ctx, id, strings.ToLower(in.NS), in.putReq)
			if err != nil {
				return "", err
			}
			return text(recipeDoc(strings.ToLower(in.NS), rc)), nil
		},
		"cnsg": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				NS string `json:"ns"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			rc, err := s.get(ctx, strings.ToLower(in.NS))
			if err != nil {
				return "", err
			}
			return text(recipeDoc(strings.ToLower(in.NS), rc)), nil
		},
	}
}

// writeOK mirrors core.AuthWrite for ops: token, not banned, no write freeze.
func (s *svc) writeOK(id *core.Ident) error {
	switch {
	case id == nil:
		return core.ErrAuth
	case id.Banned:
		return core.ErrBanned
	case s.d.Frozen("write"):
		return core.Frozen("write")
	}
	return nil
}

// Help is the op list for help{t:cache} (<= 200 tokens).
const Help = `cache namespaces (declared canonicalisation recipes for the result cache): ckey{ns,in} -> "key <sha256> ns=<ns>@<v>" + canonical (no storage) | cnear{ns,in} -> up to 3 "near <key> sim=0.71 tok=N by a… lvl=L2 <preview>" (similar cached inputs, previews only, never bodies) | cns{ns,rules:[{re,to}],lower,strip_ts,strip_hex,strip_paths,strip_lines,desc} -> "cns <ns>@<v>" (L2+, 5/root, RE2 rules; a change bumps v so old keys stay reachable) | cnsg{ns} -> the recipe. Built-ins: ISO ts -> <ts>, 12+ hex -> <hex>, home dirs -> ~, line:col -> :n.`

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"ckey":  {Scope: "*", Cost: 0.2},
	"cnear": {Scope: "*", Cost: 0.5},
	"cns":   {Scope: "know:w", Cost: 1, Mutating: true},
	"cnsg":  {Scope: "*", Cost: 0.2},
}
