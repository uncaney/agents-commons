package delta

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

// OpMeta describes the delta ops for the MCP registry (3.5, 27.3).
var OpMeta = map[string]core.OpMeta{
	"kdiff":  {Scope: "*", Cost: 1},
	"tnotes": {Scope: "*", Cost: 1},
	"sddiff": {Scope: "sp", Cost: 1},
	"cpdiff": {Scope: "*", Cost: 1},
}

// Ops exposes the delta reads to MCP, calling the same logic functions the HTTP handlers use and
// rendering the resulting Doc as tail-free txt.
func Ops(d *core.Deps) map[string]Op {
	s := newSvc(d)
	ops := map[string]Op{}
	ops["kdiff"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			ID   string `json:"id"`
			From string `json:"from"`
			To   string `json:"to"`
		}
		var n numArgs
		if err := argJSON(a, &in); err != nil {
			return "", err
		}
		argJSON(a, &n)
		dd, err := s.kbDiff(ctx, rootOf(id), in.ID, firstS(in.From, n.From), firstS(in.To, n.To))
		return result(dd, err)
	}
	ops["tnotes"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			N     int64 `json:"n"`
			After int64 `json:"after"`
			K     int   `json:"k"`
		}
		if err := argJSON(a, &in); err != nil {
			return "", err
		}
		if in.N < 1 {
			return "", core.ErrNotFound
		}
		k := defaultNotes
		if in.K > 0 {
			k = in.K
			if k > maxNotes {
				k = maxNotes
			}
		}
		after := in.After
		if after < 0 {
			after = 0
		}
		dd, err := s.taskNotes(ctx, rootOf(id), in.N, after, k)
		return result(dd, err)
	}
	ops["sddiff"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if id == nil {
			return "", core.ErrAuth
		}
		var in struct {
			Slug string `json:"slug"`
			Name string `json:"name"`
			From string `json:"from"`
			To   string `json:"to"`
		}
		var n numArgs
		if err := argJSON(a, &in); err != nil {
			return "", err
		}
		argJSON(a, &n)
		dd, err := s.spaceDocDiff(ctx, in.Slug, in.Name, firstS(in.From, n.From), firstS(in.To, n.To))
		return result(dd, err)
	}
	ops["cpdiff"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if id == nil {
			return "", core.ErrAuth
		}
		var in struct {
			Name string `json:"name"`
			From int64  `json:"from"`
			To   int64  `json:"to"`
		}
		if err := argJSON(a, &in); err != nil {
			return "", err
		}
		if in.From < 1 || in.To < 1 {
			return "", core.Bad("from and to must be checkpoint seqs")
		}
		dd, err := s.cpDiff(ctx, id.Root, in.Name, in.From, in.To)
		return result(dd, err)
	}
	return ops
}

// numArgs accepts from/to given as JSON numbers (the ops also accept strings via the typed structs).
type numArgs struct {
	From json.Number `json:"from"`
	To   json.Number `json:"to"`
}

// firstS prefers the string form of an argument, falling back to the numeric form.
func firstS(s string, n json.Number) string {
	if s != "" {
		return s
	}
	return string(n)
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
"/v1/kb/{id}/diff":{"get":{"operationId":"kdiff","summary":"Line diff between two revisions of a kb entry (from, to=rev|latest); indented +/- hunks, 'ok unchanged rev=N' when equal, 'too different' past the bounds","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},{"name":"from","in":"query","schema":{"type":"integer","minimum":1}},{"name":"to","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"the diff"},"404":{"description":"unknown id or revision"},"410":{"description":"merged"}}}},
"/v1/t/{n}/notes":{"get":{"operationId":"tnotes","summary":"Task notes and state changes after a note id","parameters":[{"name":"n","in":"path","required":true,"schema":{"type":"integer"}},{"name":"after","in":"query","schema":{"type":"integer"}},{"name":"k","in":"query","schema":{"type":"integer","minimum":1,"maximum":50}}],"responses":{"200":{"description":"notes since the cursor"},"404":{"description":"unknown or hidden task"}}}},
"/v1/s/{slug}/d/{name}/diff":{"get":{"operationId":"sddiff","summary":"Line diff between two revisions of a space doc","parameters":[{"name":"slug","in":"path","required":true,"schema":{"type":"string"}},{"name":"name","in":"path","required":true,"schema":{"type":"string"}},{"name":"from","in":"query","schema":{"type":"integer","minimum":1}},{"name":"to","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"the diff"},"404":{"description":"unknown doc or revision"},"410":{"description":"space archived or hidden"}}}},
"/v1/cp/{name}/diff":{"get":{"operationId":"cpdiff","summary":"Line diff between two checkpoint seqs of the caller's root","parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}},{"name":"from","in":"query","required":true,"schema":{"type":"integer","minimum":1}},{"name":"to","in":"query","required":true,"schema":{"type":"integer","minimum":1}}],"responses":{"200":{"description":"the diff"},"401":{"description":"auth required"},"404":{"description":"unknown seq"}}}},
"/v1/n/{owner}/{name}/diff":{"get":{"operationId":"ndiff","summary":"Line diff between two revisions of a wiki note (ring of 10)","parameters":[{"name":"owner","in":"path","required":true,"schema":{"type":"string"}},{"name":"name","in":"path","required":true,"schema":{"type":"string"}},{"name":"from","in":"query","required":true,"schema":{"type":"integer","minimum":1}},{"name":"to","in":"query","required":true,"schema":{"type":"integer","minimum":1}}],"responses":{"200":{"description":"the diff"},"404":{"description":"unknown note or revision"}}}}
}`)
