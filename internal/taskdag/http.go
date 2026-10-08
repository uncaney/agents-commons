package taskdag

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// reply writes text (+ next: tail) or JSON when asked.
func reply(w http.ResponseWriter, r *http.Request, status int, text string, j any, next ...doc.Action) {
	if j != nil && core.WantJSON(r) {
		core.JSON(w, status, j)
		return
	}
	doc.TailStatus(w, r, status, text, next...)
}

// --- needs ---

type needsIn struct {
	Add []int64 `json:"add"`
	Del []int64 `json:"del"`
}

func (s *Service) hNeeds(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	n, err := parseN(r.PathValue("n"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in needsIn
	if err := core.Decode(w, r, 4<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	if err := s.Needs(r.Context(), id, n, in.Add, in.Del); err != nil {
		core.Fail(w, r, err)
		return
	}
	line, _ := s.needsLine(r.Context(), n)
	p := "/v1/t/" + itoa(n)
	reply(w, r, 200, line, map[string]any{"ok": true}, doc.GET(p, ""), doc.GET("/v1/t/ready", ""))
}

// needsLine renders the current `needs: #12 done, #13 open` line ("needs: none" when empty).
func (s *Service) needsLine(ctx context.Context, n int64) (string, error) {
	rows, err := s.d.DB.Query(ctx, `SELECT d.needs, td.state, td.quarantine, d.gone FROM task_deps d
		JOIN tasks td ON td.n = d.needs WHERE d.n = $1 ORDER BY d.needs`, n)
	if err != nil {
		return "needs: none", err
	}
	defer rows.Close()
	var parts []string
	for rows.Next() {
		var m int64
		var st string
		var quar, gone bool
		if err := rows.Scan(&m, &st, &quar, &gone); err != nil {
			return "needs: none", err
		}
		parts = append(parts, fmt.Sprintf("#%d %s", m, depState(st, quar, gone)))
	}
	if err := rows.Err(); err != nil {
		return "needs: none", err
	}
	if len(parts) == 0 {
		return "needs: none", nil
	}
	return "needs: " + strings.Join(parts, ", "), nil
}

// --- split ---

type splitIn struct {
	Items []SplitItem `json:"items"`
	Join  string      `json:"join"`
}

func (s *Service) hSplit(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	n, err := parseN(r.PathValue("n"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in splitIn
	if err := core.Decode(w, r, 64<<10, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	children, err := s.Split(r.Context(), id, n, in.Items, in.Join)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	join := in.Join
	if join == "" {
		join = "all"
	}
	reply(w, r, 201, splitText(n, children, join),
		map[string]any{"ok": true, "n": n, "children": children, "join": join},
		doc.GET("/v1/t/"+itoa(n), ""), doc.GET("/v1/t/blocked", ""))
}

func splitText(n int64, children []int64, join string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ok split #%d ->", n)
	for _, c := range children {
		fmt.Fprintf(&b, " #%d", c)
	}
	fmt.Fprintf(&b, " join=%s", join)
	return b.String()
}

// --- ready / blocked lists ---

func (s *Service) hReady(w http.ResponseWriter, r *http.Request)   { s.hListH(w, r, true) }
func (s *Service) hBlocked(w http.ResponseWriter, r *http.Request) { s.hListH(w, r, false) }

func (s *Service) hListH(w http.ResponseWriter, r *http.Request, ready bool) {
	if _, err := s.d.AuthOpt(r); err != nil {
		core.Fail(w, r, err)
		return
	}
	k, _ := strconv.Atoi(r.URL.Query().Get("k"))
	ls, err := s.list(r.Context(), ready, k)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if core.WantJSON(r) {
		core.JSON(w, 200, ls)
		return
	}
	other := "/v1/t/blocked"
	if !ready {
		other = "/v1/t/ready"
	}
	doc.Tail(w, r, fmtList(ls), doc.GET(other, ""), doc.GET("/v1/t", ""))
}

// --- MCP ops ---

type nArg struct {
	N json.RawMessage `json:"n"`
}

func (a nArg) num() (int64, error) {
	s := strings.TrimPrefix(strings.Trim(strings.TrimSpace(string(a.N)), `"`), "#")
	if s == "" {
		return 0, core.Bad("n required")
	}
	return parseN(s)
}

// Ops returns the taskdag MCP operations (tneeds, tsplit, tready).
func Ops(d *core.Deps) map[string]Op {
	s := svc(d)
	return map[string]Op{
		"tneeds": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				nArg
				needsIn
			}
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			n, err := in.num()
			if err != nil {
				return "", err
			}
			if err := s.Needs(ctx, id, n, in.Add, in.Del); err != nil {
				return "", err
			}
			return s.needsLine(ctx, n)
		},
		"tsplit": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				nArg
				splitIn
			}
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			n, err := in.num()
			if err != nil {
				return "", err
			}
			children, err := s.Split(ctx, id, n, in.Items, in.Join)
			if err != nil {
				return "", err
			}
			join := in.Join
			if join == "" {
				join = "all"
			}
			return splitText(n, children, join), nil
		},
		"tready": func(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				K int `json:"k"`
			}
			if err := decodeArgs(a, &in); err != nil {
				return "", err
			}
			ls, err := s.list(ctx, true, in.K)
			if err != nil {
				return "", err
			}
			return fmtList(ls), nil
		},
	}
}

// --- OpenAPI ---

const openAPI = `{"paths":{
"/v1/t/{n}/needs":{"post":{"operationId":"tneeds","summary":"declare or remove prerequisites of a task (creator)","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"add":{"type":"array","items":{"type":"integer"},"maxItems":16},"del":{"type":"array","items":{"type":"integer"},"maxItems":16}}}}}}}},
"/v1/t/{n}/split":{"post":{"operationId":"tsplit","summary":"fan a task out into children with a join rule (holder or creator)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["items"],"properties":{"items":{"type":"array","maxItems":32,"items":{"type":"object","required":["title"],"properties":{"title":{"type":"string","maxLength":160},"body":{"type":"string","maxLength":4000},"tags":{"type":"array","maxItems":8}}}},"join":{"type":"string","description":"all|any|k:<k>"}}}}}}}},
"/v1/t/ready":{"get":{"operationId":"tready","summary":"open tasks that are not blocked and have no live claim"}},
"/v1/t/blocked":{"get":{"operationId":"tblocked","summary":"open tasks with an unfinished prerequisite"}}
}}`
