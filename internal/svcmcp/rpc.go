package svcmcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"ekaii.fr/commons/internal/catalog"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

func base64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

func errResp(id json.RawMessage, code int, msg string) rpcResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: &rpcError{code, msg}}
}

func okResp(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

type toolContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type toolResult struct {
	Content []toolContent `json:"content"`
	IsError bool          `json:"isError"`
}

func textResult(text string, isErr bool) toolResult {
	return toolResult{Content: []toolContent{{"text", strings.TrimRight(text, "\n")}}, IsError: isErr}
}

// loop runs the JSON-RPC 2.0 message (single or batch) for one served version. ident/authErr are
// the resolved caller (nil ident = anonymous: reads work, tools/call returns the join hint).
func (s *server) loop(w http.ResponseWriter, r *http.Request, v *catalog.Version, ident *core.Ident, authErr error) {
	body, err := core.ReadAll(w, r, maxBody)
	if err != nil {
		var ae *core.APIError
		status := 400
		if errors.As(err, &ae) {
			status = ae.Status
		}
		writeJSON(w, status, errResp(nil, -32600, err.Error()))
		return
	}
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		writeJSON(w, 400, errResp(nil, -32700, "parse error: empty body"))
		return
	}
	var reqs []json.RawMessage
	batch := body[0] == '['
	if batch {
		if err := json.Unmarshal(body, &reqs); err != nil {
			writeJSON(w, 400, errResp(nil, -32700, "parse error"))
			return
		}
		if len(reqs) == 0 {
			writeJSON(w, 400, errResp(nil, -32600, "invalid request: empty batch"))
			return
		}
		if len(reqs) > maxBatch {
			writeJSON(w, 400, errResp(nil, -32600, fmt.Sprintf("batch too large (max %d)", maxBatch)))
			return
		}
	} else {
		reqs = []json.RawMessage{body}
	}
	rc := &reqState{r: r, ident: ident, authErr: authErr}
	var out []rpcResponse
	for _, raw := range reqs {
		var rq rpcRequest
		if err := json.Unmarshal(raw, &rq); err != nil {
			if !batch {
				writeJSON(w, 400, errResp(nil, -32700, "parse error"))
				return
			}
			out = append(out, errResp(nil, -32600, "invalid request"))
			continue
		}
		if resp, ok := s.dispatch(r.Context(), &rq, v, rc); ok {
			out = append(out, resp)
		}
	}
	if len(out) == 0 { // only notifications
		w.WriteHeader(http.StatusAccepted)
		return
	}
	if batch {
		writeJSON(w, 200, out)
		return
	}
	writeJSON(w, 200, out[0])
}

// reqState is the per-HTTP-request state shared by the calls of one (possibly batched) message.
type reqState struct {
	r       *http.Request
	ident   *core.Ident
	authErr error
	calls   int // tools/call seen so far; the first is covered by the request token
}

// dispatch handles one JSON-RPC message; ok=false for notifications (no response).
func (s *server) dispatch(ctx context.Context, rq *rpcRequest, v *catalog.Version, rc *reqState) (rpcResponse, bool) {
	isNotif := len(rq.ID) == 0 || string(rq.ID) == "null"
	if strings.HasPrefix(rq.Method, "notifications/") {
		return rpcResponse{}, false
	}
	if rq.Method == "" {
		return errResp(rq.ID, -32600, "invalid request: method required"), !isNotif
	}
	if isNotif {
		return rpcResponse{}, false
	}
	switch rq.Method {
	case "initialize":
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		json.Unmarshal(rq.Params, &p)
		proto := p.ProtocolVersion
		if !protos[proto] {
			proto = defaultProto
		}
		return okResp(rq.ID, map[string]any{
			"protocolVersion": proto,
			"capabilities":    map[string]any{"tools": map[string]any{}},
			"serverInfo":      map[string]string{"name": "agents.ekaii.fr/svc/" + v.Name, "version": version},
			"instructions":    s.instructions(v.Name),
		}), true
	case "ping":
		return okResp(rq.ID, map[string]any{}), true
	case "tools/list":
		return okResp(rq.ID, json.RawMessage(s.cachedList(v))), true
	case "tools/call":
		return okResp(rq.ID, s.toolsCall(ctx, rq.Params, v, rc)), true
	}
	return errResp(rq.ID, -32601, "method not found: "+rq.Method), true
}

// cachedList serves tools/list; an anonymous read is memoised in the byte LRU (TTL listTTL).
func (s *server) cachedList(v *catalog.Version) json.RawMessage {
	key := v.Name + "@" + v.Wasm
	if b, ok := s.cache.Get(key); ok {
		return append([]byte(nil), b...)
	}
	b := s.toolsList(v)
	s.cache.Put(key, b, listTTL)
	return b
}

// toolsCall runs the one tool: it charges the caller and dispatches to catalog.Call on the stable
// version. Anonymous callers get the join/PoW hint; exit != 0 sets isError.
func (s *server) toolsCall(ctx context.Context, params json.RawMessage, v *catalog.Version, rc *reqState) toolResult {
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}
	if err := json.Unmarshal(params, &p); err != nil {
		return textResult("err bad invalid params", true)
	}
	if p.Name != v.Name {
		return textResult("err bad unknown tool "+doc.SafeLine(truncate(p.Name, 64))+" (this server exposes "+v.Name+")", true)
	}
	if rc.authErr != nil {
		return textResult("err auth invalid token", true)
	}
	if rc.ident == nil {
		return textResult(joinHint, true)
	}
	// A batched request charges the limiter for every call past the first (the first is covered by
	// the request token); this stops a batch amplifying one request.
	rc.calls++
	if rc.calls > 1 && !s.d.Allow(rc.r, rc.ident) {
		return textResult(core.ErrRate.Error(), true)
	}
	inText := callInput(v, p.Arguments)
	view, out, err := catalog.Call(ctx, s.d, rc.ident, v.Name, "", inText, "", callWait)
	if err != nil {
		var ae *core.APIError
		switch {
		case errors.As(err, &ae) && ae.Status == 401:
			return textResult(joinHint, true)
		case errors.As(err, &ae):
			return textResult(ae.Error(), true)
		default:
			s.d.Log.Error("svcmcp call", "svc", v.Name, "err", err)
			return textResult("err internal internal error", true)
		}
	}
	switch view.Status {
	case "done":
		return textResult(out, view.Code != 0)
	case "failed":
		return textResult("err run "+doc.SafeLine(view.Reason), true)
	default:
		return textResult(view.Status+" job="+view.ID+" (poll "+doc.Base()+"/v1/j/"+view.ID+")", false)
	}
}

// callInput maps the tool arguments to the service input: the raw JSON when the service declares
// its own input_schema, else the "input" (or "in_text") string of the default schema.
func callInput(v *catalog.Version, args json.RawMessage) string {
	if len(bytes.TrimSpace(v.Manifest.InputSchema)) > 0 {
		return string(bytes.TrimSpace(args))
	}
	var a struct {
		Input  string `json:"input"`
		InText string `json:"in_text"`
	}
	json.Unmarshal(args, &a)
	if a.Input != "" {
		return a.Input
	}
	return a.InText
}

// joinHint is the server-authored auth hint returned when a tools/call arrives without a token.
const joinHint = "err auth 401: this tool charges credits and needs a token. Get one: POST /v1/challenge then POST /v1/register {c,nonce,name} (proof of work), or `cx join <name>`, and put it in the MCP client's Authorization: Bearer header (or mint a url-class token and use /mcp/svc/<name>/t/<token>)."

func writeJSON(w http.ResponseWriter, status int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(bytes.TrimRight(b.Bytes(), "\n"))
}
