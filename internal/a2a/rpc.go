package a2a

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"ekaii.fr/commons/internal/core"
)

// JSON-RPC 2.0 framing shared with the hosted endpoints (27.7): body <= 256 KiB, batch <= 10.
const (
	MaxBody  = 256 << 10
	MaxBatch = 10
)

// Error codes: JSON-RPC standard, A2A 0.3 (-32001..-32007) and -32000 carrying our APIError
// (data.err, data.status, data.next).
const (
	CodeParse        = -32700
	CodeInvalid      = -32600
	CodeMethod       = -32601
	CodeParams       = -32602
	CodeInternal     = -32603
	CodeServer       = -32000
	CodeTaskNotFound = -32001
	CodeNotCancel    = -32002
	CodePushUnsup    = -32003
	CodeUnsupported  = -32004
	CodeContentType  = -32005
	CodeNoExtCard    = -32007
)

// Request is one JSON-RPC call. bad marks a batch element that was not an object.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
	bad     bool
}

// Notification reports a call without an id (no response is owed).
func (r *Request) Notification() bool { return len(r.ID) == 0 || string(r.ID) == "null" }

// Error is a JSON-RPC error object; it also travels as a Go error inside the handlers.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("rpc %d %s", e.Code, e.Message) }

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

func rpcErr(code int, msg string, data any) *Error {
	return &Error{Code: code, Message: msg, Data: data}
}

func errResp(id json.RawMessage, e *Error) response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return response{JSONRPC: "2.0", ID: id, Error: e}
}

func okResp(id json.RawMessage, result any) response {
	return response{JSONRPC: "2.0", ID: id, Result: result}
}

// IsBatch reports whether a trimmed body is a JSON array.
func IsBatch(body []byte) bool {
	body = bytes.TrimSpace(body)
	return len(body) > 0 && body[0] == '['
}

// Parse splits a JSON-RPC body into requests: a single object or a batch of 1..MaxBatch. A batch
// element that is not an object comes back with bad set (answered -32600 by the dispatcher); a
// body that is not JSON, an empty batch or an oversized one fail as a whole with an *Error.
func Parse(body []byte) ([]Request, error) {
	body = bytes.TrimSpace(body)
	if len(body) == 0 {
		return nil, rpcErr(CodeParse, "parse error: empty body", nil)
	}
	if !IsBatch(body) {
		var rq Request
		if err := json.Unmarshal(body, &rq); err != nil {
			return nil, rpcErr(CodeParse, "parse error", nil)
		}
		return []Request{rq}, nil
	}
	var raws []json.RawMessage
	if err := json.Unmarshal(body, &raws); err != nil {
		return nil, rpcErr(CodeParse, "parse error", nil)
	}
	if len(raws) == 0 {
		return nil, rpcErr(CodeInvalid, "invalid request: empty batch", nil)
	}
	if len(raws) > MaxBatch {
		return nil, rpcErr(CodeInvalid, fmt.Sprintf("batch too large (max %d)", MaxBatch), nil)
	}
	out := make([]Request, len(raws))
	for i, raw := range raws {
		if err := json.Unmarshal(raw, &out[i]); err != nil || len(bytes.TrimSpace(raw)) == 0 || bytes.TrimSpace(raw)[0] != '{' {
			out[i] = Request{bad: true}
		}
	}
	return out, nil
}

// nextFor is the recovery line of an error (data.next), server-authored like core's.
func nextFor(status int, retry int) []string {
	switch {
	case status == 429 || status == 503:
		return []string{fmt.Sprintf("retry retry_s=%d", retry), "GET /status"}
	case status == 401:
		return []string{"POST /v1/challenge", "GET /help"}
	}
	return []string{"GET /help"}
}

// toRPC maps any handler error to a JSON-RPC error: *Error as-is, *core.APIError to -32000 with
// data {err, status, next} (404 on a task id is the caller's job via taskNotFound), the rest to
// -32603 after logging.
func (s *server) toRPC(err error, method string) *Error {
	var re *Error
	if errors.As(err, &re) {
		return re
	}
	var ae *core.APIError
	if errors.As(err, &ae) {
		retry := 0
		if ae.Status == 429 || ae.Status == 503 {
			retry = 5
		}
		data := map[string]any{"err": ae.Code, "status": ae.Status, "next": nextFor(ae.Status, retry)}
		if retry > 0 {
			data["retry_s"] = retry
		}
		if len(ae.Extra) > 0 {
			data["hint"] = ae.Extra
		}
		return rpcErr(CodeServer, ae.Error(), data)
	}
	var mb *http.MaxBytesError
	if errors.As(err, &mb) {
		return rpcErr(CodeServer, "err size body too large", map[string]any{"err": "size", "status": 413})
	}
	s.d.Log.Error("a2a", "method", method, "err", err)
	return rpcErr(CodeInternal, "err internal internal error", nil)
}

func taskNotFound(id string) *Error {
	return rpcErr(CodeTaskNotFound, "err notfound task "+safe(id, 40), map[string]any{"err": "notfound", "status": 404, "next": []string{"GET /v1/t", "GET /help"}})
}

func notCancelable(id, state string) *Error {
	return rpcErr(CodeNotCancel, "err bad task "+safe(id, 40)+" is "+state, map[string]any{"err": "bad", "status": 409, "next": []string{"GET /t/" + safe(id, 40)[1:], "GET /help"}})
}

func authErr(ae *core.APIError) *Error {
	return rpcErr(CodeServer, ae.Error(), map[string]any{"err": ae.Code, "status": ae.Status, "next": nextFor(ae.Status, 0)})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	w.Write(bytes.TrimRight(b.Bytes(), "\n"))
}
