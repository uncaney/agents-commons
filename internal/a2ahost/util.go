package a2ahost

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"

	"ekaii.fr/commons/internal/a2a"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// JSON-RPC response framing (local; the request parsing is reused from internal/a2a).
type rpcResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *a2a.Error      `json:"error,omitempty"`
}

func rpcErr(code int, msg string, data any) *a2a.Error {
	return &a2a.Error{Code: code, Message: msg, Data: data}
}

func errResp(id json.RawMessage, e *a2a.Error) rpcResponse {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return rpcResponse{JSONRPC: "2.0", ID: id, Error: e}
}

func okResp(id json.RawMessage, result any) rpcResponse {
	return rpcResponse{JSONRPC: "2.0", ID: id, Result: result}
}

// apiToRPC maps an APIError (or plain error) to a -32000 server error carrying {err, status, next}.
func apiToRPC(err error) *a2a.Error {
	var re *a2a.Error
	if errors.As(err, &re) {
		return re
	}
	var ae *core.APIError
	if errors.As(err, &ae) {
		return rpcErr(a2a.CodeServer, ae.Error(), map[string]any{"err": ae.Code, "status": ae.Status, "next": []string{"GET /help"}})
	}
	return rpcErr(a2a.CodeInternal, "err internal internal error", nil)
}

func taskNotFound(id string) *a2a.Error {
	return rpcErr(a2a.CodeTaskNotFound, "err notfound task "+safe(id, 40), map[string]any{"err": "notfound", "status": 404})
}

// writeRPC writes a JSON-RPC response (single or batch) with HTML escaping off.
func writeRPC(w http.ResponseWriter, status int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Robots-Tag", "noindex")
	w.WriteHeader(status)
	w.Write(bytes.TrimRight(b.Bytes(), "\n"))
}

// writeJSON writes a plain JSON document (agent.json) with a short public cache and an ETag.
func writeJSON(w http.ResponseWriter, r *http.Request, status int, v any) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v)
	body := bytes.TrimRight(b.Bytes(), "\n")
	h := w.Header()
	h.Set("Content-Type", "application/json")
	h.Set("Cache-Control", "public, max-age=300")
	et := doc.ETag(body)
	h.Set("ETag", et)
	if match := r.Header.Get("If-None-Match"); match == et {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// safe is a one-line, length-capped rendering of client text for error messages.
func safe(s string, n int) string {
	s = doc.SafeLine(s)
	if len(s) > n {
		s = s[:n]
	}
	return s
}
