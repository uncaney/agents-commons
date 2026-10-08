package doc

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http/httptest"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
)

const kbSchema = `{"type":"object","required":["title"],"properties":{
	"kind":{"type":"string","enum":["fix","status","note"]},"title":{"type":"string","maxLength":160},"symptom":{"type":"string"},
	"cause":{"type":"string"},"fix":{"type":"string"},"versions":{"type":"string"},"tags":{"type":"array","items":{"type":"string"},"maxItems":10},
	"force":{"type":"boolean"},"saved":{"type":"integer"},"ids":{"type":"array","items":{"type":"integer"}},"meta":{"type":"object"}}}`

func parse(t *testing.T, method, ct, body string) (map[string]any, error) {
	t.Helper()
	r := httptest.NewRequest(method, "/v1/kb", strings.NewReader(body))
	if ct != "" {
		r.Header.Set("Content-Type", ct)
	}
	raw, err := Parse(r, json.RawMessage(kbSchema))
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("Parse returned invalid JSON %q: %v", raw, err)
	}
	return m, nil
}

func status(err error) (int, string) {
	var ae *core.APIError
	if errors.As(err, &ae) {
		return ae.Status, ae.Msg
	}
	return 0, ""
}

func TestParseTextGrammarRoundTrip(t *testing.T) {
	// GET /k/<id>.txt minus head/next is a valid POST /v1/kb body.
	d := &Doc{Head: "k7x2a9q fix ok3 bad0 2026-10-06 by a3fz9qk", Fields: []F{
		{"kind", "fix", false}, {"title", "ECONNRESET on keep-alive", false}, {"symptom", "socket hang up\n\nafter 5s", true},
		{"fix", "set agent:\n  keepAlive: true\n```\nnpm i\n```", true}, {"versions", "node@22", false}, {"tags", "node, http", false},
		{"force", "true", false}, {"saved", "1200", false}, {"ids", "1,2,3", false}, {"meta", `{"a":1}`, false},
	}, Next: []Action{POST("/v1/kb/k7x2a9q/ok", "")}}
	txt := get(t, "/k/k7x2a9q", nil, d).Body.String()
	got, err := parse(t, "POST", "text/plain; charset=utf-8", txt)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := map[string]any{"kind": "fix", "title": "ECONNRESET on keep-alive", "symptom": "socket hang up\n\nafter 5s",
		"fix": "set agent:\n  keepAlive: true\n```\nnpm i\n```", "versions": "node@22", "tags": []any{"node", "http"},
		"force": true, "saved": float64(1200), "ids": []any{float64(1), float64(2), float64(3)}, "meta": map[string]any{"a": float64(1)}}
	gj, _ := json.Marshal(got)
	wj, _ := json.Marshal(want)
	if string(gj) != string(wj) {
		t.Errorf("round trip:\n%s\nwant\n%s\nfrom\n%s", gj, wj, txt)
	}
	// Key order follows the body.
	r := httptest.NewRequest("POST", "/v1/kb", strings.NewReader("title: a\nfix: b\n"))
	r.Header.Set("Content-Type", "text/plain")
	raw, _ := Parse(r, json.RawMessage(kbSchema))
	if string(raw) != `{"title":"a","fix":"b"}` {
		t.Errorf("order: %s", raw)
	}
	// A body starting directly with fields (no head) parses; CRLF accepted; a copied reply's
	// head, next: and … lines are ignored (a first line shaped like a field is a field).
	for body, wantTitle := range map[string]string{
		"title: direct\r\nfix: x\r\n":                                  "direct",
		"k7x fix ok3\ntitle: after head\nnext: GET /x\n":               "after head",
		"k7x fix ok3 bad0\ntitle: t\n… +3 more: /k/k7x?b=0\nnext: x\n": "t",
	} {
		m, err := parse(t, "POST", "text/plain", body)
		if err != nil || m["title"] != wantTitle {
			t.Errorf("%q: %v %v", body, m, err)
		}
	}
	// Errors.
	cases := []struct {
		body, msg string
	}{
		{"title: a\ntitle: b\n", "dup field title"},
		{"title: a\nbogus: b\n", "bad field bogus"},
		{"title: a\nk7x 0.9 fix row\n", "bad line 2"},
		{"title: a\nTitle2: b\n", "bad line 2"},
		{"head\n  orphan continuation\n", "bad line 2"},
		{"title: a\nsaved: lots\n", "bad field saved: integer expected"},
		{"title: a\nforce: maybe\n", "bad field force: boolean expected"},
		{"title: a\nids: 1,x\n", "bad field ids: integer items expected"},
		{"title: a\nmeta: nope\n", "bad field meta: JSON object expected"},
		{"title: a\ntags: " + strings.Repeat("t,", 11) + "\n", "bad field tags: at most 10 items"},
		{strings.Repeat("x\n", 2001), "too many lines"},
	}
	for _, c := range cases {
		_, err := parse(t, "POST", "text/plain", c.body)
		if st, msg := status(err); st != 422 || msg != c.msg {
			t.Errorf("%q: got %d %q want 422 %q", c.body, st, msg, c.msg)
		}
	}
	var many strings.Builder
	for i := 0; i < 33; i++ {
		many.WriteString("f" + strings.Repeat("a", i%5) + string(rune('a'+i%26)) + ": v\n")
	}
	r = httptest.NewRequest("POST", "/v1/kb", strings.NewReader(many.String()))
	r.Header.Set("Content-Type", "text/plain")
	if _, err := Parse(r, json.RawMessage(`{"type":"object","additionalProperties":true}`)); err == nil || !strings.Contains(err.Error(), "too many fields") {
		t.Errorf("33 fields: %v", err)
	}
	// Hyphenated names map to underscores; names with digits are rejected.
	m, err := parse(t, "POST", "text/plain", "title: a\nwhy-safe: ok\n")
	if st, _ := status(err); st != 422 {
		t.Errorf("why-safe -> why_safe unknown here: %v %v", m, err)
	}
	if _, err := parse(t, "POST", "text/plain", "title: a\nf1: x\n"); err == nil {
		t.Errorf("digits in names accepted")
	}
	// Forms.
	m, err = parse(t, "POST", "application/x-www-form-urlencoded", "title=a+b&tags=x&tags=y&force=on&saved=3")
	if err != nil || m["title"] != "a b" || len(m["tags"].([]any)) != 2 || m["force"] != true || m["saved"] != float64(3) {
		t.Errorf("form: %v %v", m, err)
	}
	if _, err := parse(t, "POST", "application/x-www-form-urlencoded", "title=a&title=b"); err == nil {
		t.Errorf("repeated string field in form accepted")
	}
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	mw.WriteField("title", "multi part")
	mw.WriteField("tags", "a")
	mw.WriteField("tags", "b")
	mw.Close()
	m, err = parse(t, "POST", mw.FormDataContentType(), mp.String())
	if err != nil || m["title"] != "multi part" || len(m["tags"].([]any)) != 2 {
		t.Errorf("multipart: %v %v", m, err)
	}
	mp.Reset()
	mw = multipart.NewWriter(&mp)
	fw, _ := mw.CreateFormFile("fix", "x.txt")
	fw.Write([]byte("data"))
	mw.Close()
	if _, err := parse(t, "POST", mw.FormDataContentType(), mp.String()); err == nil || !strings.Contains(err.Error(), "files not accepted") {
		t.Errorf("multipart file: %v", err)
	}
	// Query parameters: POST/PATCH only, lowest precedence, schema fields only.
	r = httptest.NewRequest("POST", "/v1/kb?title=fromquery&force=1&f=json&bogus=1", strings.NewReader("title: frombody\n"))
	r.Header.Set("Content-Type", "text/plain")
	raw, err = Parse(r, json.RawMessage(kbSchema))
	if err != nil || string(raw) != `{"title":"frombody","force":true}` {
		t.Errorf("query merge: %s %v", raw, err)
	}
	r = httptest.NewRequest("GET", "/v1/kb?title=fromquery", strings.NewReader(""))
	r.Header.Set("Content-Type", "text/plain")
	if raw, _ := Parse(r, json.RawMessage(kbSchema)); string(raw) != "{}" {
		t.Errorf("GET query ignored: %s", raw)
	}
	// Content type sniffing and JSON passthrough.
	m, err = parse(t, "POST", "", "title: sniffed\n")
	if err != nil || m["title"] != "sniffed" {
		t.Errorf("sniff text: %v %v", m, err)
	}
	if raw, err := Parse(httptest.NewRequest("POST", "/v1/kb", strings.NewReader(` {"title":"j","x":1}`)), json.RawMessage(kbSchema)); err != nil || string(raw) != ` {"title":"j","x":1}` {
		t.Errorf("sniff json passthrough: %s %v", raw, err)
	}
	if _, err := parse(t, "POST", "application/json", "{bad"); err == nil {
		t.Errorf("invalid json accepted")
	}
	if _, err := parse(t, "POST", "image/png", "x"); err == nil {
		t.Errorf("unknown content type accepted")
	} else if st, _ := status(err); st != 415 {
		t.Errorf("unknown content type: %v", err)
	}
	// Without a schema every field is a string; MaxBytes overflow maps to size.
	raw, err = Parse(httptest.NewRequest("POST", "/x", strings.NewReader("a: 1\nb: x\n")), nil)
	if err != nil || string(raw) != `{"a":"1","b":"x"}` {
		t.Errorf("schemaless: %s %v", raw, err)
	}
	r = httptest.NewRequest("POST", "/v1/kb", strings.NewReader(strings.Repeat("x", 100)))
	r.Header.Set("Content-Type", "text/plain")
	core.MaxBytes(httptest.NewRecorder(), r, 10)
	if _, err := Parse(r, nil); !errors.Is(err, core.ErrSize) {
		t.Errorf("MaxBytes overflow: %v", err)
	}
	// Compile accepts schema, requestBody and operation shapes.
	for _, raw := range []string{kbSchema, `{"requestBody":{"content":{"text/plain":{"schema":` + kbSchema + `}}}}`, `{"content":{"application/json":{"schema":` + kbSchema + `}}}`} {
		if s := Compile(json.RawMessage(raw)); len(s.Props) != 11 || s.Props[1].Name != "title" || !s.Props[1].Required || s.Props[1].Max != 160 {
			t.Errorf("Compile(%s): %+v", raw[:20], s.Props)
		}
	}
	if s := Compile(nil); !s.Additional {
		t.Errorf("nil schema must be permissive")
	}
	// SchemaFor matches templates, wildcards and query-less paths.
	ResetSchemas()
	defer ResetSchemas()
	RegisterSchema("post", "/v1/kv/{ns}/{k...}", json.RawMessage(kbSchema))
	RegisterSchema("PUT", "/d/{secret}", json.RawMessage(`{"type":"object"}`))
	for _, c := range []struct {
		m, p string
		ok   bool
	}{{"POST", "/v1/kv/ns1/a/b/c", true}, {"POST", "/v1/kv/ns1", false}, {"PUT", "/d/abc?x=1", true}, {"GET", "/d/abc", false}, {"PUT", "/d/abc/def", false}} {
		if _, ok := SchemaFor(c.m, c.p); ok != c.ok {
			t.Errorf("SchemaFor(%s %s) = %v", c.m, c.p, ok)
		}
	}
}
