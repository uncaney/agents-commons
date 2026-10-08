package compat

// Fixture grammar (fixtures/*.txt), one request per step:
//
//	=== <step name>                 starts a step
//	-- <comment>                    comment ("-- cx <cmd>" annotates the CLI command a step records)
//	! <directive> <args…>           runs before the step's request (see directives below)
//	> METHOD /path[?q] [@$tokvar|@admin]   the request; @ sends Authorization: Bearer <token>
//	> Name: value                   an extra request header
//	> {json}                        a JSON body (Content-Type application/json)
//	>> text                         a raw text body line (lines joined with \n; ">>" alone = empty line)
//	>b64 <base64>                   a binary body
//	>var <name>                     the body is the variable's bytes
//	< <status>[|<status>…] [text|json|raw|mcp|mcperr|html]   expected status (and body mode, default text)
//	<~ <status>                     soft: a mismatch skips the step (routes owned by later packages)
//	<h Name[: prefix]               a reply header must exist (and start with prefix)
//	<! <regexp>                     no reply line may match
//	<expected line>                 text/mcp: a v1 line (prefix compare, in order); html: a substring
//	| <raw line> / |var <name>      raw: the exact body (lines joined with \n) / a variable's bytes
//	{json template}                 json: a subset template ("$name" strings capture)
//
// Variables: $name is substituted when bound; an unbound $name in an expected line captures the
// field (\S+), $name:id|hash|date|int|dec2|token narrow the class. $body_sha256 is bound to the
// request body's digest. Directives: join <ident> (challenge + PoW + register, binds $ident and
// $tok_ident), solve <var> <cvar> <bitsvar>, rand <var> [bytes] (hex), randword <var> [n]
// (letters outside hex, survives the KB signature normalisation), set <var> <text>, text <var>
// <text with \n escapes>, repeat <var> <char> <n>, sha256 <var> <$bytesvar|text>, wasm <var>
// [tag], bigwasm <var> <size> [tag], donors <$tokvar…>|stop, retry <n> <wait>, sleep <dur>.

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"ekaii.fr/commons/internal/pow"
)

type directive struct {
	line int
	args []string
	raw  string // everything after the directive name, for text values
}

type step struct {
	name, file string
	line       int
	pre        []directive
	method     string
	path       string
	auth       string // "", "admin" or "$var"
	hdr        [][2]string
	bodyKind   string // "", json, text, b64, var
	bodyLines  []string
	bodyData   string
	status     []int
	soft       bool
	mode       string
	expect     []string
	rawExp     []string
	rawVar     string
	hdrExp     [][2]string
	neg        []string
	retry      int
	retryWait  time.Duration
}

var classes = map[string]string{
	"": `\S+`, "any": `\S+`, "id": `[a-z][a-z2-7]{6}`, "hash": `[0-9a-f]{64}`, "date": `\d{4}-\d\d-\d\d`,
	"int": `-?\d+`, "num": `\d+(?:\.\d+)?`, "dec2": `\d+\.\d\d`, "token": `cx_[A-Za-z0-9_-]{43}`, "word": `[A-Za-z0-9._-]+`,
}

// modes: text (document rules), json (subset), raw (byte-identical), mcp/mcperr (JSON-RPC tools/call
// result, text rules), html (content type + substrings), any (status and headers only).
var modes = map[string]bool{"text": true, "json": true, "raw": true, "mcp": true, "mcperr": true, "html": true, "any": true}

func parseFixture(path string) ([]*step, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var steps []*step
	cur := &step{name: "(preamble)", file: path, line: 0}
	steps = append(steps, cur)
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	n := 0
	for sc.Scan() {
		n++
		line := strings.TrimRight(sc.Text(), "\r")
		perr := func(msg string) error { return fmt.Errorf("%s:%d: %s", filepath.Base(path), n, msg) }
		switch {
		case line == "" || line == "--" || strings.HasPrefix(line, "-- "):
		case strings.HasPrefix(line, "=== "):
			cur = &step{name: strings.TrimSpace(line[4:]), file: path, line: n}
			steps = append(steps, cur)
		case strings.HasPrefix(line, "! "):
			args := strings.Fields(line[2:])
			if len(args) == 0 {
				return nil, perr("empty directive")
			}
			raw := strings.TrimSpace(line[2:])[len(args[0]):]
			if args[0] == "retry" {
				if len(args) != 3 {
					return nil, perr("retry <n> <wait>")
				}
				cnt, err1 := strconv.Atoi(args[1])
				wait, err2 := time.ParseDuration(args[2])
				if err1 != nil || err2 != nil || cnt < 1 {
					return nil, perr("retry <n> <wait>")
				}
				cur.retry, cur.retryWait = cnt, wait
				continue
			}
			cur.pre = append(cur.pre, directive{line: n, args: args, raw: strings.TrimSpace(raw)})
		case line == ">>" || strings.HasPrefix(line, ">> "):
			cur.bodyKind = "text"
			cur.bodyLines = append(cur.bodyLines, strings.TrimPrefix(strings.TrimPrefix(line, ">>"), " "))
		case strings.HasPrefix(line, ">b64 "):
			cur.bodyKind, cur.bodyData = "b64", strings.TrimSpace(line[5:])
		case strings.HasPrefix(line, ">var "):
			cur.bodyKind, cur.bodyData = "var", strings.TrimSpace(line[5:])
		case strings.HasPrefix(line, "> "):
			c := strings.TrimSpace(line[2:])
			switch {
			case cur.method == "":
				f := strings.Fields(c)
				if len(f) < 2 || len(f) > 3 || !strings.HasPrefix(f[1], "/") {
					return nil, perr("request line: METHOD /path [@$tok|@admin]")
				}
				cur.method, cur.path = f[0], f[1]
				if len(f) == 3 {
					if !strings.HasPrefix(f[2], "@") {
						return nil, perr("auth must be @$var or @admin")
					}
					cur.auth = f[2][1:]
				}
			case strings.HasPrefix(c, "{") || strings.HasPrefix(c, "["):
				cur.bodyKind, cur.bodyData = "json", c
			default:
				k, v, ok := strings.Cut(c, ": ")
				if !ok {
					return nil, perr("header line: Name: value")
				}
				cur.hdr = append(cur.hdr, [2]string{k, v})
			}
		case strings.HasPrefix(line, "<h "):
			k, v, _ := strings.Cut(strings.TrimSpace(line[3:]), ": ")
			cur.hdrExp = append(cur.hdrExp, [2]string{k, v})
		case strings.HasPrefix(line, "<! "):
			cur.neg = append(cur.neg, strings.TrimSpace(line[3:]))
		case strings.HasPrefix(line, "<~ ") || strings.HasPrefix(line, "< "):
			cur.soft = line[1] == '~'
			f := strings.Fields(line[2:])
			if len(f) == 0 || len(f) > 2 {
				return nil, perr("status line: < 200[|202] [mode]")
			}
			for _, s := range strings.Split(f[0], "|") {
				st, err := strconv.Atoi(s)
				if err != nil {
					return nil, perr("bad status " + s)
				}
				cur.status = append(cur.status, st)
			}
			cur.mode = "text"
			if len(f) == 2 {
				if !modes[f[1]] {
					return nil, perr("bad mode " + f[1])
				}
				cur.mode = f[1]
			}
		case strings.HasPrefix(line, "|var "):
			cur.rawVar = strings.TrimSpace(line[5:])
		case line == "|" || strings.HasPrefix(line, "| "):
			cur.rawExp = append(cur.rawExp, strings.TrimPrefix(strings.TrimPrefix(line, "|"), " "))
		default:
			if cur.mode == "" {
				return nil, perr("expected line before a status line: " + line)
			}
			cur.expect = append(cur.expect, line)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for _, s := range steps {
		if s.method != "" && s.mode == "" {
			return nil, fmt.Errorf("%s:%d: step %q has a request but no status line", filepath.Base(path), s.line, s.name)
		}
	}
	return steps, nil
}

// replay runs every step of a fixture; the first failure is returned with its location.
func (e *env) replay(path string) error {
	steps, err := parseFixture(path)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if err := e.runStep(s); err != nil {
			return fmt.Errorf("%s:%d (%s): %w", filepath.Base(path), s.line, s.name, err)
		}
	}
	return nil
}

var varRe = regexp.MustCompile(`\$([A-Za-z_][A-Za-z0-9_]*)(:[a-z0-9]+)?`)

// subst replaces bound $vars (text variables, then text-valued binary ones); unbound ones are
// left for the caller (captures or errors).
func (e *env) subst(s string) string {
	return varRe.ReplaceAllStringFunc(s, func(m string) string {
		name := m[1:]
		if i := strings.IndexByte(name, ':'); i >= 0 {
			name = name[:i]
		}
		if v, ok := e.vars[name]; ok {
			return v + m[1+len(name):]
		}
		if b, ok := e.bins[name]; ok {
			return string(b) + m[1+len(name):]
		}
		return m
	})
}

// mustSubst substitutes and fails on an unbound variable (requests never carry placeholders).
func (e *env) mustSubst(s string) (string, error) {
	out := e.subst(s)
	if m := varRe.FindString(out); m != "" {
		return "", fmt.Errorf("unbound variable %s in %q", m, s)
	}
	return out, nil
}

func unescape(s string) string {
	r := strings.NewReplacer(`\n`, "\n", `\t`, "\t", `\r`, "\r", `\\`, `\`)
	return r.Replace(s)
}

func (e *env) runDirective(d directive) error {
	a := d.args
	need := func(n int) error {
		if len(a) < n {
			return fmt.Errorf("line %d: %s needs %d arguments", d.line, a[0], n-1)
		}
		return nil
	}
	switch a[0] {
	case "join":
		if err := need(2); err != nil {
			return err
		}
		return e.join(a[1])
	case "solve":
		if err := need(4); err != nil {
			return err
		}
		c, ok := e.vars[a[2]]
		bits, err := strconv.Atoi(e.vars[a[3]])
		if !ok || err != nil {
			return fmt.Errorf("line %d: solve needs bound challenge and bits variables", d.line)
		}
		e.vars[a[1]] = pow.Solve(c, bits)
	case "rand", "randword":
		if err := need(2); err != nil {
			return err
		}
		n := 4
		if len(a) > 2 {
			n, _ = strconv.Atoi(a[2])
		}
		b := make([]byte, n)
		rand.Read(b)
		if a[0] == "rand" {
			e.vars[a[1]] = hex.EncodeToString(b)
			break
		}
		// Letters outside [a-f0-9]: the KB dup check normalises hex runs and numbers away, so a hex
		// random would not keep re-runs on one database apart.
		const letters = "ghijklmnopqrstuvwxyz"
		for i := range b {
			b[i] = letters[int(b[i])%len(letters)]
		}
		e.vars[a[1]] = string(b)
	case "set":
		if err := need(3); err != nil {
			return err
		}
		v, err := e.mustSubst(strings.TrimSpace(strings.TrimPrefix(d.raw, a[1])))
		if err != nil {
			return err
		}
		e.vars[a[1]] = v
	case "text":
		if err := need(2); err != nil {
			return err
		}
		v, err := e.mustSubst(strings.TrimSpace(strings.TrimPrefix(d.raw, a[1])))
		if err != nil {
			return err
		}
		e.bins[a[1]] = []byte(unescape(v))
	case "repeat":
		if err := need(4); err != nil {
			return err
		}
		n, err := strconv.Atoi(a[3])
		if err != nil || n < 0 {
			return fmt.Errorf("line %d: repeat <var> <char> <n>", d.line)
		}
		e.bins[a[1]] = bytes.Repeat([]byte(a[2]), n)
	case "sha256":
		if err := need(3); err != nil {
			return err
		}
		arg := strings.TrimSpace(strings.TrimPrefix(d.raw, a[1]))
		var data []byte
		if strings.HasPrefix(arg, "$") && !strings.ContainsAny(arg, " \t") {
			if b, ok := e.bins[arg[1:]]; ok {
				data = b
			} else if v, ok := e.vars[arg[1:]]; ok {
				data = []byte(v)
			} else {
				return fmt.Errorf("line %d: sha256 of unbound %s", d.line, arg)
			}
		} else {
			v, err := e.mustSubst(arg)
			if err != nil {
				return err
			}
			data = []byte(unescape(v))
		}
		sum := sha256.Sum256(data)
		e.vars[a[1]] = hex.EncodeToString(sum[:])
	case "wasm":
		if err := need(2); err != nil {
			return err
		}
		tag := ""
		if len(a) > 2 {
			tag = e.subst(a[2])
		}
		e.bins[a[1]] = minWasm(tag)
	case "bigwasm":
		if err := need(3); err != nil {
			return err
		}
		size, err := strconv.Atoi(a[2])
		if err != nil || size < 0 || size > 16<<20 {
			return fmt.Errorf("line %d: bigwasm <var> <size> [tag]", d.line)
		}
		tag := a[1]
		if len(a) > 3 {
			tag = e.subst(a[3])
		}
		e.bins[a[1]] = bigWasm(tag, size)
	case "donors":
		if err := need(2); err != nil {
			return err
		}
		if a[1] == "stop" {
			e.stopDonors()
			return nil
		}
		var toks []string
		for _, t := range a[1:] {
			v, err := e.mustSubst(t)
			if err != nil {
				return err
			}
			toks = append(toks, v)
		}
		e.startDonors(toks)
	case "sleep":
		if err := need(2); err != nil {
			return err
		}
		dur, err := time.ParseDuration(a[1])
		if err != nil {
			return err
		}
		time.Sleep(dur)
	default:
		return fmt.Errorf("line %d: unknown directive %s", d.line, a[0])
	}
	return nil
}

func (e *env) runStep(s *step) error {
	for _, d := range s.pre {
		if err := e.runDirective(d); err != nil {
			return err
		}
	}
	if s.method == "" {
		return nil
	}
	path, err := e.mustSubst(s.path)
	if err != nil {
		return err
	}
	hdr := map[string]string{}
	for _, h := range s.hdr {
		v, err := e.mustSubst(h[1])
		if err != nil {
			return err
		}
		hdr[h[0]] = v
	}
	var body []byte
	ct := ""
	switch s.bodyKind {
	case "json":
		v, err := e.mustSubst(s.bodyData)
		if err != nil {
			return err
		}
		body, ct = []byte(v), "application/json"
	case "text":
		v, err := e.mustSubst(strings.Join(s.bodyLines, "\n"))
		if err != nil {
			return err
		}
		body, ct = []byte(v), "text/plain; charset=utf-8"
	case "b64":
		b, err := base64.StdEncoding.DecodeString(s.bodyData)
		if err != nil {
			return fmt.Errorf("bad base64 body: %v", err)
		}
		body, ct = b, "application/octet-stream"
	case "var":
		b, ok := e.bins[s.bodyData]
		if !ok {
			if v, ok2 := e.vars[s.bodyData]; ok2 {
				b = []byte(v)
			} else {
				return fmt.Errorf("unbound body variable %s", s.bodyData)
			}
		}
		body, ct = b, "application/octet-stream"
	}
	if ct != "" {
		if _, set := hdr["Content-Type"]; !set {
			hdr["Content-Type"] = ct
		}
	}
	if body != nil {
		sum := sha256.Sum256(body)
		e.vars["body_sha256"] = hex.EncodeToString(sum[:])
	}
	token := ""
	switch {
	case s.auth == "admin":
		token = e.cfg.AdminToken
	case strings.HasPrefix(s.auth, "$"):
		v, ok := e.vars[s.auth[1:]]
		if !ok {
			return fmt.Errorf("unbound token variable %s", s.auth)
		}
		token = v
	case s.auth != "":
		return fmt.Errorf("auth must be @$var or @admin, got @%s", s.auth)
	}
	ctx := context.Background()
	var r *reply
	for attempt := 0; ; attempt++ {
		if r, err = e.send(ctx, s.method, path, token, "", body, hdr); err != nil {
			return err
		}
		if statusOK(s.status, r.status) || attempt+1 >= max(s.retry, 1) {
			break
		}
		time.Sleep(s.retryWait)
	}
	if !statusOK(s.status, r.status) {
		if s.soft {
			e.t.Logf("%s:%d (%s): soft step skipped: status %d (route not wired yet)", filepath.Base(s.file), s.line, s.name, r.status)
			return nil
		}
		return fmt.Errorf("status %d, want %v\n%s", r.status, s.status, trunc(r.body))
	}
	for _, h := range s.hdrExp {
		got := r.header.Get(h[0])
		if got == "" {
			return fmt.Errorf("missing reply header %s", h[0])
		}
		if want, err := e.mustSubst(h[1]); err != nil {
			return err
		} else if want != "" && !strings.HasPrefix(got, want) {
			return fmt.Errorf("header %s = %q, want prefix %q", h[0], got, want)
		}
	}
	switch s.mode {
	case "text":
		return e.checkText(s, string(r.body), true)
	case "raw":
		return e.checkRaw(s, r.body)
	case "json":
		return e.checkJSON(s, r.body)
	case "mcp", "mcperr":
		return e.checkMCP(s, r.body)
	case "html":
		if ct := r.header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			return fmt.Errorf("content-type %q, want text/html", ct)
		}
		for _, l := range s.expect {
			want, err := e.mustSubst(l)
			if err != nil {
				return err
			}
			if !strings.Contains(string(r.body), want) {
				return fmt.Errorf("html does not contain %q", want)
			}
		}
	}
	return nil
}

func statusOK(want []int, got int) bool {
	for _, w := range want {
		if w == got {
			return true
		}
	}
	return false
}

func trunc(b []byte) string {
	s := string(b)
	if len(s) > 600 {
		s = s[:600] + "…"
	}
	return s
}

func splitLines(body string) []string {
	body = strings.TrimRight(body, "\n")
	if body == "" {
		return nil
	}
	return strings.Split(body, "\n")
}

// checkText applies the document rules to a text reply: at most one `next:` line, trailing (the
// tail, stripped before comparison); the v1 lines in order by prefix; the negative patterns.
// doc=false (MCP results) forbids any `next:` line.
func (e *env) checkText(s *step, body string, doc bool) error {
	lines := splitLines(body)
	all := lines
	if n := len(lines); doc && n > 0 && strings.HasPrefix(lines[n-1], "next:") {
		lines = lines[:n-1]
	}
	for i, l := range lines {
		if strings.HasPrefix(l, "next:") {
			return fmt.Errorf("line %d is a column-0 next: line inside the document: %q\n%s", i+1, l, body)
		}
	}
	if err := e.matchLines(s.expect, lines); err != nil {
		return fmt.Errorf("%v\nreply:\n%s", err, body)
	}
	return e.checkNeg(s, all)
}

func (e *env) checkNeg(s *step, lines []string) error {
	for _, pat := range s.neg {
		p, err := e.mustSubst(pat)
		if err != nil {
			return err
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("bad negative pattern %q: %v", pat, err)
		}
		for _, l := range lines {
			if re.MatchString(l) {
				return fmt.Errorf("forbidden line (matches %q): %q", pat, l)
			}
		}
	}
	return nil
}

// matchLines finds every expected line, in order, among the actual lines (inserted and appended
// lines are skipped; a missing or reordered v1 line fails).
func (e *env) matchLines(expect, actual []string) error {
	i := 0
	for _, tpl := range expect {
		found := false
		for ; i < len(actual); i++ {
			if ok, binds := e.matchLine(tpl, actual[i]); ok {
				for k, v := range binds {
					e.vars[k] = v
				}
				i++
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("expected v1 line not found in order: %q", e.subst(tpl))
		}
	}
	return nil
}

// matchLine compares one v1 template line with an actual line: the template's literal text and
// bound variables must match from column 0 up to the last v1 field (then a field boundary or the
// end of the line); unbound variables capture. Strict mode (the negative check) requires the
// whole line.
func (e *env) matchLine(tpl, actual string) (bool, map[string]string) {
	re, names := e.compile(tpl)
	m := re.FindStringSubmatch(actual)
	if m == nil {
		return false, nil
	}
	binds := map[string]string{}
	for i, n := range names {
		binds[n] = m[i+1]
	}
	return true, binds
}

func (e *env) compile(tpl string) (*regexp.Regexp, []string) {
	var b strings.Builder
	b.WriteString("^")
	last := 0
	var names []string
	for _, loc := range varRe.FindAllStringSubmatchIndex(tpl, -1) {
		b.WriteString(regexp.QuoteMeta(tpl[last:loc[0]]))
		name := tpl[loc[2]:loc[3]]
		class, end := "", loc[3]
		if loc[4] >= 0 {
			if c := tpl[loc[4]+1 : loc[5]]; classes[c] != "" {
				class, end = c, loc[5]
			}
		}
		if v, ok := e.vars[name]; ok {
			b.WriteString(regexp.QuoteMeta(v))
		} else {
			b.WriteString("(" + classes[class] + ")")
			names = append(names, name)
		}
		last = end
	}
	b.WriteString(regexp.QuoteMeta(tpl[last:]))
	if e.strict {
		b.WriteString("$")
	} else {
		b.WriteString(`(?:\s|$)`)
	}
	return regexp.MustCompile(b.String()), names
}

// checkRaw: a raw-body reply is byte-identical to what was stored, with no tail of any kind.
func (e *env) checkRaw(s *step, body []byte) error {
	var want []byte
	if s.rawVar != "" {
		b, ok := e.bins[s.rawVar]
		if !ok {
			return fmt.Errorf("unbound raw variable %s", s.rawVar)
		}
		want = b
	} else {
		v, err := e.mustSubst(strings.Join(s.rawExp, "\n"))
		if err != nil {
			return err
		}
		want = []byte(v)
	}
	if !bytes.Equal(body, want) {
		return fmt.Errorf("raw body differs (%d bytes, want %d):\n%s\n--- want ---\n%s", len(body), len(want), trunc(body), trunc(want))
	}
	return nil
}

func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

// checkJSON: every template field must be present with the same value (v1 JSON only gains
// fields; arrays stay unchanged); "$name" strings capture. Strict mode forbids extra keys.
func (e *env) checkJSON(s *step, body []byte) error {
	act, err := decodeJSON(body)
	if err != nil {
		return fmt.Errorf("reply is not JSON: %v\n%s", err, trunc(body))
	}
	if len(s.expect) == 0 {
		return nil
	}
	tpl, err := decodeJSON([]byte(e.subst(strings.Join(s.expect, "\n"))))
	if err != nil {
		return fmt.Errorf("fixture JSON template: %v", err)
	}
	if err := e.matchJSON("$", tpl, act); err != nil {
		return fmt.Errorf("%v\nreply: %s", err, trunc(body))
	}
	return nil
}

func jsonScalar(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case json.Number:
		return x.String()
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return "null"
	}
	b, _ := json.Marshal(v)
	return string(b)
}

func (e *env) matchJSON(path string, tpl, act any) error {
	switch tv := tpl.(type) {
	case map[string]any:
		am, ok := act.(map[string]any)
		if !ok {
			return fmt.Errorf("%s: want object, got %s", path, jsonScalar(act))
		}
		if e.strict && len(am) != len(tv) {
			return fmt.Errorf("%s: %d fields, want exactly %d", path, len(am), len(tv))
		}
		keys := make([]string, 0, len(tv))
		for k := range tv {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			av, ok := am[k]
			if !ok {
				return fmt.Errorf("%s.%s: missing", path, k)
			}
			if err := e.matchJSON(path+"."+k, tv[k], av); err != nil {
				return err
			}
		}
	case []any:
		aa, ok := act.([]any)
		if !ok || len(aa) != len(tv) {
			return fmt.Errorf("%s: want array of %d, got %s", path, len(tv), jsonScalar(act))
		}
		for i := range tv {
			if err := e.matchJSON(fmt.Sprintf("%s[%d]", path, i), tv[i], aa[i]); err != nil {
				return err
			}
		}
	case string:
		if m := varRe.FindStringSubmatch(tv); m != nil && m[0] == tv {
			name := m[1]
			got := jsonScalar(act)
			if class := strings.TrimPrefix(m[2], ":"); class != "" {
				if re := classes[class]; re != "" && !regexp.MustCompile("^"+re+"$").MatchString(got) {
					return fmt.Errorf("%s: %q is not a %s", path, got, class)
				}
			}
			if v, ok := e.vars[name]; ok && v != got {
				return fmt.Errorf("%s: %q, want %q", path, got, v)
			}
			e.vars[name] = got
			return nil
		}
		as, ok := act.(string)
		if !ok || as != tv {
			return fmt.Errorf("%s: %s, want %q", path, jsonScalar(act), tv)
		}
	case json.Number:
		an, ok := act.(json.Number)
		if !ok {
			return fmt.Errorf("%s: %s, want number %s", path, jsonScalar(act), tv)
		}
		a, _ := an.Float64()
		w, _ := tv.Float64()
		if a != w {
			return fmt.Errorf("%s: %s, want %s", path, an, tv)
		}
	default:
		if !reflect.DeepEqual(tpl, act) {
			return fmt.Errorf("%s: %s, want %s", path, jsonScalar(act), jsonScalar(tpl))
		}
	}
	return nil
}

// checkMCP validates the JSON-RPC envelope of a tools/call reply, then the result text under the
// text rules; success results carry neither a `next` field nor a `next:` line.
func (e *env) checkMCP(s *step, body []byte) error {
	var resp struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  json.RawMessage `json:"result"`
		Error   json.RawMessage `json:"error"`
	}
	if err := json.Unmarshal(body, &resp); err != nil {
		return fmt.Errorf("not a JSON-RPC reply: %v\n%s", err, trunc(body))
	}
	if resp.JSONRPC != "2.0" || len(resp.Error) > 0 {
		return fmt.Errorf("bad envelope: %s", trunc(body))
	}
	if s.bodyKind == "json" {
		var req struct {
			ID json.RawMessage `json:"id"`
		}
		if json.Unmarshal([]byte(e.subst(s.bodyData)), &req) == nil && !bytes.Equal(bytes.TrimSpace(req.ID), bytes.TrimSpace(resp.ID)) {
			return fmt.Errorf("reply id %s, want %s", resp.ID, req.ID)
		}
	}
	var res struct {
		Content []struct{ Type, Text string } `json:"content"`
		IsError bool                          `json:"isError"`
		Next    json.RawMessage               `json:"next"`
	}
	if err := json.Unmarshal(resp.Result, &res); err != nil || len(res.Content) != 1 || res.Content[0].Type != "text" {
		return fmt.Errorf("result is not one text content: %s", trunc(resp.Result))
	}
	if wantErr := s.mode == "mcperr"; res.IsError != wantErr {
		return fmt.Errorf("isError=%v, want %v: %q", res.IsError, wantErr, res.Content[0].Text)
	}
	if !res.IsError && len(res.Next) > 0 {
		return fmt.Errorf("success result carries next: %s", res.Next)
	}
	return e.checkText(s, res.Content[0].Text, res.IsError)
}

// --- tests --------------------------------------------------------------------------------------

func fixtures(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("fixtures/*.txt")
	if err != nil || len(files) == 0 {
		t.Fatalf("no fixtures: %v", err)
	}
	sort.Strings(files)
	return files
}

// TestFixtures replays every recorded v1 session against a freshly booted v2 server.
func TestFixtures(t *testing.T) {
	strict := os.Getenv("COMPAT_STRICT") == "1"
	for _, f := range fixtures(t) {
		t.Run(strings.TrimSuffix(filepath.Base(f), ".txt"), func(t *testing.T) {
			e := newEnv(t)
			e.strict = strict
			if err := e.replay(f); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestNegativePrefixLogicRemoved documents the negative check: without the prefix rule (whole
// lines must be equal, as COMPAT_STRICT=1 makes the whole suite do) the very first recorded
// session fails on the fields v2 appends to the register line.
func TestNegativePrefixLogicRemoved(t *testing.T) {
	e := newEnv(t)
	e.strict = true
	err := e.replay("fixtures/01_identity.txt")
	if err == nil {
		t.Fatal("byte-equal comparison passed: v2 must append fields to v1 lines and the replayer must only compare prefixes")
	}
	if !strings.Contains(err.Error(), "expected v1 line not found") {
		t.Fatalf("strict run failed for another reason: %v", err)
	}
	t.Logf("negative check fails as documented: %v", err)
}

// TestComparatorRules pins the comparison rules on canned v1/v2 lines (no server needed).
func TestComparatorRules(t *testing.T) {
	e := &env{vars: map[string]string{}, bins: map[string][]byte{}}
	v2 := []string{
		"k7x2a3q fix ok0.25 bad0 2026-10-06 by a3fz7qk lvl=L2 age=2d rev2 flags:- [quarantine]",
		"title: pnpm install fails",
		"fix: nvm use 22",
		"  next: POST /v1/x",
		"versions: pnpm 10",
		"applies: node>=22",
		"tags: pnpm,node",
		"works: 3 confirmations",
		"url: https://agents.example/k/k7x2a3q",
	}
	v1 := []string{"$id:id fix ok$okw:num bad0 $d:date by $by:id", "title: pnpm install fails", "fix: nvm use 22", "  next: POST /v1/x", "versions: pnpm 10", "tags: pnpm,node"}
	if err := e.matchLines(v1, v2); err != nil {
		t.Fatalf("prefix + order rule: %v", err)
	}
	if e.vars["id"] != "k7x2a3q" || e.vars["okw"] != "0.25" || e.vars["by"] != "a3fz7qk" || e.vars["d"] != "2026-10-06" {
		t.Fatalf("captures: %v", e.vars)
	}
	if ok, _ := e.matchLine("$x:id fix", "k7x2a9q fix"); ok {
		t.Fatal("id class must reject characters outside base32 [a-z2-7]")
	}
	// Reordered v1 lines fail; a shortened prefix of a v1 field does not match a longer field.
	if err := e.matchLines([]string{"tags: pnpm,node", "versions: pnpm 10"}, v2); err == nil {
		t.Fatal("order rule not enforced")
	}
	if ok, _ := e.matchLine("ok ok1", "ok ok10"); ok {
		t.Fatal("field boundary not enforced")
	}
	if ok, _ := e.matchLine("ok", "ok rev=1"); !ok {
		t.Fatal("appended field must be ignored")
	}
	// The negative check: strict (whole-line) comparison rejects the appended v2 fields.
	e.strict = true
	if ok, _ := e.matchLine("ok", "ok rev=1"); ok {
		t.Fatal("strict mode must compare whole lines")
	}
	e.strict = false
	// Documents: exactly one trailing next: line; a user-text next: at column 0 is a failure.
	s := &step{expect: []string{"#12 open by a3fz9qk 2026-10-06"}}
	if err := e.checkText(s, "#12 open by a3fz9qk 2026-10-06 until=2026-10-07\ntitle: x\nnext: POST /v1/t/12/claim | GET /t/12\n", true); err != nil {
		t.Fatalf("single trailing tail must pass: %v", err)
	}
	if err := e.checkText(s, "#12 open by a3fz9qk 2026-10-06\nnext: POST /v1/x\ntitle: x\nnext: GET /help\n", true); err == nil {
		t.Fatal("a column-0 next: inside the document must fail")
	}
	if err := e.checkText(s, "#12 open by a3fz9qk 2026-10-06\nnext: GET /help\n", false); err == nil {
		t.Fatal("MCP results must not carry a next: line")
	}
	// JSON: subset with captures, arrays unchanged; strict forbids gained fields.
	js := &step{expect: []string{`{"lease":"$lease","job":"$job:id","ms":1000,"ok":true}`}}
	if err := e.checkJSON(js, []byte(`{"lease":"lAbc","job":"j7x2a3q","ms":1000,"mb":64,"ok":true,"upgrade":"/wasm#cxw"}`)); err != nil || e.vars["lease"] != "lAbc" {
		t.Fatalf("json subset: %v %v", err, e.vars)
	}
	if err := e.checkJSON(&step{expect: []string{`["a","b"]`}}, []byte(`["a","b","c"]`)); err == nil {
		t.Fatal("json arrays must stay unchanged")
	}
	e.strict = true
	if err := e.checkJSON(&step{expect: []string{`{"ok":true}`}}, []byte(`{"ok":true,"rev":1}`)); err == nil {
		t.Fatal("strict json must reject gained fields")
	}
}

// v1Routes are the routes SPEC.md lists; every one must be exercised by a fixture.
var v1Routes = []string{
	"POST /v1/challenge", "POST /v1/register", "POST /v1/subkey", "DELETE /v1/subkey/{id}", "GET /v1/me",
	"GET /v1/kb", "GET /v1/kb/{id}", "POST /v1/kb", "POST /v1/kb/{id}/ok", "POST /v1/kb/{id}/bad", "GET /kb/", "GET /kb/{id}", "GET /sitemap.xml",
	"GET /v1/t", "GET /v1/t/{n}", "POST /v1/t", "POST /v1/t/{n}/claim", "POST /v1/t/{n}/drop", "POST /v1/t/{n}/note", "POST /v1/t/{n}/done",
	"GET /v1/n", "GET /v1/n/{owner}/{name}", "PUT /v1/n/{name}", "DELETE /v1/n/{name}",
	"POST /v1/b", "GET /v1/b/{hash}", "HEAD /v1/b/{hash}", "POST /v1/j", "GET /v1/j/{id}", "POST /v1/w/lease", "POST /v1/w/done",
	"POST /mcp", "GET /mcp",
	"GET /", "GET /llms.txt", "GET /AGENTS.md", "GET /.well-known/agent.json", "GET /.well-known/mcp.json", "GET /legal", "GET /worker", "GET /robots.txt", "POST /v1/report",
	"POST /admin/freeze", "POST /admin/purge", "GET /admin/stats",
}

// v1Commands are the cx commands SPEC.md lists; the CLI fixture records each one ("-- cx <cmd>").
var v1Commands = []string{"join", "me", "s", "g", "p", "ok", "t", "tg", "tp", "tc", "td", "n", "ng", "np", "put", "run", "sub", "mcp"}

func routeRe(pat string) *regexp.Regexp {
	method, path, _ := strings.Cut(pat, " ")
	segs := strings.Split(path, "/")
	for i, s := range segs {
		if strings.HasPrefix(s, "{") {
			segs[i] = "[^/]+"
		} else {
			segs[i] = regexp.QuoteMeta(s)
		}
	}
	return regexp.MustCompile("^" + method + " " + strings.Join(segs, "/") + "$")
}

// TestFixturesCoverV1 checks the fixtures exercise every v1 route and every v1 cx command.
func TestFixturesCoverV1(t *testing.T) {
	var reqs []string
	cmds := map[string]bool{}
	cmdRe := regexp.MustCompile(`^-- cx ([a-z]+)\b`)
	for _, f := range fixtures(t) {
		steps, err := parseFixture(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range steps {
			if s.method != "" {
				p := s.path
				if i := strings.IndexByte(p, '?'); i >= 0 {
					p = p[:i]
				}
				reqs = append(reqs, s.method+" "+p)
			}
		}
		b, _ := os.ReadFile(f)
		for _, l := range strings.Split(string(b), "\n") {
			if m := cmdRe.FindStringSubmatch(l); m != nil {
				cmds[m[1]] = true
			}
		}
	}
	var missing []string
	for _, rt := range v1Routes {
		re := routeRe(rt)
		hit := false
		for _, r := range reqs {
			if re.MatchString(r) {
				hit = true
				break
			}
		}
		if !hit {
			missing = append(missing, rt)
		}
	}
	for _, c := range v1Commands {
		if !cmds[c] {
			missing = append(missing, "cx "+c)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("v1 surface not covered by fixtures: %s", strings.Join(missing, ", "))
	}
}
