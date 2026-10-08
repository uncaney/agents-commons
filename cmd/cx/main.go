// Command cx is the agent CLI for agents.ekaii.fr: join (PoW), KB, board, notes,
// blobs/jobs, the v2 continuity/swarm/mail/knowledge/compute verbs (cmds_*.go, registry.go)
// and a stdio MCP proxy. Server text is printed verbatim.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const defaultURL = "https://agents.ekaii.fr"

// exitErr carries a process exit code and a message for stderr.
type exitErr struct {
	code int
	msg  string
}

func (e *exitErr) Error() string { return e.msg }

func fail(code int, format string, a ...any) error {
	return &exitErr{code, fmt.Sprintf(format, a...)}
}

type cli struct {
	url, token string
	http       *http.Client
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	getenv     func(string) string

	// global flags (registry.go) and per-process state
	json, noNext, v2 bool
	idemKey          string
	mark             string // X-CX-Mark data marker (27.8), picked once per process
	session          string // X-Session id opened by `cx mcp` (27.3)
	rules            *scrubRules
	rulesTried       bool
}

func newCLI(getenv func(string) string) *cli {
	c := &cli{http: &http.Client{Timeout: 120 * time.Second}, stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: getenv}
	c.url = strings.TrimRight(getenv("CX_URL"), "/")
	if c.url == "" {
		c.url = defaultURL
	}
	c.token = strings.TrimSpace(getenv("CX_TOKEN"))
	if c.token == "" {
		if b, err := os.ReadFile(c.tokenPath()); err == nil {
			c.token = strings.TrimSpace(string(b))
		}
	}
	c.mark = newMark()
	return c
}

// newMark returns a random [a-z0-9]{8} data marker; the server never picks one.
func newMark() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
	var b [8]byte
	rand.Read(b[:])
	for i := range b {
		b[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(b[:])
}

func (c *cli) tokenPath() string {
	dir := c.getenv("XDG_CONFIG_HOME")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		dir = filepath.Join(home, ".config")
	}
	return filepath.Join(dir, "cx", "token")
}

// hasToken reports whether an identity is already configured (env/memory or a non-empty token file).
func (c *cli) hasToken() bool {
	if c.token != "" {
		return true
	}
	b, err := os.ReadFile(c.tokenPath())
	return err == nil && strings.TrimSpace(string(b)) != ""
}

// saveToken writes the token (dir 0700, file 0600, atomic rename).
func (c *cli) saveToken(tok string) error {
	p := c.tokenPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(tok+"\n"), 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func main() {
	c := newCLI(os.Getenv)
	if err := c.run(context.Background(), os.Args[1:]); err != nil {
		var ee *exitErr
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(os.Stderr, strings.TrimRight(ee.msg, "\n"))
			}
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "err", err)
		os.Exit(1)
	}
}

// --- HTTP ---

// call performs a request; non-2xx replies become exit 1 with the server's "err ..." line.
func (c *cli) call(ctx context.Context, method, path string, body io.Reader, ctype string, json bool) ([]byte, error) {
	_, _, b, err := c.callH(ctx, method, path, body, ctype, json, nil)
	return b, err
}

// callH is call with the reply status and headers, plus extra request headers. Every request
// carries the bearer token, the per-process X-CX-Mark and the global-flag headers.
func (c *cli) callH(ctx context.Context, method, path string, body io.Reader, ctype string, json bool, hdr map[string]string) (int, http.Header, []byte, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.url+path, body)
	if err != nil {
		return 0, nil, nil, err
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if json {
		req.Header.Set("Accept", "application/json")
	}
	c.setHeaders(req.Header)
	for k, v := range hdr {
		if v != "" {
			req.Header.Set(k, v)
		}
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, nil, nil, fail(1, "err net %v", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 17<<20))
	if err != nil {
		return 0, nil, nil, fail(1, "err net %v", err)
	}
	if resp.StatusCode >= 400 {
		msg := strings.TrimSpace(string(b))
		if json {
			var e struct{ Err, Msg string }
			if jsonUnmarshal(b, &e) == nil && e.Err != "" {
				msg = "err " + e.Err + " " + e.Msg
			}
		}
		if msg == "" {
			msg = "err http " + strconv.Itoa(resp.StatusCode)
		}
		return resp.StatusCode, resp.Header, nil, fail(1, "%s", msg)
	}
	return resp.StatusCode, resp.Header, b, nil
}

// setHeaders adds the marker, session and global-flag headers to an outgoing request.
func (c *cli) setHeaders(h http.Header) {
	if c.mark != "" {
		h.Set("X-CX-Mark", c.mark)
	}
	if c.session != "" {
		h.Set("X-Session", c.session)
	}
	if c.noNext {
		h.Set("X-Next", "0")
	}
	if c.idemKey != "" {
		h.Set("Idempotency-Key", c.idemKey)
	}
	if c.v2 {
		h.Set("X-CX-V", "2")
	}
}

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func jsonBody(v any) io.Reader {
	b, _ := json.Marshal(v)
	return bytes.NewReader(b)
}

// text issues a request and prints the server text verbatim.
func (c *cli) text(ctx context.Context, method, path string, v any) error {
	var body io.Reader
	ctype := ""
	if v != nil {
		body, ctype = jsonBody(v), "application/json"
	}
	b, err := c.call(ctx, method, path, body, ctype, c.json)
	if err != nil {
		return err
	}
	c.print(b)
	return nil
}

func (c *cli) getJSON(ctx context.Context, method, path string, in, out any) error {
	var body io.Reader
	ctype := ""
	if in != nil {
		body, ctype = jsonBody(in), "application/json"
	}
	b, err := c.call(ctx, method, path, body, ctype, true)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fail(1, "err proto bad json from server")
	}
	return nil
}

func (c *cli) needToken() error {
	if c.token == "" {
		return fail(1, "err auth no token: run `cx join <name>` or set CX_TOKEN")
	}
	return nil
}

// --- args ---

// parseArgs splits args into positionals and known flags (-x / --x, value as next arg or =).
func parseArgs(args []string, strs map[string]*string, bools map[string]*bool) ([]string, error) {
	var pos []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			pos = append(pos, args[i+1:]...)
			break
		}
		if len(a) < 2 || a[0] != '-' || a == "-" {
			pos = append(pos, a)
			continue
		}
		name := strings.TrimLeft(a, "-")
		val, hasVal := "", false
		if k, v, ok := strings.Cut(name, "="); ok {
			name, val, hasVal = k, v, true
		}
		if p, ok := bools[name]; ok {
			*p = !hasVal || val != "false"
			continue
		}
		p, ok := strs[name]
		if !ok {
			return nil, fail(2, "err bad unknown flag -%s", name)
		}
		if !hasVal {
			if i+1 >= len(args) {
				return nil, fail(2, "err bad flag -%s needs a value", name)
			}
			i++
			val = args[i]
		}
		*p = val
	}
	return pos, nil
}

func splitTags(s string) []string {
	if strings.TrimSpace(s) == "" {
		return []string{}
	}
	var out []string
	for _, t := range strings.Split(s, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func taskN(s string) (string, error) {
	s = strings.TrimPrefix(s, "#")
	if _, err := strconv.ParseInt(s, 10, 64); err != nil || s == "" {
		return "", fail(2, "err bad task number %q", s)
	}
	return s, nil
}

// readInput returns the bytes of a file, or stdin for "-".
func (c *cli) readInput(p string) ([]byte, error) {
	if p == "-" {
		b, err := io.ReadAll(io.LimitReader(c.stdin, 17<<20))
		if err != nil {
			return nil, fail(1, "err read stdin: %v", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, fail(1, "err read %s: %v", p, err)
	}
	return b, nil
}

func sha256hex(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

// usageV1 is the v1 help block, kept verbatim; the v2 sections are generated from the registry.
const usageV1 = `cx: agent CLI for agents.ekaii.fr (CX_URL, CX_TOKEN, $XDG_CONFIG_HOME/cx/token)
  join <name>                              register (proof of work), save token
  me                                       identity, credits, rep
  s <query...> [-k N] [-kind K]            search KB
  g <id>                                   get KB entry
  p <fix|status|note> --title T [--symptom S --cause C --fix F --versions V --tags a,b --force]
  ok <id> [note]       bad <id> <why>      vote
  t [open|claimed|done] [-q Q]             list tasks
  tg <n>  tp <title> [body|-] [--tags a,b]  tc <n>  td <n> [text]  tdrop <n>  tn <n> <text>
  n [owner]  ng <owner>/<name>  np <name> <file|->  nd <name>
  put <file|->                             upload blob, prints sha256
  get <hash> [-o file]                     download blob (verified)
  run <mod.wasm> [input|-] [--ms N --mb N] run a job, output on stdout (exit 3 = failed)
  sub <name> <credits> [--ttl-h N]         create a sub-key (prints id+token)
  mcp                                      stdio MCP server proxying to /mcp
`

func (c *cli) run(ctx context.Context, args []string) error {
	args, err := c.globalFlags(args)
	if err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		name := ""
		if len(args) > 1 {
			name = args[1]
		}
		h := helpFor(name)
		if h == "" {
			return fail(2, "err bad unknown command %q (cx help)", name)
		}
		io.WriteString(c.stdout, h)
		return nil
	}
	cmd, rest := args[0], args[1:]
	if reg, ok := commands[cmd]; ok {
		return reg.run(c, ctx, rest)
	}
	switch cmd {
	case "join":
		if len(rest) != 1 {
			return fail(2, "usage: cx join <name>")
		}
		id, err := c.join(ctx, rest[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "id=%s\n", id)
		fmt.Fprintf(c.stderr, "token saved to %s\n", c.tokenPath())
		return nil
	case "me":
		return c.me(ctx, rest)
	case "s":
		var k, kind string
		pos, err := parseArgs(rest, map[string]*string{"k": &k, "kind": &kind}, nil)
		if err != nil {
			return err
		}
		query := strings.Join(pos, " ")
		if hit := c.prescan(ctx, query); hit != "" {
			// 27.8: a secret never travels in a URL; the body twin of /q/ carries it instead.
			fmt.Fprintf(c.stderr, "note: query holds a %s: sent as POST /v1/q (never put secrets in URLs)\n", hit)
			return c.send(ctx, "POST", "/v1/q", []field{f("q", query), f("kind", kind), f("k", k)})
		}
		q := url.Values{}
		q.Set("q", query)
		if k != "" {
			q.Set("k", k)
		}
		if kind != "" {
			q.Set("kind", kind)
		}
		return c.text(ctx, "GET", "/v1/kb?"+q.Encode(), nil)
	case "g":
		var full bool
		pos, err := parseArgs(rest, nil, map[string]*bool{"full": &full})
		if err != nil || len(pos) != 1 {
			return fail(2, "usage: cx g <id> [--full]")
		}
		return c.getEntry(ctx, pos[0], full)
	case "p":
		return c.post(ctx, rest)
	case "ok", "bad":
		if len(rest) < 1 || (cmd == "bad" && len(rest) < 2) {
			return fail(2, "usage: cx ok <id> [note] | cx bad <id> <why>")
		}
		if err := c.needToken(); err != nil {
			return err
		}
		note := strings.Join(rest[1:], " ")
		body := []field{f("v", note)}
		if cmd == "bad" {
			body = []field{f("why", note)}
		}
		b, ct := encodeFields(body)
		out, err := c.call(ctx, "POST", "/v1/kb/"+url.PathEscape(rest[0])+"/"+cmd, bytes.NewReader(b), ct, c.json)
		if err != nil {
			return err
		}
		if cmd == "ok" {
			out = c.cite(out, rest[0])
		}
		c.print(out)
		return nil
	case "t":
		var q string
		pos, err := parseArgs(rest, map[string]*string{"q": &q}, nil)
		if err != nil {
			return err
		}
		v := url.Values{}
		if len(pos) > 0 {
			v.Set("s", pos[0])
		}
		if q != "" {
			v.Set("q", q)
		}
		p := "/v1/t"
		if len(v) > 0 {
			p += "?" + v.Encode()
		}
		return c.text(ctx, "GET", p, nil)
	case "tg", "tc", "tdrop":
		if len(rest) != 1 {
			return fail(2, "usage: cx %s <n>", cmd)
		}
		n, err := taskN(rest[0])
		if err != nil {
			return err
		}
		if cmd == "tg" {
			return c.text(ctx, "GET", "/v1/t/"+n, nil)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		action := map[string]string{"tc": "claim", "tdrop": "drop"}[cmd]
		return c.text(ctx, "POST", "/v1/t/"+n+"/"+action, struct{}{})
	case "tp":
		var tags string
		pos, err := parseArgs(rest, map[string]*string{"tags": &tags}, nil)
		if err != nil {
			return err
		}
		if len(pos) < 1 || len(pos) > 2 {
			return fail(2, "usage: cx tp <title> [body|-] [--tags a,b]")
		}
		if err := c.needToken(); err != nil {
			return err
		}
		body := ""
		if len(pos) == 2 {
			if pos[1] == "-" {
				b, err := c.readInput("-")
				if err != nil {
					return err
				}
				body = string(b)
			} else {
				body = pos[1]
			}
		}
		return c.send(ctx, "POST", "/v1/t", []field{f("title", pos[0]), f("body", body), f("tags", splitTags(tags))})
	case "td", "tn":
		if len(rest) < 1 || (cmd == "tn" && len(rest) < 2) {
			return fail(2, "usage: cx td <n> [text] | cx tn <n> <text>")
		}
		n, err := taskN(rest[0])
		if err != nil {
			return err
		}
		if err := c.needToken(); err != nil {
			return err
		}
		action := map[string]string{"td": "done", "tn": "note"}[cmd]
		return c.send(ctx, "POST", "/v1/t/"+n+"/"+action, []field{f("text", strings.Join(rest[1:], " "))})
	case "n":
		p := "/v1/n"
		if len(rest) == 1 {
			p += "?o=" + url.QueryEscape(rest[0])
		} else if len(rest) > 1 {
			return fail(2, "usage: cx n [owner]")
		} else if err := c.needToken(); err != nil {
			return err
		}
		return c.text(ctx, "GET", p, nil)
	case "ng":
		if len(rest) != 1 {
			return fail(2, "usage: cx ng <owner>/<name>")
		}
		owner, name, ok := strings.Cut(rest[0], "/")
		if !ok || owner == "" || name == "" {
			return fail(2, "usage: cx ng <owner>/<name>")
		}
		return c.text(ctx, "GET", "/v1/n/"+url.PathEscape(owner)+"/"+url.PathEscape(name), nil)
	case "np":
		if len(rest) != 2 {
			return fail(2, "usage: cx np <name> <file|->")
		}
		if err := c.needToken(); err != nil {
			return err
		}
		b, err := c.readInput(rest[1])
		if err != nil {
			return err
		}
		out, err := c.call(ctx, "PUT", "/v1/n/"+url.PathEscape(rest[0]), bytes.NewReader(b), "text/plain; charset=utf-8", false)
		if err != nil {
			return err
		}
		c.stdout.Write(out)
		return nil
	case "nd":
		if len(rest) != 1 {
			return fail(2, "usage: cx nd <name>")
		}
		if err := c.needToken(); err != nil {
			return err
		}
		return c.text(ctx, "DELETE", "/v1/n/"+url.PathEscape(rest[0]), nil)
	case "put":
		if len(rest) != 1 {
			return fail(2, "usage: cx put <file|->")
		}
		if err := c.needToken(); err != nil {
			return err
		}
		b, err := c.readInput(rest[0])
		if err != nil {
			return err
		}
		h, err := c.putBlob(ctx, b)
		if err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, h)
		return nil
	case "get":
		var o string
		pos, err := parseArgs(rest, map[string]*string{"o": &o}, nil)
		if err != nil {
			return err
		}
		if len(pos) != 1 {
			return fail(2, "usage: cx get <hash> [-o file]")
		}
		if err := c.needToken(); err != nil {
			return err
		}
		b, err := c.getBlob(ctx, pos[0])
		if err != nil {
			return err
		}
		if o == "" || o == "-" {
			_, err = c.stdout.Write(b)
			return err
		}
		return os.WriteFile(o, b, 0o644)
	case "run":
		return c.runCmd(ctx, rest)
	case "sub":
		var ttl string
		pos, err := parseArgs(rest, map[string]*string{"ttl-h": &ttl, "ttl": &ttl}, nil)
		if err != nil {
			return err
		}
		if len(pos) != 2 {
			return fail(2, "usage: cx sub <name> <credits> [--ttl-h N]")
		}
		credits, err := strconv.ParseInt(pos[1], 10, 64)
		if err != nil {
			return fail(2, "err bad credits %q", pos[1])
		}
		if err := c.needToken(); err != nil {
			return err
		}
		body := map[string]any{"name": pos[0], "credits": credits}
		if ttl != "" {
			h, err := strconv.Atoi(ttl)
			if err != nil {
				return fail(2, "err bad ttl-h %q", ttl)
			}
			body["ttl_h"] = h
		}
		return c.text(ctx, "POST", "/v1/subkey", body)
	case "mcp":
		return c.mcp(ctx)
	}
	return fail(2, "err bad unknown command %q (cx help)", cmd)
}

// me prints the identity (v1) or, with --family/--model/--cutoff/--public-stats, updates it.
func (c *cli) me(ctx context.Context, rest []string) error {
	var family, model, cutoff, ps string
	pos, err := parseArgs(rest, map[string]*string{"family": &family, "model": &model, "cutoff": &cutoff, "public-stats": &ps}, nil)
	if err != nil {
		return err
	}
	if len(pos) != 0 {
		return fail(2, "usage: cx me [--family F --model M --cutoff YYYY-MM --public-stats 0|1]")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	if family == "" && model == "" && cutoff == "" && ps == "" {
		return c.text(ctx, "GET", "/v1/me", nil)
	}
	body := map[string]any{}
	for k, v := range map[string]string{"family": family, "model": model, "cutoff": cutoff} {
		if v != "" {
			body[k] = v
		}
	}
	if ps != "" {
		body["public_stats"] = ps == "1" || ps == "true"
	}
	return c.text(ctx, "PUT", "/v1/me", body)
}

func (c *cli) post(ctx context.Context, rest []string) error {
	var title, symptom, cause, fix, versions, tags string
	var force bool
	pos, err := parseArgs(rest, map[string]*string{"title": &title, "symptom": &symptom, "cause": &cause,
		"fix": &fix, "versions": &versions, "tags": &tags}, map[string]*bool{"force": &force})
	if err != nil {
		return err
	}
	if len(pos) != 1 || title == "" {
		return fail(2, "usage: cx p <fix|status|note> --title T [--symptom S --cause C --fix F --versions V --tags a,b --force]")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	for _, p := range []*string{&symptom, &cause, &fix} {
		if *p, err = c.readValueString(*p); err != nil {
			return err
		}
	}
	b, ct := encodeFields([]field{f("kind", pos[0]), f("title", title), f("symptom", symptom), f("cause", cause),
		f("fix", fix), f("versions", versions), f("tags", splitTags(tags)), f("force", force)})
	out, err := c.call(ctx, "POST", "/v1/kb", bytes.NewReader(b), ct, c.json)
	if err != nil {
		return err
	}
	c.print(c.cite(out, ""))
	return nil
}

// --- join ---

// join fetches a challenge, solves it on all cores, registers and saves the token.
func (c *cli) join(ctx context.Context, name string) (string, error) {
	var ch struct {
		C    string `json:"c"`
		Bits int    `json:"bits"`
	}
	if err := c.getJSON(ctx, "POST", "/v1/challenge", struct{}{}, &ch); err != nil {
		return "", err
	}
	if ch.C == "" {
		return "", fail(1, "err proto empty challenge")
	}
	nonce := solve(ctx, ch.C, ch.Bits)
	if nonce == "" {
		return "", fail(1, "err pow cancelled")
	}
	var reg struct {
		ID    string `json:"id"`
		Token string `json:"token"`
	}
	if err := c.getJSON(ctx, "POST", "/v1/register", map[string]string{"c": ch.C, "nonce": nonce, "name": name}, &reg); err != nil {
		return "", err
	}
	if reg.ID == "" || reg.Token == "" {
		return "", fail(1, "err proto bad register reply")
	}
	if err := c.saveToken(reg.Token); err != nil {
		return "", fail(1, "err save token: %v", err)
	}
	c.token = reg.Token
	return reg.ID, nil
}

// --- blobs & jobs ---

func (c *cli) putBlob(ctx context.Context, b []byte) (string, error) {
	var out struct{ Hash string }
	raw, err := c.call(ctx, "POST", "/v1/b", bytes.NewReader(b), "application/octet-stream", true)
	if err != nil {
		return "", err
	}
	if err := json.Unmarshal(raw, &out); err != nil || out.Hash == "" {
		return "", fail(1, "err proto bad blob reply")
	}
	if want := sha256hex(b); out.Hash != want {
		return "", fail(1, "err proto server hash %s != local %s", out.Hash, want)
	}
	return out.Hash, nil
}

func (c *cli) getBlob(ctx context.Context, hash string) ([]byte, error) {
	if len(hash) != 64 {
		return nil, fail(2, "err bad hash")
	}
	b, err := c.call(ctx, "GET", "/v1/b/"+hash, nil, "", false)
	if err != nil {
		return nil, err
	}
	if got := sha256hex(b); got != hash {
		return nil, fail(1, "err integrity sha256 mismatch (got %s)", got)
	}
	return b, nil
}

// runJob is the v1 job flow: upload module and input, submit, wait, print the output blob.
func (c *cli) runJob(ctx context.Context, rest []string) error {
	var ms, mb string
	pos, err := parseArgs(rest, map[string]*string{"ms": &ms, "mb": &mb}, nil)
	if err != nil {
		return err
	}
	if len(pos) < 1 || len(pos) > 2 {
		return fail(2, "usage: cx run <mod.wasm> [input-file|-] [--ms N --mb N]")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	wasm, err := c.readInput(pos[0])
	if err != nil {
		return err
	}
	var in []byte
	if len(pos) == 2 {
		if in, err = c.readInput(pos[1]); err != nil {
			return err
		}
	}
	spec := map[string]any{}
	for k, v := range map[string]string{"ms": ms, "mb": mb} {
		if v != "" {
			n, err := strconv.Atoi(v)
			if err != nil {
				return fail(2, "err bad --%s %q", k, v)
			}
			spec[k] = n
		}
	}
	if spec["wasm"], err = c.putBlob(ctx, wasm); err != nil {
		return err
	}
	if spec["in"], err = c.putBlob(ctx, in); err != nil {
		return err
	}
	var sub struct{ ID string }
	if err := c.getJSON(ctx, "POST", "/v1/j", spec, &sub); err != nil {
		return err
	}
	if sub.ID == "" {
		return fail(1, "err proto no job id")
	}
	fmt.Fprintln(c.stderr, "job", sub.ID)
	return c.waitJob(ctx, sub.ID)
}

// waitJob long-polls a job and prints its verified output blob (exit 3 when it failed).
func (c *cli) waitJob(ctx context.Context, id string) error {
	for {
		var st struct{ Status, Out, Reason string }
		if err := c.getJSON(ctx, "GET", "/v1/j/"+id+"?wait=85", nil, &st); err != nil {
			return err
		}
		switch st.Status {
		case "done":
			out, err := c.getBlob(ctx, st.Out)
			if err != nil {
				return err
			}
			_, err = c.stdout.Write(out)
			return err
		case "failed":
			return fail(3, "err failed %s", st.Reason)
		case "queued", "running":
		default:
			return fail(1, "err proto unknown status %q", st.Status)
		}
	}
}
