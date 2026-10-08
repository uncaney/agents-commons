package main

// registry.go: the command registry consulted before the v1 switch (feature packages add verbs
// from their own cmd/cx/cmds_<pkg>.go through register / registerOp), the help text generated
// from it, the global flags and the request helpers every cmds_*.go file shares.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
)

// usage is one help line of a command: its arguments and a short description.
type usage struct{ args, desc string }

func u(args, desc string) usage { return usage{args, desc} }

type command struct {
	group, name string
	lines       []usage
	run         func(c *cli, ctx context.Context, args []string) error
}

var (
	commands = map[string]*command{}
	cmdOrder []string   // registration order (= help order inside a group)
	groups   []string   // help sections in first-seen order
	extras   []*command // help-only lines (v2 forms of v1 verbs), no handler
	// localOps are MCP tools/call ops answered inside `cx mcp` instead of being forwarded
	// (join; the sealed-lane ops of cmds_e2e). name -> handler.
	localOps = map[string]func(c *cli, ctx context.Context, m *rpcMsg) []byte{}
)

// v1Names are the verbs handled by the v1 switch in main.go; register refuses to shadow them.
var v1Names = []string{"join", "me", "s", "g", "p", "ok", "bad", "t", "tg", "tp", "tc", "td", "tdrop", "tn",
	"n", "ng", "np", "nd", "put", "get", "run", "sub", "mcp", "help"}

// register adds a verb; a duplicate name (v1 or registered) is a programming error.
func register(group, name string, run func(*cli, context.Context, []string) error, lines ...usage) {
	if _, dup := commands[name]; dup || slices.Contains(v1Names, name) {
		panic("cx: duplicate command " + name)
	}
	if !slices.Contains(groups, group) {
		groups = append(groups, group)
	}
	commands[name] = &command{group: group, name: name, lines: lines, run: run}
	cmdOrder = append(cmdOrder, name)
}

// describe adds help lines for a verb handled elsewhere (the v2 forms of v1 verbs).
func describe(group, name string, lines ...usage) {
	if !slices.Contains(groups, group) {
		groups = append(groups, group)
	}
	extras = append(extras, &command{group: group, name: name, lines: lines})
}

// registerOp adds a local MCP op handled by the proxy; duplicates are a programming error.
func registerOp(op string, fn func(c *cli, ctx context.Context, m *rpcMsg) []byte) {
	if _, dup := localOps[op]; dup {
		panic("cx: duplicate local op " + op)
	}
	localOps[op] = fn
}

const flagsHelp = `flags (any position): --json  --no-next (X-Next: 0)  --key K (Idempotency-Key)  --v2 (X-CX-V: 2)
values: literal, - (stdin) or @file; multi-line fields are sent as text/plain field: lines
state: $XDG_STATE_HOME/cx (default <config>/cx/state): last-seen revs (g sends ?since=), cached scrub rules
`

// usageText is the full help: the v1 block verbatim, the global flags, then one section per group.
func usageText() string {
	var b strings.Builder
	b.WriteString(usageV1)
	b.WriteString(flagsHelp)
	for _, g := range groups {
		b.WriteString(g + ":\n")
		var cmds []*command
		for _, n := range cmdOrder {
			cmds = append(cmds, commands[n])
		}
		for _, cmd := range append(cmds, extras...) {
			if cmd.group != g {
				continue
			}
			for _, l := range cmd.lines {
				left := strings.TrimSpace(cmd.name + " " + l.args)
				switch {
				case l.desc == "":
					b.WriteString("  " + left + "\n")
				case len(left) < 41:
					fmt.Fprintf(&b, "  %-41s%s\n", left, l.desc)
				default:
					b.WriteString("  " + left + "  " + l.desc + "\n")
				}
			}
		}
	}
	return b.String()
}

// helpFor prints the help lines mentioning one verb (every line of the full help otherwise).
func helpFor(name string) string {
	if name == "" {
		return usageText()
	}
	var out []string
	for _, l := range strings.Split(strings.TrimRight(usageText(), "\n"), "\n") {
		if slices.Contains(strings.Fields(l), name) {
			out = append(out, l)
		}
	}
	if len(out) == 0 {
		return ""
	}
	return strings.Join(out, "\n") + "\n"
}

// --- global flags ---

// globalFlags strips --json, --no-next, --key K and --v2 from any position before "--" and
// records them on c; everything else is returned for the command's own parser.
func (c *cli) globalFlags(args []string) ([]string, error) {
	var out []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			return append(out, args[i:]...), nil
		}
		name, val, hasVal := strings.TrimLeft(a, "-"), "", false
		if k, v, ok := strings.Cut(name, "="); ok {
			name, val, hasVal = k, v, true
		}
		if !strings.HasPrefix(a, "--") {
			out = append(out, a)
			continue
		}
		switch name {
		case "json":
			c.json = true
		case "no-next":
			c.noNext = true
		case "v2":
			c.v2 = true
		case "key":
			if !hasVal {
				if i+1 >= len(args) {
					return nil, fail(2, "err bad flag --key needs a value")
				}
				i++
				val = args[i]
			}
			c.idemKey = val
		default:
			out = append(out, a)
		}
	}
	return out, nil
}

// --- request helpers ---

// field is one request field; v is a string, bool, int, int64, []string or a nested value.
type field struct {
	k string
	v any
}

func f(k string, v any) field { return field{k, v} }

// encodeFields renders fields as JSON, or as the text/plain field grammar (27.2) when a string
// value spans several lines: `name: first line`, continuation lines indented two spaces, so user
// text never reaches column 0. Empty strings and false booleans are omitted in the text form.
func encodeFields(fs []field) ([]byte, string) {
	multi := false
	m := make(map[string]any, len(fs))
	for _, x := range fs {
		m[x.k] = x.v
		if s, ok := x.v.(string); ok && strings.Contains(s, "\n") {
			multi = true
		}
	}
	if !multi {
		b, _ := json.Marshal(m)
		return b, "application/json"
	}
	var b strings.Builder
	for _, x := range fs {
		var s string
		switch v := x.v.(type) {
		case string:
			if v == "" {
				continue
			}
			s = strings.ReplaceAll(strings.ReplaceAll(v, "\r\n", "\n"), "\r", "")
			s = strings.ReplaceAll(strings.TrimRight(s, "\n"), "\n", "\n  ")
		case bool:
			if !v {
				continue
			}
			s = "true"
		case int:
			s = strconv.Itoa(v)
		case int64:
			s = strconv.FormatInt(v, 10)
		case []string:
			if len(v) == 0 {
				continue
			}
			s = strings.Join(v, ",")
		default: // nested values have no text form
			j, _ := json.Marshal(m)
			return j, "application/json"
		}
		b.WriteString(x.k + ": " + s + "\n")
	}
	return []byte(b.String()), "text/plain; charset=utf-8"
}

// send issues a request with fields as its body and prints the reply verbatim.
func (c *cli) send(ctx context.Context, method, path string, fs []field) error {
	var body io.Reader
	ctype := ""
	if fs != nil {
		b, ct := encodeFields(fs)
		body, ctype = bytes.NewReader(b), ct
	}
	b, err := c.call(ctx, method, path, body, ctype, c.json)
	if err != nil {
		return err
	}
	c.print(b)
	return nil
}

// sendRaw issues a request with a raw body and prints the reply verbatim.
func (c *cli) sendRaw(ctx context.Context, method, path string, body []byte, ctype string, hdr map[string]string) error {
	_, _, b, err := c.callH(ctx, method, path, bytes.NewReader(body), ctype, c.json, hdr)
	if err != nil {
		return err
	}
	c.print(b)
	return nil
}

// get issues a GET with a query (empty values skipped) and prints the reply verbatim.
func (c *cli) get(ctx context.Context, path string, q url.Values) error {
	return c.send(ctx, "GET", withQuery(path, q), nil)
}

func withQuery(path string, q url.Values) string {
	for k, vs := range q {
		if len(vs) == 0 || vs[0] == "" {
			delete(q, k)
		}
	}
	if len(q) == 0 {
		return path
	}
	return path + "?" + q.Encode()
}

// print writes a reply, newline-terminated.
func (c *cli) print(b []byte) {
	c.stdout.Write(b)
	if len(b) > 0 && b[len(b)-1] != '\n' {
		io.WriteString(c.stdout, "\n")
	}
}

// readValue resolves a value argument: "-" reads stdin, "@path" reads a file, anything else is
// the literal text.
func (c *cli) readValue(s string) ([]byte, error) {
	switch {
	case s == "-":
		return c.readInput("-")
	case strings.HasPrefix(s, "@") && len(s) > 1:
		return c.readInput(s[1:])
	}
	return []byte(s), nil
}

func (c *cli) readValueString(s string) (string, error) {
	b, err := c.readValue(s)
	return string(b), err
}

// atoiFlag parses an optional integer flag ("" -> 0).
func atoiFlag(name, v string) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fail(2, "err bad --%s %q", name, v)
	}
	return n, nil
}

// writeFile0600 writes a private file through a temporary name.
func writeFile0600(p string, b []byte) error {
	if err := os.MkdirAll(p[:strings.LastIndex(p, string(os.PathSeparator))], 0o700); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
