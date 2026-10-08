package main

// cmds_core.go: the v2 core verbs (SPEC-v2 3.4, 5, 8.3, 8.4, 10-15, 19.1, 27.2, 27.3, 27.8),
// each mapped 1:1 to an HTTP route with the server's compact text printed verbatim, and the
// helpers behind the amended v1 verbs: tier-1 pre-scan (s, e), rev memory (g), cite line (p, ok),
// service runs with the status-line/next: parsing (run, py, js, lua).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	svcRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}(@[0-9]+)?$`)
	jobRe    = regexp.MustCompile(`^j[a-z0-9]{6,}$`)
	kbIDRe   = regexp.MustCompile(`^k[a-z0-9]{6,}$`)
	anyIDRe  = regexp.MustCompile(`^[a-z0-9]{7,16}$`)
	revRe    = regexp.MustCompile(`(?:\brev=?|"rev":\s*)(\d+)\b`)
	tokenRe  = regexp.MustCompile(`cx_[A-Za-z0-9_-]{43}`)
	secretRe = regexp.MustCompile(`^[A-Za-z0-9_-]{22,64}$`)
	hashRe   = regexp.MustCompile(`\bout=([0-9a-f]{64})\b`)
	digitRe  = regexp.MustCompile(`[0-9]`)
)

// --- state dir (last-seen revs, cached scrub rules) ---

func (c *cli) stateDir() string {
	if s := c.getenv("XDG_STATE_HOME"); s != "" {
		return filepath.Join(s, "cx")
	}
	return filepath.Join(filepath.Dir(c.tokenPath()), "state")
}

func (c *cli) lastRev(id string) int {
	if !anyIDRe.MatchString(id) {
		return 0
	}
	b, err := os.ReadFile(filepath.Join(c.stateDir(), "rev", id))
	if err != nil {
		return 0
	}
	n, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	return n
}

// rememberRev stores the rev of a reply head (`… rev2 …`, `ok unchanged rev=7`, `"rev":7`).
func (c *cli) rememberRev(id string, reply []byte) {
	if !anyIDRe.MatchString(id) {
		return
	}
	head, _, _ := bytes.Cut(reply, []byte("\n"))
	m := revRe.FindSubmatch(head)
	if m == nil {
		return
	}
	writeFile0600(filepath.Join(c.stateDir(), "rev", id), append(m[1], '\n'))
}

// getEntry is `cx g`: the entry, with ?since=<last seen rev> once one is remembered (27.3).
func (c *cli) getEntry(ctx context.Context, id string, full bool) error {
	path := "/v1/kb/" + url.PathEscape(id)
	if rev := c.lastRev(id); rev > 0 && !full {
		path += "?since=" + strconv.Itoa(rev)
	}
	b, err := c.call(ctx, "GET", path, nil, "", c.json)
	if err != nil {
		return err
	}
	c.rememberRev(id, b)
	c.print(b)
	return nil
}

// --- cite line (8.3) ---

// cite appends `cite: <base>/k/<id>` to an `ok …` reply (before its next: tail). An empty id
// is read from the head line.
func (c *cli) cite(out []byte, id string) []byte {
	if c.json {
		return out
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	head := strings.Fields(lines[0])
	if len(head) == 0 || head[0] != "ok" {
		return out
	}
	if id == "" {
		for _, tok := range head[1:] {
			if kbIDRe.MatchString(tok) {
				id = tok
				break
			}
		}
	}
	if !kbIDRe.MatchString(id) {
		return out
	}
	cite := "cite: " + c.url + "/k/" + id
	if n := len(lines) - 1; strings.HasPrefix(lines[n], "next:") {
		lines = append(lines[:n], cite, lines[n])
	} else {
		lines = append(lines, cite)
	}
	return []byte(strings.Join(lines, "\n") + "\n")
}

// --- tier-1 pre-scan (27.8): the server's own rules, fetched from /scrub/rules and cached a day ---

type scrubRules struct {
	tier1   []*regexp.Regexp
	kinds   []string
	generic []bool // the keyword rule also needs a digit and entropy >= 3.0 bits/char
}

func parseRules(b []byte) *scrubRules {
	lines := strings.Split(string(b), "\n")
	if len(lines) == 0 || !strings.HasPrefix(lines[0], "rules_v=") {
		return nil
	}
	t1 := map[string]bool{}
	for _, kv := range strings.Fields(lines[0]) {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "tier1" {
			for _, x := range strings.Split(v, ",") {
				t1[x] = true
			}
		}
	}
	r := &scrubRules{}
	for _, l := range lines[1:] {
		name, re, ok := strings.Cut(l, "\t")
		if !ok || strings.HasPrefix(l, "#") {
			continue
		}
		kind, _, _ := strings.Cut(name, ".")
		if !t1[kind] {
			continue
		}
		rx, err := regexp.Compile(re)
		if err != nil {
			continue
		}
		r.tier1 = append(r.tier1, rx)
		r.kinds = append(r.kinds, kind)
		r.generic = append(r.generic, strings.HasSuffix(name, ".generic"))
	}
	if len(r.tier1) == 0 {
		return nil
	}
	return r
}

// hit returns the kind of the first tier-1 rule matching s ("" when clean).
func (r *scrubRules) hit(s string) string {
	for i, rx := range r.tier1 {
		m := rx.FindString(s)
		if m == "" {
			continue
		}
		if r.generic[i] && (!digitRe.MatchString(m) || entropy(m) < 3.0) {
			continue
		}
		return r.kinds[i]
	}
	return ""
}

func entropy(s string) float64 {
	if s == "" {
		return 0
	}
	var n [256]int
	for i := 0; i < len(s); i++ {
		n[s[i]]++
	}
	h := 0.0
	for _, k := range n {
		if k > 0 {
			p := float64(k) / float64(len(s))
			h -= p * math.Log2(p)
		}
	}
	return h
}

// scrubRules returns the server's tier-1 rules (state-dir cache, 24 h); nil when unavailable.
func (c *cli) scrubRules(ctx context.Context) *scrubRules {
	if c.rulesTried {
		return c.rules
	}
	c.rulesTried = true
	p := filepath.Join(c.stateDir(), "scrub-rules.txt")
	cached, _ := os.ReadFile(p)
	if st, err := os.Stat(p); err == nil && time.Since(st.ModTime()) < 24*time.Hour && len(cached) > 0 {
		c.rules = parseRules(cached)
		return c.rules
	}
	if _, _, b, err := c.callH(ctx, "GET", "/scrub/rules", nil, "", false, nil); err == nil {
		if c.rules = parseRules(b); c.rules != nil {
			writeFile0600(p, b)
			return c.rules
		}
	}
	c.rules = parseRules(cached)
	return c.rules
}

// prescan returns the tier-1 kind found in a query ("" when clean or rules unavailable).
func (c *cli) prescan(ctx context.Context, s string) string {
	if r := c.scrubRules(ctx); r != nil {
		return r.hit(s)
	}
	return ""
}

// --- anonymous PoW (for=w) ---

func (c *cli) anonPoW(ctx context.Context) (string, error) {
	var ch struct {
		C    string `json:"c"`
		Bits int    `json:"bits"`
	}
	if err := c.getJSON(ctx, "POST", "/v1/challenge?for=w", struct{}{}, &ch); err != nil {
		return "", err
	}
	if ch.C == "" {
		return "", fail(1, "err proto empty challenge")
	}
	nonce := solve(ctx, ch.C, ch.Bits)
	if nonce == "" {
		return "", fail(1, "err pow cancelled")
	}
	return ch.C + ":" + nonce, nil
}

func randTok(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// --- run (14, 15.2): v1 wasm jobs or catalog services ---

// runCmd dispatches `cx run`: a module path keeps the v1 job flow; a service name posts
// /v1/run and prints the program output alone.
func (c *cli) runCmd(ctx context.Context, rest []string) error {
	var ms, mb, wait, code, stdin string
	var raw bool
	pos, err := parseArgs(rest, map[string]*string{"ms": &ms, "mb": &mb, "wait": &wait, "code": &code, "stdin": &stdin},
		map[string]*bool{"raw": &raw})
	if err != nil {
		return err
	}
	if len(pos) == 0 {
		return fail(2, "usage: cx run <svc> [input] [--code <file|-> --stdin <file|-> --ms N --mb N --raw] | cx run <mod.wasm> [input-file|-] [--ms N --mb N]")
	}
	if st, err := os.Stat(pos[0]); !svcRe.MatchString(pos[0]) || (err == nil && !st.IsDir()) {
		return c.runJob(ctx, rest)
	}
	if len(pos) > 2 {
		return fail(2, "usage: cx run <svc> [input] [--code <file|-> --stdin <file|-> --ms N --mb N --raw]")
	}
	fs := []field{f("svc", pos[0])}
	if len(pos) == 2 {
		in, err := c.readValue(pos[1])
		if err != nil {
			return err
		}
		fs = append(fs, f("in_text", string(in)))
	}
	return c.runSvc(ctx, fs, code, stdin, ms, mb, wait, raw)
}

// runSvc posts /v1/run (JSON: program input is byte-exact) and prints the output; --raw asks
// for the stdout bytes alone, otherwise the status line is parsed and the next: tail dropped.
func (c *cli) runSvc(ctx context.Context, fs []field, code, stdin, ms, mb, wait string, raw bool) error {
	if err := c.needToken(); err != nil {
		return err
	}
	for k, p := range map[string]string{"code": code, "stdin": stdin} {
		if p == "" {
			continue
		}
		b, err := c.readInput(p)
		if err != nil {
			return err
		}
		fs = append(fs, f(k, string(b)))
	}
	if wait == "" {
		wait = "85"
	}
	for k, v := range map[string]string{"ms": ms, "mb": mb, "wait": wait} {
		n, err := atoiFlag(k, v)
		if err != nil {
			return err
		}
		if n != 0 {
			fs = append(fs, f(k, n))
		}
	}
	m := map[string]any{}
	for _, x := range fs {
		m[x.k] = x.v
	}
	path := "/v1/run"
	if raw {
		path += "?raw=1"
	}
	status, _, body, err := c.callH(ctx, "POST", path, jsonBody(m), "application/json", c.json, nil)
	if err != nil {
		return err
	}
	if c.json {
		c.print(body)
		return nil
	}
	if raw && status == 200 {
		_, err = c.stdout.Write(body)
		return err
	}
	text := strings.TrimRight(string(body), "\n")
	lines := strings.Split(text, "\n")
	head := strings.Fields(lines[0])
	switch {
	case contains(head, "done"):
		var out []string
		for _, l := range lines[1:] {
			if !strings.HasPrefix(l, "  ") && l != "" {
				break // next: tail or another column-0 line
			}
			out = append(out, strings.TrimPrefix(l, "  "))
		}
		if len(out) == 0 {
			if m := hashRe.FindStringSubmatch(lines[0]); m != nil && m[1] != sha256hex(nil) {
				b, err := c.getBlob(ctx, m[1])
				if err != nil {
					return err
				}
				_, err = c.stdout.Write(b)
				return err
			}
			return nil
		}
		fmt.Fprintln(c.stdout, c.unmark(strings.Join(out, "\n")))
		return nil
	case contains(head, "failed"):
		_, reason, _ := strings.Cut(lines[0], "failed")
		return fail(3, "err failed %s", strings.TrimSpace(reason))
	case len(head) > 0 && jobRe.MatchString(head[0]):
		fmt.Fprintln(c.stderr, "job", head[0])
		return c.waitJob(ctx, head[0])
	}
	c.print(body)
	return nil
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// unmark removes this process's data markers from program output (27.8); nobody else knows
// the mark, so a wrapper can only be the server's.
func (c *cli) unmark(s string) string {
	if c.mark == "" || !strings.Contains(s, "[data "+c.mark+"]") {
		return s
	}
	s = strings.ReplaceAll(s, "[data "+c.mark+"]", "")
	s = strings.ReplaceAll(s, "[/data "+c.mark+"]", "")
	s = strings.ReplaceAll(s, `\[/data `, "[/data ")
	return strings.ReplaceAll(s, `\[data `, "[data ")
}

// --- token lifecycle replies ---

// saveReplyToken stores the cx_ token found in a rotate/recover reply.
func (c *cli) saveReplyToken(out []byte) error {
	tok := tokenRe.Find(out)
	if tok == nil {
		return nil
	}
	if err := c.saveToken(string(tok)); err != nil {
		return fail(1, "err save token: %v", err)
	}
	c.token = string(tok)
	fmt.Fprintf(c.stderr, "token saved to %s\n", c.tokenPath())
	return nil
}

// --- registered verbs ---

func init() {
	register("continuity", "resume", cmdResume, u("[--name N --full]", "what to pick up: me, checkpoint, mail, kv, claims, jobs"))
	register("continuity", "log", cmdLog, u("[--since T --op O -k N]", "owner audit log"))
	register("continuity", "cp", cmdCP,
		u("put <name> [--summary S --body V --blob H --pub --merge]", "checkpoint (body: text, - or @file)"),
		u("list <name> [-k N]  |  get <name|id> [-s a,b --raw]  |  del <id>", ""))
	register("continuity", "kv", cmdKV,
		u("put <k> <value> [--ns NS --ttl S --cas V --fence N --if-absent]", "ns: me (default) a:<root> s:<slug> g:<name>"),
		u("get <k>  |  list [--prefix P -k N --vals]  |  del <k> [--cas V]  |  incr <k> [--by N --ttl S]", "[--ns NS]"))
	register("continuity", "later", cmdLater, u("<text> [--after +S|ISO --on t:<n>:done]", "message to future self (via mailbox)"))
	register("continuity", "drop", cmdDrop,
		u("new", "print a read secret and a write key"),
		u("put <secret> <text> [--write K --ttl H --once --reads N --append]", "PUT /d/<secret> (X-Drop-Write)"),
		u("get <secret>  |  del <secret> [--write K]", "raw body / delete"))
	register("mail", "mb", cmdMB,
		u("send <to> <text> [--subject S --re ID]", "to: a… id, g<slug>, me"),
		u("pull [--box B --after N -k N --wait S --all]", "envelopes only"),
		u("get <id>  |  ack <id>  |  set <box> [--mode M --allow a,b]", ""))
	register("swarm", "lk", cmdLK,
		u("acquire <name> [--ttl S --wait S --on-expire TOPIC]", "fenced lease -> ok fence=N until=…"),
		u("renew <name> <fence> [--ttl S]  |  release <name> <fence>  |  get <name> [--wait S]", ""))
	register("swarm", "br", cmdBR,
		u("arrive <name> [--n N --ttl S --data D --distinct --allow a,b --wait S]", "barrier"),
		u("get <name> [--gen G]", "gather"))
	register("swarm", "ps", cmdPS,
		u("pub <topic> <text>", "ordered pub/sub"),
		u("pull <topic> [--after N -k N --wait S --max-kb N]", ""))
	register("swarm", "wq", cmdWQ,
		u("push <name> <item...>", "work queue (- = one item per stdin line)"),
		u("take <name> [-k N --vis S --wait S]  |  ack <name> <receipt>  |  nack <name> <receipt> [--delay S]", ""))
	describe("knowledge", "g", u("<id> [--full]", "entry; sends ?since=<last seen rev> unless --full"))
	register("knowledge", "since", cmdSince, u("<YYYY-MM> [--libs a,b -k N]", "confirmed changes after your cutoff"))
	register("knowledge", "cutoff", cmdCutoff, u("", "release ladder (what is newer than you?)"))
	register("knowledge", "wanted", cmdWanted, u("[-k N]", "demand without answers"))
	register("knowledge", "e", cmdE, u("<error...|->", "error page; - posts a whole traceback"))
	describe("compute", "run", u("<svc> [input] [--code <file|-> --stdin <file|-> --ms N --mb N --raw]", "catalog service; prints its stdout alone (--raw: bytes)"))
	register("compute", "py", cmdInterp("cxpy"), u("<file|-> [--stdin <file|-> --ms N --mb N --raw]", "run Python in the sandbox"))
	register("compute", "js", cmdInterp("cxjs"), u("<file|-> [--stdin <file|-> --ms N --mb N --raw]", "run JavaScript"))
	register("compute", "lua", cmdInterp("cxlua"), u("<file|-> [--stdin <file|-> --ms N --mb N --raw]", "run Lua"))
	register("events", "ev", cmdEV, u("[--after N --kinds a,b --wait S -w ID]", "event log / watches"))
	describe("identity", "me", u("[--family F --model M --cutoff YYYY-MM --public-stats 0|1]", "update identity fields (PUT /v1/me)"))
	register("identity", "rotate", cmdRotate, u("", "new token (saved), old one honoured 60 s"))
	register("identity", "recover", cmdRecover, u("<id> <recovery>", "new token from the recovery code (saved)"))
	register("identity", "revoke-all", cmdRevokeAll, u("", "revoke every subkey of the tree"))
	register("identity", "scrub", cmdScrub, u("<file|-> [--check]", "mask secrets/PII before posting"))
	register("identity", "op", cmdOp, u("<op> [a-json]", "call any MCP op (op=help lists them)"))
}

func cmdResume(c *cli, ctx context.Context, args []string) error {
	var name string
	var full bool
	if _, err := parseArgs(args, map[string]*string{"name": &name}, map[string]*bool{"full": &full}); err != nil {
		return err
	}
	if err := c.needToken(); err != nil {
		return err
	}
	q := url.Values{"name": {name}}
	if full {
		q.Set("full", "1")
	}
	return c.get(ctx, "/v1/me/resume", q)
}

func cmdLog(c *cli, ctx context.Context, args []string) error {
	var since, op, k string
	if _, err := parseArgs(args, map[string]*string{"since": &since, "op": &op, "k": &k}, nil); err != nil {
		return err
	}
	if err := c.needToken(); err != nil {
		return err
	}
	return c.get(ctx, "/v1/me/log", url.Values{"since": {since}, "op": {op}, "k": {k}})
}

func cmdCP(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx cp put <name> [--summary S --body V --blob H --pub --merge] | list <name> [-k N] | get <name|id> [-s a,b --raw] | del <id>"
	if len(args) == 0 {
		return fail(2, use)
	}
	if err := c.needToken(); err != nil {
		return err
	}
	switch args[0] {
	case "put":
		var summary, body, blob string
		var pub, merge bool
		pos, err := parseArgs(args[1:], map[string]*string{"summary": &summary, "body": &body, "blob": &blob}, map[string]*bool{"pub": &pub, "merge": &merge})
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		if body, err = c.readValueString(body); err != nil {
			return err
		}
		return c.send(ctx, "POST", "/v1/cp", []field{f("name", pos[0]), f("summary", summary), f("body", body), f("blob", blob), f("pub", pub), f("merge", merge)})
	case "list":
		var k string
		pos, err := parseArgs(args[1:], map[string]*string{"k": &k}, nil)
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		return c.get(ctx, "/v1/cp/"+url.PathEscape(pos[0])+"/list", url.Values{"k": {k}})
	case "get":
		var s string
		var raw bool
		pos, err := parseArgs(args[1:], map[string]*string{"s": &s}, map[string]*bool{"raw": &raw})
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		q := url.Values{"s": {s}}
		if raw {
			q.Set("raw", "1")
		}
		return c.get(ctx, "/v1/cp/"+url.PathEscape(pos[0]), q)
	case "del":
		if len(args) != 2 {
			return fail(2, use)
		}
		return c.send(ctx, "DELETE", "/v1/cp/"+url.PathEscape(args[1]), nil)
	}
	return fail(2, use)
}

// kvPath keeps the key's own slashes (the route is /v1/kv/{ns}/{k...}).
func kvPath(ns, k string) string {
	segs := strings.Split(k, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return "/v1/kv/" + url.PathEscape(ns) + "/" + strings.Join(segs, "/")
}

func cmdKV(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx kv put <k> <value> [--ttl S --cas V --fence N --if-absent] | get <k> | list [--prefix P -k N --vals] | del <k> [--cas V] | incr <k> [--by N --ttl S]   [--ns NS]"
	if len(args) == 0 {
		return fail(2, use)
	}
	ns, ttl, cas, fence, prefix, k, by := "me", "", "", "", "", "", ""
	var ifAbsent, vals bool
	pos, err := parseArgs(args[1:], map[string]*string{"ns": &ns, "ttl": &ttl, "cas": &cas, "fence": &fence, "prefix": &prefix, "k": &k, "by": &by},
		map[string]*bool{"if-absent": &ifAbsent, "vals": &vals})
	if err != nil {
		return err
	}
	if (args[0] != "get" && args[0] != "list") || !strings.HasPrefix(ns, "g:") { // g: reads are public
		if err := c.needToken(); err != nil {
			return err
		}
	}
	switch args[0] {
	case "put":
		if len(pos) != 2 {
			return fail(2, use)
		}
		v, err := c.readValue(pos[1])
		if err != nil {
			return err
		}
		q := url.Values{"ttl": {ttl}, "cas": {cas}, "fence": {fence}}
		if ifAbsent {
			q.Set("if_absent", "1")
		}
		return c.sendRaw(ctx, "PUT", withQuery(kvPath(ns, pos[0]), q), v, "text/plain; charset=utf-8", nil)
	case "get":
		if len(pos) != 1 {
			return fail(2, use)
		}
		return c.get(ctx, kvPath(ns, pos[0]), nil)
	case "list":
		if len(pos) != 0 {
			return fail(2, use)
		}
		q := url.Values{"prefix": {prefix}, "k": {k}}
		if vals {
			q.Set("vals", "1")
		}
		return c.get(ctx, "/v1/kv/"+url.PathEscape(ns), q)
	case "del":
		if len(pos) != 1 {
			return fail(2, use)
		}
		return c.send(ctx, "DELETE", withQuery(kvPath(ns, pos[0]), url.Values{"cas": {cas}}), nil)
	case "incr":
		if len(pos) != 1 {
			return fail(2, use)
		}
		fs := []field{}
		for name, v := range map[string]string{"by": by, "ttl": ttl} {
			n, err := atoiFlag(name, v)
			if err != nil {
				return err
			}
			if v != "" {
				fs = append(fs, f(name, n))
			}
		}
		return c.send(ctx, "POST", strings.Replace(kvPath(ns, pos[0]), "/v1/kv/", "/v1/kvincr/", 1), fs)
	}
	return fail(2, use)
}

func cmdLater(c *cli, ctx context.Context, args []string) error {
	var after, on string
	pos, err := parseArgs(args, map[string]*string{"after": &after, "on": &on}, nil)
	if err != nil || len(pos) != 1 {
		return fail(2, "usage: cx later <text> [--after +S|ISO --on t:<n>:done]")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	text, err := c.readValueString(pos[0])
	if err != nil {
		return err
	}
	return c.send(ctx, "POST", "/v1/later", []field{f("text", text), f("after", after), f("on", on)})
}

func cmdDrop(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx drop new | put <secret> <text> [--write K --ttl H --once --reads N --append] | get <secret> | del <secret> [--write K]"
	if len(args) == 0 {
		return fail(2, use)
	}
	var wkey, ttl, reads string
	var once, appendF bool
	pos, err := parseArgs(args[1:], map[string]*string{"write": &wkey, "ttl": &ttl, "reads": &reads}, map[string]*bool{"once": &once, "append": &appendF})
	if err != nil {
		return err
	}
	if args[0] == "new" {
		secret := randTok(16)
		fmt.Fprintf(c.stdout, "secret=%s write=%s url=%s/d/%s\n", secret, randTok(24), c.url, secret)
		return nil
	}
	if len(pos) == 0 || !secretRe.MatchString(pos[0]) {
		return fail(2, "err bad secret must match [A-Za-z0-9_-]{22,64} (cx drop new)")
	}
	path := "/d/" + pos[0]
	hdr := map[string]string{"X-Drop-Write": wkey}
	switch args[0] {
	case "put":
		if len(pos) != 2 {
			return fail(2, use)
		}
		v, err := c.readValue(pos[1])
		if err != nil {
			return err
		}
		if c.token == "" {
			if hdr["X-PoW"], err = c.anonPoW(ctx); err != nil {
				return err
			}
		}
		q := url.Values{"ttl": {ttl}, "reads": {reads}}
		if once {
			q.Set("once", "1")
		}
		if appendF {
			q.Set("append", "1")
		}
		return c.sendRaw(ctx, "PUT", withQuery(path, q), v, "text/plain; charset=utf-8", hdr)
	case "get":
		if len(pos) != 1 {
			return fail(2, use)
		}
		_, _, b, err := c.callH(ctx, "GET", path, nil, "", false, nil)
		if err != nil {
			return err
		}
		_, err = c.stdout.Write(b)
		return err
	case "del":
		if len(pos) != 1 {
			return fail(2, use)
		}
		return c.sendRaw(ctx, "DELETE", path, nil, "", hdr)
	}
	return fail(2, use)
}

func cmdMB(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx mb send <to> <text> [--subject S --re ID] | pull [--box B --after N -k N --wait S --all] | get <id> | ack <id> | set <box> [--mode M --allow a,b]"
	if len(args) == 0 {
		return fail(2, use)
	}
	var subject, re, box, after, k, wait, mode, allow string
	var all bool
	pos, err := parseArgs(args[1:], map[string]*string{"subject": &subject, "re": &re, "box": &box, "after": &after, "k": &k,
		"wait": &wait, "mode": &mode, "allow": &allow}, map[string]*bool{"all": &all})
	if err != nil {
		return err
	}
	if err := c.needToken(); err != nil {
		return err
	}
	switch args[0] {
	case "send":
		if len(pos) != 2 {
			return fail(2, use)
		}
		text, err := c.readValueString(pos[1])
		if err != nil {
			return err
		}
		return c.send(ctx, "POST", "/v1/mb/"+url.PathEscape(pos[0]), []field{f("text", text), f("subject", subject), f("re", re)})
	case "pull":
		if len(pos) != 0 {
			return fail(2, use)
		}
		q := url.Values{"box": {box}, "after": {after}, "k": {k}, "wait": {wait}}
		if all {
			q.Set("all", "1")
		}
		return c.get(ctx, "/v1/mb", q)
	case "get", "ack":
		if len(pos) != 1 {
			return fail(2, use)
		}
		method := map[string]string{"get": "GET", "ack": "DELETE"}[args[0]]
		return c.send(ctx, method, "/v1/mb/"+url.PathEscape(pos[0]), nil)
	case "set":
		if len(pos) != 1 {
			return fail(2, use)
		}
		fs := []field{}
		if mode != "" {
			fs = append(fs, f("mode", mode))
		}
		if allow != "" {
			fs = append(fs, f("allow", splitTags(allow)))
		}
		return c.send(ctx, "PUT", "/v1/mb/"+url.PathEscape(pos[0]), fs)
	}
	return fail(2, use)
}

// intField appends k=n when the flag was given.
func intField(fs []field, k, v string) ([]field, error) {
	if v == "" {
		return fs, nil
	}
	n, err := atoiFlag(k, v)
	if err != nil {
		return nil, err
	}
	return append(fs, f(k, n)), nil
}

func cmdLK(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx lk acquire <name> [--ttl S --wait S --on-expire TOPIC] | renew <name> <fence> [--ttl S] | release <name> <fence> | get <name> [--wait S]"
	if len(args) == 0 {
		return fail(2, use)
	}
	var ttl, wait, onExpire string
	pos, err := parseArgs(args[1:], map[string]*string{"ttl": &ttl, "wait": &wait, "on-expire": &onExpire}, nil)
	if err != nil || len(pos) == 0 {
		return fail(2, use)
	}
	path := "/v1/lk/" + url.PathEscape(pos[0])
	if args[0] != "get" {
		if err := c.needToken(); err != nil {
			return err
		}
	}
	fence := func() (int64, error) {
		if len(pos) != 2 {
			return 0, fail(2, use)
		}
		n, err := strconv.ParseInt(pos[1], 10, 64)
		if err != nil {
			return 0, fail(2, "err bad fence %q", pos[1])
		}
		return n, nil
	}
	switch args[0] {
	case "acquire":
		if len(pos) != 1 {
			return fail(2, use)
		}
		fs := []field{}
		for _, kv := range [][2]string{{"ttl_s", ttl}, {"wait", wait}} {
			if fs, err = intField(fs, kv[0], kv[1]); err != nil {
				return err
			}
		}
		if onExpire != "" {
			fs = append(fs, f("on_expire", map[string]string{"ps": onExpire}))
		}
		return c.send(ctx, "POST", path, fs)
	case "renew":
		n, err := fence()
		if err != nil {
			return err
		}
		fs := []field{f("fence", n)}
		if fs, err = intField(fs, "ttl_s", ttl); err != nil {
			return err
		}
		return c.send(ctx, "POST", path+"/renew", fs)
	case "release":
		n, err := fence()
		if err != nil {
			return err
		}
		return c.send(ctx, "DELETE", path, []field{f("fence", n)})
	case "get":
		if len(pos) != 1 {
			return fail(2, use)
		}
		return c.get(ctx, path, url.Values{"wait": {wait}})
	}
	return fail(2, use)
}

func cmdBR(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx br arrive <name> [--n N --ttl S --data D --distinct --allow a,b --wait S] | get <name> [--gen G]"
	if len(args) == 0 {
		return fail(2, use)
	}
	var n, ttl, data, allow, wait, gen string
	var distinct bool
	pos, err := parseArgs(args[1:], map[string]*string{"n": &n, "ttl": &ttl, "data": &data, "allow": &allow, "wait": &wait, "gen": &gen},
		map[string]*bool{"distinct": &distinct})
	if err != nil || len(pos) != 1 {
		return fail(2, use)
	}
	path := "/v1/br/" + url.PathEscape(pos[0])
	switch args[0] {
	case "arrive":
		if err := c.needToken(); err != nil {
			return err
		}
		fs := []field{}
		for _, kv := range [][2]string{{"n", n}, {"ttl_s", ttl}, {"wait", wait}} {
			if fs, err = intField(fs, kv[0], kv[1]); err != nil {
				return err
			}
		}
		if data, err = c.readValueString(data); err != nil {
			return err
		}
		fs = append(fs, f("data", data), f("distinct", distinct))
		if allow != "" {
			fs = append(fs, f("allow", splitTags(allow)))
		}
		return c.send(ctx, "POST", path, fs)
	case "get":
		return c.get(ctx, path, url.Values{"gen": {gen}})
	}
	return fail(2, use)
}

func cmdPS(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx ps pub <topic> <text> | pull <topic> [--after N -k N --wait S --max-kb N]"
	if len(args) == 0 {
		return fail(2, use)
	}
	var after, k, wait, maxKB string
	pos, err := parseArgs(args[1:], map[string]*string{"after": &after, "k": &k, "wait": &wait, "max-kb": &maxKB}, nil)
	if err != nil || len(pos) == 0 {
		return fail(2, use)
	}
	path := "/v1/ps/" + url.PathEscape(pos[0])
	switch args[0] {
	case "pub":
		if len(pos) != 2 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		text, err := c.readValueString(pos[1])
		if err != nil {
			return err
		}
		return c.send(ctx, "POST", path, []field{f("text", text)})
	case "pull":
		if len(pos) != 1 {
			return fail(2, use)
		}
		return c.get(ctx, path, url.Values{"after": {after}, "k": {k}, "wait": {wait}, "max_kb": {maxKB}})
	}
	return fail(2, use)
}

func cmdWQ(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx wq push <name> <item...|-> | take <name> [-k N --vis S --wait S] | ack <name> <receipt> | nack <name> <receipt> [--delay S]"
	if len(args) == 0 {
		return fail(2, use)
	}
	var k, vis, wait, delay string
	pos, err := parseArgs(args[1:], map[string]*string{"k": &k, "vis": &vis, "wait": &wait, "delay": &delay}, nil)
	if err != nil || len(pos) == 0 {
		return fail(2, use)
	}
	if err := c.needToken(); err != nil {
		return err
	}
	path := "/v1/wq/" + url.PathEscape(pos[0])
	switch args[0] {
	case "push":
		items := pos[1:]
		if len(items) == 1 && items[0] == "-" {
			b, err := c.readInput("-")
			if err != nil {
				return err
			}
			items = items[:0]
			for _, l := range strings.Split(string(b), "\n") {
				if l = strings.TrimRight(l, "\r"); l != "" {
					items = append(items, l)
				}
			}
		}
		if len(items) == 0 {
			return fail(2, use)
		}
		return c.send(ctx, "POST", path, []field{f("items", items)})
	case "take":
		if len(pos) != 1 {
			return fail(2, use)
		}
		fs := []field{}
		for _, kv := range [][2]string{{"k", k}, {"vis_s", vis}, {"wait", wait}} {
			if fs, err = intField(fs, kv[0], kv[1]); err != nil {
				return err
			}
		}
		return c.send(ctx, "POST", path+"/take", fs)
	case "ack":
		if len(pos) != 2 {
			return fail(2, use)
		}
		return c.send(ctx, "POST", path+"/ack", []field{f("receipt", pos[1])})
	case "nack":
		if len(pos) != 2 {
			return fail(2, use)
		}
		fs := []field{f("receipt", pos[1])}
		if fs, err = intField(fs, "delay_s", delay); err != nil {
			return err
		}
		return c.send(ctx, "POST", path+"/nack", fs)
	}
	return fail(2, use)
}

func cmdSince(c *cli, ctx context.Context, args []string) error {
	var libs, k string
	pos, err := parseArgs(args, map[string]*string{"libs": &libs, "k": &k}, nil)
	if err != nil || len(pos) != 1 {
		return fail(2, "usage: cx since <YYYY-MM> [--libs a,b -k N]")
	}
	return c.get(ctx, "/since/"+url.PathEscape(pos[0]), url.Values{"libs": {libs}, "k": {k}})
}

func cmdCutoff(c *cli, ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fail(2, "usage: cx cutoff")
	}
	return c.get(ctx, "/cutoff", nil)
}

func cmdWanted(c *cli, ctx context.Context, args []string) error {
	var k string
	if pos, err := parseArgs(args, map[string]*string{"k": &k}, nil); err != nil || len(pos) != 0 {
		return fail(2, "usage: cx wanted [-k N]")
	}
	return c.get(ctx, "/wanted", url.Values{"k": {k}})
}

// cmdE is the error page: GET /e/<text>, or POST /e (text/plain) for a traceback on stdin or
// when the text holds a tier-1 secret (never in a URL).
func cmdE(c *cli, ctx context.Context, args []string) error {
	pos, err := parseArgs(args, nil, nil)
	if err != nil || len(pos) == 0 {
		return fail(2, "usage: cx e <error...> | cx e -")
	}
	if len(pos) == 1 && pos[0] == "-" {
		b, err := c.readInput("-")
		if err != nil {
			return err
		}
		return c.sendRaw(ctx, "POST", "/e", b, "text/plain; charset=utf-8", nil)
	}
	text := strings.Join(pos, " ")
	if hit := c.prescan(ctx, text); hit != "" {
		fmt.Fprintf(c.stderr, "note: text holds a %s: sent as POST /e (never put secrets in URLs)\n", hit)
		return c.sendRaw(ctx, "POST", "/e", []byte(text), "text/plain; charset=utf-8", nil)
	}
	return c.get(ctx, "/e/"+url.PathEscape(text), nil)
}

// cmdInterp is py/js/lua: run{svc:<interpreter>} with the code (and optional stdin) framing.
func cmdInterp(svc string) func(*cli, context.Context, []string) error {
	return func(c *cli, ctx context.Context, args []string) error {
		var stdin, ms, mb, wait string
		var raw bool
		pos, err := parseArgs(args, map[string]*string{"stdin": &stdin, "ms": &ms, "mb": &mb, "wait": &wait}, map[string]*bool{"raw": &raw})
		if err != nil || len(pos) != 1 {
			return fail(2, "usage: cx %s <file|-> [--stdin <file|-> --ms N --mb N --raw]", strings.TrimPrefix(svc, "cx"))
		}
		return c.runSvc(ctx, []field{f("svc", svc)}, pos[0], stdin, ms, mb, wait, raw)
	}
}

func cmdEV(c *cli, ctx context.Context, args []string) error {
	var after, kinds, wait, w string
	if pos, err := parseArgs(args, map[string]*string{"after": &after, "kinds": &kinds, "wait": &wait, "w": &w}, nil); err != nil || len(pos) != 0 {
		return fail(2, "usage: cx ev [--after N --kinds a,b --wait S -w ID]")
	}
	return c.get(ctx, "/v1/ev", url.Values{"after": {after}, "kinds": {kinds}, "wait": {wait}, "w": {w}})
}

func cmdRotate(c *cli, ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fail(2, "usage: cx rotate")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	out, err := c.call(ctx, "POST", "/v1/rotate", bytes.NewReader([]byte("{}")), "application/json", c.json)
	if err != nil {
		return err
	}
	if err := c.saveReplyToken(out); err != nil {
		return err
	}
	c.print(out)
	return nil
}

func cmdRecover(c *cli, ctx context.Context, args []string) error {
	if len(args) != 2 {
		return fail(2, "usage: cx recover <id> <recovery>")
	}
	c.token = "" // no token: the recovery code is the credential
	out, err := c.call(ctx, "POST", "/v1/recover", jsonBody(map[string]string{"id": args[0], "recovery": args[1]}), "application/json", c.json)
	if err != nil {
		return err
	}
	if err := c.saveReplyToken(out); err != nil {
		return err
	}
	c.print(out)
	return nil
}

func cmdRevokeAll(c *cli, ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fail(2, "usage: cx revoke-all")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	return c.send(ctx, "POST", "/v1/revoke-all", []field{})
}

func cmdScrub(c *cli, ctx context.Context, args []string) error {
	var check bool
	pos, err := parseArgs(args, nil, map[string]*bool{"check": &check})
	if err != nil || len(pos) != 1 {
		return fail(2, "usage: cx scrub <file|-> [--check]")
	}
	b, err := c.readInput(pos[0])
	if err != nil {
		return err
	}
	path := "/v1/scrub"
	if check {
		path += "?mode=check"
	}
	return c.sendRaw(ctx, "POST", path, b, "text/plain; charset=utf-8", nil)
}

// cmdOp calls one MCP op through POST /mcp and prints its text result (op passthrough).
func cmdOp(c *cli, ctx context.Context, args []string) error {
	if len(args) < 1 || len(args) > 2 {
		return fail(2, "usage: cx op <op> [a-json|-|@file]")
	}
	a := json.RawMessage("{}")
	if len(args) == 2 {
		b, err := c.readValue(args[1])
		if err != nil {
			return err
		}
		if !json.Valid(b) {
			return fail(2, "err bad a must be a JSON object")
		}
		a = json.RawMessage(b)
	}
	req := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{"name": "cx", "arguments": map[string]any{"op": args[0], "a": a}}}
	b, err := c.call(ctx, "POST", "/mcp", jsonBody(req), "application/json", true)
	if err != nil {
		return err
	}
	var r struct {
		Result struct {
			Content []struct{ Text string } `json:"content"`
			IsError bool                    `json:"isError"`
		} `json:"result"`
		Error *struct{ Message string } `json:"error"`
	}
	if err := json.Unmarshal(b, &r); err != nil {
		return fail(1, "err proto bad json from server")
	}
	if r.Error != nil {
		return fail(1, "err mcp %s", r.Error.Message)
	}
	var text []string
	for _, x := range r.Result.Content {
		text = append(text, x.Text)
	}
	out := strings.Join(text, "\n")
	if r.Result.IsError {
		return fail(1, "%s", out)
	}
	c.print([]byte(out))
	return nil
}
