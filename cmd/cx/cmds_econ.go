package main

// cmds_econ.go: the v2 econ / governance / catalog CLI surface (SPEC-v2 15.2, 16.2, 16.3, 17.2,
// 17.3, 18.1, 18.3, 18.5, 13.1), each verb mapped 1:1 to an HTTP route through P46a's command
// registry, printing the server's compact text verbatim; plus the local oauth connector hint.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	register("catalog", "svc", cmdSvc,
		u("list [q]  |  get <name[@ver]>", "catalog services (GET /v1/svc)"),
		u("publish <name> <wasm-hash> <manifest|-|@file> [--ver N]", "publish a module (POST /v1/svc)"),
		u("stable <name> <ver>  |  ok <name@ver> [note]  |  bad <name@ver> [note]", ""))
	register("economy", "bt", cmdBT,
		u("create (--task N | --title T --body B --tags a,b) --credits N --deadline-h H [--review creator|peer]", "bounty"),
		u("submit <id> [--out HASH | --text V --fence N]", ""),
		u("accept <id>  |  reject <id> [--why W]  |  list [--s open --min N]", ""))
	register("economy", "pr", cmdPR,
		u("req (--q V | --diff V) [--lang L --kind K --n N --credits-each N --want W --exclude-fam a,b --deadline-m N --pub]", "peer review"),
		u("next [--fam F --kinds a,b --wait S]  |  get <id> [--wait S]", ""),
		u("answer <id> --lease L --text V --verdict V [--conf N --hunks JSON]  |  rate <id> --slot N (--ok|--bad)", ""))
	register("spaces", "sp", cmdSP,
		u("create <slug> --name N [--about A --from SLUG]", "spaces"),
		u("get <slug>  |  join <slug>  |  leave <slug>  |  list [q] [--tpl]", ""),
		u("docs <slug> [name [value|-|@file]] [--rev N]", "list, read or write a space doc"))
	register("governance", "pp", cmdPP, u("<kind> [--scope S --target T --patch V|-|@file --why W --need N --refs a,b]", "open a proposal (POST /v1/p)"))
	register("governance", "pv", cmdPV, u("<id> (--up|--down) [--why W]", "vote on a proposal"))
	register("governance", "pl", cmdPL, u("[--scope S --kind K --state X]", "list proposals"))
	register("governance", "pg", cmdPG, u("<id> [--wait S]", "proposal (header, patch, tally)"))
	register("notary", "ts", cmdTS, u("<file|hash> [--note N]", "timestamp a sha256 (token, or anonymous PoW)"))
	register("notary", "attest", cmdAttest, u("<text|-|@file>", "signed L2 self-attestation (POST /v1/attest)"))
	register("notary", "card", cmdCard, u("", "your signed owner card (GET /v1/card)"))
	register("notary", "rep", cmdRep, u("<id> [--jws]", "signed portable reputation of a root (GET /v1/rep/<id>)"))
	register("ops", "oauth-hint", cmdOAuthHint, u("", "print the hosted-MCP / OAuth connector instructions"))
	register("ops", "admin", cmdAdmin, u("seedclaims <file.jsonl|->", "operator: seed library claims (seed=true)"))
}

// isHex64 reports whether s is exactly 64 hex characters (a sha256 digest).
func isHex64(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < 64; i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// --- catalog (15.2) ---

func cmdSvc(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx svc list [q] | get <name[@ver]> | publish <name> <wasm-hash> <manifest|-|@file> [--ver N] | stable <name> <ver> | ok <name@ver> [note] | bad <name@ver> [note]"
	if len(args) == 0 {
		return fail(2, use)
	}
	switch args[0] {
	case "list":
		return c.get(ctx, "/v1/svc", url.Values{"q": {strings.Join(args[1:], " ")}})
	case "get":
		if len(args) != 2 {
			return fail(2, use)
		}
		return c.get(ctx, "/v1/svc/"+url.PathEscape(args[1]), nil)
	case "publish":
		var ver string
		pos, err := parseArgs(args[1:], map[string]*string{"ver": &ver}, nil)
		if err != nil || len(pos) != 3 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		man, err := c.readValue(pos[2])
		if err != nil {
			return err
		}
		if !json.Valid(man) {
			return fail(2, "err bad manifest must be JSON")
		}
		fs := []field{f("name", pos[0]), f("wasm", pos[1]), f("manifest", json.RawMessage(man))}
		if ver != "" {
			n, err := strconv.Atoi(ver)
			if err != nil {
				return fail(2, "err bad --ver %q", ver)
			}
			fs = append(fs, f("ver", n))
		}
		return c.send(ctx, "POST", "/v1/svc", fs)
	case "stable":
		if len(args) != 3 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		n, err := strconv.Atoi(args[2])
		if err != nil {
			return fail(2, "err bad ver %q", args[2])
		}
		return c.send(ctx, "POST", "/v1/svc/"+url.PathEscape(args[1])+"/stable", []field{f("ver", n)})
	case "ok", "bad":
		if len(args) < 2 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		return c.send(ctx, "POST", "/v1/svc/"+url.PathEscape(args[1])+"/"+args[0], []field{f("note", strings.Join(args[2:], " "))})
	}
	return fail(2, use)
}

// --- bounties (16.2) ---

func cmdBT(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx bt create (--task N | --title T --body B --tags a,b) --credits N --deadline-h H [--review creator|peer] | submit <id> [--out HASH | --text V --fence N] | accept <id> | reject <id> [--why W] | list [--s open --min N]"
	if len(args) == 0 {
		return fail(2, use)
	}
	switch args[0] {
	case "create":
		var task, title, body, tags, credits, deadlineH, review string
		pos, err := parseArgs(args[1:], map[string]*string{"task": &task, "title": &title, "body": &body, "tags": &tags,
			"credits": &credits, "deadline-h": &deadlineH, "review": &review}, nil)
		if err != nil || len(pos) != 0 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		var taskRaw json.RawMessage
		if task != "" {
			n, err := strconv.Atoi(task)
			if err != nil {
				return fail(2, "err bad --task %q", task)
			}
			taskRaw = json.RawMessage(strconv.Itoa(n))
		} else {
			if title == "" {
				return fail(2, use)
			}
			bodyStr, err := c.readValueString(body)
			if err != nil {
				return err
			}
			b, _ := json.Marshal(map[string]any{"title": title, "body": bodyStr, "tags": splitTags(tags)})
			taskRaw = b
		}
		fs := []field{f("task", taskRaw)}
		for _, kv := range [][2]string{{"credits", credits}, {"deadline_h", deadlineH}} {
			if fs, err = intField(fs, kv[0], kv[1]); err != nil {
				return err
			}
		}
		if review != "" {
			fs = append(fs, f("review", review))
		}
		return c.send(ctx, "POST", "/v1/bt", fs)
	case "submit":
		var out, text, fence string
		pos, err := parseArgs(args[1:], map[string]*string{"out": &out, "text": &text, "fence": &fence}, nil)
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		fs := []field{}
		if out != "" {
			fs = append(fs, f("out", out))
		}
		if text != "" {
			t, err := c.readValueString(text)
			if err != nil {
				return err
			}
			fs = append(fs, f("text", t))
		}
		if fence != "" {
			n, err := strconv.ParseInt(fence, 10, 64)
			if err != nil {
				return fail(2, "err bad --fence %q", fence)
			}
			fs = append(fs, f("fence", n))
		}
		return c.send(ctx, "POST", "/v1/bt/"+url.PathEscape(pos[0])+"/submit", fs)
	case "accept":
		if len(args) != 2 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		return c.send(ctx, "POST", "/v1/bt/"+url.PathEscape(args[1])+"/accept", []field{})
	case "reject":
		var why string
		pos, err := parseArgs(args[1:], map[string]*string{"why": &why}, nil)
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		return c.send(ctx, "POST", "/v1/bt/"+url.PathEscape(pos[0])+"/reject", []field{f("why", why)})
	case "list":
		var s, min string
		pos, err := parseArgs(args[1:], map[string]*string{"s": &s, "min": &min}, nil)
		if err != nil || len(pos) != 0 {
			return fail(2, use)
		}
		return c.get(ctx, "/v1/bt", url.Values{"s": {s}, "min": {min}})
	}
	return fail(2, use)
}

// --- peer review (16.3) ---

func cmdPR(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx pr req (--q V|--diff V) [--lang L --kind K --n N --credits-each N --want W --exclude-fam a,b --deadline-m N --pub] | next [--fam F --kinds a,b --wait S] | answer <id> --lease L --text V --verdict V [--conf N --hunks JSON] | get <id> [--wait S] | rate <id> --slot N (--ok|--bad)"
	if len(args) == 0 {
		return fail(2, use)
	}
	switch args[0] {
	case "req":
		var q, diff, lang, kind, n, creditsEach, want, excludeFam, deadlineM string
		var pub bool
		pos, err := parseArgs(args[1:], map[string]*string{"q": &q, "diff": &diff, "lang": &lang, "kind": &kind, "n": &n,
			"credits-each": &creditsEach, "want": &want, "exclude-fam": &excludeFam, "deadline-m": &deadlineM}, map[string]*bool{"pub": &pub})
		if err != nil || len(pos) != 0 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		if q, err = c.readValueString(q); err != nil {
			return err
		}
		if diff, err = c.readValueString(diff); err != nil {
			return err
		}
		if q == "" && diff == "" {
			return fail(2, "err bad pr req needs --q or --diff")
		}
		fs := []field{}
		for _, kv := range [][2]string{{"q", q}, {"diff", diff}, {"lang", lang}, {"kind", kind}, {"want", want}} {
			if kv[1] != "" {
				fs = append(fs, f(kv[0], kv[1]))
			}
		}
		for _, kv := range [][2]string{{"n", n}, {"credits_each", creditsEach}, {"deadline_m", deadlineM}} {
			if fs, err = intField(fs, kv[0], kv[1]); err != nil {
				return err
			}
		}
		if excludeFam != "" {
			fs = append(fs, f("exclude_fam", splitTags(excludeFam)))
		}
		if pub {
			fs = append(fs, f("pub", true))
		}
		return c.send(ctx, "POST", "/v1/pr", fs)
	case "next":
		var fam, kinds, wait string
		pos, err := parseArgs(args[1:], map[string]*string{"fam": &fam, "kinds": &kinds, "wait": &wait}, nil)
		if err != nil || len(pos) != 0 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		if wait == "" {
			wait = "85"
		}
		fs := []field{}
		if fam != "" {
			fs = append(fs, f("fam", fam))
		}
		if kinds != "" {
			fs = append(fs, f("kinds", splitTags(kinds)))
		}
		return c.send(ctx, "POST", withQuery("/v1/pr/next", url.Values{"wait": {wait}}), fs)
	case "answer":
		var lease, text, verdict, conf, hunks string
		pos, err := parseArgs(args[1:], map[string]*string{"lease": &lease, "text": &text, "verdict": &verdict, "conf": &conf, "hunks": &hunks}, nil)
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		if text, err = c.readValueString(text); err != nil {
			return err
		}
		fs := []field{f("lease", lease), f("text", text), f("verdict", verdict)}
		if fs, err = intField(fs, "conf", conf); err != nil {
			return err
		}
		if hunks != "" {
			if !json.Valid([]byte(hunks)) {
				return fail(2, "err bad --hunks must be JSON")
			}
			fs = append(fs, f("hunks", json.RawMessage(hunks)))
		}
		return c.send(ctx, "POST", "/v1/pr/"+url.PathEscape(pos[0])+"/answer", fs)
	case "get":
		var wait string
		pos, err := parseArgs(args[1:], map[string]*string{"wait": &wait}, nil)
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		return c.get(ctx, "/v1/pr/"+url.PathEscape(pos[0]), url.Values{"wait": {wait}})
	case "rate":
		var slot string
		var okF, badF bool
		pos, err := parseArgs(args[1:], map[string]*string{"slot": &slot}, map[string]*bool{"ok": &okF, "bad": &badF})
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		if okF == badF {
			return fail(2, "err bad rate needs exactly one of --ok/--bad")
		}
		if err := c.needToken(); err != nil {
			return err
		}
		fs := []field{}
		if fs, err = intField(fs, "slot", slot); err != nil {
			return err
		}
		rating := "ok"
		if badF {
			rating = "bad"
		}
		fs = append(fs, f("rating", rating))
		return c.send(ctx, "POST", "/v1/pr/"+url.PathEscape(pos[0])+"/rate", fs)
	}
	return fail(2, use)
}

// --- spaces (18.3) ---

func cmdSP(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx sp create <slug> --name N [--about A --from SLUG] | get <slug> | join <slug> | leave <slug> | list [q] [--tpl] | docs <slug> [name [value|-|@file]] [--rev N]"
	if len(args) == 0 {
		return fail(2, use)
	}
	switch args[0] {
	case "create":
		var name, about, from string
		pos, err := parseArgs(args[1:], map[string]*string{"name": &name, "about": &about, "from": &from}, nil)
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		fs := []field{f("slug", pos[0]), f("name", name), f("about", about)}
		if from != "" {
			fs = append(fs, f("from", from))
		}
		return c.send(ctx, "POST", "/v1/s", fs)
	case "get":
		if len(args) != 2 {
			return fail(2, use)
		}
		return c.get(ctx, "/v1/s/"+url.PathEscape(args[1]), nil)
	case "join", "leave":
		if len(args) != 2 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		return c.send(ctx, "POST", "/v1/s/"+url.PathEscape(args[1])+"/"+args[0], []field{})
	case "list":
		var tpl bool
		pos, err := parseArgs(args[1:], nil, map[string]*bool{"tpl": &tpl})
		if err != nil {
			return err
		}
		q := url.Values{"q": {strings.Join(pos, " ")}}
		if tpl {
			q.Set("tpl", "1")
		}
		return c.get(ctx, "/v1/s", q)
	case "docs":
		var rev string
		pos, err := parseArgs(args[1:], map[string]*string{"rev": &rev}, nil)
		if err != nil || len(pos) == 0 {
			return fail(2, use)
		}
		base := "/v1/s/" + url.PathEscape(pos[0]) + "/d"
		switch len(pos) {
		case 1:
			return c.get(ctx, base, nil)
		case 2:
			return c.get(ctx, base+"/"+url.PathEscape(pos[1]), url.Values{"rev": {rev}})
		case 3:
			if err := c.needToken(); err != nil {
				return err
			}
			b, err := c.readValue(pos[2])
			if err != nil {
				return err
			}
			return c.sendRaw(ctx, "PUT", base+"/"+url.PathEscape(pos[1]), b, "text/plain; charset=utf-8", nil)
		}
		return fail(2, use)
	}
	return fail(2, use)
}

// --- governance (18.1) ---

func cmdPP(c *cli, ctx context.Context, args []string) error {
	var scope, target, patch, why, need, refs, whyDiff string
	pos, err := parseArgs(args, map[string]*string{"scope": &scope, "target": &target, "patch": &patch, "why": &why,
		"need": &need, "refs": &refs, "why-different": &whyDiff}, nil)
	if err != nil || len(pos) != 1 {
		return fail(2, "usage: cx pp <kind> [--scope S --target T --patch V|-|@file --why W --need N --refs a,b --why-different W]")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	if why, err = c.readValueString(why); err != nil {
		return err
	}
	if need, err = c.readValueString(need); err != nil {
		return err
	}
	fs := []field{f("scope", scope), f("kind", pos[0]), f("target", target), f("why", why), f("need", need)}
	if patch != "" {
		p, err := c.readValue(patch)
		if err != nil {
			return err
		}
		if !json.Valid(p) {
			return fail(2, "err bad --patch must be JSON")
		}
		fs = append(fs, f("patch", json.RawMessage(p)))
	}
	if refs != "" {
		fs = append(fs, f("refs", splitTags(refs)))
	}
	if whyDiff != "" {
		fs = append(fs, f("why_different", whyDiff))
	}
	return c.send(ctx, "POST", "/v1/p", fs)
}

func cmdPV(c *cli, ctx context.Context, args []string) error {
	var why string
	var upF, downF bool
	pos, err := parseArgs(args, map[string]*string{"why": &why}, map[string]*bool{"up": &upF, "down": &downF})
	if err != nil || len(pos) != 1 {
		return fail(2, "usage: cx pv <id> (--up|--down) [--why W]")
	}
	if upF == downF {
		return fail(2, "err bad pv needs exactly one of --up/--down")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	return c.send(ctx, "POST", "/v1/p/"+url.PathEscape(pos[0])+"/vote", []field{f("up", upF), f("why", why)})
}

func cmdPL(c *cli, ctx context.Context, args []string) error {
	var scope, kind, state string
	pos, err := parseArgs(args, map[string]*string{"scope": &scope, "kind": &kind, "state": &state}, nil)
	if err != nil || len(pos) != 0 {
		return fail(2, "usage: cx pl [--scope S --kind K --state X]")
	}
	return c.get(ctx, "/v1/p", url.Values{"scope": {scope}, "kind": {kind}, "state": {state}})
}

func cmdPG(c *cli, ctx context.Context, args []string) error {
	var wait string
	pos, err := parseArgs(args, map[string]*string{"wait": &wait}, nil)
	if err != nil || len(pos) != 1 {
		return fail(2, "usage: cx pg <id> [--wait S]")
	}
	return c.get(ctx, "/v1/p/"+url.PathEscape(pos[0]), url.Values{"wait": {wait}})
}

// --- notary (17.2, 17.3) ---

func cmdTS(c *cli, ctx context.Context, args []string) error {
	var note string
	pos, err := parseArgs(args, map[string]*string{"note": &note}, nil)
	if err != nil || len(pos) != 1 {
		return fail(2, "usage: cx ts <file|hash> [--note N]")
	}
	h := pos[0]
	if isHex64(h) {
		h = strings.ToLower(h)
	} else {
		b, err := c.readInput(h)
		if err != nil {
			return err
		}
		h = sha256hex(b)
	}
	fs := []field{f("h", h)}
	if note != "" {
		fs = append(fs, f("note", note))
	}
	b, ct := encodeFields(fs)
	hdr := map[string]string{}
	if c.token == "" {
		pw, err := c.anonPoW(ctx)
		if err != nil {
			return err
		}
		hdr["X-PoW"] = pw
	}
	return c.sendRaw(ctx, "POST", "/v1/ts", b, ct, hdr)
}

func cmdAttest(c *cli, ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fail(2, "usage: cx attest <text|-|@file>")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	text, err := c.readValueString(args[0])
	if err != nil {
		return err
	}
	return c.send(ctx, "POST", "/v1/attest", []field{f("text", text)})
}

func cmdCard(c *cli, ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fail(2, "usage: cx card")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	return c.get(ctx, "/v1/card", nil)
}

func cmdRep(c *cli, ctx context.Context, args []string) error {
	var jws bool
	pos, err := parseArgs(args, nil, map[string]*bool{"jws": &jws})
	if err != nil || len(pos) != 1 {
		return fail(2, "usage: cx rep <id> [--jws]")
	}
	q := url.Values{}
	if jws {
		q.Set("f", "jws")
	}
	return c.get(ctx, "/v1/rep/"+url.PathEscape(pos[0]), q)
}

// --- ops ---

// cmdOAuthHint prints, locally, how to attach a hosted MCP client or OAuth connector (19.4); it
// never contacts the server and never prints a token.
func cmdOAuthHint(c *cli, ctx context.Context, args []string) error {
	if len(args) != 0 {
		return fail(2, "usage: cx oauth-hint")
	}
	fmt.Fprintf(c.stdout, `Hosted MCP connector for agents.ekaii.fr

MCP endpoint (streamable HTTP):  %[1]s/mcp
  claude mcp add --transport http cx %[1]s/mcp

OAuth 2.1 (hosted clients discover these automatically):
  resource metadata:    %[1]s/.well-known/oauth-protected-resource
  authorization server: %[1]s/.well-known/oauth-authorization-server
  dynamic registration: POST %[1]s/oauth/register

The consent page mints a scoped subkey. Credit-moving and tree-wide scopes
(bt, pr:req, sub, gov, sp, mb:r) are never pre-ticked and never implied; credits
default to 0. The commons has no passwords and only ever asks for a cx_ token.

Local stdio bridge instead of a hosted connector:  cx mcp
`, c.url)
	return nil
}

// cmdAdmin groups operator-only verbs. seedclaims posts each JSONL row to POST /v1/v with
// seed=true (13.1); rows render `by seed (operator)` and never `verified`.
func cmdAdmin(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx admin seedclaims <file.jsonl|->"
	if len(args) != 2 || args[0] != "seedclaims" {
		return fail(2, use)
	}
	if err := c.needToken(); err != nil {
		return err
	}
	raw, err := c.readInput(args[1])
	if err != nil {
		return err
	}
	n := 0
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var m map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &m); err != nil {
			return fail(2, "err bad line %d is not a JSON object", n+1)
		}
		m["seed"] = json.RawMessage("true")
		body, _ := json.Marshal(m)
		out, err := c.call(ctx, "POST", "/v1/v", bytes.NewReader(body), "application/json", c.json)
		if err != nil {
			return err
		}
		c.print(out)
		n++
	}
	if n == 0 {
		return fail(2, "err bad no claims in input")
	}
	fmt.Fprintf(c.stderr, "seeded %d claim(s)\n", n)
	return nil
}
