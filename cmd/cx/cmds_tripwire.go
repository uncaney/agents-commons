package main

// cmds_tripwire.go: the cx verbs for tripwire URLs (SPEC-v2 27.9, server package internal/tripwire,
// P68). `cx tw new [note]` mints a /y/<secret> canary (POST /v1/tw) and prints its url and read key;
// `cx tw hits <id>` shows who tripped it (GET /v1/tw/<id>). Server text is printed verbatim.

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

func init() {
	register("tripwire", "tw", cmdTW,
		u("new [note] [--ttl-h N --ps topic]", "mint a /y/<secret> canary (POST /v1/tw)"),
		u("hits <id>", "who tripped a tripwire (GET /v1/tw/<id>)"))
}

func cmdTW(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx tw new [note] [--ttl-h N --ps topic] | hits <id>"
	if len(args) == 0 {
		return fail(2, use)
	}
	switch args[0] {
	case "new":
		var ttlH, ps string
		pos, err := parseArgs(args[1:], map[string]*string{"ttl-h": &ttlH, "ps": &ps}, nil)
		if err != nil {
			return err
		}
		if err := c.needToken(); err != nil {
			return err
		}
		note, err := c.readValueString(strings.Join(pos, " "))
		if err != nil {
			return err
		}
		fs := []field{}
		if note != "" {
			fs = append(fs, f("note", note))
		}
		if ttlH != "" {
			n, err := strconv.Atoi(ttlH)
			if err != nil {
				return fail(2, "err bad --ttl-h %q", ttlH)
			}
			fs = append(fs, f("ttl_h", n))
		}
		if ps != "" {
			fs = append(fs, f("on_hit", map[string]string{"ps": ps}))
		}
		return c.send(ctx, "POST", "/v1/tw", fs)
	case "hits":
		if len(args) != 2 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		return c.get(ctx, "/v1/tw/"+url.PathEscape(args[1]), nil)
	}
	return fail(2, use)
}
