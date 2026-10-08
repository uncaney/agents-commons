package main

// cmds_sync.go: `cx sync` mirrors the row-level replication feed (GET /v1/sync, SPEC-v2 27.7)
// into a local destination (md / pg / jsonl), the same surface as the standalone cmd/cxsync, but
// through the CLI's own URL and token. Every signed row is verified against the server's
// /.well-known/cx-key (or a pinned --key) before it is written; tombstone lines remove the row,
// so hidden, quarantined and purged content never lands locally.

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"

	csync "ekaii.fr/commons/internal/sync"
)

func init() {
	register("interop", "sync", cmdSync,
		u("--to md <dir>", "mirror GET /v1/sync into front-matter Markdown (<dir>/<kind>/<id>.md)"),
		u("--to pg <url>  |  --to jsonl <dir>", "mirror into cx_mirror.<kind> or append <dir>/<kind>.jsonl"),
		u("[--kinds kb,claim,digest,task,svc] [--key HEX] [--cursor FILE]", "deletes remove the row; sigs verified before write"))
}

type syncOpts struct {
	to, dest, kinds, key, cursor string
}

func parseSyncArgs(args []string) (syncOpts, error) {
	var o syncOpts
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fail(2, "err bad flag %s needs a value", a)
			}
			i++
			return args[i], nil
		}
		var err error
		switch a {
		case "--to":
			if o.to, err = next(); err != nil {
				return o, err
			}
			o.dest, err = next()
		case "--kinds":
			o.kinds, err = next()
		case "--key":
			o.key, err = next()
		case "--cursor":
			o.cursor, err = next()
		default:
			return o, fail(2, "err bad flag %q", a)
		}
		if err != nil {
			return o, err
		}
	}
	if o.to == "" || o.dest == "" {
		return o, fail(2, "err usage cx sync --to <md|pg|jsonl> <dest>")
	}
	return o, nil
}

func cmdSync(c *cli, ctx context.Context, args []string) error {
	o, err := parseSyncArgs(args)
	if err != nil {
		return err
	}
	var v *csync.Verifier
	if o.key != "" {
		v, err = csync.NewVerifier(o.key)
	} else {
		v, err = csync.FetchVerifier(ctx, c.http, c.url)
	}
	if err != nil {
		return fail(1, "err sync %s", err)
	}
	sink, cursor, err := syncSink(ctx, o)
	if err != nil {
		return fail(1, "err sync %s", err)
	}
	defer sink.Close()
	f := &csync.HTTPFetcher{Base: c.url, Client: c.http, Token: c.token, Kinds: o.kinds, Verify: v}
	applied, err := csync.Mirror(ctx, func(after int64, k int) ([]csync.Line, int64, error) {
		return f.Page(ctx, after, k)
	}, sink, cursor)
	if err != nil {
		return fail(1, "err sync %s", err)
	}
	c.print([]byte(fmt.Sprintf("synced %d rows to %s %s", applied, o.to, o.dest)))
	return nil
}

func syncSink(ctx context.Context, o syncOpts) (csync.Sink, string, error) {
	cursor := o.cursor
	switch o.to {
	case "md":
		if cursor == "" {
			cursor = filepath.Join(o.dest, csync.CursorName)
		}
		return &csync.MdSink{Dir: o.dest}, cursor, nil
	case "jsonl":
		if cursor == "" {
			cursor = filepath.Join(o.dest, csync.CursorName)
		}
		return &csync.JsonlSink{Dir: o.dest}, cursor, nil
	case "pg":
		if cursor == "" {
			cursor = csync.CursorName
		}
		sink, err := csync.NewPgSink(ctx, o.dest)
		return sink, cursor, err
	}
	return nil, "", fmt.Errorf("--to must be md, pg or jsonl (got %q)", strings.TrimSpace(o.to))
}
