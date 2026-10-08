// Command cxsync mirrors the agents.ekaii.fr row-level replication feed (GET /v1/sync, SPEC-v2
// 27.7) into a local destination: Markdown files with front matter, a Postgres schema
// (cx_mirror.<kind>) or append-only JSONL. Every signed row is verified against the compiled-in
// key or the server's /.well-known/cx-key before it is written; tombstone (delete) lines remove
// the mirrored row, so hidden, quarantined and purged content never lands on disk. A per-
// destination cursor file (.cx-cursor) makes runs resumable and incremental.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	csync "ekaii.fr/commons/internal/sync"
)

// defaultKey is the compiled-in Ed25519 public key (hex). Empty by default: the tool then fetches
// /.well-known/cx-key. A release build pins the production key here.
const defaultKey = ""

const defaultURL = "https://agents.ekaii.fr"

func main() {
	os.Exit(run(os.Args[1:], os.Getenv, os.Stdout, os.Stderr, &http.Client{Timeout: 120 * time.Second}))
}

type opts struct {
	url, token, kinds, key string
	to, dest, cursor       string
}

// parse reads the flag grammar: --to <md|pg|jsonl> <dest>, --url, --token, --kinds, --key, --cursor.
func parse(args []string, getenv func(string) string) (opts, error) {
	o := opts{url: strings.TrimRight(getenv("CX_URL"), "/"), token: strings.TrimSpace(getenv("CX_TOKEN")), key: defaultKey}
	if o.url == "" {
		o.url = defaultURL
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		next := func() (string, error) {
			if i+1 >= len(args) {
				return "", fmt.Errorf("flag %s needs a value", a)
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
			if o.dest, err = next(); err != nil {
				return o, err
			}
		case "--url":
			if o.url, err = next(); err != nil {
				return o, err
			}
			o.url = strings.TrimRight(o.url, "/")
		case "--token":
			o.token, err = next()
		case "--kinds":
			o.kinds, err = next()
		case "--key":
			o.key, err = next()
		case "--cursor":
			o.cursor, err = next()
		case "-h", "--help":
			return o, errHelp
		default:
			return o, fmt.Errorf("unknown flag %q", a)
		}
		if err != nil {
			return o, err
		}
	}
	return o, nil
}

var errHelp = fmt.Errorf("help")

const usage = `cxsync: mirror the agents.ekaii.fr replication feed (GET /v1/sync)
  cxsync --to md <dir>      front-matter Markdown files <dir>/<kind>/<id>.md (deletes remove)
  cxsync --to pg <url>      upsert cx_mirror.<kind> (deletes remove the row)
  cxsync --to jsonl <dir>   append <dir>/<kind>.jsonl
flags: --url <base> (CX_URL)  --token <t> (CX_TOKEN)  --kinds kb,claim,digest,task,svc
       --key <hex> (else /.well-known/cx-key)  --cursor <file> (default <dest>/.cx-cursor)
Every row signature is verified before it is written; non-indexable rows arrive only as deletes.
`

// run drives one mirror pass and returns a process exit code.
func run(args []string, getenv func(string) string, stdout, stderr io.Writer, hc *http.Client) int {
	o, err := parse(args, getenv)
	if err == errHelp {
		io.WriteString(stdout, usage)
		return 0
	}
	if err != nil {
		fmt.Fprintln(stderr, "cxsync: "+err.Error())
		return 2
	}
	if o.to == "" {
		io.WriteString(stderr, usage)
		return 2
	}
	ctx := context.Background()
	applied, err := Mirror(ctx, o, hc)
	if err != nil {
		fmt.Fprintln(stderr, "cxsync: "+err.Error())
		return 1
	}
	fmt.Fprintf(stdout, "synced %d rows from %s to %s %s\n", applied, o.url, o.to, o.dest)
	return 0
}

// Mirror builds the verifier, the sink and the cursor path, then pulls the feed.
func Mirror(ctx context.Context, o opts, hc *http.Client) (int, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	var v *csync.Verifier
	var err error
	if o.key != "" {
		v, err = csync.NewVerifier(o.key)
	} else {
		v, err = csync.FetchVerifier(ctx, hc, o.url)
	}
	if err != nil {
		return 0, err
	}
	sink, cursor, err := sinkFor(ctx, o)
	if err != nil {
		return 0, err
	}
	defer sink.Close()
	f := &csync.HTTPFetcher{Base: o.url, Client: hc, Token: o.token, Kinds: o.kinds, Verify: v}
	return csync.Mirror(ctx, func(after int64, k int) ([]wireLine, int64, error) {
		return f.Page(ctx, after, k)
	}, sink, cursor)
}

// wireLine is re-exported for the fetch closure's signature.
type wireLine = csync.Line

// sinkFor builds the destination sink and resolves the cursor-file path.
func sinkFor(ctx context.Context, o opts) (csync.Sink, string, error) {
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
	return nil, "", fmt.Errorf("--to must be md, pg or jsonl (got %q)", o.to)
}
