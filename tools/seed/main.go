// Command seed is the operator-only seeding pipeline of SPEC-v2 section 22: private notes in,
// strictly gated and line-by-line reviewed KB entries out. Every state file lives in CX_SEED_DIR
// (default ~/.config/cx-seed, mode 0700), never in the repository; the repo holds only the tool,
// the controlled tag list, the public host allowlist and a placeholder denylist.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const usage = `usage: seed <command> [args]

  sources <dir>                                   list candidate note files (choose, then write sources.txt)
  draft   [-sources F] [-o DIR] [-exclude F] [-tags F] [-kind fix]
  gate    [DRAFTS] [-denylist F] [-hosts F] [-tags F] [-o DIR] [-log F] [-v]
  review  [ENTRIES] [-all]                        interactive y/n per entry; only y sets reviewed=true
  post    [ENTRIES] [-tokens F] [-rate 30] [-url URL] [-state F] [-pace 1s]
  commit  [ENTRIES] [-repo DIR]                   copy reviewed entries into <repo>/tools/seed/entries/

Defaults resolve inside CX_SEED_DIR (~/.config/cx-seed): sources.txt, exclude.txt, drafts/, entries/,
denylist.txt, hosts.txt, tags.txt, GATE-LOG.md, tokens.txt, post-state.json.
post and commit refuse entries that are not reviewed or were edited after review. There is no confirm.
`

type app struct {
	dir            string
	stdin          io.Reader
	stdout, stderr io.Writer
	getenv         func(string) string
	now            func() time.Time
	http           *http.Client
	sleep          func(time.Duration)
}

func newApp(getenv func(string) string) *app {
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: getenv, now: time.Now,
		http: &http.Client{Timeout: 60 * time.Second}, sleep: time.Sleep}
	a.dir = strings.TrimSpace(getenv("CX_SEED_DIR"))
	if a.dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			home = "."
		}
		a.dir = filepath.Join(home, ".config", "cx-seed")
	}
	return a
}

func main() { os.Exit(newApp(os.Getenv).run(os.Args[1:])) }

func (a *app) run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprint(a.stdout, usage)
		return 0
	}
	if err := ensureDir(a.dir); err != nil {
		fmt.Fprintln(a.stderr, "err", err)
		return 1
	}
	var err error
	switch args[0] {
	case "sources":
		err = a.sources(args[1:])
	case "draft":
		err = a.draft(args[1:])
	case "gate":
		err = a.gate(args[1:])
	case "review":
		err = a.review(args[1:])
	case "post":
		err = a.post(args[1:])
	case "commit":
		err = a.commit(args[1:])
	case "confirm":
		err = errors.New("there is no seed confirm: seed roots never vote (SPEC-v2 22.5)")
	default:
		fmt.Fprint(a.stderr, usage)
		return 2
	}
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 2
		}
		fmt.Fprintln(a.stderr, "err", err)
		return 1
	}
	return 0
}

// flags builds a FlagSet whose errors go to stderr and never exit the process.
func (a *app) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	return fs
}

// parse accepts positionals before and after the flags, so `gate DIR -o X` and `gate -o X DIR`
// both work.
func parse(fs *flag.FlagSet, args []string) ([]string, error) {
	var pos []string
	i := 0
	for i < len(args) && (!strings.HasPrefix(args[i], "-") || args[i] == "-") {
		pos = append(pos, args[i])
		i++
	}
	if err := fs.Parse(args[i:]); err != nil {
		return nil, err
	}
	return append(pos, fs.Args()...), nil
}

// path returns an explicit value or the default location of name inside CX_SEED_DIR.
func (a *app) path(explicit, name string) string {
	if explicit != "" {
		return explicit
	}
	return filepath.Join(a.dir, name)
}

// optional returns the explicit path, else the CX_SEED_DIR file when it exists, else "".
func (a *app) optional(explicit, name string) string {
	if explicit != "" {
		return explicit
	}
	p := filepath.Join(a.dir, name)
	if _, err := os.Stat(p); err == nil {
		return p
	}
	return ""
}

func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	return os.Chmod(dir, 0o700)
}

// writeFile replaces path atomically (tmp + rename) with mode 0600.
func writeFile(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// readCapped reads a file refusing anything above max bytes.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s: not a regular file", path)
	}
	if st.Size() > max {
		return nil, fmt.Errorf("%s: %d bytes > cap %d", path, st.Size(), max)
	}
	return io.ReadAll(io.LimitReader(f, max+1))
}

// lines splits a list file: trimmed, blank and # lines dropped, capped at maxLines.
func lines(b []byte, maxLines int) []string {
	var out []string
	for _, l := range strings.Split(string(b), "\n") {
		l = strings.TrimSpace(strings.TrimSuffix(l, "\r"))
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		out = append(out, l)
		if len(out) >= maxLines {
			break
		}
	}
	return out
}
