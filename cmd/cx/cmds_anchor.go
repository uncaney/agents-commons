package main

// cmds_anchor.go: the cx verbs for anchor pages (SPEC-v2 27.9, server package internal/waypoint,
// P120). `cx init` discovers the current git checkout, writes .cx/anchor with its
// gh:<owner>/<repo> rendezvous key (and, with --url, a read-only url-token URL minted via the
// subkey endpoint), and optionally claims it. `cx anchor claim|list` claim a key or read its
// claimants. Server text is printed verbatim.

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	register("anchor", "init", cmdInit,
		u("[key] [--dir PATH --claim --note N --cp ID --url]", "write .cx/anchor for this checkout (gh:<owner>/<repo>)"))
	register("anchor", "anchor", cmdAnchor,
		u("claim <key> [--note N --cp ID]", "claim a rendezvous key (POST /v1/anchor)"),
		u("list <key>", "read a key's claimants (GET /anchor/<key>)"))
}

// cmdAnchor is `cx anchor claim|list`.
func cmdAnchor(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx anchor claim <key> [--note N --cp ID] | list <key>"
	if len(args) == 0 {
		return fail(2, use)
	}
	switch args[0] {
	case "claim":
		var note, cp string
		pos, err := parseArgs(args[1:], map[string]*string{"note": &note, "cp": &cp}, nil)
		if err != nil || len(pos) != 1 {
			return fail(2, use)
		}
		if err := c.needToken(); err != nil {
			return err
		}
		if note, err = c.readValueString(note); err != nil {
			return err
		}
		fs := []field{f("key", pos[0])}
		if note != "" {
			fs = append(fs, f("note", note))
		}
		if cp != "" {
			fs = append(fs, f("cp", cp))
		}
		return c.send(ctx, "POST", "/v1/anchor", fs)
	case "list":
		if len(args) != 2 {
			return fail(2, use)
		}
		return c.get(ctx, "/anchor/"+anchorPath(args[1]), nil)
	}
	return fail(2, use)
}

// anchorPath escapes a key for the /anchor/<key...> path, keeping the ':' and '/' that the grammar
// uses (PathEscape would percent-encode them and the wildcard route would not match).
func anchorPath(key string) string {
	parts := strings.Split(key, "/")
	for i, p := range parts {
		parts[i] = strings.ReplaceAll(url.PathEscape(p), "%3A", ":")
	}
	return strings.Join(parts, "/")
}

// cmdInit is `cx init`: derive the gh key, write .cx/anchor, and optionally mint a url-token URL
// and claim the key.
func cmdInit(c *cli, ctx context.Context, args []string) error {
	var dir, note, cp string
	var claim, mintURL bool
	pos, err := parseArgs(args, map[string]*string{"dir": &dir, "note": &note, "cp": &cp},
		map[string]*bool{"claim": &claim, "url": &mintURL})
	if err != nil || len(pos) > 1 {
		return fail(2, "usage: cx init [key] [--dir PATH --claim --note N --cp ID --url]")
	}
	key := ""
	if len(pos) == 1 {
		key = pos[0]
	}
	if dir == "" {
		if dir, err = os.Getwd(); err != nil {
			return fail(1, "err cwd %v", err)
		}
	}
	if key == "" {
		k, kerr := gitAnchorKey(dir)
		if kerr != nil {
			return kerr
		}
		key = k
	}
	// .cx/anchor lines: the key, and (with --url) a read-only resume URL for teammates.
	lines := []string{"key: " + key}
	if mintURL {
		if err := c.needToken(); err != nil {
			return err
		}
		u, err := c.mintURLToken(ctx)
		if err != nil {
			return err
		}
		lines = append(lines, "url: "+u)
	}
	path := filepath.Join(dir, ".cx", "anchor")
	if err := writeFile0600(path, []byte(strings.Join(lines, "\n")+"\n")); err != nil {
		return fail(1, "err write %s: %v", path, err)
	}
	fmt.Fprintf(c.stdout, "key: %s\n", key)
	fmt.Fprintf(c.stderr, "wrote %s\n", path)
	if claim {
		if err := c.needToken(); err != nil {
			return err
		}
		noteStr, err := c.readValueString(note)
		if err != nil {
			return err
		}
		fs := []field{f("key", key)}
		if noteStr != "" {
			fs = append(fs, f("note", noteStr))
		}
		if cp != "" {
			fs = append(fs, f("cp", cp))
		}
		return c.send(ctx, "POST", "/v1/anchor", fs)
	}
	return nil
}

// mintURLToken mints a read-only url-class subkey (POST /v1/subkey {class:url}) and returns its
// resume URL (the server's `url:` line), so .cx/anchor can carry a shareable, scope-limited link.
func (c *cli) mintURLToken(ctx context.Context) (string, error) {
	var out struct {
		URL string `json:"url"`
	}
	if err := c.getJSON(ctx, "POST", "/v1/subkey", map[string]any{"class": "url", "credits": 0}, &out); err != nil {
		return "", err
	}
	if out.URL == "" {
		return "", fail(1, "err proto subkey reply carried no url")
	}
	return out.URL, nil
}

// gitAnchorKey derives gh:<owner>/<repo> from the git checkout containing dir: it finds the .git of
// the repo, reads the origin remote url from its config and parses the owner/repo.
func gitAnchorKey(dir string) (string, error) {
	cfg, err := gitConfigPath(dir)
	if err != nil {
		return "", err
	}
	remote, err := gitOriginURL(cfg)
	if err != nil {
		return "", err
	}
	owner, repo, ok := parseGitHubRemote(remote)
	if !ok {
		return "", fail(1, "err bad remote.origin.url %q is not an owner/repo remote (pass --key gh:<owner>/<repo>)", remote)
	}
	return "gh:" + strings.ToLower(owner) + "/" + strings.ToLower(repo), nil
}

// gitConfigPath walks up from dir to the repository's .git and returns the path of its config
// (handling both a .git directory and a .git file pointing at a worktree's gitdir).
func gitConfigPath(dir string) (string, error) {
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", fail(1, "err path %v", err)
	}
	for {
		gitPath := filepath.Join(abs, ".git")
		if info, err := os.Stat(gitPath); err == nil {
			if info.IsDir() {
				return filepath.Join(gitPath, "config"), nil
			}
			// A .git file: "gitdir: <path>" (a worktree); its config lives in the common dir.
			if cfg, ok := worktreeConfig(gitPath); ok {
				return cfg, nil
			}
		}
		parent := filepath.Dir(abs)
		if parent == abs {
			return "", fail(1, "err notfound no git checkout at or above %s (pass --key gh:<owner>/<repo>)", dir)
		}
		abs = parent
	}
}

// worktreeConfig resolves the config path from a ".git" file ("gitdir: <path>"): a worktree's gitdir
// holds a commondir pointer whose config is the shared one.
func worktreeConfig(gitFile string) (string, bool) {
	b, err := os.ReadFile(gitFile)
	if err != nil {
		return "", false
	}
	line := strings.TrimSpace(string(b))
	gitdir := strings.TrimSpace(strings.TrimPrefix(line, "gitdir:"))
	if gitdir == "" || gitdir == line {
		return "", false
	}
	if !filepath.IsAbs(gitdir) {
		gitdir = filepath.Join(filepath.Dir(gitFile), gitdir)
	}
	if cb, err := os.ReadFile(filepath.Join(gitdir, "commondir")); err == nil {
		common := strings.TrimSpace(string(cb))
		if !filepath.IsAbs(common) {
			common = filepath.Join(gitdir, common)
		}
		return filepath.Join(common, "config"), true
	}
	return filepath.Join(gitdir, "config"), true
}

// gitOriginURL parses `url = <...>` from the [remote "origin"] section of a git config file.
func gitOriginURL(configPath string) (string, error) {
	fh, err := os.Open(configPath)
	if err != nil {
		return "", fail(1, "err read %s: %v", configPath, err)
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	inOrigin := false
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "[") {
			inOrigin = sectionIsOriginRemote(line)
			continue
		}
		if !inOrigin {
			continue
		}
		if k, v, ok := strings.Cut(line, "="); ok && strings.TrimSpace(k) == "url" {
			return strings.TrimSpace(v), nil
		}
	}
	if err := sc.Err(); err != nil {
		return "", fail(1, "err read %s: %v", configPath, err)
	}
	return "", fail(1, "err notfound no remote.origin.url in %s (pass --key gh:<owner>/<repo>)", configPath)
}

// sectionIsOriginRemote reports whether a config section header is [remote "origin"].
func sectionIsOriginRemote(header string) bool {
	h := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(header, "["), "]"))
	kind, rest, ok := strings.Cut(h, " ")
	if !ok || strings.TrimSpace(kind) != "remote" {
		return false
	}
	return strings.Trim(strings.TrimSpace(rest), `"`) == "origin"
}

// parseGitHubRemote extracts owner and repo from a git remote URL in any common shape:
// https://host/owner/repo(.git), ssh://git@host/owner/repo(.git), git@host:owner/repo(.git).
func parseGitHubRemote(remote string) (owner, repo string, ok bool) {
	remote = strings.TrimSpace(remote)
	if remote == "" {
		return "", "", false
	}
	var path string
	switch {
	case strings.Contains(remote, "://"):
		if i := strings.Index(remote, "://"); i >= 0 {
			rest := remote[i+3:]
			if j := strings.IndexByte(rest, '/'); j >= 0 {
				path = rest[j+1:]
			}
		}
	case strings.Contains(remote, ":"):
		// scp-like: [user@]host:owner/repo
		path = remote[strings.LastIndex(remote, ":")+1:]
	default:
		path = remote
	}
	path = strings.TrimSuffix(strings.Trim(path, "/"), ".git")
	segs := strings.Split(path, "/")
	if len(segs) < 2 {
		return "", "", false
	}
	repo = segs[len(segs)-1]
	owner = segs[len(segs)-2]
	if owner == "" || repo == "" {
		return "", "", false
	}
	return owner, repo, true
}
