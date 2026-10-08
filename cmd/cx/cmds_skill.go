package main

// cmds_skill.go: the cx verbs for the on-domain Agent Skill (SPEC-v2 27.1, server package
// internal/skills, P85). `cx skill install [claude|cursor|codex]` downloads the deterministic
// bundle at GET /skills/commons.zip and writes the `commons/` directory into the client's skills
// path; `cx skill check` compares the local SKILL.md's sha256 with the one advertised at
// GET /skills/index.json. Reads are anonymous, so neither verb needs a token.
//
// Client skills paths (from each vendor's documentation at build time; override with --dir):
//   claude  ~/.claude/skills   (Claude Code reads skills from ~/.claude/skills/<name>/)
//   cursor  ~/.cursor/skills
//   codex   ~/.codex/skills
// A skill installs as <path>/commons/ holding SKILL.md and references/.

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

func init() {
	register("skills", "skill", cmdSkill,
		u("install [claude|cursor|codex] [--dir PATH]", "write the commons skill into the client's skills path (GET /skills/commons.zip)"),
		u("check [claude|cursor|codex] [--dir PATH]", "compare the local skill's sha256 with /skills/index.json"))
}

// skillDirs maps a client name to its default skills directory, relative to $HOME.
var skillDirs = map[string][]string{
	"claude": {".claude", "skills"},
	"cursor": {".cursor", "skills"},
	"codex":  {".codex", "skills"},
}

const skillName = "commons"

func cmdSkill(c *cli, ctx context.Context, args []string) error {
	const use = "usage: cx skill install [claude|cursor|codex] [--dir PATH] | check [claude|cursor|codex] [--dir PATH]"
	if len(args) == 0 {
		return fail(2, use)
	}
	sub := args[0]
	if sub != "install" && sub != "check" {
		return fail(2, use)
	}
	var dir string
	pos, err := parseArgs(args[1:], map[string]*string{"dir": &dir}, nil)
	if err != nil {
		return err
	}
	client := "claude"
	if len(pos) > 0 {
		client = pos[0]
	}
	if len(pos) > 1 {
		return fail(2, use)
	}
	base, err := c.skillBaseDir(client, dir)
	if err != nil {
		return err
	}
	dest := filepath.Join(base, skillName)
	if sub == "install" {
		return c.skillInstall(ctx, dest)
	}
	return c.skillCheck(ctx, dest)
}

// skillBaseDir resolves the skills directory: an explicit --dir wins; otherwise the client's
// documented default under $HOME.
func (c *cli) skillBaseDir(client, dir string) (string, error) {
	if dir != "" {
		return dir, nil
	}
	parts, ok := skillDirs[client]
	if !ok {
		return "", fail(2, "err bad client %q (want claude|cursor|codex)", client)
	}
	home := c.getenv("HOME")
	if home == "" {
		home = c.getenv("USERPROFILE")
	}
	if home == "" {
		return "", fail(1, "err no HOME: pass --dir PATH")
	}
	return filepath.Join(append([]string{home}, parts...)...), nil
}

// skillInstall downloads /skills/commons.zip and extracts it into dest (safely: no absolute paths,
// no "..", no symlinks).
func (c *cli) skillInstall(ctx context.Context, dest string) error {
	_, _, body, err := c.callH(ctx, "GET", "/skills/"+skillName+".zip", nil, "", false, nil)
	if err != nil {
		return err
	}
	zr, err := zip.NewReader(bytes.NewReader(body), int64(len(body)))
	if err != nil {
		return fail(1, "err bad bundle: %v", err)
	}
	n := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() {
			continue
		}
		rel := filepath.Clean(filepath.FromSlash(f.Name))
		if rel == "." || filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return fail(1, "err bad bundle path %q", f.Name)
		}
		if f.Mode()&os.ModeSymlink != 0 {
			return fail(1, "err bundle contains a symlink %q", f.Name)
		}
		out := filepath.Join(dest, rel)
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return fail(1, "err mkdir: %v", err)
		}
		rc, err := f.Open()
		if err != nil {
			return fail(1, "err read bundle: %v", err)
		}
		data, err := io.ReadAll(io.LimitReader(rc, 1<<20))
		rc.Close()
		if err != nil {
			return fail(1, "err read bundle: %v", err)
		}
		if err := os.WriteFile(out, data, 0o644); err != nil {
			return fail(1, "err write %s: %v", out, err)
		}
		n++
	}
	if n == 0 {
		return fail(1, "err empty bundle")
	}
	fmt.Fprintf(c.stdout, "ok installed %s -> %s (%d files)\n", skillName, dest, n)
	return nil
}

// skillCheck hashes the local SKILL.md and compares it with the sha256 advertised in
// /skills/index.json.
func (c *cli) skillCheck(ctx context.Context, dest string) error {
	var idx struct {
		Skills []struct {
			Name, Version, SHA256 string
		} `json:"skills"`
	}
	if err := c.getJSON(ctx, "GET", "/skills/index.json", nil, &idx); err != nil {
		return err
	}
	if len(idx.Skills) == 0 {
		return fail(1, "err proto no skills in index")
	}
	want := idx.Skills[0]
	local := filepath.Join(dest, "SKILL.md")
	b, err := os.ReadFile(local)
	if err != nil {
		if os.IsNotExist(err) {
			return fail(1, "skill not installed at %s; run cx skill install", local)
		}
		return fail(1, "err read %s: %v", local, err)
	}
	sum := sha256.Sum256(b)
	got := hex.EncodeToString(sum[:])
	if got != want.SHA256 {
		return fail(1, "skill stale: local %s server %s (version %s); run cx skill install", short(got), short(want.SHA256), want.Version)
	}
	fmt.Fprintf(c.stdout, "ok %s up to date sha256=%s version=%s\n", want.Name, short(got), want.Version)
	return nil
}

func short(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
