package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// commit copies approved entries into <repo>/tools/seed/entries/ for a human-driven commit (the
// directory is gitignored; the human uses `git add -f`). Unreviewed or edited entries are refused.
// Builders never run this (SPEC-v2 22.4).
func (a *app) commit(args []string) error {
	fl := a.flags("commit")
	var repo string
	fl.StringVar(&repo, "repo", ".", "repository root (must contain tools/seed)")
	pos, err := parse(fl, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("usage: seed commit [ENTRIES] [-repo DIR]")
	}
	dir := a.path(first(pos), "entries")
	if _, err := os.Stat(filepath.Join(repo, "tools", "seed", "tags.txt")); err != nil {
		return fmt.Errorf("%s: not the commons repo (tools/seed/tags.txt missing)", repo)
	}
	files, err := listEntries(dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("%s: no entries", dir)
	}
	dest := filepath.Join(repo, "tools", "seed", "entries")
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	committed, refused := 0, 0
	for _, f := range files {
		base := filepath.Base(f)
		e, err := loadEntry(f)
		if err != nil || !e.approved() {
			refused++
			fmt.Fprintf(a.stdout, "refused %s: not reviewed or edited after review\n", base)
			continue
		}
		b, err := marshalEntry(e)
		if err != nil {
			return err
		}
		tmp := filepath.Join(dest, base+".tmp")
		if err := os.WriteFile(tmp, b, 0o644); err != nil {
			return err
		}
		if err := os.Rename(tmp, filepath.Join(dest, base)); err != nil {
			os.Remove(tmp)
			return err
		}
		committed++
	}
	fmt.Fprintf(a.stdout, "committed=%d refused=%d dest=%s\nnext: read the files, then `git add -f %s` and commit by hand (the directory is gitignored on purpose)\n",
		committed, refused, dest, dest)
	return nil
}
