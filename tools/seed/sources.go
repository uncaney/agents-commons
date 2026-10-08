package main

import (
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"strings"
)

const (
	maxSources = 10000
	maxNote    = 1 << 20
)

var (
	noteExt  = map[string]bool{".md": true, ".markdown": true, ".txt": true}
	skipDirs = map[string]bool{"node_modules": true, "vendor": true, "target": true, "dist": true, "build": true}
	errTrunc = errors.New("truncated")
)

// sources lists candidate note files under dir, one absolute path per line, ready to be pruned by
// the operator into sources.txt. Files whose path matches an exclude term are printed commented
// out with the class, so a blind copy still skips them.
func (a *app) sources(args []string) error {
	fl := a.flags("sources")
	var excludeF string
	fl.StringVar(&excludeF, "exclude", "", "additional exclude regexes, one per line (default $CX_SEED_DIR/exclude.txt if present)")
	pos, err := parse(fl, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		return errors.New("usage: seed sources <dir>")
	}
	ex, err := a.excludes(excludeF)
	if err != nil {
		return err
	}
	root, err := filepath.Abs(pos[0])
	if err != nil {
		return err
	}
	n, excluded := 0, 0
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if p != root && (strings.HasPrefix(d.Name(), ".") || skipDirs[d.Name()]) {
				return filepath.SkipDir
			}
			return nil
		}
		if !d.Type().IsRegular() || strings.HasPrefix(d.Name(), ".") || !noteExt[strings.ToLower(filepath.Ext(d.Name()))] {
			return nil
		}
		if n++; n > maxSources {
			return errTrunc
		}
		if c := ex.class(p); c != "" {
			excluded++
			fmt.Fprintf(a.stdout, "# excluded %s: %s\n", c, p)
			return nil
		}
		fmt.Fprintln(a.stdout, p)
		return nil
	})
	if errors.Is(err, errTrunc) {
		fmt.Fprintf(a.stdout, "# truncated at %d files\n", maxSources)
		err = nil
	}
	if err != nil {
		return err
	}
	fmt.Fprintf(a.stderr, "candidates=%d excluded=%d\n", n-excluded, excluded)
	return nil
}
