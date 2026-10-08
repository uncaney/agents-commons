package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"ekaii.fr/commons/internal/scrub"
)

type gateRow struct {
	idx     int
	classes []string
}

// gate applies the mandatory gates of SPEC-v2 22.3 to every draft and writes the accepted ones to
// the entries directory; GATE-LOG.md gets counts and rejection classes only, never text or names.
func (a *app) gate(args []string) error {
	fl := a.flags("gate")
	var denyF, hostsF, tagsF, out, logF string
	var verbose bool
	fl.StringVar(&denyF, "denylist", "", "operator denylist (default $CX_SEED_DIR/denylist.txt when present)")
	fl.StringVar(&hostsF, "hosts", "", "extra public host allowlist (additive to tools/seed/hosts.txt)")
	fl.StringVar(&tagsF, "tags", "", "extra controlled tags file (additive to the embedded tags.txt)")
	fl.StringVar(&out, "o", "", "output directory for gated entries (default $CX_SEED_DIR/entries)")
	fl.StringVar(&logF, "log", "", "gate log (default $CX_SEED_DIR/GATE-LOG.md)")
	fl.BoolVar(&verbose, "v", false, "print per-draft verdicts with file names to stderr")
	pos, err := parse(fl, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("usage: seed gate [DRAFTS] [flags]")
	}
	drafts := a.path(first(pos), "drafts")
	out, logF = a.path(out, "entries"), a.path(logF, "GATE-LOG.md")
	var deny *denylist
	if p := a.optional(denyF, "denylist.txt"); p != "" {
		if deny, err = loadDenylist(p); err != nil {
			return err
		}
	} else {
		fmt.Fprintln(a.stderr, "warn: no denylist (pass -denylist or write $CX_SEED_DIR/denylist.txt)")
	}
	allow, err := a.loadHosts(hostsF)
	if err != nil {
		return err
	}
	tags, err := a.loadTags(tagsF)
	if err != nil {
		return err
	}
	files, err := listEntries(drafts)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("%s: no drafts (*.json)", drafts)
	}
	if err := ensureDir(out); err != nil {
		return err
	}
	batch := map[string]bool{}
	for _, f := range files {
		batch[filepath.Base(f)] = true
	}
	// Entries already in out/: those from this batch are re-gated (and keep their review when
	// unchanged); the others are dedupe references.
	prev := map[string]*Entry{}
	var others []map[string]bool
	outFiles, err := listEntries(out)
	if err != nil {
		return err
	}
	for _, f := range outFiles {
		e, err := loadEntry(f)
		if err != nil {
			continue
		}
		if batch[filepath.Base(f)] {
			prev[filepath.Base(f)] = e
		} else {
			others = append(others, trigrams(e.Title))
		}
	}
	counts := map[string]int{}
	rows := make([]gateRow, 0, len(files))
	accepted := 0
	var seen []map[string]bool
	for i, f := range files {
		base := filepath.Base(f)
		e, err := loadEntry(f)
		var cs []string
		switch {
		case err != nil && strings.Contains(err.Error(), "> cap"):
			cs = []string{"size"}
		case err != nil:
			cs = []string{"json"}
		default:
			cs = gateEntry(e, tags, allow, deny, append(seen, others...))
		}
		if len(cs) == 0 {
			accepted++
			seen = append(seen, trigrams(e.Title))
			if p := prev[base]; p != nil && p.hash() == e.hash() {
				e.Reviewed, e.ReviewHash = p.Reviewed, p.ReviewHash
			} else {
				e.Reviewed, e.ReviewHash = false, ""
			}
			if err := saveEntry(filepath.Join(out, base), e); err != nil {
				return err
			}
		} else if err := os.Remove(filepath.Join(out, base)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		for _, c := range cs {
			counts[c]++
		}
		rows = append(rows, gateRow{i + 1, cs})
		if verbose {
			v := "ok"
			if len(cs) > 0 {
				v = "rejected " + strings.Join(cs, ",")
			}
			fmt.Fprintf(a.stderr, "#%d %s %s\n", i+1, base, v)
		}
	}
	outFiles, err = listEntries(out)
	if err != nil {
		return err
	}
	if err := writeFile(logF, gateLog(a.now(), len(files), accepted, counts, rows, len(outFiles))); err != nil {
		return err
	}
	fmt.Fprintf(a.stdout, "drafts=%d accepted=%d rejected=%d entries=%d\nlog=%s\n", len(files), accepted, len(files)-accepted, len(outFiles), logF)
	return nil
}

// gateEntry normalises e in place and returns its rejection classes (empty = accepted). Accepted
// hazardous entries (hazard_ok=true) carry their families in e.Hazard.
func gateEntry(e *Entry, tags map[string]bool, allow func(string) bool, deny *denylist, refs []map[string]bool) []string {
	e.normalize()
	cs := e.check(tags)
	txt := e.text()
	for _, f := range scrub.StrictHosts(txt, allow) {
		cs = append(cs, "scrub."+f.Rule)
	}
	cs = append(cs, deny.classes(txt)...)
	e.Hazard = nil
	if hz := scrub.Hazards(txt); len(hz) > 0 {
		if e.HazardOK {
			e.Hazard = hz
		} else {
			for _, h := range hz {
				cs = append(cs, "hazard."+h)
			}
		}
	}
	if !e.DupOK && isDup(trigrams(e.Title), refs) {
		cs = append(cs, "dup")
	}
	return uniq(cs)
}

func isDup(tri map[string]bool, refs []map[string]bool) bool {
	for _, r := range refs {
		if similarity(tri, r) >= dupThreshold {
			return true
		}
	}
	return false
}

func gateLog(now time.Time, drafts, accepted int, counts map[string]int, rows []gateRow, entries int) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "# seed gate log\n\n- at: %s\n- drafts: %d\n- accepted: %d\n- rejected: %d\n- entries: %d (files in the output directory)\n\n",
		now.UTC().Format(time.RFC3339), drafts, accepted, drafts-accepted, entries)
	b.WriteString("## rejections by class\n\n| class | count |\n|---|---:|\n")
	classes := make([]string, 0, len(counts))
	for c := range counts {
		classes = append(classes, c)
	}
	sort.Strings(classes)
	for _, c := range classes {
		fmt.Fprintf(&b, "| %s | %d |\n", c, counts[c])
	}
	if len(classes) == 0 {
		b.WriteString("| - | 0 |\n")
	}
	b.WriteString("\n## drafts (by position in the sorted input; names and text are never logged)\n\n| # | result | classes |\n|---:|---|---|\n")
	for _, r := range rows {
		if len(r.classes) == 0 {
			fmt.Fprintf(&b, "| %d | ok | - |\n", r.idx)
		} else {
			fmt.Fprintf(&b, "| %d | rejected | %s |\n", r.idx, strings.Join(r.classes, ", "))
		}
	}
	return []byte(b.String())
}

func first(pos []string) string {
	if len(pos) > 0 {
		return pos[0]
	}
	return ""
}
