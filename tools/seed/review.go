package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// review walks every gated entry in the terminal and records reviewed=true only on an explicit y,
// together with the content hash; any later edit invalidates the approval (SPEC-v2 22.4).
func (a *app) review(args []string) error {
	fl := a.flags("review")
	var all bool
	fl.BoolVar(&all, "all", false, "walk approved entries too")
	pos, err := parse(fl, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("usage: seed review [ENTRIES] [-all]")
	}
	dir := a.path(first(pos), "entries")
	files, err := listEntries(dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("%s: no entries", dir)
	}
	rd := bufio.NewReader(a.stdin)
	approved, left, deleted, skipped := 0, 0, 0, 0
	done := func() {
		fmt.Fprintf(a.stdout, "approved=%d left=%d deleted=%d skipped=%d\n", approved, left, deleted, skipped)
	}
	for i, f := range files {
		base := filepath.Base(f)
		e, err := loadEntry(f)
		if err != nil {
			skipped++
			fmt.Fprintf(a.stdout, "skip %s: unreadable (re-run seed gate)\n", base)
			continue
		}
		if e.approved() && !all {
			skipped++
			continue
		}
		a.show(i+1, len(files), base, e)
	prompt:
		for {
			fmt.Fprint(a.stdout, "approve? [y]es [n]o [d]elete [q]uit: ")
			line, err := rd.ReadString('\n')
			ans := strings.ToLower(strings.TrimSpace(line))
			if err != nil && ans == "" {
				ans = "q"
			}
			switch ans {
			case "y":
				e.Reviewed, e.ReviewHash = true, e.hash()
				if err := saveEntry(f, e); err != nil {
					return err
				}
				approved++
			case "n":
				e.Reviewed, e.ReviewHash = false, ""
				if err := saveEntry(f, e); err != nil {
					return err
				}
				left++
			case "d":
				if err := os.Remove(f); err != nil {
					return err
				}
				deleted++
			case "q":
				fmt.Fprintln(a.stdout)
				done()
				return nil
			default:
				continue prompt
			}
			break
		}
	}
	done()
	return nil
}

// show renders one entry for the operator; every field goes through term so note content can
// never drive the terminal.
func (a *app) show(i, n int, base string, e *Entry) {
	const pad = "          "
	fmt.Fprintf(a.stdout, "\n--- [%d/%d] %s ---\n", i, n, term(base, pad))
	fmt.Fprintf(a.stdout, "kind:     %s\ntitle:    %s\nsymptom:  %s\ncause:    %s\nfix:      %s\nversions: %s\ntags:     %s\n",
		term(e.Kind, pad), term(e.Title, pad), term(e.Symptom, pad), term(e.Cause, pad), term(e.Fix, pad), term(e.Versions, pad),
		term(strings.Join(e.Tags, ", "), pad))
	if len(e.Hazard) > 0 {
		fmt.Fprintf(a.stdout, "hazard:   %s (hazard_ok=%v)\n", term(strings.Join(e.Hazard, ","), pad), e.HazardOK)
	}
	if e.DupOK {
		fmt.Fprintln(a.stdout, "dup_ok:   true (posted with force)")
	}
	if e.Reviewed {
		state := "approved"
		if !e.approved() {
			state = "edited after approval (approval void)"
		}
		fmt.Fprintf(a.stdout, "review:   %s\n", state)
	}
}
