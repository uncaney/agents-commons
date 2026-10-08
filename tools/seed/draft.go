package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"ekaii.fr/commons/internal/scrub"
)

// builtinExclude is SPEC-v2 22.1: any source whose path or content matches is refused; exclude.txt
// only ever adds terms.
// builtinExclude is a conservative default: it refuses a source that merely mentions an employer,
// customer, tenant or client so private-notes seeding never leaks an organisation name. Operators add
// their own hostnames, project and product names through exclude.txt (never hardcoded here).
var builtinExclude = regexp.MustCompile(`(?i)\bemployer\b|\bcustomer\b|\btenant\b|\bclient\b`)

type excludes struct{ res []*regexp.Regexp }

func (a *app) excludes(explicit string) (*excludes, error) {
	ex := &excludes{res: []*regexp.Regexp{builtinExclude}}
	p := a.optional(explicit, "exclude.txt")
	if p == "" {
		return ex, nil
	}
	b, err := readCapped(p, maxListFile)
	if err != nil {
		return nil, err
	}
	for i, l := range lines(b, 1000) {
		if len(l) > 200 {
			return nil, fmt.Errorf("exclude.txt line %d: longer than 200 bytes", i+1)
		}
		if !strings.HasPrefix(l, "(?i)") {
			l = "(?i)" + l
		}
		re, err := regexp.Compile(l)
		if err != nil {
			return nil, fmt.Errorf("exclude.txt line %d: bad regex", i+1)
		}
		ex.res = append(ex.res, re)
	}
	return ex, nil
}

// class is the refusal class of text: the matched term reduced to [a-z0-9] (never its context),
// "" when nothing matches.
func (ex *excludes) class(text string) string {
	for _, re := range ex.res {
		if m := re.FindString(text); m != "" {
			return classOf(m)
		}
	}
	return ""
}

func classOf(m string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(m) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		}
		if b.Len() >= 24 {
			break
		}
	}
	if b.Len() == 0 {
		return "pattern"
	}
	return b.String()
}

// draft turns every allowlisted note into entry drafts (SPEC-v2 22.2). Refusals print the class
// and the source index only.
func (a *app) draft(args []string) error {
	fl := a.flags("draft")
	var sourcesF, out, excludeF, tagsF, kind string
	fl.StringVar(&sourcesF, "sources", "", "allowlist of note files, one path per line (default $CX_SEED_DIR/sources.txt)")
	fl.StringVar(&out, "o", "", "output directory for drafts (default $CX_SEED_DIR/drafts)")
	fl.StringVar(&excludeF, "exclude", "", "additional exclude regexes, one per line (default $CX_SEED_DIR/exclude.txt if present)")
	fl.StringVar(&tagsF, "tags", "", "extra controlled tags file (additive to the embedded tags.txt)")
	fl.StringVar(&kind, "kind", "fix", "entry kind: fix|status|note")
	pos, err := parse(fl, args)
	if err != nil {
		return err
	}
	if len(pos) > 0 {
		return errors.New("draft takes flags only (see seed help)")
	}
	sourcesF, out = a.path(sourcesF, "sources.txt"), a.path(out, "drafts")
	ex, err := a.excludes(excludeF)
	if err != nil {
		return err
	}
	tags, err := a.loadTags(tagsF)
	if err != nil {
		return err
	}
	b, err := readCapped(sourcesF, maxListFile)
	if err != nil {
		return err
	}
	srcs := lines(b, maxSources)
	if len(srcs) == 0 {
		return fmt.Errorf("%s: no sources listed", sourcesF)
	}
	if err := ensureDir(out); err != nil {
		return err
	}
	n := nextIndex(out)
	drafted, refused, files := 0, 0, 0
	refuse := func(i int, class string) {
		refused++
		fmt.Fprintf(a.stdout, "refused #%d: class=%s\n", i, class)
	}
	for i, src := range srcs {
		if c := ex.class(src); c != "" {
			refuse(i+1, c)
			continue
		}
		raw, err := readCapped(src, maxNote)
		if err != nil {
			if strings.Contains(err.Error(), "> cap") {
				refuse(i+1, "size")
			} else {
				refuse(i+1, "unreadable")
			}
			continue
		}
		if !utf8.Valid(raw) {
			refuse(i+1, "binary")
			continue
		}
		text := scrub.Normalize(string(raw))
		if c := ex.class(text); c != "" {
			refuse(i+1, c)
			continue
		}
		entries := draftNote(text, stem(src), kind, tags)
		for _, e := range entries {
			name := fmt.Sprintf("%03d-%s.json", n, slug(e.Title))
			n++
			if err := saveEntry(filepath.Join(out, name), e); err != nil {
				return err
			}
			files++
		}
		drafted++
		fmt.Fprintf(a.stdout, "drafted #%d: %d entries\n", i+1, len(entries))
	}
	fmt.Fprintf(a.stdout, "sources=%d drafted=%d refused=%d drafts=%d out=%s\n", len(srcs), drafted, refused, files, out)
	return nil
}

var indexRe = regexp.MustCompile(`^([0-9]{3,})-`)

// nextIndex continues the NNN- numbering of an existing drafts directory.
func nextIndex(dir string) int {
	n := 1
	ents, _ := os.ReadDir(dir)
	for _, d := range ents {
		if m := indexRe.FindStringSubmatch(d.Name()); m != nil {
			if v, err := strconv.Atoi(m[1]); err == nil && v >= n {
				n = v + 1
			}
		}
	}
	return n
}

func stem(path string) string {
	b := filepath.Base(path)
	return strings.TrimSuffix(b, filepath.Ext(b))
}

func slug(title string) string {
	var parts []string
	for _, w := range strings.FieldsFunc(strings.ToLower(title), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9')
	}) {
		parts = append(parts, w)
		if len(strings.Join(parts, "-")) > 40 {
			break
		}
	}
	s := strings.Join(parts, "-")
	if len(s) > 40 {
		s = strings.TrimRight(s[:40], "-")
	}
	if s == "" {
		return "entry"
	}
	return s
}

// --- markdown blocks ---

type block struct {
	kind  byte // 'h' heading, 'c' code, 'p' paragraph, 'l' list
	level int
	text  string
	items []string
}

var (
	headingRe = regexp.MustCompile(`^(#{1,6})\s+(.+?)\s*#*\s*$`)
	listRe    = regexp.MustCompile(`^\s*(?:[-*+]|[0-9]+[.)])\s+(.*)$`)
)

func parseBlocks(text string) []block {
	var bs []block
	var cur *block
	flush := func() {
		if cur != nil {
			bs = append(bs, *cur)
			cur = nil
		}
	}
	inCode, fence := false, ""
	var code strings.Builder
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if inCode {
			if strings.HasPrefix(trimmed, fence) {
				bs = append(bs, block{kind: 'c', text: strings.TrimRight(code.String(), "\n")})
				code.Reset()
				inCode = false
				continue
			}
			code.WriteString(line + "\n")
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "```") || strings.HasPrefix(trimmed, "~~~"):
			flush()
			inCode, fence = true, trimmed[:3]
		case headingRe.MatchString(line):
			flush()
			m := headingRe.FindStringSubmatch(line)
			bs = append(bs, block{kind: 'h', level: len(m[1]), text: strings.TrimSpace(m[2])})
		case listRe.MatchString(line):
			if cur == nil || cur.kind != 'l' {
				flush()
				cur = &block{kind: 'l'}
			}
			cur.items = append(cur.items, listRe.FindStringSubmatch(line)[1])
		case trimmed == "":
			flush()
		case cur != nil && cur.kind == 'l' && (strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t")):
			cur.items[len(cur.items)-1] += "\n" + trimmed
		default:
			if cur == nil || cur.kind != 'p' {
				flush()
				cur = &block{kind: 'p'}
			}
			if cur.text != "" {
				cur.text += "\n"
			}
			cur.text += trimmed
		}
	}
	if inCode {
		bs = append(bs, block{kind: 'c', text: strings.TrimRight(code.String(), "\n")})
	}
	flush()
	return bs
}

// sectionKind maps a heading to a named sub-section, "" when the heading titles a new entry.
func sectionKind(h string) string {
	h = strings.ToLower(strings.Trim(h, " :.-"))
	switch {
	case has(h, "symptom", "error", "problem", "output", "traceback", "logs", "log", "what happened", "message"):
		return "symptom"
	case has(h, "cause", "why", "reason", "diagnosis", "root"):
		return "cause"
	case has(h, "fix", "solution", "workaround", "resolution", "steps", "repair", "how to", "remedy"):
		return "fix"
	case has(h, "context", "env", "environment", "setup", "versions", "version", "system"):
		return "env"
	case h == "tags" || h == "tag":
		return "tags"
	}
	return ""
}

// has: the heading is one of the words or starts with one of them (short section titles only).
func has(h string, words ...string) bool {
	if len(h) > 32 {
		return false
	}
	for _, w := range words {
		if h == w || strings.HasPrefix(h, w+" ") || strings.HasPrefix(h, w+":") || strings.HasSuffix(h, " "+w) {
			return true
		}
	}
	return false
}

type section struct {
	heading string
	level   int
	blocks  []block
	sub     map[string][]block
}

// sections groups blocks into entries: an unnamed heading starts an entry, a named heading
// (symptom/cause/fix/env/tags) opens a sub-section of the current one, deeper unnamed headings
// inside a sub-section are kept as text.
func sections(bs []block, fallback string) []section {
	var out []section
	var cur *section
	sub := ""
	start := func(h string, level int) {
		if cur != nil {
			out = append(out, *cur)
		}
		cur = &section{heading: h, level: level, sub: map[string][]block{}}
		sub = ""
	}
	for _, b := range bs {
		if b.kind == 'h' {
			if k := sectionKind(b.text); k != "" {
				if cur == nil {
					start(fallback, 0)
				}
				sub = k
				continue
			}
			if cur != nil && cur.level > 0 && b.level > cur.level && sub != "" {
				cur.sub[sub] = append(cur.sub[sub], block{kind: 'p', text: b.text})
				continue
			}
			start(b.text, b.level)
			continue
		}
		if cur == nil {
			start(fallback, 0)
		}
		if sub == "" {
			cur.blocks = append(cur.blocks, b)
		} else {
			cur.sub[sub] = append(cur.sub[sub], b)
		}
	}
	if cur != nil {
		out = append(out, *cur)
	}
	return out
}

func (s *section) all() []block {
	out := append([]block{}, s.blocks...)
	for _, k := range []string{"symptom", "cause", "fix", "env", "tags"} {
		out = append(out, s.sub[k]...)
	}
	return out
}

func firstCode(bs []block) *block {
	for i := range bs {
		if bs[i].kind == 'c' {
			return &bs[i]
		}
	}
	return nil
}

func firstList(bs []block) *block {
	for i := range bs {
		if bs[i].kind == 'l' {
			return &bs[i]
		}
	}
	return nil
}

func paraText(bs []block) string {
	var out []string
	for _, b := range bs {
		if b.kind == 'p' {
			out = append(out, b.text)
		}
	}
	return strings.Join(out, "\n")
}

func viable(s *section) bool {
	return firstCode(s.all()) != nil || len(s.sub["fix"]) > 0 || firstList(s.blocks) != nil
}

// draftNote turns one note into entry drafts, one per viable section.
func draftNote(text, fallback, kind string, tags map[string]bool) []*Entry {
	var out []*Entry
	for _, s := range sections(parseBlocks(text), fallback) {
		if viable(&s) {
			out = append(out, s.entry(kind, tags))
		}
	}
	return out
}

// errorRe marks error lines as tools print them; a match in the first 24 bytes (ERROR:, fatal:,
// XError:, npm ERR!) is preferred, else the last matching line (tracebacks end with the exception).
var (
	errorRe  = regexp.MustCompile(`(?i)\b(error|exception|fatal|panic|failed|failure|cannot|can't|could not|couldn't|unable|denied|refused|not found|no such|invalid|unexpected|timeout|timed out|unmet|missing|segmentation fault|killed|E[A-Z]{3,}|ERR!)`)
	promptRe = regexp.MustCompile(`^\s*([$#>%]|PS [A-Z]:\\)\s`)
)

func errorLine(text string) string {
	last := ""
	for _, l := range strings.Split(text, "\n") {
		if strings.TrimSpace(l) == "" || promptRe.MatchString(l) {
			continue
		}
		loc := errorRe.FindStringIndex(l)
		if loc == nil {
			continue
		}
		if loc[0] < 24 {
			return squash(l)
		}
		last = squash(l)
	}
	return last
}

func (s *section) entry(kind string, tags map[string]bool) *Entry {
	code := firstCode(s.sub["symptom"])
	if code == nil {
		code = firstCode(s.blocks)
	}
	title := ""
	if code != nil {
		title = errorLine(code.text)
	}
	if title == "" {
		title = errorLine(paraText(s.sub["symptom"]) + "\n" + paraText(s.blocks))
	}
	vers := versions(allText(s.all()) + "\n" + s.heading)
	if title == "" {
		title = s.heading
		if len(vers) > 0 {
			title = vers[0] + ": " + title
		}
	}
	symptom := ""
	switch {
	case code != nil:
		symptom = code.text
	case paraText(s.sub["symptom"]) != "":
		symptom = paraText(s.sub["symptom"])
	default:
		symptom = paraText(s.blocks[:min(len(s.blocks), 1)])
	}
	cause := render(s.sub["cause"])
	if cause == "" {
		cause = paraAfter(s.blocks, code)
	}
	fix := renderFix(s.sub["fix"])
	if fix == "" {
		fix = fallbackFix(s.blocks, code)
	}
	e := &Entry{Kind: kind, Title: cut(squash(title), maxTitle), Symptom: cut(symptom, maxSymptom), Cause: cut(cause, maxCause),
		Fix: cut(fix, maxFix), Versions: cut(strings.Join(vers, ", "), maxVersions), Tags: pickTags(s, vers, tags), License: license}
	e.normalize()
	return e
}

func allText(bs []block) string {
	var b strings.Builder
	for _, bl := range bs {
		b.WriteString(bl.text + "\n" + strings.Join(bl.items, "\n") + "\n")
	}
	return b.String()
}

// paraAfter is the first paragraph following the symptom code block (the usual "because ..." line).
func paraAfter(bs []block, code *block) string {
	seen := code == nil
	for i := range bs {
		if code != nil && &bs[i] == code {
			seen = true
			continue
		}
		if seen && bs[i].kind == 'p' {
			return bs[i].text
		}
	}
	return ""
}

func fallbackFix(bs []block, code *block) string {
	if l := firstList(bs); l != nil {
		return renderFix([]block{*l})
	}
	n := 0
	for i := range bs {
		if bs[i].kind == 'c' && &bs[i] != code {
			n++
			return indentLines(bs[i].text)
		}
	}
	return ""
}

// render joins a sub-section as plain text: paragraphs, numbered list items, code indented.
func render(bs []block) string {
	var out []string
	for _, b := range bs {
		switch b.kind {
		case 'p', 'h':
			out = append(out, b.text)
		case 'l':
			out = append(out, strings.Join(b.items, "\n"))
		case 'c':
			out = append(out, indentLines(b.text))
		}
	}
	return strings.Join(out, "\n")
}

// renderFix renders the fix as numbered steps; code blocks are indented under the current step.
func renderFix(bs []block) string {
	var out []string
	n := 0
	for _, b := range bs {
		switch b.kind {
		case 'l':
			for _, it := range b.items {
				n++
				out = append(out, fmt.Sprintf("%d. %s", n, strings.ReplaceAll(it, "\n", "\n   ")))
			}
		case 'p', 'h':
			out = append(out, b.text)
		case 'c':
			out = append(out, indentLines(b.text))
		}
	}
	return strings.Join(out, "\n")
}

func indentLines(s string) string {
	return "    " + strings.ReplaceAll(s, "\n", "\n    ")
}

// --- versions: `lib 1.2.3`, `lib@1.2`, `lib==1.2`, `lib/1.2`, `lib:1.2`, `lib v1.2`, `go1.22` -> lib@ver ---

var versionRe = regexp.MustCompile(`(?i)\b([a-z][a-z0-9_+.-]{1,40}?)(?:@|==|/|:|\s+v?|-v?|_v?|)v?([0-9]+\.[0-9]+(?:\.[0-9]+){0,2}(?:[.+-][0-9a-z.+-]{0,20})?)\b`)

var stopLibs = func() map[string]bool {
	m := map[string]bool{}
	for _, w := range strings.Fields(`version versions ver on in at to from with for and the release released since build port line using use used
		of is was are be or by after before than as into update updated upgrade upgraded install installed running run runs between step see host
		section chapter page figure table id size value number no nr rev revision about around over under up down only now then when until till
		through via per vs versus like has have had got get set out this that these those it its near err error exit code status http https
		www ip addr address mask netmask gateway dns id pid uid gid tcp udp ttl mtu rtt ms sec secs min mins hour hours day days week weeks
		month months year years kb mb gb tb kib mib gib tib`) {
		m[w] = true
	}
	return m
}()

var libAlias = map[string]string{"python3": "python", "pip3": "pip", "nodejs": "node", "golang": "go", "postgresql": "postgres",
	"psql": "postgres", "k8s": "kubernetes", "osx": "macos", "mac": "macos", "docker-compose": "compose", "pnpm": "pnpm", "openjdk": "java",
	"jdk": "java", "jre": "java", "nvm": "node", "cargo": "rust", "rustc": "rust", "gcc": "gcc", "g++": "gcc", "clang++": "clang"}

func versions(text string) []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range versionRe.FindAllStringSubmatch(text, -1) {
		lib := strings.ToLower(strings.TrimRight(m[1], ".-_+"))
		ver := strings.TrimLeft(m[2], "vV")
		if len(lib) < 2 || stopLibs[lib] || seen[lib] || strings.Count(ver, ".") > 3 {
			continue
		}
		seen[lib] = true
		out = append(out, lib+"@"+ver)
		if len(out) == 8 {
			break
		}
	}
	return out
}

// pickTags keeps the controlled tags found among the heading words, the libraries and an explicit
// tags sub-section, in order of appearance.
func pickTags(s *section, vers []string, tags map[string]bool) []string {
	var cands []string
	cands = append(cands, strings.FieldsFunc(strings.ToLower(s.heading), func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '+' || r == '.' || r == '-')
	})...)
	for _, v := range vers {
		lib := v[:strings.IndexByte(v, '@')]
		cands = append(cands, lib)
		if al := libAlias[lib]; al != "" {
			cands = append(cands, al)
		}
	}
	for _, b := range s.sub["tags"] {
		cands = append(cands, strings.FieldsFunc(strings.ToLower(b.text+" "+strings.Join(b.items, " ")), func(r rune) bool {
			return r == ',' || r == ' ' || r == '\n' || r == '#'
		})...)
	}
	out := []string{}
	seen := map[string]bool{}
	for _, c := range cands {
		c = strings.Trim(c, ".-")
		if tags[c] && !seen[c] {
			seen[c] = true
			out = append(out, c)
			if len(out) == maxTags {
				break
			}
		}
	}
	return out
}
