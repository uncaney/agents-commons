package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	tok1 = "cx_" + strings.Repeat("a", 43)
	tok2 = "cx_" + strings.Repeat("b", 43)
)

func newTestApp(t *testing.T) (*app, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	a := &app{dir: filepath.Join(t.TempDir(), "cx-seed"), stdin: strings.NewReader(""), stdout: out, stderr: errb,
		getenv: func(string) string { return "" }, http: http.DefaultClient, sleep: func(time.Duration) {},
		now: func() time.Time { return time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC) }}
	return a, out, errb
}

func abs(t *testing.T, rel string) string {
	t.Helper()
	p, err := filepath.Abs(rel)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func write(t *testing.T, path, s string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
		t.Fatal(err)
	}
}

func load(t *testing.T, path string) *Entry {
	t.Helper()
	e, err := loadEntry(path)
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func save(t *testing.T, path string, e *Entry) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := saveEntry(path, e); err != nil {
		t.Fatal(err)
	}
}

func cleanEntry(title string) *Entry {
	e := &Entry{Kind: "fix", Title: title, Symptom: "$ run\n" + title, Cause: "the usual cause", Fix: "1. first step\n2. second step",
		Versions: "python@3.12", Tags: []string{"python"}, License: license}
	e.normalize()
	return e
}

func approvedEntry(title string) *Entry {
	e := cleanEntry(title)
	e.Reviewed, e.ReviewHash = true, e.hash()
	return e
}

func names(files []string) []string {
	out := make([]string, len(files))
	for i, f := range files {
		out[i] = filepath.Base(f)
	}
	return out
}

func TestDraftFromMarkdown(t *testing.T) {
	a, out, _ := newTestApp(t)
	notes := abs(t, "testdata/notes")
	write(t, filepath.Join(a.dir, "sources.txt"), filepath.Join(notes, "pip-ssl.md")+"\n# a comment\n\n"+filepath.Join(notes, "two-errors.md")+"\n")
	if code := a.run([]string{"draft"}); code != 0 {
		t.Fatalf("draft exit %d: %s", code, out)
	}
	files, err := listEntries(filepath.Join(a.dir, "drafts"))
	if err != nil || len(files) != 3 {
		t.Fatalf("drafts = %v (%v)\n%s", names(files), err, out)
	}
	e := load(t, files[0])
	if !strings.HasPrefix(e.Title, "ERROR: Could not install packages due to an OSError") || len(e.Title) > maxTitle || !oneLine(e.Title) {
		t.Errorf("title = %q", e.Title)
	}
	if !strings.Contains(e.Symptom, "CERTIFICATE_VERIFY_FAILED") || !strings.HasPrefix(e.Symptom, "$ pip install requests\n") || len(e.Symptom) > maxSymptom {
		t.Errorf("symptom = %q", e.Symptom)
	}
	if !strings.Contains(e.Cause, "certifi bundle") {
		t.Errorf("cause = %q", e.Cause)
	}
	if !strings.HasPrefix(e.Fix, "1. Run the bundled script") || !strings.Contains(e.Fix, "\n2. Re-run `pip install requests`\n3. If it still fails") {
		t.Errorf("fix = %q", e.Fix)
	}
	if e.Versions != "python@3.12, macos@14.5, pip@24.0" {
		t.Errorf("versions = %q", e.Versions)
	}
	tags, _ := a.loadTags("")
	have := map[string]bool{}
	for _, tg := range e.Tags {
		have[tg] = true
		if !tags[tg] {
			t.Errorf("tag %q not in tags.txt", tg)
		}
	}
	for _, want := range []string{"python", "pip", "tls", "macos"} {
		if !have[want] {
			t.Errorf("tags %v miss %q", e.Tags, want)
		}
	}
	if len(e.Tags) > maxTags || e.Reviewed || e.ReviewHash != "" || e.License != license || e.Kind != "fix" {
		t.Errorf("entry state: %+v", e)
	}
	// second note: one entry per section, fallback heuristics (first list = fix, paragraph after the block = cause)
	e2, e3 := load(t, files[1]), load(t, files[2])
	if e2.Title != "error: failed to push some refs to 'origin'" || !strings.HasPrefix(e2.Fix, "1. Fetch and inspect") ||
		!strings.Contains(e2.Fix, "\n2. If the remote commits are expendable") || e2.Cause != "The remote has commits that the local branch lost during the rebase." ||
		strings.Join(e2.Tags, ",") != "git" || e2.Versions != "" {
		t.Errorf("entry 2 = %+v", e2)
	}
	if e3.Title != "#8 0.412 exec /bin/sh: exec format error" || e3.Versions != "docker@26.1" || e3.Fix != "" || !strings.Contains(strings.Join(e3.Tags, ","), "docker") {
		t.Errorf("entry 3 = %+v", e3)
	}
	for _, p := range []struct {
		path string
		perm os.FileMode
	}{{a.dir, 0o700}, {filepath.Join(a.dir, "drafts"), 0o700}, {files[0], 0o600}} {
		if st, err := os.Stat(p.path); err != nil || st.Mode().Perm() != p.perm {
			t.Errorf("%s perm = %v want %v (%v)", p.path, st.Mode().Perm(), p.perm, err)
		}
	}
	// the drafts of clean notes pass the strict gate, except the one left without a fix
	out.Reset()
	if code := a.run([]string{"gate", "-denylist", abs(t, "denylist.example.txt")}); code != 0 {
		t.Fatalf("gate exit %d: %s", code, out)
	}
	if !strings.Contains(out.String(), "drafts=3 accepted=2 rejected=1 entries=2") {
		t.Errorf("gate: %s", out)
	}
	log, _ := os.ReadFile(filepath.Join(a.dir, "GATE-LOG.md"))
	if !strings.Contains(string(log), "| empty.fix | 1 |") {
		t.Errorf("log: %s", log)
	}
	// draft again: numbering continues, nothing is overwritten
	out.Reset()
	a.run([]string{"draft"})
	files, _ = listEntries(filepath.Join(a.dir, "drafts"))
	if len(files) != 6 || !strings.HasPrefix(filepath.Base(files[3]), "004-") {
		t.Errorf("second draft run: %v", names(files))
	}
}

func TestDraftRefusesExcludedSources(t *testing.T) {
	a, out, _ := newTestApp(t)
	work := filepath.Join(t.TempDir(), "notes")
	byPath := filepath.Join(work, "customer-notes.md")
	byContent := filepath.Join(work, "laptop.md")
	byExtra := filepath.Join(work, "project.md")
	ok := filepath.Join(work, "ok.md")
	write(t, byPath, "# a note\n\n```\nerror: x\n```\n\n1. step\n")
	write(t, byContent, "# Laptop setup\n\nRollout for the tenant account.\n\n```\nerror: y\n```\n\n1. step\n")
	write(t, byExtra, "# Build\n\nNotes for ProjectX only.\n\n```\nerror: z\n```\n\n1. step\n")
	write(t, ok, "# ok\n\n```\nerror: fine\n```\n\n1. do it\n")
	write(t, filepath.Join(a.dir, "exclude.txt"), "# additive terms\nprojectx\n")
	write(t, filepath.Join(a.dir, "sources.txt"), strings.Join([]string{byPath, byContent, byExtra, ok}, "\n")+"\n")
	if code := a.run([]string{"draft"}); code != 0 {
		t.Fatalf("draft exit %d: %s", code, out)
	}
	s := out.String()
	for _, want := range []string{"refused #1: class=customer\n", "refused #2: class=tenant\n", "refused #3: class=projectx\n", "drafted #4: 1 entries\n", "sources=4 drafted=1 refused=3 drafts=1"} {
		if !strings.Contains(s, want) {
			t.Errorf("output misses %q:\n%s", want, s)
		}
	}
	for _, leak := range []string{"Rollout", "account", "laptop.md", work, "ProjectX only"} {
		if strings.Contains(s, leak) {
			t.Errorf("output leaks %q:\n%s", leak, s)
		}
	}
	files, _ := listEntries(filepath.Join(a.dir, "drafts"))
	if len(files) != 1 || load(t, files[0]).Title != "error: fine" {
		t.Errorf("drafts = %v", names(files))
	}
	// the exclude list is additive: the built-in terms still apply with exclude.txt present
	ex, err := a.excludes("")
	if err != nil || ex.class("notes about the employer") != "employer" || ex.class("ProjectX") != "projectx" || ex.class("ordinary text") != "" {
		t.Errorf("excludes: %v %q", err, ex.class("notes about the employer"))
	}
	// sources lists candidates and comments excluded paths out with the class only
	out.Reset()
	if code := a.run([]string{"sources", work}); code != 0 {
		t.Fatalf("sources exit %d", code)
	}
	if s := out.String(); !strings.Contains(s, "# excluded customer: "+byPath) || !strings.Contains(s, ok+"\n") || strings.Count(s, "\n") != 4 {
		t.Errorf("sources:\n%s", s)
	}
}

func TestGateStrictRejectsSecretsIPsEmailsHosts(t *testing.T) {
	a, out, _ := newTestApp(t)
	outDir := filepath.Join(a.dir, "entries")
	code := a.run([]string{"gate", abs(t, "testdata/drafts"), "-denylist", abs(t, "denylist.example.txt"), "-o", outDir})
	if code != 0 || !strings.Contains(out.String(), "drafts=15 accepted=1 rejected=14 entries=1\n") {
		t.Fatalf("gate exit %d: %s", code, out)
	}
	logb, err := os.ReadFile(filepath.Join(a.dir, "GATE-LOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	log := string(logb)
	for _, c := range []string{"scrub.key.aws", "scrub.email", "scrub.ip.v4", "scrub.host.internal", "scrub.host.dotted", "scrub.path.unix",
		"scrub.entropy", "scrub.phone", "denylist", "denylist.re", "hazard.exec-remote", "cap.symptom", "tag.unknown", "dup"} {
		if !strings.Contains(log, "| "+c+" |") {
			t.Errorf("log misses class %s", c)
		}
	}
	for _, leak := range []string{"AKIAQ7R2M9XKT4P8ZL3W", "mailbox-example", "10.42.0.7", "nas.local", "someprivatehost", "/Users/jane",
		"Qw8rT2yU6iO1pA5sD9fG3hJ7kL0zX4cVbN", "my-nas", "ExampleCorp", "install.sh", "+33", ".json", "Permission denied", "clean"} {
		if strings.Contains(log, leak) {
			t.Errorf("log leaks %q", leak)
		}
	}
	if st, err := os.Stat(filepath.Join(a.dir, "GATE-LOG.md")); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("log perm: %v", err)
	}
	files, _ := listEntries(outDir)
	if strings.Join(names(files), ",") != "001-clean.json" {
		t.Fatalf("entries = %v", names(files))
	}
	if e := load(t, files[0]); e.Reviewed || e.ReviewHash != "" || e.License != license || len(e.Hazard) != 0 {
		t.Errorf("accepted entry state: %+v", e)
	}
	// Strict on a single field: every tier-2 class rejects, nothing is masked
	for text, class := range map[string]string{
		"mail me at someone@mail-host.org":                 "scrub.email",
		"the box is 10.0.0.5":                              "scrub.ip.v4",
		"see /home/someone/x":                              "scrub.path.unix",
		"ssh nas.local":                                    "scrub.host.internal",
		"docs at https://wiki.some-private-box.io":         "scrub.host.dotted",
		"key: ghp_" + strings.Repeat("Zq9", 12) + "x1":     "scrub.key.github",
		"PrivateKey = " + strings.Repeat("Ab3", 14) + "Q=": "scrub.key.wireguard",
	} {
		e := cleanEntry("some error happened")
		e.Cause = text
		cs := gateEntry(e, nil, func(string) bool { return false }, nil, nil)
		if len(cs) != 1 || cs[0] != class {
			t.Errorf("%q -> %v want [%s]", text, cs, class)
		}
		if e.Cause != text {
			t.Errorf("%q was masked to %q", text, e.Cause)
		}
	}
	// hazard_ok accepts a hazardous entry and records its families
	hz := t.TempDir()
	e := load(t, abs(t, "testdata/drafts/011-hazard.json"))
	e.HazardOK = true
	save(t, filepath.Join(hz, "h.json"), e)
	out.Reset()
	if code := a.run([]string{"gate", hz, "-denylist", abs(t, "denylist.example.txt"), "-o", filepath.Join(a.dir, "hz")}); code != 0 || !strings.Contains(out.String(), "accepted=1 rejected=0") {
		t.Fatalf("hazard_ok gate: %d %s", code, out)
	}
	if g := load(t, filepath.Join(a.dir, "hz", "h.json")); len(g.Hazard) == 0 || g.Hazard[0] != "exec-remote" || !g.HazardOK {
		t.Errorf("hazard recorded: %+v", g)
	}
	// a host allowlisted in $CX_SEED_DIR/hosts.txt passes the dotted-host rule
	hs := t.TempDir()
	save(t, filepath.Join(hs, "d.json"), load(t, abs(t, "testdata/drafts/006-dotted-host.json")))
	write(t, filepath.Join(a.dir, "hosts.txt"), "notes.someprivatehost.net\n")
	out.Reset()
	if code := a.run([]string{"gate", hs, "-denylist", abs(t, "denylist.example.txt"), "-o", filepath.Join(a.dir, "hs")}); code != 0 || !strings.Contains(out.String(), "accepted=1 rejected=0") {
		t.Fatalf("hosts.txt gate: %d %s", code, out)
	}
	allow, _ := a.loadHosts("")
	for h, want := range map[string]bool{"docs.anything.io": true, "pkg.go.dev": true, "notes.someprivatehost.net": true, "other.someprivatehost.net": false, "cdn.pypi.org": true, "evil.example-not.co": false} {
		if allow(h) != want {
			t.Errorf("allow(%s) = %v", h, !want)
		}
	}
}

func TestGateDenylist(t *testing.T) {
	a, out, errb := newTestApp(t)
	drafts := t.TempDir()
	a1 := cleanEntry("smb mount fails with Permission denied")
	a1.Cause = "The share on the my-nas box requires SMB3 signing."
	a2 := cleanEntry("openvpn: AUTH_FAILED after password rotation")
	a2.Cause = "The ExampleCorp profile still had old credentials."
	a3 := cleanEntry("rsync: connection unexpectedly closed")
	a3.Cause = "The mynas-x device went to sleep; my-nasx is a different word."
	for i, e := range []*Entry{a1, a2, a3} {
		save(t, filepath.Join(drafts, fmt.Sprintf("%d.json", i+1)), e)
	}
	deny := filepath.Join(t.TempDir(), "deny.txt")
	write(t, deny, "# hosts\nmy-nas\nre:(?i)\\bexample-?corp\\b\n")
	code := a.run([]string{"gate", drafts, "-denylist", deny, "-o", filepath.Join(a.dir, "entries")})
	if code != 0 || !strings.Contains(out.String(), "drafts=3 accepted=1 rejected=2") {
		t.Fatalf("gate exit %d: %s", code, out)
	}
	log, _ := os.ReadFile(filepath.Join(a.dir, "GATE-LOG.md"))
	for _, want := range []string{"| denylist | 1 |", "| denylist.re | 1 |", "| 1 | rejected | denylist |", "| 2 | rejected | denylist.re |", "| 3 | ok | - |"} {
		if !strings.Contains(string(log), want) {
			t.Errorf("log misses %q:\n%s", want, log)
		}
	}
	for _, leak := range []string{"my-nas", "ExampleCorp", "examplecorp", "smb", "openvpn"} {
		if strings.Contains(string(log), leak) {
			t.Errorf("log leaks %q", leak)
		}
	}
	files, _ := listEntries(filepath.Join(a.dir, "entries"))
	if strings.Join(names(files), ",") != "3.json" {
		t.Errorf("entries = %v", names(files))
	}
	// the example denylist parses; a missing denylist only warns
	if d, err := loadDenylist(abs(t, "denylist.example.txt")); err != nil || len(d.tokens) < 5 || len(d.res) < 3 {
		t.Errorf("denylist.example.txt: %v", err)
	}
	if d, _ := parseDenylist([]byte("Jane Doe\n")); len(d.classes("Thanks to jane doe for the fix")) != 1 || len(d.classes("janedoe")) != 0 {
		t.Error("multi-word token matching")
	}
	errb.Reset()
	a.run([]string{"gate", drafts, "-o", filepath.Join(a.dir, "e2")})
	if !strings.Contains(errb.String(), "warn: no denylist") {
		t.Errorf("stderr: %s", errb)
	}
}

func TestDedupe(t *testing.T) {
	a, out, _ := newTestApp(t)
	drafts := t.TempDir()
	title := "ERROR: Could not install packages due to an OSError: [Errno 13] Permission denied"
	save(t, filepath.Join(drafts, "a.json"), cleanEntry(title))
	save(t, filepath.Join(drafts, "b.json"), cleanEntry("ERROR Could not install packages due to an OSError Errno 13 Permission denied!"))
	save(t, filepath.Join(drafts, "c.json"), cleanEntry("ssh: connect to host port 22: Connection refused"))
	d := cleanEntry(title)
	d.DupOK = true
	save(t, filepath.Join(drafts, "d.json"), d)
	deny := abs(t, "denylist.example.txt")
	outDir := filepath.Join(a.dir, "entries")
	run := func() string {
		out.Reset()
		if code := a.run([]string{"gate", drafts, "-denylist", deny, "-o", outDir}); code != 0 {
			t.Fatalf("gate exit %d: %s", code, out)
		}
		return out.String()
	}
	if s := run(); !strings.Contains(s, "drafts=4 accepted=3 rejected=1 entries=3") {
		t.Fatalf("first run: %s", s)
	}
	log, _ := os.ReadFile(filepath.Join(a.dir, "GATE-LOG.md"))
	if !strings.Contains(string(log), "| 2 | rejected | dup |") || !strings.Contains(string(log), "| dup | 1 |") {
		t.Errorf("log: %s", log)
	}
	// re-gating the same drafts never flags them as duplicates of their own previous output
	if s := run(); !strings.Contains(s, "drafts=4 accepted=3 rejected=1 entries=3") {
		t.Fatalf("second run: %s", s)
	}
	// a new draft similar to an entry already gated is a dup
	save(t, filepath.Join(drafts, "e.json"), cleanEntry(strings.ToLower(title)))
	if s := run(); !strings.Contains(s, "drafts=5 accepted=3 rejected=2 entries=3") {
		t.Fatalf("third run: %s", s)
	}
	if sim := similarity(trigrams(title), trigrams("ssh: connect to host port 22: Connection refused")); sim >= dupThreshold {
		t.Errorf("unrelated titles similarity %.2f", sim)
	}
	if sim := similarity(trigrams("ModuleNotFoundError: No module named 'foo'"), trigrams("ModuleNotFoundError: No module named 'bar'")); sim < dupThreshold {
		t.Errorf("near-duplicate similarity %.2f", sim)
	}
}

func TestReviewFlagAndInvalidation(t *testing.T) {
	a, out, _ := newTestApp(t)
	dir := filepath.Join(a.dir, "entries")
	e1, e2 := cleanEntry("first error: one"), cleanEntry("second error: two")
	e2.Symptom = "line\twith tab\nand\x1b[31mescape"
	save(t, filepath.Join(dir, "1.json"), e1)
	save(t, filepath.Join(dir, "2.json"), e2)
	a.stdin = strings.NewReader("maybe\ny\nn\n")
	if code := a.run([]string{"review"}); code != 0 {
		t.Fatalf("review exit %d: %s", code, out)
	}
	if s := out.String(); !strings.Contains(s, "approved=1 left=1 deleted=0 skipped=0") || strings.Contains(s, "\x1b") || !strings.Contains(s, `\x1b[31mescape`) ||
		!strings.Contains(s, "[1/2] 1.json") || !strings.Contains(s, "title:    second error: two") {
		t.Errorf("review output:\n%s", s)
	}
	r1, r2 := load(t, filepath.Join(dir, "1.json")), load(t, filepath.Join(dir, "2.json"))
	if !r1.Reviewed || r1.ReviewHash != r1.hash() || !r1.approved() {
		t.Errorf("entry 1 not approved: %+v", r1)
	}
	if r2.Reviewed || r2.ReviewHash != "" || r2.approved() {
		t.Errorf("entry 2 approved without y: %+v", r2)
	}
	// an edit after approval voids it
	r1.Fix += "\n3. one more step"
	save(t, filepath.Join(dir, "1.json"), r1)
	if load(t, filepath.Join(dir, "1.json")).approved() {
		t.Fatal("edited entry still approved")
	}
	// re-gating an unchanged approved entry keeps the approval; a changed draft loses it
	drafts := t.TempDir()
	save(t, filepath.Join(drafts, "3.json"), cleanEntry("third error: three"))
	save(t, filepath.Join(dir, "3.json"), approvedEntry("third error: three"))
	changed := cleanEntry("fourth error: four")
	save(t, filepath.Join(drafts, "4.json"), changed)
	changed.Fix = "1. different"
	changed.Reviewed, changed.ReviewHash = true, changed.hash()
	save(t, filepath.Join(dir, "4.json"), changed)
	out.Reset()
	if code := a.run([]string{"gate", drafts, "-denylist", abs(t, "denylist.example.txt"), "-o", dir}); code != 0 {
		t.Fatalf("gate: %s", out)
	}
	if !load(t, filepath.Join(dir, "3.json")).approved() || load(t, filepath.Join(dir, "4.json")).approved() {
		t.Error("gate did not preserve/clear approvals correctly")
	}
	// the voided entry comes back in the walk; q quits early without changes; d deletes
	a.stdin = strings.NewReader("q\n")
	out.Reset()
	a.run([]string{"review"})
	if !strings.Contains(out.String(), "edited after approval") || !strings.Contains(out.String(), "approved=0 left=0") {
		t.Errorf("q run:\n%s", out)
	}
	a.stdin = strings.NewReader("d\ny\ny\n")
	out.Reset()
	a.run([]string{"review"})
	if _, err := os.Stat(filepath.Join(dir, "1.json")); !os.IsNotExist(err) {
		t.Error("d did not delete")
	}
	if !strings.Contains(out.String(), "approved=2 left=0 deleted=1 skipped=1") {
		t.Errorf("final run:\n%s", out)
	}
	if term("a\x00b\x1bc", "") != `a\x00b\x1bc` {
		t.Error("term escaping")
	}
}

// fakeKB stands in for POST /v1/kb: it decodes the body exactly like the gateway (unknown fields
// rejected), records the token used per post and simulates dup and quota replies.
type fakeKB struct {
	mu     sync.Mutex
	auths  []string
	titles []string
	quota  map[string]bool
	next   int
}

func (f *fakeKB) handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/kb", func(w http.ResponseWriter, r *http.Request) {
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !tokenRe.MatchString(tok) {
			w.WriteHeader(401)
			io.WriteString(w, "err auth invalid token\n")
			return
		}
		if r.Header.Get("Content-Type") != "application/json" {
			w.WriteHeader(415)
			io.WriteString(w, "err bad content type\n")
			return
		}
		var in struct {
			Kind, Title, Symptom, Cause, Fix, Versions string
			Tags                                       []string
			Force                                      bool
			License                                    string
		}
		dec := json.NewDecoder(r.Body)
		dec.DisallowUnknownFields()
		if err := dec.Decode(&in); err != nil || in.Title == "" {
			w.WriteHeader(400)
			fmt.Fprintf(w, "err bad json: %v\n", err)
			return
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.quota[tok] {
			w.WriteHeader(429)
			io.WriteString(w, "err quota daily quota reached\n")
			return
		}
		if strings.Contains(in.Title, "DUPLICATE") {
			w.WriteHeader(409)
			io.WriteString(w, "err dup k0000001 Existing title\n")
			return
		}
		f.next++
		f.auths = append(f.auths, tok)
		f.titles = append(f.titles, in.Title)
		w.WriteHeader(201)
		fmt.Fprintf(w, "ok k%07d\n", f.next)
	})
	return mux
}

func TestPostRefusesUnreviewed(t *testing.T) {
	a, out, _ := newTestApp(t)
	f := &fakeKB{quota: map[string]bool{}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	dir := filepath.Join(a.dir, "entries")
	save(t, filepath.Join(dir, "1.json"), approvedEntry("approved error: one"))
	save(t, filepath.Join(dir, "2.json"), cleanEntry("unreviewed error: two"))
	edited := approvedEntry("edited error: three")
	edited.Cause = "changed after the review"
	save(t, filepath.Join(dir, "3.json"), edited)
	write(t, filepath.Join(a.dir, "tokens.txt"), "# seed roots\n"+tok1+"\n")
	if code := a.run([]string{"post", "-url", srv.URL, "-pace", "0"}); code != 0 {
		t.Fatalf("post exit %d: %s", code, out)
	}
	if len(f.titles) != 1 || f.titles[0] != "approved error: one" {
		t.Fatalf("server saw %v", f.titles)
	}
	s := out.String()
	for _, want := range []string{"ok 1.json k0000001\n", "refused 2.json: not reviewed\n", "refused 3.json: edited after review\n", "posted=1 dup=0 refused=2 failed=0 remaining=0\n"} {
		if !strings.Contains(s, want) {
			t.Errorf("output misses %q:\n%s", want, s)
		}
	}
	st, err := os.ReadFile(filepath.Join(a.dir, "post-state.json"))
	if err != nil || !strings.Contains(string(st), `"id": "k0000001"`) || strings.Contains(string(st), tok1) || strings.Contains(string(st), "aaaaaaaa") {
		t.Errorf("state: %v %s", err, st)
	}
	// a second run posts nothing new and still refuses the two others
	out.Reset()
	a.run([]string{"post", "-url", srv.URL, "-pace", "0"})
	if len(f.titles) != 1 || !strings.Contains(out.String(), "posted=0 dup=0 refused=2") {
		t.Errorf("second run: %v %s", f.titles, out)
	}
	// a bad token stops the run before anything is posted
	write(t, filepath.Join(a.dir, "tokens.txt"), "not-a-token\n")
	out.Reset()
	if code := a.run([]string{"post", "-url", srv.URL, "-pace", "0"}); code == 0 {
		t.Error("garbage token accepted")
	}
	// confirm does not exist
	if code := a.run([]string{"confirm"}); code == 0 {
		t.Error("confirm exists")
	}
}

func TestPostRateAndResume(t *testing.T) {
	a, out, _ := newTestApp(t)
	f := &fakeKB{quota: map[string]bool{}}
	srv := httptest.NewServer(f.handler())
	defer srv.Close()
	dir := filepath.Join(a.dir, "entries")
	for i := 1; i <= 5; i++ {
		save(t, filepath.Join(dir, fmt.Sprintf("%d.json", i)), approvedEntry(fmt.Sprintf("error number %d: something failed", i)))
	}
	save(t, filepath.Join(dir, "6.json"), approvedEntry("DUPLICATE error: already there"))
	write(t, filepath.Join(a.dir, "tokens.txt"), tok1+"\n"+tok2+"\n")
	args := []string{"post", "-url", srv.URL, "-pace", "0", "-rate", "2"}
	if code := a.run(args); code != 0 {
		t.Fatalf("run 1 exit %d: %s", code, out)
	}
	if got := strings.Join(f.auths, ","); got != strings.Join([]string{tok1, tok2, tok1, tok2}, ",") {
		t.Fatalf("round robin: %v", f.auths)
	}
	if s := out.String(); !strings.Contains(s, "quota: all 2 tokens reached 2 posts today") || !strings.Contains(s, "posted=4 dup=0 refused=0 failed=0 remaining=2") {
		t.Errorf("run 1:\n%s", s)
	}
	stb, _ := os.ReadFile(filepath.Join(a.dir, "post-state.json"))
	if strings.Contains(string(stb), tok1) || strings.Contains(string(stb), tok2) || !strings.Contains(string(stb), `"day": "2026-10-07"`) {
		t.Errorf("state leaks tokens or lacks the day:\n%s", stb)
	}
	// same day: nothing more is sent, the state keeps the counts
	out.Reset()
	a.run(args)
	if len(f.auths) != 4 || !strings.Contains(out.String(), "posted=0 dup=0 refused=0 failed=0 remaining=2") {
		t.Errorf("run 2: %d posts\n%s", len(f.auths), out)
	}
	// next day: the counters reset, the two remaining entries go out, the dup is recorded once
	a.now = func() time.Time { return time.Date(2026, 10, 8, 9, 0, 0, 0, time.UTC) }
	out.Reset()
	if code := a.run(args); code != 0 {
		t.Fatalf("run 3 exit %d: %s", code, out)
	}
	if len(f.titles) != 5 || !strings.Contains(out.String(), "ok 5.json k0000005") || !strings.Contains(out.String(), "dup 6.json k0000001") ||
		!strings.Contains(out.String(), "posted=1 dup=1 refused=0 failed=0 remaining=0") {
		t.Errorf("run 3: %v\n%s", f.titles, out)
	}
	seen := map[string]bool{}
	for _, ti := range f.titles {
		if seen[ti] {
			t.Errorf("posted twice: %s", ti)
		}
		seen[ti] = true
	}
	var st postState
	stb, _ = os.ReadFile(filepath.Join(a.dir, "post-state.json"))
	if err := json.Unmarshal(stb, &st); err != nil || len(st.Posted) != 6 || st.Day != "2026-10-08" || st.Counts[fingerprint(tok1)] != 1 || !st.Posted["6.json"].Dup {
		t.Errorf("state: %v %+v", err, st)
	}
	// idempotent: a fourth run changes nothing
	out.Reset()
	a.run(args)
	if len(f.titles) != 5 || !strings.Contains(out.String(), "posted=0 dup=0 refused=0 failed=0 remaining=0") {
		t.Errorf("run 4:\n%s", out)
	}
	// a server-side 429 quota exhausts that token for the day and the run moves to the next token
	b, _, _ := newTestApp(t)
	b.http = http.DefaultClient
	bdir := filepath.Join(b.dir, "entries")
	save(t, filepath.Join(bdir, "x.json"), approvedEntry("quota error: x"))
	save(t, filepath.Join(bdir, "y.json"), approvedEntry("quota error: y"))
	write(t, filepath.Join(b.dir, "tokens.txt"), tok1+"\n"+tok2+"\n")
	f.quota[tok1] = true
	if code := b.run([]string{"post", "-url", srv.URL, "-pace", "0", "-rate", "10"}); code != 0 {
		t.Fatalf("quota run exit %d: %s", code, b.stdout)
	}
	if got := f.auths[len(f.auths)-2:]; got[0] != tok2 || got[1] != tok2 {
		t.Errorf("after 429 quota the run should use token 2: %v", got)
	}
	stb, _ = os.ReadFile(filepath.Join(b.dir, "post-state.json"))
	json.Unmarshal(stb, &st)
	if st.Counts[fingerprint(tok1)] != 10 || st.Counts[fingerprint(tok2)] != 2 {
		t.Errorf("counts after quota: %v", st.Counts)
	}
}

func TestCommitRefusesUnreviewed(t *testing.T) {
	a, out, _ := newTestApp(t)
	repo := t.TempDir()
	write(t, filepath.Join(repo, "tools", "seed", "tags.txt"), "python\n")
	dir := filepath.Join(a.dir, "entries")
	save(t, filepath.Join(dir, "ok.json"), approvedEntry("committed error: ok"))
	save(t, filepath.Join(dir, "no.json"), cleanEntry("unreviewed error: no"))
	if code := a.run([]string{"commit", "-repo", repo}); code != 0 {
		t.Fatalf("commit exit %d: %s", code, out)
	}
	files, _ := listEntries(filepath.Join(repo, "tools", "seed", "entries"))
	if strings.Join(names(files), ",") != "ok.json" || !strings.Contains(out.String(), "committed=1 refused=1") || !strings.Contains(out.String(), "git add -f") {
		t.Errorf("commit: %v\n%s", names(files), out)
	}
	if code := a.run([]string{"commit", "-repo", t.TempDir()}); code == 0 {
		t.Error("commit into a non-repo dir succeeded")
	}
}
