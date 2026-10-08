package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeGitConfig makes dir look like a git checkout whose origin remote is remoteURL.
func writeGitConfig(t *testing.T, dir, remoteURL string) {
	t.Helper()
	gd := filepath.Join(dir, ".git")
	if err := os.MkdirAll(gd, 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = " + remoteURL + "\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
	if err := os.WriteFile(filepath.Join(gd, "config"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestCxInitWritesAnchorFile(t *testing.T) {
	f, srv := newRec(t)

	// A plain init in a git checkout writes .cx/anchor with the gh key and contacts nothing.
	dir := t.TempDir()
	writeGitConfig(t, dir, "https://github.com/Acme/Widgets.git")
	c, out, _ := recCLI(t, srv, t.TempDir(), "tok")
	mustRun(t, c, "init", "--dir", dir)
	got := readAnchor(t, dir)
	if !strings.Contains(got, "key: gh:acme/widgets") {
		t.Fatalf(".cx/anchor = %q, want key gh:acme/widgets", got)
	}
	if !strings.Contains(out.String(), "gh:acme/widgets") {
		t.Fatalf("init stdout %q", out.String())
	}
	if len(f.reqs) != 0 {
		t.Fatalf("plain init made %d request(s), want 0", len(f.reqs))
	}

	// --claim posts the key to /v1/anchor with the note.
	dir2 := t.TempDir()
	writeGitConfig(t, dir2, "git@github.com:Acme/Other.git")
	f.set("POST", "/v1/anchor", 201, "ok an key=gh:acme/other claimants=1\n")
	c, out, _ = recCLI(t, srv, t.TempDir(), "tok")
	mustRun(t, c, "init", "--dir", dir2, "--claim", "--note", "rebuilding auth")
	if !strings.Contains(readAnchor(t, dir2), "key: gh:acme/other") {
		t.Fatalf(".cx/anchor for dir2 = %q", readAnchor(t, dir2))
	}
	r := f.last()
	if r.method != "POST" || r.uri != "/v1/anchor" {
		t.Fatalf("claim request %+v", r)
	}
	var body struct{ Key, Note string }
	json.Unmarshal([]byte(r.body), &body)
	if body.Key != "gh:acme/other" || body.Note != "rebuilding auth" {
		t.Fatalf("claim body = %+v", body)
	}
	if !strings.Contains(out.String(), "claimants=1") {
		t.Fatalf("claim stdout %q", out.String())
	}

	// --url mints a url-token and records its URL in .cx/anchor.
	dir3 := t.TempDir()
	writeGitConfig(t, dir3, "https://github.com/acme/urlrepo.git")
	f.set("POST", "/v1/subkey", 201, `{"id":"a1","token":"cx_url_tok","class":"url","url":"`+srv.URL+`/v1/me/resume?t=cx_url_tok"}`)
	c, _, _ = recCLI(t, srv, t.TempDir(), "tok")
	mustRun(t, c, "init", "--dir", dir3, "--url")
	got3 := readAnchor(t, dir3)
	if !strings.Contains(got3, "key: gh:acme/urlrepo") || !strings.Contains(got3, "url: "+srv.URL+"/v1/me/resume?t=cx_url_tok") {
		t.Fatalf(".cx/anchor for dir3 = %q", got3)
	}

	// A positional key overrides the git derivation (and still writes the file without git).
	dir4 := t.TempDir()
	c, _, _ = recCLI(t, srv, t.TempDir(), "tok")
	mustRun(t, c, "init", "task:ship the release", "--dir", dir4)
	if !strings.Contains(readAnchor(t, dir4), "key: task:ship the release") {
		t.Fatalf(".cx/anchor for dir4 = %q", readAnchor(t, dir4))
	}

	// No git checkout and no --key is an error.
	dir5 := t.TempDir()
	c, _, _ = recCLI(t, srv, t.TempDir(), "tok")
	var ee *exitErr
	if err := c.run(context.Background(), []string{"init", "--dir", dir5}); !asExit(err, &ee) || ee.code != 1 {
		t.Fatalf("init without git or --key: %v", err)
	}
}

func readAnchor(t *testing.T, dir string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(dir, ".cx", "anchor"))
	if err != nil {
		t.Fatalf("read .cx/anchor: %v", err)
	}
	return string(b)
}

func TestParseGitHubRemote(t *testing.T) {
	cases := []struct{ in, owner, repo string }{
		{"https://github.com/acme/widgets.git", "acme", "widgets"},
		{"https://github.com/acme/widgets", "acme", "widgets"},
		{"git@github.com:acme/widgets.git", "acme", "widgets"},
		{"ssh://git@github.com/acme/widgets.git", "acme", "widgets"},
		{"https://git.acmecorp.net/group/sub/repo.git", "sub", "repo"},
	}
	for _, c := range cases {
		o, r, ok := parseGitHubRemote(c.in)
		if !ok || o != c.owner || r != c.repo {
			t.Fatalf("parseGitHubRemote(%q) = %q/%q ok=%v, want %q/%q", c.in, o, r, ok, c.owner, c.repo)
		}
	}
	if _, _, ok := parseGitHubRemote("not a url"); ok {
		t.Fatal("parseGitHubRemote accepted a bare word")
	}
}

func TestAnchorPathKeepsGrammar(t *testing.T) {
	if got := anchorPath("gh:acme/widgets"); got != "gh:acme/widgets" {
		t.Fatalf("anchorPath = %q", got)
	}
}
