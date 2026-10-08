package main

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// buildTestBundle returns a zip of SKILL.md + references/grammar.md and the sha256 of the SKILL.md.
func buildTestBundle(t *testing.T, skillBody string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct{ name, body string }{
		{"SKILL.md", skillBody},
		{"references/grammar.md", "# URL grammar\n\nsearch, permalinks, hubs.\n"},
	} {
		w, err := zw.Create(f.name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte(f.body))
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(skillBody))
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

func TestSkillInstallAndCheck(t *testing.T) {
	f, srv := newRec(t)
	skillBody := "---\nname: commons\n---\n\n# agents.ekaii.fr\n\nThe commons, as data.\n"
	zipBytes, sum := buildTestBundle(t, skillBody)
	f.set("GET", "/skills/commons.zip", 200, string(zipBytes))
	f.set("GET", "/skills/index.json", 200,
		`{"skills":[{"name":"commons","description":"d","url":"`+srv.URL+`/skills/commons/SKILL.md","version":"v1234","sha256":"`+sum+`"}]}`)

	dir := t.TempDir()

	// install writes the directory, anonymously (no token needed).
	c, out, _ := recCLI(t, srv, t.TempDir(), "")
	mustRun(t, c, "skill", "install", "--dir", dir)
	if !strings.Contains(out.String(), "ok installed commons") {
		t.Fatalf("install stdout %q", out.String())
	}
	got, err := os.ReadFile(filepath.Join(dir, "commons", "SKILL.md"))
	if err != nil {
		t.Fatalf("SKILL.md not written: %v", err)
	}
	if string(got) != skillBody {
		t.Fatalf("SKILL.md body = %q", got)
	}
	if _, err := os.Stat(filepath.Join(dir, "commons", "references", "grammar.md")); err != nil {
		t.Fatalf("references/grammar.md not written: %v", err)
	}
	// It downloaded the zip, not individual files.
	if f.find("GET", "/skills/commons.zip") == nil {
		t.Fatal("install did not GET /skills/commons.zip")
	}

	// check against a matching index: up to date.
	c, out, _ = recCLI(t, srv, t.TempDir(), "")
	mustRun(t, c, "skill", "check", "--dir", dir)
	if !strings.Contains(out.String(), "up to date") || !strings.Contains(out.String(), "sha256="+sum[:12]) {
		t.Fatalf("check stdout %q", out.String())
	}

	// A tampered local copy is reported stale with a non-zero exit.
	if err := os.WriteFile(filepath.Join(dir, "commons", "SKILL.md"), []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c, out, _ = recCLI(t, srv, t.TempDir(), "")
	var ee *exitErr
	if err := c.run(context.Background(), []string{"skill", "check", "--dir", dir}); !asExit(err, &ee) || ee.code != 1 {
		t.Fatalf("stale check: %v", err)
	}
	if !strings.Contains(ee.Error(), "stale") {
		t.Fatalf("stale message %q", ee.Error())
	}

	// check with nothing installed: not-installed, non-zero exit.
	c, _, _ = recCLI(t, srv, t.TempDir(), "")
	if err := c.run(context.Background(), []string{"skill", "check", "--dir", t.TempDir()}); !asExit(err, &ee) || ee.code != 1 {
		t.Fatalf("not-installed check: %v", err)
	}
	if !strings.Contains(ee.Error(), "not installed") {
		t.Fatalf("not-installed message %q", ee.Error())
	}

	// Unknown client (no --dir) is a usage error.
	c, _, _ = recCLI(t, srv, t.TempDir(), "")
	if err := c.run(context.Background(), []string{"skill", "install", "bogus"}); !asExit(err, &ee) || ee.code != 2 {
		t.Fatalf("bogus client: %v", err)
	}

	// Unknown subverb is a usage error.
	c, _, _ = recCLI(t, srv, t.TempDir(), "")
	if err := c.run(context.Background(), []string{"skill", "frob"}); !asExit(err, &ee) || ee.code != 2 {
		t.Fatalf("bogus subverb: %v", err)
	}
}
