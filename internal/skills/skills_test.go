package skills

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
)

// newServer mounts the skill routes against a bare mux (no DB, no middleware): the handlers depend
// only on doc.Base(), gov.DocsSections() and pages.Grammar(), so a *core.Deps is not needed here.
func newServer(t *testing.T) *httptest.Server {
	t.Helper()
	cfg := core.Config{PublicURL: "https://agents.example"}
	doc.Configure(&cfg)
	z, err := buildZip()
	if err != nil {
		t.Fatal(err)
	}
	h := &handlers{zip: z}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /skills/commons/SKILL.md", h.skill)
	mux.HandleFunc("GET /skills/index.json", h.index)
	mux.HandleFunc("GET /skills/commons.zip", h.bundle)
	mux.HandleFunc("GET /skills", h.page)
	for _, ext := range []string{".txt", ".md", ".json", ".html"} {
		mux.HandleFunc("GET /skills"+ext, h.page)
	}
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func getBody(t *testing.T, url string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

func TestSkillMdWithApprovedSections(t *testing.T) {
	srv := newServer(t)

	// No approved sections: the served file is the embedded base, no community-notes heading.
	gov.SetDocsSections(map[string][]string{})
	st, body, h := getBody(t, srv.URL+"/skills/commons/SKILL.md")
	if st != 200 {
		t.Fatalf("SKILL.md status %d", st)
	}
	if ct := h.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Fatalf("SKILL.md content-type %q", ct)
	}
	if h.Get("ETag") == "" {
		t.Fatal("SKILL.md has no ETag")
	}
	if !strings.HasPrefix(body, "---\nname: commons") {
		t.Fatalf("SKILL.md does not start with the embedded front matter:\n%.80s", body)
	}
	if strings.Contains(body, "Community notes") {
		t.Fatal("empty sections should not add the community-notes heading")
	}
	etagBase := h.Get("ETag")

	// Approve two sections: they appear appended, under the heading, after the embedded base.
	note1 := "On Postgres, the P85 builders use a scratch database per lane to avoid races."
	note2 := "Reports confirm FT-SAE roaming regressions on 5 GHz in Paris."
	gov.SetDocsSections(map[string][]string{"skill": {note1, note2}})
	t.Cleanup(func() { gov.SetDocsSections(map[string][]string{}) })

	st, body, h = getBody(t, srv.URL+"/skills/commons/SKILL.md")
	if st != 200 {
		t.Fatalf("SKILL.md status %d", st)
	}
	if !strings.Contains(body, "## Community notes (operator-approved)") {
		t.Fatal("approved sections did not add the community-notes heading")
	}
	if !strings.Contains(body, note1) || !strings.Contains(body, note2) {
		t.Fatalf("approved sections missing from SKILL.md:\n%s", body)
	}
	if i, j := strings.Index(body, "# agents.ekaii.fr"), strings.Index(body, note1); j < i {
		t.Fatal("approved sections should come after the embedded base")
	}
	if h.Get("ETag") == etagBase {
		t.Fatal("ETag must change when approved sections change the body")
	}
}

func TestIndexJsonSha(t *testing.T) {
	srv := newServer(t)
	gov.SetDocsSections(map[string][]string{})

	st, idx, h := getBody(t, srv.URL+"/skills/index.json")
	if st != 200 {
		t.Fatalf("index.json status %d", st)
	}
	if ct := h.Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("index.json content-type %q", ct)
	}
	var idxDoc1 indexDoc
	if err := json.Unmarshal([]byte(idx), &idxDoc1); err != nil {
		t.Fatalf("index.json bad json: %v\n%s", err, idx)
	}
	if len(idxDoc1.Skills) != 1 {
		t.Fatalf("index.json has %d skills, want 1", len(idxDoc1.Skills))
	}
	e := idxDoc1.Skills[0]
	if e.Name != "commons" || e.Version == "" || e.Description == "" {
		t.Fatalf("index.json entry = %+v", e)
	}
	if want := "https://agents.example/skills/commons/SKILL.md"; e.URL != want {
		t.Fatalf("index.json url = %q, want %q", e.URL, want)
	}

	// The acceptance invariant: the advertised sha256 is the hash of the served SKILL.md bytes.
	_, skill, _ := getBody(t, srv.URL+"/skills/commons/SKILL.md")
	sum := sha256.Sum256([]byte(skill))
	if e.SHA256 != hex.EncodeToString(sum[:]) {
		t.Fatalf("index.json sha256 %s != sha256(SKILL.md) %s", e.SHA256, hex.EncodeToString(sum[:]))
	}

	// It still holds once community notes are appended (both move together).
	gov.SetDocsSections(map[string][]string{"skill": {"A community note."}})
	t.Cleanup(func() { gov.SetDocsSections(map[string][]string{}) })
	_, idx2, _ := getBody(t, srv.URL+"/skills/index.json")
	var idxDoc2 indexDoc
	json.Unmarshal([]byte(idx2), &idxDoc2)
	_, skill2, _ := getBody(t, srv.URL+"/skills/commons/SKILL.md")
	sum2 := sha256.Sum256([]byte(skill2))
	if idxDoc2.Skills[0].SHA256 != hex.EncodeToString(sum2[:]) {
		t.Fatal("index.json sha256 does not track the served SKILL.md after a section is approved")
	}
	if idxDoc2.Skills[0].SHA256 == e.SHA256 {
		t.Fatal("sha256 should change when the served body changes")
	}
}

func TestZipDeterministic(t *testing.T) {
	a, err := buildZip()
	if err != nil {
		t.Fatal(err)
	}
	b, err := buildZip()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("buildZip is not deterministic: two builds differ")
	}
	if len(a) > 64<<10 {
		t.Fatalf("zip bundle is %d bytes, over the 64 KiB cap", len(a))
	}
	// It contains exactly the three expected members, each non-empty.
	zr, err := zip.NewReader(bytes.NewReader(a), int64(len(a)))
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, f := range zr.File {
		rc, err := f.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, _ := io.ReadAll(rc)
		rc.Close()
		got[f.Name] = len(data)
	}
	for _, name := range []string{"SKILL.md", "references/grammar.md", "references/errsig.md"} {
		if got[name] == 0 {
			t.Fatalf("zip missing or empty member %q (members: %v)", name, got)
		}
	}
	if len(got) != 3 {
		t.Fatalf("zip has %d members, want 3: %v", len(got), got)
	}
	// The bundled grammar reference carries the live URL grammar.
	if !strings.Contains(GrammarMD(), "permalinks") {
		t.Fatalf("grammar reference does not look like the URL grammar:\n%s", GrammarMD())
	}
}

func TestSkillsPageIndexable(t *testing.T) {
	srv := newServer(t)

	st, body, _ := getBody(t, srv.URL+"/skills", "Accept", "text/html")
	if st != 200 {
		t.Fatalf("/skills status %d", st)
	}
	if !strings.Contains(body, "index,follow") {
		t.Fatalf("/skills is not indexable (robots meta):\n%s", body)
	}
	if strings.Contains(body, `content="noindex"`) {
		t.Fatal("/skills must not be noindex")
	}
	if !strings.Contains(body, `rel="canonical"`) || !strings.Contains(body, "/skills") {
		t.Fatal("/skills lacks a canonical link")
	}
	if !strings.Contains(body, "WebPage") {
		t.Fatal("/skills lacks WebPage structured data")
	}
	// What it is, how it is installed by hand, what it does not do.
	for _, want := range []string{"install", "cx skill", "not"} {
		if !strings.Contains(strings.ToLower(body), want) {
			t.Fatalf("/skills page missing %q", want)
		}
	}
	// The .md twin negotiates to markdown.
	_, md, h := getBody(t, srv.URL+"/skills.md")
	if ct := h.Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Fatalf("/skills.md content-type %q", ct)
	}
	if !strings.Contains(md, "skills:") {
		t.Fatalf("/skills.md body unexpected:\n%s", md)
	}
}

func TestNoImperatives(t *testing.T) {
	// The embedded repo file (the skill itself) must have no reader-directed imperative lead.
	if line := FirstImperativeLine(skillMD); line != "" {
		t.Fatalf("SKILL.md line leads with a reader-directed imperative: %q", line)
	}
	// The references ship in the bundle and the same discipline applies to them.
	if line := FirstImperativeLine(errsigRef); line != "" {
		t.Fatalf("references/errsig.md leads with an imperative: %q", line)
	}
	if line := FirstImperativeLine(GrammarMD()); line != "" {
		t.Fatalf("references/grammar.md leads with an imperative: %q", line)
	}
	// The validator is not vacuous: it catches a plainly reader-directed line, and skips code
	// fences, front matter and third-person / gerund forms.
	if FirstImperativeLine("Run the migration on your server.") == "" {
		t.Fatal("validator should flag a leading imperative")
	}
	if FirstImperativeLine("```\nrun this\n```\n") != "" {
		t.Fatal("validator should skip fenced code blocks")
	}
	if FirstImperativeLine("Reads are anonymous; adding a suffix negotiates.") != "" {
		t.Fatal("validator should not flag third-person or gerund leads")
	}
}
