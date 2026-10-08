package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// ---- shared fake GitHub Git Data + gateway server (used by mirror and anchor tests) ----

type ghCall struct {
	method, path string
	body         map[string]any
}

type fakeGH struct {
	t       *testing.T
	srv     *httptest.Server
	mu      sync.Mutex
	calls   []ghCall
	refs    map[string]string // "heads/main" -> commit sha (absent => 404)
	commits map[string]struct{ tree, message string }
	blobN   int
	treeN   int
	commitN int
	shard   []byte // gzip JSONL for the kb shard
	roots   string // /ts/roots.txt body
}

func newGHFake(t *testing.T) *fakeGH {
	f := &fakeGH{t: t, refs: map[string]string{}, commits: map[string]struct{ tree, message string }{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeGH) handle(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Egress-Host") == "api.github.com" {
		f.github(w, r)
		return
	}
	// Gateway routes (reached over the internal client, no X-Egress-Host).
	switch {
	case r.URL.Path == "/export/latest.jsonl.gz":
		http.Redirect(w, r, "/export/kb-2026-10-07.jsonl.gz", http.StatusFound)
	case r.URL.Path == "/export/kb-2026-10-07.jsonl.gz":
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(f.shard)
	case r.URL.Path == "/ts/roots.txt":
		io.WriteString(w, f.roots)
	default:
		w.WriteHeader(404)
	}
}

func (f *fakeGH) github(w http.ResponseWriter, r *http.Request) {
	var body map[string]any
	if r.Body != nil {
		b, _ := io.ReadAll(r.Body)
		json.Unmarshal(b, &body)
	}
	f.mu.Lock()
	f.calls = append(f.calls, ghCall{method: r.Method, path: r.URL.Path, body: body})
	p := r.URL.Path
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/git/blobs"):
		f.blobN++
		n := f.blobN
		f.mu.Unlock()
		writeJSON(w, 201, map[string]string{"sha": sha("blob", n)})
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/git/trees"):
		f.treeN++
		n := f.treeN
		f.mu.Unlock()
		writeJSON(w, 201, map[string]string{"sha": sha("tree", n)})
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/git/commits"):
		f.commitN++
		cs := sha("commit", f.commitN)
		tree, _ := body["tree"].(string)
		msg, _ := body["message"].(string)
		f.commits[cs] = struct{ tree, message string }{tree, msg}
		f.mu.Unlock()
		writeJSON(w, 201, map[string]string{"sha": cs})
	case r.Method == http.MethodGet && strings.Contains(p, "/git/ref/heads/"):
		branch := p[strings.LastIndex(p, "/heads/")+len("/heads/"):]
		csha, ok := f.refs["heads/"+branch]
		f.mu.Unlock()
		if !ok {
			writeJSON(w, 404, map[string]string{"message": "Not Found"})
			return
		}
		writeJSON(w, 200, map[string]any{"ref": "refs/heads/" + branch, "object": map[string]string{"sha": csha}})
	case r.Method == http.MethodGet && strings.Contains(p, "/git/commits/"):
		cs := p[strings.LastIndex(p, "/")+1:]
		c := f.commits[cs]
		f.mu.Unlock()
		if c.tree == "" {
			c.tree = "basetree"
		}
		writeJSON(w, 200, map[string]any{"sha": cs, "message": c.message, "tree": map[string]string{"sha": c.tree}})
	case r.Method == http.MethodPatch && strings.Contains(p, "/git/refs/heads/"):
		branch := p[strings.LastIndex(p, "/heads/")+len("/heads/"):]
		cs, _ := body["sha"].(string)
		f.refs["heads/"+branch] = cs
		f.mu.Unlock()
		writeJSON(w, 200, map[string]any{"ref": "refs/heads/" + branch, "object": map[string]string{"sha": cs}})
	case r.Method == http.MethodPost && strings.HasSuffix(p, "/git/refs"):
		ref, _ := body["ref"].(string)
		cs, _ := body["sha"].(string)
		f.refs[strings.TrimPrefix(ref, "refs/")] = cs
		f.mu.Unlock()
		writeJSON(w, 201, map[string]any{"ref": ref, "object": map[string]string{"sha": cs}})
	default:
		f.mu.Unlock()
		writeJSON(w, 404, map[string]string{"message": "Not Found"})
	}
}

func sha(kind string, n int) string {
	return fmt.Sprintf("%s-%040d", kind, n)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

// callsCopy returns a snapshot of the recorded GitHub calls.
func (f *fakeGH) callsCopy() []ghCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ghCall(nil), f.calls...)
}

func gzJSONL(rows []map[string]any) []byte {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	enc := json.NewEncoder(gz)
	for _, r := range rows {
		enc.Encode(r)
	}
	gz.Close()
	return buf.Bytes()
}

func mirrorTestEnv(t *testing.T, f *fakeGH) *tenv {
	te := testEnv(t, f.srv)
	te.envs["GITHUB_REPO"] = "owner/repo"
	te.secret(t, "gh_token", "ghp_testtoken")
	return te
}

func kbRowsShard() []byte {
	return gzJSONL([]map[string]any{
		{"id": "kabc123", "kind": "error", "title": "nil deref in foo", "symptom": "panic", "cause": "unchecked", "fix": "check it", "url": "https://agents.example/kb/kabc123", "license": "CC0-1.0", "author": "seed", "created": "2026-10-01T00:00:00Z"},
		{"id": "kdef456", "kind": "howto", "title": "do the thing", "fix": "like so", "url": "https://agents.example/kb/kdef456", "license": "CC0-1.0", "author": "a9", "created": "2026-10-02T00:00:00Z"},
		{"id": "../escape", "title": "bad id ignored"}, // path-traversal id is skipped
	})
}

func TestGitDataOrphanCommitFlow(t *testing.T) {
	f := newGHFake(t)
	f.shard = kbRowsShard()
	f.refs["heads/main"] = "oldmaincommit" // main already exists -> force update
	te := mirrorTestEnv(t, f)

	raw, err := runMirror(context.Background(), te.e, &Job{ID: 1, Kind: "mirror", Payload: json.RawMessage(`{}`)})
	if err != nil {
		t.Fatalf("runMirror: %v", err)
	}
	var res struct {
		Commit  string `json:"commit"`
		Tree    string `json:"tree"`
		Files   int    `json:"files"`
		Rows    int    `json:"rows"`
		Ref     string `json:"ref"`
		Forced  bool   `json:"forced"`
		Created bool   `json:"created"`
	}
	if err := json.Unmarshal(raw, &res); err != nil {
		t.Fatal(err)
	}
	if res.Rows != 2 || res.Files != 3 || !res.Forced || res.Created || res.Ref != "main" {
		t.Fatalf("result %+v", res)
	}

	var blobs, trees, commits, patchMainForce, createRef int
	var commitParents []any
	var treeHadBase bool
	for _, c := range f.callsCopy() {
		switch {
		case c.method == "POST" && strings.HasSuffix(c.path, "/git/blobs"):
			blobs++
		case c.method == "POST" && strings.HasSuffix(c.path, "/git/trees"):
			trees++
			if _, ok := c.body["base_tree"]; ok {
				treeHadBase = true
			}
		case c.method == "POST" && strings.HasSuffix(c.path, "/git/commits"):
			commits++
			commitParents, _ = c.body["parents"].([]any)
		case c.method == "PATCH" && strings.HasSuffix(c.path, "/git/refs/heads/main"):
			if force, _ := c.body["force"].(bool); force {
				patchMainForce++
			}
		case c.method == "POST" && strings.HasSuffix(c.path, "/git/refs"):
			createRef++
		}
	}
	if blobs != 3 {
		t.Fatalf("blobs = %d, want 3 (README + 2 entries)", blobs)
	}
	if trees != 1 || treeHadBase {
		t.Fatalf("trees=%d base_tree-present=%v (orphan tree must have no base)", trees, treeHadBase)
	}
	if commits != 1 || len(commitParents) != 0 {
		t.Fatalf("commits=%d parents=%v (orphan commit has no parents)", commits, commitParents)
	}
	if patchMainForce != 1 {
		t.Fatalf("force updates of main = %d, want exactly 1", patchMainForce)
	}
	if createRef != 0 {
		t.Fatalf("create-ref calls = %d, want 0 (main already existed)", createRef)
	}

	// First run against an empty repo creates main instead of force-updating it.
	f2 := newGHFake(t)
	f2.shard = kbRowsShard()
	te2 := mirrorTestEnv(t, f2)
	raw, err = runMirror(context.Background(), te2.e, &Job{ID: 2, Kind: "mirror"})
	if err != nil {
		t.Fatalf("first-run mirror: %v", err)
	}
	json.Unmarshal(raw, &res)
	if !res.Created || res.Forced {
		t.Fatalf("first run should create, not force: %+v", res)
	}
	var created2, patched2 int
	for _, c := range f2.callsCopy() {
		if c.method == "POST" && strings.HasSuffix(c.path, "/git/refs") {
			created2++
		}
		if c.method == "PATCH" && strings.Contains(c.path, "/git/refs/heads/") {
			patched2++
		}
	}
	if created2 != 1 || patched2 != 0 {
		t.Fatalf("first run refs: created=%d patched=%d", created2, patched2)
	}
}

func TestMirrorRewriteForcesMainOnly(t *testing.T) {
	f := newGHFake(t)
	f.shard = kbRowsShard()
	f.refs["heads/main"] = "oldmaincommit"
	f.refs["heads/anchors"] = "anchorhead" // anchors exists; mirror_rewrite must never touch it
	te := mirrorTestEnv(t, f)

	k, ok := Lookup("mirror_rewrite")
	if !ok || k.Run == nil {
		t.Fatal("mirror_rewrite not registered with Run")
	}
	if _, err := k.Run(context.Background(), te.e, &Job{ID: 7, Kind: "mirror_rewrite", Payload: json.RawMessage(`{}`)}); err != nil {
		t.Fatalf("mirror_rewrite: %v", err)
	}
	var forceMain, touchedAnchors, nonForce int
	for _, c := range f.callsCopy() {
		if strings.Contains(c.path, "anchors") {
			touchedAnchors++
		}
		if c.method == "PATCH" && strings.HasSuffix(c.path, "/git/refs/heads/main") {
			if force, _ := c.body["force"].(bool); force {
				forceMain++
			} else {
				nonForce++
			}
		}
	}
	if forceMain != 1 {
		t.Fatalf("force updates of main = %d, want 1", forceMain)
	}
	if touchedAnchors != 0 {
		t.Fatalf("mirror_rewrite touched anchors %d times", touchedAnchors)
	}
	if nonForce != 0 {
		t.Fatalf("mirror_rewrite did a non-force main update %d times", nonForce)
	}
}

func TestKindsRegisteredAndHostsAllowlisted(t *testing.T) {
	for _, name := range []string{"mirror", "mirror_rewrite", "anchor", "backup_ship"} {
		k, ok := Lookup(name)
		if !ok {
			t.Fatalf("kind %q not registered", name)
		}
		if k.Run == nil {
			t.Fatalf("kind %q has no Run", name)
		}
	}
	mirror, _ := Lookup("mirror")
	anchor, _ := Lookup("anchor")
	backup, _ := Lookup("backup_ship")
	if len(mirror.Hosts) != 1 || mirror.Hosts[0] != "api.github.com" {
		t.Fatalf("mirror hosts %v", mirror.Hosts)
	}
	if len(anchor.Hosts) != 1 || anchor.Hosts[0] != "api.github.com" {
		t.Fatalf("anchor hosts %v", anchor.Hosts)
	}
	if len(backup.Hosts) != 0 {
		t.Fatalf("backup_ship contributes hosts %v (S3 host comes from S3_ENDPOINT)", backup.Hosts)
	}
	// The allowlist built from the enabled kinds + S3_ENDPOINT must admit api.github.com and the S3 host.
	allow := buildAllowlist([]*Kind{mirror, anchor, backup}, s3Host("https://s3.example.net"))
	if !allow.Allow("api.github.com") {
		t.Fatal("api.github.com not allowlisted")
	}
	if !allow.Allow("s3.example.net") {
		t.Fatal("S3 endpoint host not allowlisted")
	}
	if allow.Allow("evil.example") {
		t.Fatal("evil host allowlisted")
	}
}
