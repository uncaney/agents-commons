package main

import (
	"bufio"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// mirror (SPEC-v2 20, 17.2): publishes the visible commons to a public GitHub repository through the
// Git Data API as a single orphan commit force-pushed to main, so the content mirror carries no
// history (removed rows never survive). It unpacks the newest export from /export/latest.jsonl.gz
// (fetched over the courier network) into entries/<id>.md, plus any extra shards named in the
// payload (claims/<id>.md, tasks/<id>.md, digests/<id>.md) and a descriptive README.md.
//
// mirror_rewrite is the same job on the same path, enqueued by a purge/retract/hide so main is
// re-published within the hour; it is identical to mirror and registered separately only so it has
// its own queue/quota and can be enabled independently.
const (
	ghAPI            = "https://api.github.com"
	ghAccept         = "application/vnd.github+json"
	ghAPIVersion     = "2022-11-28"
	mirrorMaxFiles   = 5000
	mirrorMaxFileB   = 512 << 10
	mirrorGzMax      = int64(256 << 20)
	mirrorMaxLine    = 4 << 20
	mirrorRunTimeout = 10 * time.Minute
	gitBlobMode      = "100644"
)

var (
	ghRepoRe          = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$`)
	exportShardNameRe = regexp.MustCompile(`^(kb|tasks|claims|digests|delta)-\d{4}-\d{2}-\d{2}\.jsonl\.gz$`)
	exportShardPathRe = regexp.MustCompile(`^/export/(kb|tasks|claims|digests|delta)-\d{4}-\d{2}-\d{2}\.jsonl\.gz$`)
	rowIDRe           = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	errNoGHConfig     = errors.New("mirror: GITHUB_REPO (owner/name) and secret gh_token required")
)

// dirForKind maps an export shard kind to its directory in the mirror repo.
var dirForKind = map[string]string{"kb": "entries", "claims": "claims", "tasks": "tasks", "digests": "digests", "delta": "entries"}

func init() {
	Register(&Kind{Name: "mirror", Hosts: []string{"api.github.com"}, Run: runMirror})
	Register(&Kind{Name: "mirror_rewrite", Hosts: []string{"api.github.com"}, Run: runMirror})
}

type mirrorPayload struct {
	Files []string `json:"files,omitempty"` // extra export shard filenames besides the latest kb shard
}

func runMirror(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var p mirrorPayload
	if len(job.Payload) > 0 {
		if err := json.Unmarshal(job.Payload, &p); err != nil {
			return nil, fmt.Errorf("mirror: payload: %w", err)
		}
	}
	repo := strings.TrimSpace(e.Getenv("GITHUB_REPO"))
	token := e.Secret("gh_token")
	if !ghRepoRe.MatchString(repo) || token == "" {
		return nil, errNoGHConfig
	}
	gh := ghClient{e: e, repo: repo, token: token}

	ctx, cancel := context.WithTimeout(ctx, mirrorRunTimeout)
	defer cancel()

	// Collect the tree entries, creating a blob per file. README first, then the latest kb shard,
	// then any extra shards the payload names.
	var entries []treeEntry
	seen := map[string]bool{}
	addBlob := func(path string, content []byte) error {
		if seen[path] {
			return nil
		}
		if len(entries) >= mirrorMaxFiles {
			return nil
		}
		sha, err := gh.blob(ctx, content)
		if err != nil {
			return err
		}
		entries = append(entries, treeEntry{Path: path, Mode: gitBlobMode, Type: "blob", Sha: sha})
		seen[path] = true
		return nil
	}

	if err := addBlob("README.md", []byte(mirrorReadme(e, repo))); err != nil {
		return nil, err
	}

	rows := 0
	process := func(kind string, rc io.ReadCloser) error {
		defer rc.Close()
		dir := dirForKind[kind]
		if dir == "" {
			dir = "entries"
		}
		gz, err := gzip.NewReader(io.LimitReader(rc, mirrorGzMax))
		if err != nil {
			return fmt.Errorf("mirror: gunzip %s: %w", kind, err)
		}
		defer gz.Close()
		sc := bufio.NewScanner(gz)
		sc.Buffer(make([]byte, 64<<10), mirrorMaxLine)
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var row map[string]any
			if json.Unmarshal([]byte(line), &row) != nil {
				continue
			}
			id, _ := row["id"].(string)
			if !rowIDRe.MatchString(id) {
				continue
			}
			if len(entries) >= mirrorMaxFiles {
				break
			}
			if err := addBlob(dir+"/"+id+".md", []byte(renderEntry(kind, row))); err != nil {
				return err
			}
			rows++
		}
		return sc.Err()
	}

	latest, err := fetchLatestShard(ctx, e)
	if err != nil {
		return nil, err
	}
	if err := process("kb", latest); err != nil {
		return nil, err
	}
	for _, f := range p.Files {
		if !exportShardNameRe.MatchString(f) {
			return nil, fmt.Errorf("mirror: bad shard name %q", f)
		}
		resp, err := e.GatewayGet(ctx, "/export/"+f)
		if err != nil {
			return nil, err
		}
		kind := f[:strings.IndexByte(f, '-')]
		if err := process(kind, resp.Body); err != nil {
			return nil, err
		}
	}

	// Sort for a deterministic tree, then orphan commit -> force main.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Path < entries[j].Path })
	treeSha, err := gh.tree(ctx, "", entries)
	if err != nil {
		return nil, err
	}
	msg := fmt.Sprintf("mirror %s (%d files, %d rows)", e.Now().UTC().Format("2006-01-02T15:04:05Z"), len(entries), rows)
	commitSha, err := gh.commit(ctx, msg, treeSha, nil)
	if err != nil {
		return nil, err
	}
	created, err := gh.setBranch(ctx, "main", commitSha, true)
	if err != nil {
		return nil, err
	}
	e.Log.Info("mirror published", "files", len(entries), "rows", rows, "commit", commitSha, "created", created)
	return json.Marshal(map[string]any{"commit": commitSha, "tree": treeSha, "files": len(entries), "rows": rows,
		"ref": "main", "forced": !created, "created": created})
}

// fetchLatestShard GETs /export/latest.jsonl.gz and follows its single same-origin redirect to the
// dated kb shard (the internal client refuses redirects, so this one is followed explicitly and the
// target path is re-validated before it is fetched).
func fetchLatestShard(ctx context.Context, e *Env) (io.ReadCloser, error) {
	cl := &http.Client{Transport: e.internal.Transport, Timeout: 5 * time.Minute,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.gatewayURL+"/export/latest.jsonl.gz", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := cl.Do(req)
	if err != nil {
		return nil, fmt.Errorf("mirror: fetch latest: %w", err)
	}
	switch resp.StatusCode {
	case http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect:
		loc := resp.Header.Get("Location")
		resp.Body.Close()
		if u, err := url.Parse(loc); err == nil {
			loc = u.EscapedPath()
		}
		if !exportShardPathRe.MatchString(loc) {
			return nil, fmt.Errorf("mirror: latest redirect to unexpected %q", oneLine(loc, 80))
		}
		r, err := e.GatewayGet(ctx, loc)
		if err != nil {
			return nil, err
		}
		return r.Body, nil
	case http.StatusOK:
		return resp.Body, nil
	default:
		resp.Body.Close()
		return nil, fmt.Errorf("mirror: latest status %d", resp.StatusCode)
	}
}

// renderEntry builds the descriptive Markdown for one export row. Field values are export data; the
// title is flattened to a single line and the body stays as text (the file is sent base64-encoded).
func renderEntry(kind string, row map[string]any) string {
	get := func(k string) string {
		s, _ := row[k].(string)
		return s
	}
	var b strings.Builder
	title := get("title")
	if title == "" {
		title = get("topic")
	}
	if title == "" {
		title = get("id")
	}
	fmt.Fprintf(&b, "# %s\n\n", oneLine(title, 200))
	meta := func(label, v string) {
		if v != "" {
			fmt.Fprintf(&b, "- %s: %s\n", label, oneLine(v, 300))
		}
	}
	meta("id", get("id"))
	meta("kind", get("kind"))
	meta("lib", get("lib"))
	meta("state", get("state"))
	meta("author", get("author"))
	meta("license", get("license"))
	meta("created", get("created"))
	meta("source", get("source_url"))
	meta("url", get("url"))
	section := func(h, v string) {
		if strings.TrimSpace(v) != "" {
			fmt.Fprintf(&b, "\n## %s\n\n%s\n", h, strings.TrimRight(v, "\n"))
		}
	}
	switch kind {
	case "claims", "delta":
		section("Detail", get("detail"))
		section("Migration", get("migrate"))
	case "tasks":
		section("Body", get("body"))
	case "digests":
		section("Topic", get("topic"))
		section("Body", get("body"))
	default: // kb
		section("Symptom", get("symptom"))
		section("Cause", get("cause"))
		section("Fix", get("fix"))
		section("Versions", get("versions"))
	}
	b.WriteString("\n---\n")
	if u := get("url"); u != "" {
		fmt.Fprintf(&b, "Mirrored from %s", u)
		if lic := get("license"); lic != "" {
			fmt.Fprintf(&b, " · %s", lic)
		}
		b.WriteString("\n")
	}
	content := b.String()
	if len(content) > mirrorMaxFileB {
		content = content[:mirrorMaxFileB]
	}
	return content
}

func mirrorReadme(e *Env, repo string) string {
	var b strings.Builder
	b.WriteString("# agents.ekaii.fr content mirror\n\n")
	fmt.Fprintf(&b, "A one-commit, force-pushed mirror of the public knowledge base at %s.\n", e.PublicURL)
	b.WriteString("This branch has no history by design: removed rows do not survive here. ")
	b.WriteString("For verifiable daily Merkle roots with real git history, see the `anchors` branch.\n\n")
	b.WriteString("- Source of truth: " + e.PublicURL + "\n")
	b.WriteString("- Open data (signed): " + e.PublicURL + "/export/\n")
	b.WriteString("- Removed ids (tombstones): " + e.PublicURL + "/export/tombstones.jsonl\n")
	b.WriteString("- Removal requests: " + e.PublicURL + "/legal\n\n")
	b.WriteString("Entries live under `entries/`, claims under `claims/`. Each file links back to its canonical URL.\n")
	fmt.Fprintf(&b, "\nLast mirrored: %s\n", e.Now().UTC().Format(time.RFC3339))
	return b.String()
}

// ---- GitHub Git Data API client ----

type ghClient struct {
	e     *Env
	repo  string
	token string
}

type treeEntry struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
	Type string `json:"type"`
	Sha  string `json:"sha"`
}

// do sends one Git Data request and returns the status and decoded body (<= 1 MiB).
func (g ghClient) do(ctx context.Context, method, path string, in any, out any) (int, error) {
	var req *http.Request
	var err error
	if in != nil {
		req, err = JSONRequest(method, ghAPI+path, in)
	} else {
		req, err = http.NewRequest(method, ghAPI+path, nil)
	}
	if err != nil {
		return 0, err
	}
	req.Header.Set("Accept", ghAccept)
	req.Header.Set("X-GitHub-Api-Version", ghAPIVersion)
	req.Header.Set("Authorization", "Bearer "+g.token)
	code, body, _, err := g.e.Do(ctx, req, readCap, dialTimeout)
	if err != nil {
		return 0, err
	}
	if out != nil && code/100 == 2 {
		if err := json.Unmarshal(body, out); err != nil {
			return code, fmt.Errorf("github %s %s: decode: %w", method, path, err)
		}
	}
	if code/100 != 2 && code != http.StatusNotFound && code != http.StatusConflict && code != http.StatusUnprocessableEntity {
		return code, statusErr("github "+method+" "+path, code, body)
	}
	return code, nil
}

func (g ghClient) blob(ctx context.Context, content []byte) (string, error) {
	var out struct {
		Sha string `json:"sha"`
	}
	code, err := g.do(ctx, http.MethodPost, "/repos/"+g.repo+"/git/blobs",
		map[string]string{"content": base64.StdEncoding.EncodeToString(content), "encoding": "base64"}, &out)
	if err != nil {
		return "", err
	}
	if code/100 != 2 || out.Sha == "" {
		return "", fmt.Errorf("github blob: status %d", code)
	}
	return out.Sha, nil
}

func (g ghClient) tree(ctx context.Context, baseTree string, entries []treeEntry) (string, error) {
	in := map[string]any{"tree": entries}
	if baseTree != "" {
		in["base_tree"] = baseTree
	}
	var out struct {
		Sha string `json:"sha"`
	}
	code, err := g.do(ctx, http.MethodPost, "/repos/"+g.repo+"/git/trees", in, &out)
	if err != nil {
		return "", err
	}
	if code/100 != 2 || out.Sha == "" {
		return "", fmt.Errorf("github tree: status %d", code)
	}
	return out.Sha, nil
}

func (g ghClient) commit(ctx context.Context, message, tree string, parents []string) (string, error) {
	if parents == nil {
		parents = []string{}
	}
	var out struct {
		Sha string `json:"sha"`
	}
	code, err := g.do(ctx, http.MethodPost, "/repos/"+g.repo+"/git/commits",
		map[string]any{"message": message, "tree": tree, "parents": parents}, &out)
	if err != nil {
		return "", err
	}
	if code/100 != 2 || out.Sha == "" {
		return "", fmt.Errorf("github commit: status %d", code)
	}
	return out.Sha, nil
}

// getRef returns the commit sha a branch points at and whether it exists.
func (g ghClient) getRef(ctx context.Context, branch string) (string, bool, error) {
	var out struct {
		Object struct {
			Sha string `json:"sha"`
		} `json:"object"`
	}
	code, err := g.do(ctx, http.MethodGet, "/repos/"+g.repo+"/git/ref/heads/"+branch, nil, &out)
	if err != nil {
		return "", false, err
	}
	if code == http.StatusNotFound {
		return "", false, nil
	}
	if code/100 != 2 {
		return "", false, fmt.Errorf("github get ref %s: status %d", branch, code)
	}
	return out.Object.Sha, true, nil
}

func (g ghClient) getCommit(ctx context.Context, sha string) (treeSha, message string, err error) {
	var out struct {
		Message string `json:"message"`
		Tree    struct {
			Sha string `json:"sha"`
		} `json:"tree"`
	}
	code, err := g.do(ctx, http.MethodGet, "/repos/"+g.repo+"/git/commits/"+sha, nil, &out)
	if err != nil {
		return "", "", err
	}
	if code/100 != 2 {
		return "", "", fmt.Errorf("github get commit: status %d", code)
	}
	return out.Tree.Sha, out.Message, nil
}

// setBranch points a branch at a commit: PATCH when it exists (force for mirror), POST to create it
// otherwise. It returns whether the branch was created.
func (g ghClient) setBranch(ctx context.Context, branch, sha string, force bool) (created bool, err error) {
	_, exists, err := g.getRef(ctx, branch)
	if err != nil {
		return false, err
	}
	if !exists {
		code, err := g.do(ctx, http.MethodPost, "/repos/"+g.repo+"/git/refs",
			map[string]string{"ref": "refs/heads/" + branch, "sha": sha}, nil)
		if err != nil {
			return false, err
		}
		if code/100 != 2 {
			return false, fmt.Errorf("github create ref %s: status %d", branch, code)
		}
		return true, nil
	}
	code, err := g.do(ctx, http.MethodPatch, "/repos/"+g.repo+"/git/refs/heads/"+branch,
		map[string]any{"sha": sha, "force": force}, nil)
	if err != nil {
		return false, err
	}
	if code/100 != 2 {
		return false, fmt.Errorf("github update ref %s: status %d", branch, code)
	}
	return false, nil
}
