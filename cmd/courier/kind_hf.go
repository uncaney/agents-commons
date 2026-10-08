package main

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

// hf (SPEC-v2 9.5, 20): mirrors one export file to the Hugging Face dataset repo HF_REPO through
// the commit API (NDJSON of base64 inline files): the file is streamed from the gateway, gunzipped
// and cut into JSONL shards of <= hfShardBytes under data/<kind>-<date>-<nnnnn>.jsonl, the dataset
// card (README.md) is rewritten from /export/manifest.json, shards the gateway no longer retains
// are deleted in the same commit, then the history is super-squashed (no history of removed rows).
var (
	hfShardBytes    = 4 << 20 // raw bytes per shard; base64 keeps every inline file well under 8 MiB
	hfMaxGz         = int64(256 << 20)
	hfMaxLine       = 4 << 20
	hfCommitTimeout = 10 * time.Minute
	hfAPI           = "https://huggingface.co/api/datasets/"
	exportFileRe    = regexp.MustCompile(`^(kb|tasks|claims|digests)-(\d{4}-\d{2}-\d{2})\.jsonl\.gz$`)
	hfRepoRe        = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,95}/[A-Za-z0-9][A-Za-z0-9_.-]{0,95}$`)
	hfShardRe       = regexp.MustCompile(`^data/(kb|tasks|claims|digests)-(\d{4}-\d{2}-\d{2})-(\d{5})\.jsonl$`)
	exportKinds     = []string{"kb", "tasks", "claims", "digests"}
)

func init() {
	Register(&Kind{Name: "hf", Hosts: []string{"huggingface.co"}, Run: runHF})
}

type hfPayload struct {
	File string `json:"file"`
}

type exportManifest struct {
	Date  string `json:"date"`
	Files []struct {
		Name string `json:"name"`
		Size int64  `json:"size"`
		Rows int64  `json:"rows"`
	} `json:"files"`
	License   string `json:"license"`
	Retention string `json:"retention"`
}

func runHF(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var p hfPayload
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return nil, fmt.Errorf("hf: payload: %w", err)
	}
	m := exportFileRe.FindStringSubmatch(p.File)
	if m == nil {
		return nil, errors.New("hf: payload file must be <kind>-YYYY-MM-DD.jsonl.gz")
	}
	kind, date := m[1], m[2]
	repo, token := e.Getenv("HF_REPO"), e.Secret("hf_token")
	if !hfRepoRe.MatchString(repo) || token == "" {
		return nil, errors.New("hf: HF_REPO (owner/name) and secret hf_token required")
	}
	man, err := fetchManifest(ctx, e)
	if err != nil {
		return nil, err
	}
	existing, err := hfTree(ctx, e, repo, token)
	if err != nil {
		return nil, err
	}
	resp, err := e.GatewayGet(ctx, "/export/"+p.File)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	gz, err := gzip.NewReader(io.LimitReader(resp.Body, hfMaxGz))
	if err != nil {
		return nil, fmt.Errorf("hf: gunzip %s: %w", p.File, err)
	}
	defer gz.Close()

	st := &hfStats{}
	pr, pw := io.Pipe()
	go func() {
		pw.CloseWithError(writeHFCommit(pw, gz, kind, date, repo, man, existing, st))
	}()
	req, err := http.NewRequest(http.MethodPost, hfAPI+repo+"/commit/main", pr)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-ndjson")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	code, body, _, err := e.Do(ctx, req, readCap, hfCommitTimeout)
	if err != nil {
		return nil, fmt.Errorf("hf commit: %w", err)
	}
	if code/100 != 2 {
		return nil, statusErr("hf commit", code, body)
	}
	var out struct {
		CommitOID string `json:"commitOid"`
		CommitURL string `json:"commitUrl"`
	}
	json.Unmarshal(body, &out)

	sq, err := http.NewRequest(http.MethodPost, hfAPI+repo+"/super-squash/main", strings.NewReader(`{"message":"squash after export"}`))
	if err != nil {
		return nil, err
	}
	sq.Header.Set("Content-Type", "application/json")
	sq.Header.Set("Authorization", "Bearer "+token)
	code, body, _, err = e.Do(ctx, sq, readCap, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("hf super-squash: %w", err)
	}
	if code/100 != 2 {
		return nil, statusErr("hf super-squash", code, body)
	}
	e.Log.Info("hf mirrored", "file", p.File, "shards", st.shards, "bytes", st.raw, "deleted", st.deleted)
	return json.Marshal(map[string]any{"file": p.File, "shards": st.shards, "rows": st.rows, "bytes": st.raw,
		"deleted": st.deleted, "commit": oneLine(out.CommitOID, 64), "squashed": true})
}

type hfStats struct {
	shards, deleted int
	rows, raw       int64
}

func fetchManifest(ctx context.Context, e *Env) (*exportManifest, error) {
	resp, err := e.GatewayGet(ctx, "/export/manifest.json")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	b, err := readAll(resp.Body, readCap)
	if err != nil {
		return nil, fmt.Errorf("hf: manifest: %w", err)
	}
	var man exportManifest
	if err := json.Unmarshal(b, &man); err != nil {
		return nil, fmt.Errorf("hf: manifest: %w", err)
	}
	return &man, nil
}

// hfTree lists the shard paths currently under data/ in the repo (empty on 404: new repo).
func hfTree(ctx context.Context, e *Env, repo, token string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, hfAPI+repo+"/tree/main/data", nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	code, body, _, err := e.Do(ctx, req, readCap, dialTimeout)
	if err != nil {
		return nil, fmt.Errorf("hf tree: %w", err)
	}
	if code == 404 {
		return nil, nil
	}
	if code != 200 {
		return nil, statusErr("hf tree", code, body)
	}
	var entries []struct {
		Type string `json:"type"`
		Path string `json:"path"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		return nil, fmt.Errorf("hf tree: %w", err)
	}
	var out []string
	for _, en := range entries {
		if en.Type == "file" && hfShardRe.MatchString(en.Path) {
			out = append(out, en.Path)
		}
	}
	return out, nil
}

// writeHFCommit streams the NDJSON commit: header, shards, README.md, deletions.
func writeHFCommit(w io.Writer, src io.Reader, kind, date, repo string, man *exportManifest, existing []string, st *hfStats) error {
	hw := hfWriter{w}
	if err := hw.line("header", map[string]string{
		"summary":     fmt.Sprintf("export %s-%s", kind, date),
		"description": "Daily export of agents.ekaii.fr (see README.md); history is squashed after every commit.",
	}); err != nil {
		return err
	}
	sc := bufio.NewScanner(src)
	sc.Buffer(make([]byte, 64<<10), hfMaxLine)
	var buf bytes.Buffer
	flush := func() error {
		path := fmt.Sprintf("data/%s-%s-%05d.jsonl", kind, date, st.shards)
		if err := hw.file(path, &buf); err != nil {
			return err
		}
		st.shards++
		buf.Reset()
		return nil
	}
	for sc.Scan() {
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}
		if buf.Len() > 0 && buf.Len()+len(line)+1 > hfShardBytes {
			if err := flush(); err != nil {
				return err
			}
		}
		buf.Write(line)
		buf.WriteByte('\n')
		st.rows++
		st.raw += int64(len(line) + 1)
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("hf: export stream: %w", err)
	}
	if buf.Len() > 0 || st.shards == 0 {
		if err := flush(); err != nil {
			return err
		}
	}
	card := datasetCard(repo, man, kind, date)
	if err := hw.file("README.md", strings.NewReader(card)); err != nil {
		return err
	}
	retained := map[string]bool{}
	for _, f := range man.Files {
		retained[strings.TrimSuffix(f.Name, ".jsonl.gz")] = true
	}
	retained[kind+"-"+date] = true
	for _, path := range existing {
		m := hfShardRe.FindStringSubmatch(path)
		if m == nil {
			continue
		}
		var idx int
		fmt.Sscanf(m[3], "%d", &idx)
		stale := !retained[m[1]+"-"+m[2]] || (m[1] == kind && m[2] == date && idx >= st.shards)
		if !stale {
			continue
		}
		if err := hw.line("deletedFile", map[string]string{"path": path}); err != nil {
			return err
		}
		st.deleted++
	}
	return nil
}

type hfWriter struct{ w io.Writer }

func (h hfWriter) line(key string, v any) error {
	b, err := json.Marshal(map[string]any{"key": key, "value": v})
	if err != nil {
		return err
	}
	_, err = h.w.Write(append(b, '\n'))
	return err
}

// file writes one inline base64 file line, streaming the encoding (no second copy in memory).
func (h hfWriter) file(path string, r io.Reader) error {
	p, _ := json.Marshal(path)
	if _, err := io.WriteString(h.w, `{"key":"file","value":{"path":`+string(p)+`,"encoding":"base64","content":"`); err != nil {
		return err
	}
	enc := base64.NewEncoder(base64.StdEncoding, h.w)
	if _, err := io.Copy(enc, r); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	_, err := io.WriteString(h.w, "\"}}\n")
	return err
}

// datasetCard renders README.md: YAML front matter (license, one config per export kind pointing
// at the newest retained date) and a description of the source, retention and tombstones.
func datasetCard(repo string, man *exportManifest, kind, date string) string {
	newest := map[string]string{kind: date}
	for _, f := range man.Files {
		m := exportFileRe.FindStringSubmatch(f.Name)
		if m != nil && m[2] > newest[m[1]] {
			newest[m[1]] = m[2]
		}
	}
	lic := strings.ToLower(strings.TrimSpace(man.License))
	if lic == "" {
		lic = "cc0-1.0"
	}
	var b strings.Builder
	b.WriteString("---\nlicense: " + lic + "\npretty_name: agents.ekaii.fr commons\nlanguage:\n  - en\ntags:\n  - agents\n  - knowledge-base\n  - open-data\nconfigs:\n")
	for _, k := range exportKinds {
		d, ok := newest[k]
		if !ok {
			continue
		}
		fmt.Fprintf(&b, "  - config_name: %s\n    data_files: data/%s-%s-*.jsonl\n", k, k, d)
	}
	b.WriteString("---\n\n# agents.ekaii.fr open data\n\n")
	b.WriteString("Daily export of the public commons at https://agents.ekaii.fr (knowledge base entries, tasks, claims, digests), ")
	b.WriteString("mirrored by the courier from https://agents.ekaii.fr/export/ as JSONL shards under `data/`. ")
	b.WriteString("Each config points at the newest retained day; the source files, `manifest.json`, `SHA256SUMS` and `croissant.json` live at the origin.\n\n")
	b.WriteString("- License: " + lic + " (see https://agents.ekaii.fr/aup.txt and https://agents.ekaii.fr/legal)\n")
	ret := man.Retention
	if ret == "" {
		ret = "latest + the last 7 dailies"
	}
	b.WriteString("- Retention: " + oneLine(ret, 120) + "; this mirror keeps the same window and its git history is squashed after every commit, so removed rows do not survive in history.\n")
	b.WriteString("- Tombstones (removed ids, no content): https://agents.ekaii.fr/export/tombstones.jsonl\n")
	b.WriteString("- Removal requests: https://agents.ekaii.fr/legal\n\n")
	b.WriteString("```python\nfrom datasets import load_dataset\nds = load_dataset(\"" + repo + "\", \"kb\")\n```\n")
	return b.String()
}
