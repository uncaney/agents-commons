package sync

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/sign"
)

// Client-side replication (agent side): verifies each signed row against the server key, then
// applies it to a destination mirror (md / pg / jsonl). Shared by cmd/cxsync and `cx sync`.

// Verifier checks a row signature against one or more published public keys (current + previous).
type Verifier struct{ keys []ed25519.PublicKey }

// NewVerifier builds a verifier from hex-encoded Ed25519 public keys.
func NewVerifier(hexKeys ...string) (*Verifier, error) {
	v := &Verifier{}
	for _, h := range hexKeys {
		h = strings.TrimSpace(h)
		if h == "" {
			continue
		}
		b, err := hex.DecodeString(h)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("sync: bad public key %q", h)
		}
		v.keys = append(v.keys, ed25519.PublicKey(b))
	}
	if len(v.keys) == 0 {
		return nil, errors.New("sync: no verification key")
	}
	return v, nil
}

// wellKnown is the subset of /.well-known/cx-key the verifier needs.
type wellKnown struct {
	Pub  string `json:"pub"`
	Prev []struct {
		Pub string `json:"pub"`
	} `json:"prev"`
}

// FetchVerifier downloads /.well-known/cx-key from base and builds a verifier over the current
// and previous keys.
func FetchVerifier(ctx context.Context, hc *http.Client, base string) (*Verifier, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(base, "/")+"/.well-known/cx-key", nil)
	if err != nil {
		return nil, err
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sync: cx-key status %d", resp.StatusCode)
	}
	var wk wellKnown
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&wk); err != nil {
		return nil, err
	}
	keys := []string{wk.Pub}
	for _, p := range wk.Prev {
		keys = append(keys, p.Pub)
	}
	return NewVerifier(keys...)
}

// Verify reports whether sig ("sig=<b64url>" or the bare token) covers the row bytes under the
// row1 statement domain for any known key.
func (v *Verifier) Verify(rowBytes []byte, sig string) bool {
	raw, err := sign.DecodeSig(sig)
	if err != nil {
		return false
	}
	msg := sign.Message(SigType, rowDigest(rowBytes))
	for _, k := range v.keys {
		if ed25519.Verify(k, msg, raw) {
			return true
		}
	}
	return false
}

// Sink applies replication lines to a destination.
type Sink interface {
	Upsert(l wireLine, row map[string]any) error
	Delete(l wireLine) error
	Close() error
}

// Mirror pulls pages from fetch, verifies every upsert, applies each line to sink and advances
// the cursor file. fetch returns the page's lines and the seq to continue from; it returns zero
// lines when the log is exhausted. Returns the number of lines applied.
func Mirror(ctx context.Context, fetch func(after int64, k int) ([]wireLine, int64, error), sink Sink, cursorPath string) (int, error) {
	after, err := readCursor(cursorPath)
	if err != nil {
		return 0, err
	}
	applied := 0
	for {
		lines, next, err := fetch(after, MaxK)
		if err != nil {
			return applied, err
		}
		if len(lines) == 0 {
			break
		}
		for _, l := range lines {
			if err := apply(sink, l); err != nil {
				return applied, err
			}
			applied++
			if l.Seq > after {
				after = l.Seq
			}
		}
		if err := writeCursor(cursorPath, after); err != nil {
			return applied, err
		}
		if next <= after && len(lines) < MaxK {
			break
		}
		if next <= after {
			// No progress though a full page returned: avoid an infinite loop.
			break
		}
	}
	return applied, nil
}

// apply dispatches one line to the sink (delete lines carry no row).
func apply(sink Sink, l wireLine) error {
	if l.Op == "delete" || len(l.Row) == 0 {
		return sink.Delete(l)
	}
	var row map[string]any
	if err := json.Unmarshal(l.Row, &row); err != nil {
		return fmt.Errorf("sync: bad row for %s/%s: %w", l.Kind, l.ID, err)
	}
	return sink.Upsert(l, row)
}

// --- HTTP fetcher -------------------------------------------------------------------------------

// HTTPFetcher pulls /v1/sync pages and (optionally) verifies each signed row.
type HTTPFetcher struct {
	Base   string
	Client *http.Client
	Token  string
	Kinds  string
	Verify *Verifier
}

// Page fetches one page past after; it parses the NDJSON body into wire lines and verifies every
// upsert signature. The continuation seq is the greatest seq on the page.
func (f *HTTPFetcher) Page(ctx context.Context, after int64, k int) ([]wireLine, int64, error) {
	q := url.Values{}
	q.Set("after", strconv.FormatInt(after, 10))
	if f.Kinds != "" {
		q.Set("kinds", f.Kinds)
	}
	if k > 0 {
		q.Set("k", strconv.Itoa(k))
	}
	u := strings.TrimRight(f.Base, "/") + "/v1/sync?" + q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, 0, err
	}
	if f.Token != "" {
		req.Header.Set("Authorization", "Bearer "+f.Token)
	}
	hc := f.Client
	if hc == nil {
		hc = http.DefaultClient
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<10))
		return nil, 0, fmt.Errorf("sync: /v1/sync status %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return parseNDJSON(resp.Body, after, f.Verify)
}

// parseNDJSON reads NDJSON wire lines, verifies every upsert, and returns the lines plus the
// greatest seq (the continuation cursor).
func parseNDJSON(r io.Reader, after int64, v *Verifier) ([]wireLine, int64, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64<<10), MaxBytes+1<<16)
	var out []wireLine
	next := after
	for sc.Scan() {
		b := bytes.TrimSpace(sc.Bytes())
		if len(b) == 0 {
			continue
		}
		var l wireLine
		if err := json.Unmarshal(b, &l); err != nil {
			return nil, 0, fmt.Errorf("sync: bad NDJSON line: %w", err)
		}
		if l.Op == "upsert" && len(l.Row) > 0 {
			if v == nil {
				return nil, 0, errors.New("sync: no verification key for a signed row")
			}
			if !v.Verify(l.Row, l.Sig) {
				return nil, 0, fmt.Errorf("sync: signature verification failed for %s/%s", l.Kind, l.ID)
			}
		}
		out = append(out, l)
		if l.Seq > next {
			next = l.Seq
		}
	}
	return out, next, sc.Err()
}

// --- cursor file --------------------------------------------------------------------------------

// CursorName is the per-destination cursor file name.
const CursorName = ".cx-cursor"

func readCursor(path string) (int64, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		return 0, nil
	}
	return n, nil
}

func writeCursor(path string, seq int64) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, []byte(strconv.FormatInt(seq, 10)+"\n"), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// --- md sink ------------------------------------------------------------------------------------

// mdNameRe guards the id used in a file path (defence in depth; ids are already server-built).
var pathSafe = func(s string) bool {
	if s == "" || strings.ContainsAny(s, "/\\.") {
		return false
	}
	return true
}

// MdSink writes <dir>/<kind>/<id>.md with YAML front matter; a delete removes the file.
type MdSink struct{ Dir string }

func (m *MdSink) path(kind, id string) (string, bool) {
	if !pathSafe(kind) || !pathSafe(id) {
		return "", false
	}
	return filepath.Join(m.Dir, kind, id+".md"), true
}

func (m *MdSink) Upsert(l wireLine, row map[string]any) error {
	p, ok := m.path(l.Kind, l.ID)
	if !ok {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, []byte(renderMd(l, row)), 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}

func (m *MdSink) Delete(l wireLine) error {
	p, ok := m.path(l.Kind, l.ID)
	if !ok {
		return nil
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func (m *MdSink) Close() error { return nil }

// bodyFields are the long text fields rendered as the markdown body (in this order), not the
// front matter.
var bodyFields = []string{"title", "symptom", "cause", "fix", "detail", "migrate", "body", "desc", "usage"}

// renderMd renders one row as a front-matter markdown file. User text never starts a line of its
// own in the front matter: scalar values are JSON-encoded, and body fields are fenced under a
// heading so untrusted content cannot forge YAML or a new document.
func renderMd(l wireLine, row map[string]any) string {
	var b strings.Builder
	b.WriteString("---\n")
	b.WriteString("seq: " + strconv.FormatInt(l.Seq, 10) + "\n")
	b.WriteString("kind: " + jsonString(l.Kind) + "\n")
	b.WriteString("id: " + jsonString(l.ID) + "\n")
	b.WriteString("synced_at: " + jsonString(l.At) + "\n")
	body := map[string]bool{}
	for _, f := range bodyFields {
		body[f] = true
	}
	keys := make([]string, 0, len(row))
	for k := range row {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if body[k] {
			continue
		}
		enc, err := json.Marshal(row[k])
		if err != nil {
			continue
		}
		b.WriteString(k + ": " + string(enc) + "\n")
	}
	b.WriteString("---\n")
	for _, f := range bodyFields {
		v, ok := row[f]
		if !ok {
			continue
		}
		s, ok := v.(string)
		if !ok || s == "" {
			continue
		}
		b.WriteString("\n## " + f + "\n\n")
		b.WriteString(s)
		if !strings.HasSuffix(s, "\n") {
			b.WriteByte('\n')
		}
	}
	return b.String()
}

// jsonString renders s as a JSON string (single safe line).
func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// --- jsonl sink ---------------------------------------------------------------------------------

// JsonlSink appends each wire line to <dir>/<kind>.jsonl (upserts and deletes both, as a log).
type JsonlSink struct {
	Dir   string
	files map[string]*os.File
}

func (j *JsonlSink) file(kind string) (*os.File, error) {
	if !pathSafe(kind) {
		return nil, fmt.Errorf("sync: bad kind %q", kind)
	}
	if j.files == nil {
		j.files = map[string]*os.File{}
	}
	if f, ok := j.files[kind]; ok {
		return f, nil
	}
	if err := os.MkdirAll(j.Dir, 0o755); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(j.Dir, kind+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, err
	}
	j.files[kind] = f
	return f, nil
}

func (j *JsonlSink) write(l wireLine) error {
	f, err := j.file(l.Kind)
	if err != nil {
		return err
	}
	b, err := encodeLine(l)
	if err != nil {
		return err
	}
	_, err = f.Write(b)
	return err
}

func (j *JsonlSink) Upsert(l wireLine, _ map[string]any) error { return j.write(l) }
func (j *JsonlSink) Delete(l wireLine) error                   { return j.write(l) }

func (j *JsonlSink) Close() error {
	var first error
	for _, f := range j.files {
		if err := f.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}
