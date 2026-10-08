package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	defaultURL   = "https://agents.ekaii.fr"
	maxStateFile = 16 << 20
	maxTokens    = 64
)

var (
	tokenRe  = regexp.MustCompile(`^cx_[A-Za-z0-9_-]{43}$`)
	errQuota = errors.New("quota")
)

// postState is the resumable state: UTC day, per-token-fingerprint counts, the round-robin
// cursor and one record per posted entry file. Tokens themselves are never written.
type postState struct {
	Day    string            `json:"day"`
	Next   int               `json:"next"`
	Counts map[string]int    `json:"counts"`
	Posted map[string]posted `json:"posted"`
}

type posted struct {
	ID  string `json:"id"`
	At  string `json:"at"`
	By  string `json:"by"`
	Dup bool   `json:"dup,omitempty"`
}

// postBody is exactly kb.Input plus the v2 license field; the seed flag is a property of the
// seed roots (POST /admin/seed-root), never of the body.
type postBody struct {
	Kind     string   `json:"kind"`
	Title    string   `json:"title"`
	Symptom  string   `json:"symptom"`
	Cause    string   `json:"cause"`
	Fix      string   `json:"fix"`
	Versions string   `json:"versions"`
	Tags     []string `json:"tags"`
	Force    bool     `json:"force,omitempty"`
	License  string   `json:"license,omitempty"`
}

// entryError is a per-entry server refusal (4xx other than auth/quota): reported, then the run
// continues with the next entry.
type entryError struct{ msg string }

func (e *entryError) Error() string { return e.msg }

func fingerprint(tok string) string {
	sum := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(sum[:6])
}

func loadState(path, day string) (*postState, error) {
	st := &postState{Day: day, Counts: map[string]int{}, Posted: map[string]posted{}}
	b, err := readCapped(path, maxStateFile)
	if errors.Is(err, os.ErrNotExist) {
		return st, nil
	}
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(b, st); err != nil {
		return nil, fmt.Errorf("%s: %v", path, err)
	}
	if st.Counts == nil {
		st.Counts = map[string]int{}
	}
	if st.Posted == nil {
		st.Posted = map[string]posted{}
	}
	if st.Day != day {
		st.Day, st.Counts = day, map[string]int{}
	}
	return st, nil
}

func (st *postState) save(path string) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	return writeFile(path, append(b, '\n'))
}

// pick returns the next token with budget left today, round-robin from the cursor.
func (st *postState) pick(tokens []string, rate int) (int, bool) {
	n := len(tokens)
	for k := 0; k < n; k++ {
		i := (st.Next + k) % n
		if st.Counts[fingerprint(tokens[i])] < rate {
			st.Next = (i + 1) % n
			return i, true
		}
	}
	return 0, false
}

func loadTokens(path string) ([]string, error) {
	b, err := readCapped(path, 64<<10)
	if err != nil {
		return nil, err
	}
	var toks []string
	for i, l := range lines(b, maxTokens+1) {
		if !tokenRe.MatchString(l) {
			return nil, fmt.Errorf("%s line %d: not a cx_ token", filepath.Base(path), i+1)
		}
		toks = append(toks, l)
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("%s: no tokens", filepath.Base(path))
	}
	if len(toks) > maxTokens {
		return nil, fmt.Errorf("%s: more than %d tokens", filepath.Base(path), maxTokens)
	}
	return toks, nil
}

// post sends every approved entry through POST /v1/kb, rotating over the seed root tokens with a
// per-token daily budget, and records progress after each call so a rerun resumes (SPEC-v2 22.5).
func (a *app) post(args []string) error {
	fl := a.flags("post")
	var tokensF, url, stateF string
	var rate int
	var pace time.Duration
	fl.StringVar(&tokensF, "tokens", "", "seed root tokens, one per line (default $CX_SEED_DIR/tokens.txt)")
	fl.IntVar(&rate, "rate", 30, "posts per token per UTC day (the KB quota of a new root)")
	fl.StringVar(&url, "url", defaultURL, "server base URL")
	fl.StringVar(&stateF, "state", "", "resumable state file (default $CX_SEED_DIR/post-state.json)")
	fl.DurationVar(&pace, "pace", time.Second, "pause between posts")
	pos, err := parse(fl, args)
	if err != nil {
		return err
	}
	if len(pos) > 1 {
		return errors.New("usage: seed post [ENTRIES] [flags]")
	}
	if rate < 1 || rate > 1000 {
		return errors.New("-rate must be 1..1000")
	}
	dir := a.path(first(pos), "entries")
	tokensF, stateF = a.path(tokensF, "tokens.txt"), a.path(stateF, "post-state.json")
	url = strings.TrimRight(url, "/")
	tokens, err := loadTokens(tokensF)
	if err != nil {
		return err
	}
	st, err := loadState(stateF, a.now().UTC().Format("2006-01-02"))
	if err != nil {
		return err
	}
	files, err := listEntries(dir)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("%s: no entries", dir)
	}
	nposted, ndup, refused, failed, remaining := 0, 0, 0, 0, 0
	quota := false
	for _, f := range files {
		base := filepath.Base(f)
		if _, done := st.Posted[base]; done {
			continue
		}
		e, err := loadEntry(f)
		if err != nil {
			failed++
			fmt.Fprintf(a.stdout, "fail %s: unreadable\n", base)
			continue
		}
		if !e.approved() {
			refused++
			reason := "not reviewed"
			if e.Reviewed {
				reason = "edited after review"
			}
			fmt.Fprintf(a.stdout, "refused %s: %s\n", base, reason)
			continue
		}
		if quota {
			remaining++
			continue
		}
		p, err := a.postOne(st, stateF, tokens, rate, url, base, e)
		var ee *entryError
		switch {
		case errors.Is(err, errQuota):
			quota = true
			remaining++
			fmt.Fprintf(a.stdout, "quota: all %d tokens reached %d posts today; rerun later, the state file resumes\n", len(tokens), rate)
			continue
		case errors.As(err, &ee):
			failed++
			fmt.Fprintf(a.stdout, "fail %s: %s\n", base, ee.msg)
			continue
		case err != nil:
			return err
		case p.Dup:
			ndup++
			fmt.Fprintf(a.stdout, "dup %s %s\n", base, p.ID)
		default:
			nposted++
			fmt.Fprintf(a.stdout, "ok %s %s\n", base, p.ID)
		}
		if pace > 0 {
			a.sleep(pace)
		}
	}
	fmt.Fprintf(a.stdout, "posted=%d dup=%d refused=%d failed=%d remaining=%d\n", nposted, ndup, refused, failed, remaining)
	if failed > 0 {
		return fmt.Errorf("%d entries failed", failed)
	}
	return nil
}

func (a *app) postOne(st *postState, stateF string, tokens []string, rate int, url, base string, e *Entry) (posted, error) {
	body, err := json.Marshal(postBody{Kind: e.Kind, Title: e.Title, Symptom: e.Symptom, Cause: e.Cause, Fix: e.Fix,
		Versions: e.Versions, Tags: e.Tags, Force: e.DupOK, License: e.License})
	if err != nil {
		return posted{}, err
	}
	for range tokens {
		i, ok := st.pick(tokens, rate)
		if !ok {
			return posted{}, errQuota
		}
		fp := fingerprint(tokens[i])
		status, text, err := a.send(url+"/v1/kb", tokens[i], body)
		if err != nil {
			return posted{}, err
		}
		code, msg := parseErr(text)
		now := a.now().UTC().Format(time.RFC3339)
		switch {
		case status == 200 || status == 201:
			f := strings.Fields(text)
			if len(f) < 2 || f[0] != "ok" {
				return posted{}, fmt.Errorf("%s: unexpected reply (http %d)", base, status)
			}
			st.Counts[fp]++
			p := posted{ID: f[1], At: now, By: fp}
			st.Posted[base] = p
			return p, st.save(stateF)
		case status == 409:
			p := posted{ID: firstField(msg), At: now, By: fp, Dup: true}
			st.Posted[base] = p
			return p, st.save(stateF)
		case status == 429 && code == "quota":
			st.Counts[fp] = rate
			if err := st.save(stateF); err != nil {
				return posted{}, err
			}
		case status == 401 || status == 403:
			return posted{}, fmt.Errorf("token #%d refused by the server: %s", i+1, firstLine(text))
		default:
			return posted{}, &entryError{fmt.Sprintf("http %d %s", status, firstLine(text))}
		}
	}
	return posted{}, errQuota
}

// send performs one POST with bounded retries on network errors, 5xx and 429 rate (not quota).
func (a *app) send(url, token string, body []byte) (int, string, error) {
	var lastErr error
	for attempt := 0; attempt < 4; attempt++ {
		if attempt > 0 {
			a.sleep(time.Duration(1<<(attempt-1)) * time.Second)
		}
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
		if err != nil {
			return 0, "", err
		}
		req.Header.Set("Authorization", "Bearer "+token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "text/plain")
		req.Header.Set("User-Agent", "cx-seed/1")
		resp, err := a.http.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		text := string(b)
		code, _ := parseErr(text)
		if resp.StatusCode >= 500 || resp.StatusCode == 429 && code == "rate" {
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
			continue
		}
		return resp.StatusCode, text, nil
	}
	return 0, "", fmt.Errorf("net: giving up after retries: %v", lastErr)
}

// parseErr splits a server "err <code> <msg>" line (text or JSON reply).
func parseErr(text string) (code, msg string) {
	line := firstLine(text)
	if strings.HasPrefix(line, "{") {
		var j struct{ Err, Msg string }
		if json.Unmarshal([]byte(text), &j) == nil && j.Err != "" {
			return j.Err, j.Msg
		}
	}
	f := strings.SplitN(line, " ", 3)
	if len(f) >= 2 && f[0] == "err" {
		if len(f) == 3 {
			return f[1], f[2]
		}
		return f[1], ""
	}
	return "", line
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func firstField(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}
