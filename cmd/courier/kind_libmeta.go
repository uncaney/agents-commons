package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// libmeta (SPEC-v2 13.4, 20): registry fetchers for `eco:name` keys (pypi, npm, go, crates, gem),
// 1 MiB response cap, result posted back through the ack for know.ApplyLibMeta. Registry text is
// untrusted: strings are one-lined and capped, URLs must parse as http(s).
const (
	libMaxVersions = 500
	libMaxText     = 200
	libMaxURL      = 500
)

var (
	libKeyRe   = regexp.MustCompile(`^(pypi|npm|go|crates|gem|maven|nuget|apt|docker|api):([^\s]{1,200})$`)
	pypiNameRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9._-]*[A-Za-z0-9])?$`)
	npmNameRe  = regexp.MustCompile(`^(@[a-z0-9][a-z0-9._~-]*/)?[a-z0-9][a-z0-9._~-]*$`)
	goModRe    = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*\.[a-z]{2,}(/[A-Za-z0-9._~-]+)*$`)
	crateRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]*$`)
	gemNameRe  = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)
	libRegURLs = map[string]string{"pypi": "https://pypi.org", "npm": "https://registry.npmjs.org",
		"go": "https://proxy.golang.org", "crates": "https://crates.io", "gem": "https://rubygems.org"}
)

func init() {
	Register(&Kind{Name: "libmeta", Hosts: []string{"pypi.org", "registry.npmjs.org", "proxy.golang.org", "crates.io", "rubygems.org"}, Run: runLibmeta})
}

type libVersion struct {
	V          string `json:"v"`
	At         string `json:"at,omitempty"`
	Yanked     bool   `json:"yanked,omitempty"`
	Deprecated bool   `json:"deprecated,omitempty"`
	Pre        bool   `json:"pre,omitempty"`
}

type libResult struct {
	Key       string       `json:"key"`
	Eco       string       `json:"eco"`
	Name      string       `json:"name"`
	Display   string       `json:"display,omitempty"`
	Homepage  string       `json:"homepage,omitempty"`
	Repo      string       `json:"repo,omitempty"`
	Docs      string       `json:"docs,omitempty"`
	Registry  string       `json:"registry,omitempty"`
	Latest    string       `json:"latest,omitempty"`
	LatestAt  string       `json:"latest_at,omitempty"`
	Versions  []libVersion `json:"versions,omitempty"`
	Truncated bool         `json:"truncated,omitempty"`
	Partial   bool         `json:"partial,omitempty"`
	Err       string       `json:"err,omitempty"`
	Fetched   string       `json:"fetched"`
}

// softErr is a definitive registry answer (unknown package, response too large, unsupported
// ecosystem): acked with err set so the gateway stops asking; other errors fail the row (retry).
type softErr struct{ msg string }

func (s *softErr) Error() string { return s.msg }

func soft(msg string) error { return &softErr{msg} }

// parseLibKey validates an `eco:name` key per ecosystem.
func parseLibKey(key string) (eco, name string, err error) {
	m := libKeyRe.FindStringSubmatch(key)
	if m == nil {
		return "", "", errors.New("libmeta: key must be eco:name")
	}
	eco, name = m[1], m[2]
	var re *regexp.Regexp
	switch eco {
	case "pypi":
		re = pypiNameRe
	case "npm":
		re = npmNameRe
	case "go":
		re = goModRe
	case "crates":
		re = crateRe
	case "gem":
		re = gemNameRe
	default:
		return eco, name, nil // unsupported here: acked with err
	}
	if !re.MatchString(name) || strings.Contains(name, "..") {
		return "", "", fmt.Errorf("libmeta: invalid %s name", eco)
	}
	return eco, name, nil
}

func runLibmeta(ctx context.Context, e *Env, job *Job) (json.RawMessage, error) {
	var p struct {
		Key string `json:"key"`
	}
	if err := json.Unmarshal(job.Payload, &p); err != nil {
		return nil, fmt.Errorf("libmeta: payload: %w", err)
	}
	eco, name, err := parseLibKey(p.Key)
	if err != nil {
		return nil, err
	}
	res := libResult{Key: eco + ":" + name, Eco: eco, Name: name, Registry: libRegURLs[eco], Fetched: e.Now().UTC().Format(time.RFC3339)}
	switch eco {
	case "pypi":
		err = fetchPyPI(ctx, e, name, &res)
	case "npm":
		err = fetchNPM(ctx, e, name, &res)
	case "go":
		err = fetchGo(ctx, e, name, &res)
	case "crates":
		err = fetchCrates(ctx, e, name, &res)
	case "gem":
		err = fetchGem(ctx, e, name, &res)
	default:
		err = soft("unsupported ecosystem")
	}
	if err != nil {
		var s *softErr
		if !errors.As(err, &s) {
			return nil, err
		}
		res.Err = s.msg
	}
	res.finish()
	return json.Marshal(res)
}

// finish one-lines text, validates URLs and keeps the newest libMaxVersions versions.
func (r *libResult) finish() {
	r.Display = oneLine(r.Display, libMaxText)
	for _, p := range []*string{&r.Homepage, &r.Repo, &r.Docs} {
		*p = cleanURL(*p)
	}
	r.Latest = oneLine(r.Latest, 100)
	sort.SliceStable(r.Versions, func(i, j int) bool { return r.Versions[i].At < r.Versions[j].At })
	for i := range r.Versions {
		r.Versions[i].V = oneLine(r.Versions[i].V, 100)
	}
	if len(r.Versions) > libMaxVersions {
		r.Versions = r.Versions[len(r.Versions)-libMaxVersions:]
		r.Truncated = true
	}
}

// cleanURL keeps absolute http(s) URLs (<= 500 chars), normalising git+https://…/x.git forms.
func cleanURL(s string) string {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "git+")
	if strings.HasPrefix(s, "git://") {
		s = "https://" + s[len("git://"):]
	}
	s = strings.TrimSuffix(s, ".git")
	if s == "" || len(s) > libMaxURL {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil {
		return ""
	}
	return u.String()
}

// getJSON fetches a registry URL (Accept json, 1 MiB cap) and returns status + body.
func getJSON(ctx context.Context, e *Env, u string) (int, []byte, error) {
	req, err := http.NewRequest(http.MethodGet, u, nil)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Accept", "application/json")
	code, body, _, err := e.Do(ctx, req, readCap, dialTimeout)
	return code, body, err
}

// registryStatus maps a status to nil, a soft error (404/410) or a hard one.
func registryStatus(what string, code int, body []byte) error {
	switch {
	case code == 200:
		return nil
	case code == 404 || code == 410:
		return soft("not found")
	}
	return statusErr(what, code, body)
}

func fetchPyPI(ctx context.Context, e *Env, name string, r *libResult) error {
	code, body, err := getJSON(ctx, e, "https://pypi.org/pypi/"+url.PathEscape(name)+"/json")
	if errors.Is(err, errTooLarge) {
		return soft("too large")
	}
	if err != nil {
		return err
	}
	if err := registryStatus("pypi", code, body); err != nil {
		return err
	}
	var doc struct {
		Info struct {
			Name        string            `json:"name"`
			Version     string            `json:"version"`
			HomePage    string            `json:"home_page"`
			ProjectURLs map[string]string `json:"project_urls"`
		} `json:"info"`
		Releases map[string][]struct {
			UploadTime string `json:"upload_time_iso_8601"`
			Yanked     bool   `json:"yanked"`
		} `json:"releases"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return soft("pypi: unparseable json")
	}
	r.Display, r.Latest, r.Homepage = doc.Info.Name, doc.Info.Version, doc.Info.HomePage
	for k, v := range doc.Info.ProjectURLs {
		lk := strings.ToLower(k)
		switch {
		case r.Homepage == "" && lk == "homepage":
			r.Homepage = v
		case r.Repo == "" && (strings.Contains(lk, "source") || strings.Contains(lk, "repository") || strings.Contains(lk, "code") || strings.Contains(lk, "github")):
			r.Repo = v
		case r.Docs == "" && strings.Contains(lk, "doc"):
			r.Docs = v
		}
	}
	for v, files := range doc.Releases {
		lv := libVersion{V: v, Yanked: len(files) > 0}
		for _, f := range files {
			if lv.At == "" || (f.UploadTime != "" && f.UploadTime < lv.At) {
				lv.At = f.UploadTime
			}
			if !f.Yanked {
				lv.Yanked = false
			}
		}
		if lv.V == r.Latest {
			r.LatestAt = lv.At
		}
		r.Versions = append(r.Versions, lv)
	}
	return nil
}

// npmPath encodes a package name for the registry (scoped names keep the @ and encode the slash).
func npmPath(name string) string {
	if strings.HasPrefix(name, "@") {
		return strings.Replace(name, "/", "%2F", 1)
	}
	return name
}

func fetchNPM(ctx context.Context, e *Env, name string, r *libResult) error {
	base := "https://registry.npmjs.org/" + npmPath(name)
	code, body, err := getJSON(ctx, e, base)
	if errors.Is(err, errTooLarge) {
		// Big packages: the latest-version document is small and still gives latest/homepage/repo.
		code, body, err = getJSON(ctx, e, base+"/latest")
		if err != nil {
			return err
		}
		if err := registryStatus("npm", code, body); err != nil {
			return err
		}
		var doc struct {
			Name       string          `json:"name"`
			Version    string          `json:"version"`
			Homepage   string          `json:"homepage"`
			Repository json.RawMessage `json:"repository"`
			Deprecated json.RawMessage `json:"deprecated"`
		}
		if err := json.Unmarshal(body, &doc); err != nil {
			return soft("npm: unparseable json")
		}
		r.Display, r.Latest, r.Homepage, r.Repo, r.Partial = doc.Name, doc.Version, doc.Homepage, repoURL(doc.Repository), true
		r.Versions = []libVersion{{V: doc.Version, Deprecated: npmDeprecated(doc.Deprecated)}}
		return nil
	}
	if err != nil {
		return err
	}
	if err := registryStatus("npm", code, body); err != nil {
		return err
	}
	var doc struct {
		Name       string            `json:"name"`
		DistTags   map[string]string `json:"dist-tags"`
		Homepage   string            `json:"homepage"`
		Repository json.RawMessage   `json:"repository"`
		Time       map[string]string `json:"time"`
		Versions   map[string]struct {
			Deprecated json.RawMessage `json:"deprecated"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return soft("npm: unparseable json")
	}
	r.Display, r.Latest, r.Homepage, r.Repo = doc.Name, doc.DistTags["latest"], doc.Homepage, repoURL(doc.Repository)
	r.LatestAt = doc.Time[r.Latest]
	for v, info := range doc.Versions {
		r.Versions = append(r.Versions, libVersion{V: v, At: doc.Time[v], Deprecated: npmDeprecated(info.Deprecated)})
	}
	return nil
}

// repoURL reads npm's repository field (a string or {url}).
func repoURL(raw json.RawMessage) string {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s
	}
	var o struct {
		URL string `json:"url"`
	}
	json.Unmarshal(raw, &o)
	return o.URL
}

// npmDeprecated: the field is a message string when set (an empty string or false means not deprecated).
func npmDeprecated(raw json.RawMessage) bool {
	var s string
	if json.Unmarshal(raw, &s) == nil {
		return s != ""
	}
	var b bool
	return json.Unmarshal(raw, &b) == nil && b
}

// escapeModule applies the Go module proxy escaping (uppercase letters become !lowercase).
func escapeModule(m string) string {
	var b strings.Builder
	for _, r := range m {
		if r >= 'A' && r <= 'Z' {
			b.WriteByte('!')
			b.WriteRune(r + 'a' - 'A')
		} else {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func fetchGo(ctx context.Context, e *Env, name string, r *libResult) error {
	base := "https://proxy.golang.org/" + escapeModule(name)
	req, err := http.NewRequest(http.MethodGet, base+"/@v/list", nil)
	if err != nil {
		return err
	}
	code, body, _, err := e.Do(ctx, req, readCap, dialTimeout)
	if errors.Is(err, errTooLarge) {
		return soft("too large")
	}
	if err != nil {
		return err
	}
	if err := registryStatus("goproxy", code, body); err != nil {
		return err
	}
	r.Display, r.Homepage, r.Docs = name, "https://pkg.go.dev/"+name, "https://pkg.go.dev/"+name
	if parts := strings.Split(name, "/"); len(parts) >= 3 {
		switch parts[0] {
		case "github.com", "gitlab.com", "codeberg.org", "bitbucket.org":
			r.Repo = "https://" + strings.Join(parts[:3], "/")
		}
	}
	for _, line := range strings.Split(strings.TrimSpace(string(body)), "\n") {
		if v := strings.TrimSpace(line); v != "" {
			r.Versions = append(r.Versions, libVersion{V: v, Pre: strings.Contains(v, "-")})
		}
	}
	code, body, err = getJSON(ctx, e, base+"/@latest")
	if err == nil && code == 200 {
		var l struct{ Version, Time string }
		if json.Unmarshal(body, &l) == nil {
			r.Latest, r.LatestAt = l.Version, l.Time
			for i := range r.Versions {
				if r.Versions[i].V == l.Version {
					r.Versions[i].At = l.Time
				}
			}
		}
	}
	return nil
}

func fetchCrates(ctx context.Context, e *Env, name string, r *libResult) error {
	code, body, err := getJSON(ctx, e, "https://crates.io/api/v1/crates/"+url.PathEscape(name))
	if errors.Is(err, errTooLarge) {
		return soft("too large")
	}
	if err != nil {
		return err
	}
	if err := registryStatus("crates", code, body); err != nil {
		return err
	}
	var doc struct {
		Crate struct {
			Name             string `json:"name"`
			Homepage         string `json:"homepage"`
			Repository       string `json:"repository"`
			Documentation    string `json:"documentation"`
			MaxStableVersion string `json:"max_stable_version"`
			NewestVersion    string `json:"newest_version"`
		} `json:"crate"`
		Versions []struct {
			Num       string `json:"num"`
			Yanked    bool   `json:"yanked"`
			CreatedAt string `json:"created_at"`
		} `json:"versions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return soft("crates: unparseable json")
	}
	c := doc.Crate
	r.Display, r.Homepage, r.Repo, r.Docs = c.Name, c.Homepage, c.Repository, c.Documentation
	r.Latest = c.MaxStableVersion
	if r.Latest == "" {
		r.Latest = c.NewestVersion
	}
	for _, v := range doc.Versions {
		r.Versions = append(r.Versions, libVersion{V: v.Num, At: v.CreatedAt, Yanked: v.Yanked, Pre: strings.Contains(v.Num, "-")})
		if v.Num == r.Latest {
			r.LatestAt = v.CreatedAt
		}
	}
	return nil
}

func fetchGem(ctx context.Context, e *Env, name string, r *libResult) error {
	code, body, err := getJSON(ctx, e, "https://rubygems.org/api/v1/gems/"+url.PathEscape(name)+".json")
	if errors.Is(err, errTooLarge) {
		return soft("too large")
	}
	if err != nil {
		return err
	}
	if err := registryStatus("rubygems", code, body); err != nil {
		return err
	}
	var doc struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Home    string `json:"homepage_uri"`
		Source  string `json:"source_code_uri"`
		Docs    string `json:"documentation_uri"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		return soft("rubygems: unparseable json")
	}
	r.Display, r.Latest, r.Homepage, r.Repo, r.Docs = doc.Name, doc.Version, doc.Home, doc.Source, doc.Docs
	code, body, err = getJSON(ctx, e, "https://rubygems.org/api/v1/versions/"+url.PathEscape(name)+".json")
	if err != nil {
		if errors.Is(err, errTooLarge) {
			r.Partial = true
			return nil
		}
		return err
	}
	if code != 200 {
		r.Partial = true
		return nil
	}
	var vs []struct {
		Number     string `json:"number"`
		CreatedAt  string `json:"created_at"`
		Prerelease bool   `json:"prerelease"`
	}
	if json.Unmarshal(body, &vs) != nil {
		r.Partial = true
		return nil
	}
	for _, v := range vs {
		r.Versions = append(r.Versions, libVersion{V: v.Number, At: v.CreatedAt, Pre: v.Prerelease})
		if v.Number == r.Latest {
			r.LatestAt = v.CreatedAt
		}
	}
	return nil
}
