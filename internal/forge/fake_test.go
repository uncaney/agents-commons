package forge

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// fakeForge is an in-memory Forgejo implementing the API subset the client uses.
type fakeForge struct {
	srv *httptest.Server
	mu  sync.Mutex

	orgs     map[string]bool
	repos    map[string]map[string]any // "owner/repo" -> edit opts seen
	labels   map[string][]Label        // repo -> labels
	issues   map[string][]*Issue       // repo -> issues (index = number-1)
	comments map[string][]Comment      // "repo#n"
	wiki     map[string]string         // "repo/page" -> text (base64 kept decoded)
	files    map[string]string         // "repo/path" -> sha
	fileData map[string]string         // "repo/path" -> content (base64 as sent)
	nextID   int64

	base         int64  // issue numbers start at base+1 (random: the ledger is shared across tests)
	failPath     string // contents path whose next failContents writes fail with 500
	failContents atomic.Int32
	down         atomic.Bool // when set every request fails with 503
	reqs         atomic.Int32
}

func newFake() *fakeForge {
	f := &fakeForge{orgs: map[string]bool{}, repos: map[string]map[string]any{}, labels: map[string][]Label{},
		issues: map[string][]*Issue{}, comments: map[string][]Comment{}, wiki: map[string]string{}, files: map[string]string{}, fileData: map[string]string{}, nextID: 100}
	var b [4]byte
	rand.Read(b[:])
	f.base = int64(binary.BigEndian.Uint32(b[:])%1_000_000_000) * 1000
	f.srv = httptest.NewServer(http.HandlerFunc(f.serve))
	return f
}

var (
	reRepo    = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)$`)
	reLabels  = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/labels$`)
	reIssues  = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/issues$`)
	reIssue   = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/issues/(\d+)$`)
	reComment = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/issues/(\d+)/comments$`)
	reILabels = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/issues/(\d+)/labels$`)
	reILabel  = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/issues/(\d+)/labels/(\d+)$`)
	reWikiNew = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/wiki/new$`)
	reWiki    = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/wiki/page/([^/]+)$`)
	reWikis   = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/wiki/pages$`)
	reContent = regexp.MustCompile(`^/api/v1/repos/([^/]+)/([^/]+)/contents/(.+)$`)
	reOrgRepo = regexp.MustCompile(`^/api/v1/orgs/([^/]+)/repos$`)
	reOrg     = regexp.MustCompile(`^/api/v1/orgs/([^/]+)$`)
)

func wjson(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(v)
}

func (f *fakeForge) serve(w http.ResponseWriter, r *http.Request) {
	f.reqs.Add(1)
	if f.down.Load() {
		wjson(w, 503, map[string]string{"message": "down"})
		return
	}
	if r.Header.Get("Authorization") != "token fake-token" {
		wjson(w, 401, map[string]string{"message": "unauthorized"})
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p := r.URL.EscapedPath()
	var in map[string]any
	if r.Body != nil {
		json.NewDecoder(r.Body).Decode(&in)
	}
	str := func(k string) string { s, _ := in[k].(string); return s }
	switch {
	case p == "/api/v1/orgs" && r.Method == "POST":
		name := str("username")
		if f.orgs[name] {
			wjson(w, 422, map[string]string{"message": "exists"})
			return
		}
		f.orgs[name] = true
		wjson(w, 201, Org{ID: 1, Name: name})
	case reOrg.MatchString(p) && r.Method == "GET":
		name := reOrg.FindStringSubmatch(p)[1]
		if !f.orgs[name] {
			wjson(w, 404, map[string]string{"message": "not found"})
			return
		}
		wjson(w, 200, Org{ID: 1, Name: name})
	case reOrgRepo.MatchString(p) && r.Method == "POST":
		o := reOrgRepo.FindStringSubmatch(p)[1]
		if !f.orgs[o] {
			wjson(w, 404, nil)
			return
		}
		key := o + "/" + str("name")
		if _, ok := f.repos[key]; ok {
			wjson(w, 409, map[string]string{"message": "exists"})
			return
		}
		f.repos[key] = map[string]any{}
		wjson(w, 201, Repo{ID: 1, Name: str("name"), FullName: key})
	case reRepo.MatchString(p):
		m := reRepo.FindStringSubmatch(p)
		key := m[1] + "/" + m[2]
		opts, ok := f.repos[key]
		if !ok {
			wjson(w, 404, map[string]string{"message": "not found"})
			return
		}
		if r.Method == "PATCH" {
			for k, v := range in {
				opts[k] = v
			}
			wjson(w, 200, Repo{Name: m[2], FullName: key})
			return
		}
		wjson(w, 200, Repo{Name: m[2], FullName: key})
	case reLabels.MatchString(p):
		m := reLabels.FindStringSubmatch(p)
		key := m[1] + "/" + m[2]
		if r.Method == "POST" {
			for _, l := range f.labels[key] {
				if l.Name == str("name") {
					wjson(w, 409, map[string]string{"message": "exists"})
					return
				}
			}
			f.nextID++
			l := Label{ID: f.nextID, Name: str("name"), Color: str("color")}
			f.labels[key] = append(f.labels[key], l)
			wjson(w, 201, l)
			return
		}
		ls := f.labels[key]
		if ls == nil {
			ls = []Label{}
		}
		wjson(w, 200, ls)
	case reIssues.MatchString(p):
		m := reIssues.FindStringSubmatch(p)
		key := m[1] + "/" + m[2]
		if r.Method == "POST" {
			f.nextID++
			is := &Issue{Number: f.base + int64(len(f.issues[key])+1), Title: str("title"), Body: str("body"), State: "open", Created: time.Now(), Labels: []Label{}}
			if lids, ok := in["labels"].([]any); ok {
				for _, x := range lids {
					id := int64(x.(float64))
					for _, l := range f.labels[key] {
						if l.ID == id {
							is.Labels = append(is.Labels, l)
						}
					}
				}
			}
			f.issues[key] = append(f.issues[key], is)
			wjson(w, 201, is)
			return
		}
		q := r.URL.Query()
		state, want, limit := q.Get("state"), q.Get("labels"), 50
		if l, err := strconv.Atoi(q.Get("limit")); err == nil && l > 0 {
			limit = l
		}
		out := []Issue{}
		for i := len(f.issues[key]) - 1; i >= 0 && len(out) < limit; i-- {
			is := f.issues[key][i]
			if state != "all" && state != "" && is.State != state {
				continue
			}
			if want != "" && !is.HasLabel(want) {
				continue
			}
			if s := q.Get("q"); s != "" && !strings.Contains(strings.ToLower(is.Title+" "+is.Body), strings.ToLower(s)) {
				continue
			}
			out = append(out, *is)
		}
		wjson(w, 200, out)
	case reIssue.MatchString(p):
		m := reIssue.FindStringSubmatch(p)
		is := f.issue(m[1]+"/"+m[2], m[3])
		if is == nil {
			wjson(w, 404, map[string]string{"message": "not found"})
			return
		}
		if r.Method == "PATCH" {
			if s := str("state"); s != "" {
				is.State = s
			}
			if b := str("body"); b != "" {
				is.Body = b
			}
			if t := str("title"); t != "" {
				is.Title = t
			}
		}
		wjson(w, 200, is)
	case reComment.MatchString(p):
		m := reComment.FindStringSubmatch(p)
		key := m[1] + "/" + m[2]
		if f.issue(key, m[3]) == nil {
			wjson(w, 404, nil)
			return
		}
		ck := key + "#" + m[3]
		if r.Method == "POST" {
			f.nextID++
			c := Comment{ID: f.nextID, Body: str("body"), Created: time.Now()}
			f.comments[ck] = append(f.comments[ck], c)
			wjson(w, 201, c)
			return
		}
		cs := f.comments[ck]
		if cs == nil {
			cs = []Comment{}
		}
		wjson(w, 200, cs)
	case reILabels.MatchString(p) && r.Method == "POST":
		m := reILabels.FindStringSubmatch(p)
		key := m[1] + "/" + m[2]
		is := f.issue(key, m[3])
		if is == nil {
			wjson(w, 404, nil)
			return
		}
		for _, x := range in["labels"].([]any) {
			id := int64(x.(float64))
			for _, l := range f.labels[key] {
				if l.ID == id && !is.HasLabel(l.Name) {
					is.Labels = append(is.Labels, l)
				}
			}
		}
		wjson(w, 200, is.Labels)
	case reILabel.MatchString(p) && r.Method == "DELETE":
		m := reILabel.FindStringSubmatch(p)
		is := f.issue(m[1]+"/"+m[2], m[3])
		if is == nil {
			wjson(w, 404, nil)
			return
		}
		id, _ := strconv.ParseInt(m[4], 10, 64)
		keep := is.Labels[:0]
		for _, l := range is.Labels {
			if l.ID != id {
				keep = append(keep, l)
			}
		}
		is.Labels = keep
		w.WriteHeader(204)
	case reWikiNew.MatchString(p) && r.Method == "POST":
		m := reWikiNew.FindStringSubmatch(p)
		key := m[1] + "/" + m[2] + "/" + str("title")
		if _, ok := f.wiki[key]; ok {
			wjson(w, 409, map[string]string{"message": "exists"})
			return
		}
		f.wiki[key] = str("content_base64")
		wjson(w, 201, WikiPage{Title: str("title"), Content: f.wiki[key]})
	case reWiki.MatchString(p):
		m := reWiki.FindStringSubmatch(p)
		page, _ := unescape(m[3])
		key := m[1] + "/" + m[2] + "/" + page
		c, ok := f.wiki[key]
		if !ok {
			wjson(w, 404, map[string]string{"message": "not found"})
			return
		}
		switch r.Method {
		case "PATCH":
			f.wiki[key] = str("content_base64")
			wjson(w, 200, WikiPage{Title: page, Content: f.wiki[key]})
		case "DELETE":
			delete(f.wiki, key)
			w.WriteHeader(204)
		default:
			wjson(w, 200, WikiPage{Title: page, Content: c})
		}
	case reWikis.MatchString(p):
		m := reWikis.FindStringSubmatch(p)
		pfx := m[1] + "/" + m[2] + "/"
		out := []WikiPage{}
		for k := range f.wiki {
			if strings.HasPrefix(k, pfx) {
				out = append(out, WikiPage{Title: strings.TrimPrefix(k, pfx)})
			}
		}
		wjson(w, 200, out)
	case reContent.MatchString(p):
		m := reContent.FindStringSubmatch(p)
		key := m[1] + "/" + m[2] + "/" + m[3]
		sha, ok := f.files[key]
		switch r.Method {
		case "GET":
			if !ok {
				wjson(w, 404, map[string]string{"message": "not found"})
				return
			}
			wjson(w, 200, Content{SHA: sha})
		case "DELETE":
			if !ok {
				wjson(w, 404, map[string]string{"message": "not found"})
				return
			}
			if str("sha") != sha {
				wjson(w, 409, map[string]string{"message": "sha mismatch"})
				return
			}
			delete(f.files, key)
			delete(f.fileData, key)
			wjson(w, 200, map[string]any{"content": nil})
		case "POST", "PUT":
			if f.failContents.Load() > 0 && strings.HasSuffix(key, f.failPath) {
				f.failContents.Add(-1)
				wjson(w, 500, map[string]string{"message": "boom"})
				return
			}
			if r.Method == "PUT" && str("sha") != sha {
				wjson(w, 409, map[string]string{"message": "sha mismatch"})
				return
			}
			if r.Method == "POST" && ok {
				wjson(w, 422, map[string]string{"message": "exists"})
				return
			}
			f.nextID++
			f.files[key] = "sha" + strconv.FormatInt(f.nextID, 10)
			f.fileData[key] = str("content")
			wjson(w, 201, map[string]any{"content": Content{SHA: f.files[key]}})
		}
	default:
		wjson(w, 404, map[string]string{"message": "no route " + r.Method + " " + p})
	}
}

func unescape(s string) (string, error) { return url.PathUnescape(s) }

func (f *fakeForge) issue(repo, ns string) *Issue {
	n, _ := strconv.ParseInt(ns, 10, 64)
	i := n - f.base
	if i < 1 || i > int64(len(f.issues[repo])) {
		return nil
	}
	return f.issues[repo][i-1]
}

func (f *fakeForge) getIssue(n int64) Issue {
	f.mu.Lock()
	defer f.mu.Unlock()
	return *f.issues["commons/board"][n-f.base-1]
}
