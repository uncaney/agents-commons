// Package gitmirror is the read-only smart-HTTP proxy of the KB git mirror (SPEC-v2 7.3). Exactly
// two git routes exist, GET /git/kb.git/info/refs?service=git-upload-pack and
// POST /git/kb.git/git-upload-pack; both go to the fixed upstream <FORGEJO_URL>/commons/kb.git/
// with the read-only token, a header whitelist (Content-Type, Accept, Git-Protocol), a 1 MiB body
// cap, a 60 s deadline, a semaphore of 2 and a daily quota per super-group (beyond it the 429 body
// points to /git/kb.tar.gz). Client credentials are never forwarded and upstream cookies and
// challenges never come back. GET /git/kb.tar.gz serves the archive API cached daily under
// EXPORT_DIR. FORGEJO_URL="" disables the whole surface (404); startup never waits for Forgejo;
// the operator flag freeze:git (POST /admin/freeze) answers 503 on the two git routes.
package gitmirror

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Limits (7.3). Vars so tests can lower them.
var (
	CloneQuota = 10               // GET info/refs per super-group per day: one per clone or fetch
	PackQuota  = 30               // POST git-upload-pack rounds per super-group per day (a clone needs 1-2)
	MaxBody    = int64(1 << 20)   // upload-pack request body, after decompression
	Timeout    = 60 * time.Second // whole proxied exchange
	SemWait    = 5 * time.Second  // wait for one of the two slots before answering 503
	Slots      = 2
)

const (
	cost        = 3 // limiter cost of every git route (3.6)
	repoPath    = "/commons/kb.git"
	svcUpload   = "git-upload-pack"
	ctUploadReq = "application/x-git-upload-pack-request"
	userAgent   = "commons-gitmirror/1"
)

var (
	// fwdHeaders is the request whitelist; everything else, Authorization and Cookie first, stops here.
	fwdHeaders = []string{"Content-Type", "Accept", "Git-Protocol"}
	// backHeaders is the response whitelist (no Set-Cookie, no WWW-Authenticate, no server banner).
	backHeaders = []string{"Content-Type", "Content-Length", "Cache-Control", "Expires", "Pragma"}

	errDisabled = core.E(404, "notfound", "git mirror disabled")
	errNotGit   = core.E(404, "notfound", "read-only smart HTTP only: git clone .../git/kb.git or GET /git/kb.tar.gz")
	errReadOnly = core.E(403, "readonly", "kb.git is a read-only mirror: write through POST /v1/kb")
	errCT       = core.E(415, "bad", "Content-Type must be "+ctUploadReq)
	errEncoding = core.E(415, "bad", "Content-Encoding must be gzip or identity")
	errBusy     = core.E(503, "busy", "git mirror busy (2 concurrent fetches): retry or GET /git/kb.tar.gz")
	errClones   = core.E(429, "quota", "git clones per network per day reached: GET /git/kb.tar.gz")
	errPacks    = core.E(429, "quota", "git fetch rounds per network per day reached: GET /git/kb.tar.gz")
	errUpstream = core.E(503, "frozen", "forge-unavailable")
)

type targetKey struct{}

type svc struct {
	d     *core.Deps
	up    *url.URL // FORGEJO_URL, path kept as a prefix
	token string
	proxy *httputil.ReverseProxy
	hc    *http.Client
	sem   chan struct{}

	tmu       sync.Mutex // tarball single-flight (tarball.go)
	inflight  *flight
	failUntil time.Time
}

// Register mounts the three routes (plus 403 for receive-pack and 404 for anything else under
// /git/), the limiter cost, the kb:r scope, the OpenAPI fragment and the llms-full section.
func Register(mux *http.ServeMux, d *core.Deps) { register(mux, d) }

func register(mux *http.ServeMux, d *core.Deps) *svc {
	up, err := url.Parse(d.Cfg.ForgejoURL)
	if d.Cfg.ForgejoURL == "" || err != nil || up.Host == "" || (up.Scheme != "http" && up.Scheme != "https") {
		if d.Cfg.ForgejoURL != "" {
			d.Log.Error("gitmirror: bad FORGEJO_URL, mirror disabled", "url", d.Cfg.ForgejoURL)
		}
		mux.HandleFunc("/git/", func(w http.ResponseWriter, r *http.Request) { doc.Fail(w, r, errDisabled) })
		return nil
	}
	up.Path = strings.TrimRight(up.Path, "/")
	up.RawPath, up.RawQuery, up.Fragment, up.User = "", "", "", nil
	if d.Cfg.ForgejoROToken == "" {
		d.Log.Warn("gitmirror: FORGEJO_RO_TOKEN unset, proxying without credentials")
	}
	s := newSvc(d, up)
	mux.HandleFunc("GET /git/kb.git/info/refs", s.infoRefs)
	mux.HandleFunc("POST /git/kb.git/git-upload-pack", s.uploadPack)
	mux.HandleFunc("POST /git/kb.git/git-receive-pack", func(w http.ResponseWriter, r *http.Request) { doc.Fail(w, r, errReadOnly) })
	mux.HandleFunc("GET /git/kb.tar.gz", s.tarball)
	mux.HandleFunc("/git/", s.other)
	for _, p := range []string{"GET /git/kb.git/info/refs", "POST /git/kb.git/git-upload-pack", "GET /git/kb.tar.gz"} {
		d.RegisterCost(p, cost)
		d.RegisterScope(p, "kb:r")
	}
	d.RegisterOpenAPI(openAPI)
	llms := llmsText(d.Cfg.PublicURL)
	d.RegisterLLMSFull("git", func(context.Context) string { return llms })
	return s
}

func newSvc(d *core.Deps, up *url.URL) *svc {
	tr := &http.Transport{
		Proxy:                 nil, // fixed internal upstream: never honour HTTP_PROXY
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		DisableCompression:    true, // bodies pass through untouched
		MaxIdleConns:          4,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	s := &svc{d: d, up: up, token: d.Cfg.ForgejoROToken, hc: &http.Client{Transport: tr}, sem: make(chan struct{}, Slots)}
	s.proxy = &httputil.ReverseProxy{
		Rewrite:        s.rewrite,
		Transport:      tr,
		ModifyResponse: s.modify,
		ErrorHandler:   s.proxyErr,
		FlushInterval:  -1, // packfiles stream as they come
		ErrorLog:       slog.NewLogLogger(d.Log.Handler(), slog.LevelWarn),
	}
	return s
}

// upstream builds a fixed upstream URL: nothing of the client's path or query is ever used.
func (s *svc) upstream(path, query string) *url.URL {
	u := *s.up
	u.Path, u.RawQuery = s.up.Path+path, query
	return &u
}

// auth sets the read-only token when configured.
func (s *svc) auth(req *http.Request) {
	if s.token != "" {
		req.Header.Set("Authorization", "token "+s.token)
	}
	req.Header.Set("User-Agent", userAgent)
}

// rewrite replaces the outbound request line and headers wholesale: the stashed upstream URL and
// the whitelist only, then our credentials. ReverseProxy adds no X-Forwarded-* with Rewrite.
func (s *svc) rewrite(pr *httputil.ProxyRequest) {
	in, out := pr.In, pr.Out
	out.URL = in.Context().Value(targetKey{}).(*url.URL)
	out.Host = out.URL.Host
	h := make(http.Header, len(fwdHeaders)+2)
	for _, k := range fwdHeaders {
		if v := in.Header.Get(k); v != "" {
			h.Set(k, v)
		}
	}
	out.Header = h
	s.auth(out)
}

// upstreamStatus is a non-2xx upstream reply; its body never reaches the client.
type upstreamStatus int

func (u upstreamStatus) Error() string { return "upstream status " + strconv.Itoa(int(u)) }

func (s *svc) modify(res *http.Response) error {
	if res.StatusCode/100 != 2 {
		return upstreamStatus(res.StatusCode)
	}
	keep := make(http.Header, len(backHeaders))
	for _, k := range backHeaders {
		if v := res.Header.Get(k); v != "" {
			keep.Set(k, v)
		}
	}
	if keep.Get("Cache-Control") == "" {
		keep.Set("Cache-Control", "no-cache, max-age=0, must-revalidate")
	}
	res.Header = keep
	return nil
}

func (s *svc) proxyErr(w http.ResponseWriter, r *http.Request, err error) {
	var us upstreamStatus
	switch {
	case r.Context().Err() != nil && !errors.As(err, &us):
		if errors.Is(r.Context().Err(), context.DeadlineExceeded) {
			doc.Fail(w, r, core.E(504, "timeout", "git mirror timed out: GET /git/kb.tar.gz"), doc.GET("/git/kb.tar.gz", "daily tarball"))
		}
		return // client went away
	case errors.As(err, &us):
		s.d.Log.Warn("gitmirror upstream", "status", int(us), "m", r.Method)
		if us == http.StatusNotFound {
			doc.Fail(w, r, core.ErrNotFound)
			return
		}
		doc.Fail(w, r, errUpstream, doc.GET("/git/kb.tar.gz", "daily tarball"))
	default:
		s.d.Log.Warn("gitmirror upstream", "err", err, "m", r.Method)
		doc.Fail(w, r, errUpstream, doc.GET("/git/kb.tar.gz", "daily tarball"))
	}
}

// exact admits only the literal route: no percent-encoding anywhere in the path, no dot segments,
// and the raw query byte-for-byte equal to want ("" for the POST). A receive-pack attempt is told
// the mirror is read-only; anything else is not one of the two patterns.
func (s *svc) exact(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.URL.RawPath == "" && r.URL.RawQuery == want && !strings.Contains(r.URL.Path, "..") {
		return true
	}
	if r.URL.Query().Get("service") == "git-receive-pack" {
		doc.Fail(w, r, errReadOnly)
		return false
	}
	s.other(w, r)
	return false
}

func (s *svc) other(w http.ResponseWriter, r *http.Request) {
	doc.Fail(w, r, errNotGit, doc.GET("/git/kb.git/info/refs?service=git-upload-pack", "ref advertisement"),
		doc.POST("/git/kb.git/git-upload-pack", "fetch"), doc.GET("/git/kb.tar.gz", "daily tarball"))
}

func (s *svc) infoRefs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { // HEAD matches the GET pattern but is not a clone
		s.other(w, r)
		return
	}
	if !s.exact(w, r, "service="+svcUpload) || !s.d.CheckFrozen(w, r, "git") {
		return
	}
	if err := core.UseIPQuota(r.Context(), s.d.DB, s.d.IPSuper(r), "git-clone", CloneQuota); err != nil {
		s.quota(w, r, err, errClones)
		return
	}
	s.forward(w, r, s.upstream(repoPath+"/info/refs", "service="+svcUpload), nil)
}

func (s *svc) uploadPack(w http.ResponseWriter, r *http.Request) {
	if !s.exact(w, r, "") || !s.d.CheckFrozen(w, r, "git") {
		return
	}
	if ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";"); strings.TrimSpace(ct) != ctUploadReq {
		doc.Fail(w, r, errCT)
		return
	}
	if err := core.UseIPQuota(r.Context(), s.d.DB, s.d.IPSuper(r), "git-pack", PackQuota); err != nil {
		s.quota(w, r, err, errPacks)
		return
	}
	body, err := readBody(w, r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	s.forward(w, r, s.upstream(repoPath+"/"+svcUpload, ""), body)
}

// quota maps ErrQuota to the route's 429 whose body points to the tarball; other errors pass.
func (s *svc) quota(w http.ResponseWriter, r *http.Request, err error, over *core.APIError) {
	if errors.Is(err, core.ErrQuota) {
		err = over
	}
	doc.Fail(w, r, err, doc.GET("/git/kb.tar.gz", "daily tarball"))
}

// readBody buffers the upload-pack request (<= MaxBody after decompression). Git gzips fetch
// requests over 1 KiB; they are inflated here so the upstream sees plain pkt-lines and the cap
// applies to real bytes.
func readBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	var rd io.Reader = http.MaxBytesReader(w, r.Body, MaxBody)
	switch strings.ToLower(strings.TrimSpace(r.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip", "x-gzip":
		gz, err := gzip.NewReader(rd)
		if err != nil {
			return nil, core.Bad("bad gzip body")
		}
		defer gz.Close()
		rd = io.LimitReader(gz, MaxBody+1)
	default:
		return nil, errEncoding
	}
	b, err := io.ReadAll(rd)
	if err != nil {
		var mb *http.MaxBytesError
		if errors.As(err, &mb) || errors.Is(err, gzip.ErrChecksum) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, core.ErrSize
		}
		return nil, core.Bad("read: body")
	}
	if int64(len(b)) > MaxBody {
		return nil, core.ErrSize
	}
	return b, nil
}

// forward runs one proxied exchange under the deadline and a slot of the semaphore; body, when
// non-nil, replaces the request body with a known length (so Forgejo gets Content-Length).
func (s *svc) forward(w http.ResponseWriter, r *http.Request, target *url.URL, body []byte) {
	ctx, cancel := context.WithTimeout(r.Context(), Timeout)
	defer cancel()
	if !s.acquire(ctx) {
		w.Header().Set("Retry-After", "5")
		doc.Fail(w, r, errBusy, doc.GET("/git/kb.tar.gz", "daily tarball"))
		return
	}
	defer func() { <-s.sem }()
	r2 := r.Clone(context.WithValue(ctx, targetKey{}, target))
	if body != nil {
		r2.Body = io.NopCloser(bytes.NewReader(body))
		r2.ContentLength = int64(len(body))
		r2.Header.Del("Content-Encoding")
	}
	w.Header().Set("X-Robots-Tag", "noindex")
	s.proxy.ServeHTTP(w, r2)
}

func (s *svc) acquire(ctx context.Context) bool {
	t := time.NewTimer(SemWait)
	defer t.Stop()
	select {
	case s.sem <- struct{}{}:
		return true
	case <-t.C:
		return false
	case <-ctx.Done():
		return false
	}
}
