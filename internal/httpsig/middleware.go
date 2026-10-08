package httpsig

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
)

// maxSignBody bounds the body the middleware buffers to digest and sign; a larger response streams
// through unsigned (the dataset files carry their own detached SIGNATURES from P40).
const maxSignBody = 16 << 20

// staticTTL is how long a signed static rendition stays in the ByteLRU keyed by its ETag.
const staticTTL = 24 * time.Hour

// timeNow is the clock, overridable in tests so "signed once per ETag" is observable.
var timeNow = time.Now

// sigCache caches the signed headers of a static rendition so the bytes are signed once per ETag
// (per authority/path/content-type); nil until Register installs it, and nil-safe (per-request sign).
var sigCache *core.ByteLRU

// cached is the stored, reusable signature of a static rendition.
type cached struct {
	Digest  string `json:"d"`
	Input   string `json:"i"`
	Sig     string `json:"s"`
	Created int64  `json:"c"`
}

// Signable reports whether a request path is one of the signed rendition classes (27.1): the
// .md/.txt/.jsonld twins, /export/*, /sitemaps/*, /llms*.txt and /index.md.
func Signable(path string) bool {
	switch {
	case strings.HasSuffix(path, ".md"), strings.HasSuffix(path, ".txt"), strings.HasSuffix(path, ".jsonld"):
		return true
	case strings.HasPrefix(path, "/export/") || path == "/export",
		strings.HasPrefix(path, "/sitemaps/"):
		return true
	}
	return false
}

// Middleware wraps next so responses on the signed rendition classes gain Content-Digest and an
// RFC 9421 Signature over their body. It buffers the body (up to maxSignBody) to compute the digest
// before writing headers; non-200 replies, HEAD/other methods, oversize bodies and shed:anon-search
// pass through unsigned. The ByteLRU avoids re-signing static bytes.
func Middleware(d *core.Deps, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !Signable(r.URL.Path) || d.Shed(r, "anon-search") {
			next.ServeHTTP(w, r)
			return
		}
		cw := &capWriter{ResponseWriter: w}
		next.ServeHTTP(cw, r)
		cw.finish(r)
	})
}

// capWriter buffers the response until finish so the body can be digested and the headers signed; it
// switches to pass-through if the body exceeds the cap or the handler flushes.
type capWriter struct {
	http.ResponseWriter
	status   int
	buf      []byte
	wrote    bool // underlying WriteHeader called (pass-through)
	overflow bool // too large or flushed: streaming unsigned
}

func (c *capWriter) WriteHeader(status int) {
	if c.wrote || c.status != 0 {
		return
	}
	c.status = status
}

func (c *capWriter) Write(p []byte) (int, error) {
	if c.status == 0 {
		c.status = http.StatusOK
	}
	if c.overflow {
		return c.ResponseWriter.Write(p)
	}
	if len(c.buf)+len(p) > maxSignBody || c.status != http.StatusOK {
		// Give up on signing: flush what we have and stream the rest unsigned.
		c.startStream()
		return c.ResponseWriter.Write(p)
	}
	c.buf = append(c.buf, p...)
	return len(p), nil
}

// Flush switches to unsigned streaming (signed renditions are not streamed, but stay correct if one is).
func (c *capWriter) Flush() {
	if !c.overflow {
		c.startStream()
	}
	if f, ok := c.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (c *capWriter) startStream() {
	c.overflow = true
	if !c.wrote {
		c.wrote = true
		c.ResponseWriter.WriteHeader(c.statusOr200())
		if len(c.buf) > 0 {
			c.ResponseWriter.Write(c.buf)
			c.buf = nil
		}
	}
}

func (c *capWriter) statusOr200() int {
	if c.status == 0 {
		return http.StatusOK
	}
	return c.status
}

// finish signs the buffered 200 response, or writes it through unsigned.
func (c *capWriter) finish(r *http.Request) {
	if c.overflow || c.wrote {
		return
	}
	status := c.statusOr200()
	h := c.ResponseWriter.Header()
	if status == http.StatusOK && len(c.buf) > 0 {
		c.sign(r, h)
	}
	c.wrote = true
	c.ResponseWriter.WriteHeader(status)
	if len(c.buf) > 0 {
		c.ResponseWriter.Write(c.buf)
	}
}

// sign sets Content-Digest, Signature-Input and Signature on h for the buffered body, reusing a
// cached signature when the ETag (with authority/path/content-type) was signed before.
func (c *capWriter) sign(r *http.Request, h http.Header) {
	ct := h.Get("Content-Type")
	if ct == "" {
		return
	}
	authority, path := r.Host, r.URL.EscapedPath()
	etag := h.Get("ETag")
	if v, ok := loadCached(etag, authority, path, ct); ok {
		h.Set("Content-Digest", v.Digest)
		h.Set("Signature-Input", inputHeader(v.Input))
		h.Set("Signature", v.Sig)
		return
	}
	s := sign.Default()
	digest := Digest(c.buf)
	created := timeNow().Unix()
	params := Params(created, kidString(s.KID()))
	base := SignatureBase(authority, path, digest, ct, params)
	sig := signatureHeader(s.SignBytes(base))
	h.Set("Content-Digest", digest)
	h.Set("Signature-Input", inputHeader(params))
	h.Set("Signature", sig)
	storeCached(etag, authority, path, ct, cached{Digest: digest, Input: params, Sig: sig, Created: created})
}

func cacheKey(etag, authority, path, ct string) string {
	return etag + "\x00" + authority + "\x00" + path + "\x00" + ct
}

func loadCached(etag, authority, path, ct string) (cached, bool) {
	if sigCache == nil || etag == "" {
		return cached{}, false
	}
	b, ok := sigCache.Get(cacheKey(etag, authority, path, ct))
	if !ok {
		return cached{}, false
	}
	var v cached
	if json.Unmarshal(b, &v) != nil {
		return cached{}, false
	}
	return v, true
}

func storeCached(etag, authority, path, ct string, v cached) {
	if sigCache == nil || etag == "" {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	sigCache.Put(cacheKey(etag, authority, path, ct), b, staticTTL)
}
