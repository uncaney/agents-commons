package doc

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"path"
	"strconv"
	"strings"
	"time"
)

// ServeStatic serves pre-rendered bytes (sitemaps, feeds, llms*, openapi, exports, badges):
// strong ETag, Last-Modified, public Cache-Control with stale directives, 304 on If-None-Match /
// If-Modified-Since, no body on HEAD. Anything carrying a token gets private, no-store.
func ServeStatic(w http.ResponseWriter, r *http.Request, modTime time.Time, body []byte, ct string) {
	h := w.Header()
	sum := sha256.Sum256(body)
	et := `"` + hex.EncodeToString(sum[:])[:16] + `"`
	h.Set("ETag", et)
	if !modTime.IsZero() {
		h.Set("Last-Modified", modTime.UTC().Format(http.TimeFormat))
	}
	if HasToken(r) {
		h.Set("Cache-Control", "private, no-store")
	} else {
		h.Set("Cache-Control", ccPage)
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if NotModified(r, et) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if ims := r.Header.Get("If-Modified-Since"); ims != "" && !modTime.IsZero() && r.Header.Get("If-None-Match") == "" {
			if t, err := http.ParseTime(ims); err == nil && !modTime.Truncate(time.Second).After(t) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	h.Set("Content-Type", ct)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

// RedirectTwin answers 303 to the suffixed twin of an HTML canonical when the request's Accept
// lacks text/html but lists text/markdown, text/plain or application/json ("/" -> "/index.md",
// "/x/" -> "/x/index.md"). It returns true when it wrote the redirect. GET/HEAD only; requests that
// already carry a suffix or ?f= are left alone.
func RedirectTwin(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	if _, f := SplitSuffix(path.Base(r.URL.Path)); f != "" || r.URL.Query().Get("f") != "" {
		return false
	}
	ext := twinExt(r.Header.Get("Accept"))
	if ext == "" {
		return false
	}
	target := twin(r.URL.Path, ext)
	if r.URL.RawQuery != "" {
		target += "?" + r.URL.RawQuery
	}
	h := w.Header()
	h.Add("Vary", "Accept")
	h.Set("Cache-Control", "no-store")
	h.Set("Location", target)
	w.WriteHeader(http.StatusSeeOther)
	return true
}

// twinExt maps an Accept header lacking text/html to a twin suffix ("" when HTML is acceptable or
// nothing specific is listed).
func twinExt(accept string) string {
	if accept == "" {
		return ""
	}
	best, bestQ := "", -1.0
	for _, part := range strings.Split(accept, ",") {
		fields := strings.Split(strings.TrimSpace(part), ";")
		mt := strings.ToLower(strings.TrimSpace(fields[0]))
		q := 1.0
		for _, p := range fields[1:] {
			if k, v, ok := strings.Cut(strings.TrimSpace(p), "="); ok && strings.EqualFold(k, "q") {
				if x, err := strconv.ParseFloat(v, 64); err == nil {
					q = x
				}
			}
		}
		if q <= 0 {
			continue
		}
		switch mt {
		case "text/html", "application/xhtml+xml":
			return ""
		case "text/markdown":
			if q > bestQ {
				best, bestQ = ".md", q
			}
		case "text/plain":
			if q > bestQ {
				best, bestQ = ".txt", q
			}
		case "application/json":
			if q > bestQ {
				best, bestQ = ".json", q
			}
		}
	}
	return best
}
