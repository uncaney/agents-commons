// Package clients serves the zero-install single-file clients of SPEC-v2 27.2 and the E2EE
// reference clients of SECURITY-E2EE-v2 9.5 / package P10: /cx.py, /cx.mjs, /cx.sh (the cx verbs
// and a stdio MCP proxy), /e2e.py, /e2e.mjs (the full DVR and tier markers), /e2e-vectors.json,
// /seal.py, /seal.mjs (the 26.4 seal2 recipe), /srchash.py (27.3) and /cx-manifest.json.
//
// Every script is a static asset (no user text, no templating beyond the compiled-in base URL), is
// served with an ETag, Last-Modified, a strict CSP, noindex, and an X-Cx-Sig-Server signature over
// the exact bytes (the online key, via internal/keys), and is listed by sha256 in the signed
// cx-manifest.json so an agent can verify what it fetched against the mirror before trusting it. No
// eval, no shell-out, no pickle (a test greps for it); the manifest and the files never drift (a
// test recomputes every hash). cmd/gateway wires Register; a later integration package wires Ops.
package clients

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/keys"
)

//go:embed assets
var assetFS embed.FS

// assetMod is the Last-Modified of the embedded clients (bumped when they change).
var assetMod = time.Date(2026, 10, 7, 0, 0, 0, 0, time.UTC)

// signResp and onlinePub are the server-signature seams (the online key, SECURITY-E2EE-v2 3.6);
// tests override them with a throwaway key so the package needs no database.
var (
	signResp  = keys.SignServer
	onlinePub = keys.OnlinePub
)

// manifestVersion labels the client bundle; the per-file hashes are what the DVR actually checks.
const manifestVersion = "cx-clients/2"

// builtFrom records the source the reproducible clients were cut from (cross-published to the mirror).
const builtFrom = "github.com/uncaney/agents-commons"

// file is one served client: its URL path, embedded name, and content type.
type file struct {
	path, name, ctype string
}

// served is the set of files clients both routes and lists in the manifest. errsig.py/errsig.js are
// served (identically) by internal/errsig and join.py by internal/pages, so they are shipped in the
// bundle for parity and the grep gate but routed by their owners, not here.
var served = []file{
	{"/cx.py", "cx.py", "text/x-python; charset=utf-8"},
	{"/cx.mjs", "cx.mjs", "text/javascript; charset=utf-8"},
	{"/cx.sh", "cx.sh", "text/x-shellscript; charset=utf-8"},
	{"/e2e.py", "e2e.py", "text/x-python; charset=utf-8"},
	{"/e2e.mjs", "e2e.mjs", "text/javascript; charset=utf-8"},
	{"/e2e-vectors.json", "e2e-vectors.json", "application/json; charset=utf-8"},
	{"/seal.py", "seal.py", "text/x-python; charset=utf-8"},
	{"/seal.mjs", "seal.mjs", "text/javascript; charset=utf-8"},
	{"/srchash.py", "srchash.py", "text/x-python; charset=utf-8"},
}

// manifestFiles are hashed into cx-manifest.json: the routed files plus the parity clients shipped
// in the bundle (errsig.py, errsig.js, join.py), so the mirror can pin every file an agent fetches.
var manifestBundle = []string{"errsig.py", "errsig.js", "join.py"}

type handlers struct{}

// body returns the embedded bytes of a client asset (panics at init if one is missing).
func mustAsset(name string) []byte {
	b, err := assetFS.ReadFile("assets/" + name)
	if err != nil {
		panic("clients: missing embedded asset " + name + ": " + err.Error())
	}
	return b
}

// manifest is the signed {version, files:{name: sha256}, built_from} document (26.4 / 9.5). It is
// built once from the embedded bytes, so files[name] always equals the sha256 of what is served.
type manifest struct {
	Version   string            `json:"version"`
	Files     map[string]string `json:"files"`
	BuiltFrom string            `json:"built_from"`
	Built     string            `json:"built"`
}

var manifestJSON = buildManifest()

func buildManifest() []byte {
	m := manifest{Version: manifestVersion, Files: map[string]string{}, BuiltFrom: builtFrom, Built: assetMod.UTC().Format(time.RFC3339)}
	add := func(name string) {
		sum := sha256.Sum256(mustAsset(name))
		m.Files[name] = hex.EncodeToString(sum[:])
	}
	for _, f := range served {
		add(f.name)
	}
	for _, n := range manifestBundle {
		add(n)
	}
	// Deterministic key order via json marshalling of a map is sorted by Go, so the bytes are stable.
	b, err := json.MarshalIndent(m, "", " ")
	if err != nil {
		panic("clients: manifest: " + err.Error())
	}
	return append(b, '\n')
}

// Manifest returns the raw signed manifest bytes (for tests and the mirror cross-publisher).
func Manifest() []byte { return manifestJSON }

// serve writes body with the static-asset headers and an X-Cx-Sig-Server signature over the bytes.
func serve(w http.ResponseWriter, r *http.Request, body []byte, ctype string) {
	h := w.Header()
	sum := sha256.Sum256(body)
	et := `"` + hex.EncodeToString(sum[:])[:16] + `"`
	h.Set("ETag", et)
	h.Set("Last-Modified", assetMod.UTC().Format(http.TimeFormat))
	h.Set("Cache-Control", "public, max-age=86400")
	h.Set("X-Robots-Tag", "noindex")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "default-src 'none'; sandbox")
	h.Set("Referrer-Policy", "no-referrer")
	if sig := signResp(r.URL.Path, body); sig != "" {
		h.Set("X-Cx-Sig-Server", sig)
	}
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		if doc.NotModified(r, et) {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		if ims := r.Header.Get("If-Modified-Since"); ims != "" && r.Header.Get("If-None-Match") == "" {
			if t, err := http.ParseTime(ims); err == nil && !assetMod.Truncate(time.Second).After(t) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}
	h.Set("Content-Type", ctype)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	if r.Method != http.MethodHead {
		w.Write(body)
	}
}

func (handlers) asset(body []byte, ctype string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { serve(w, r, body, ctype) }
}

// Register mounts the served clients and the signed manifest (all GET/HEAD, public, cached a day).
func Register(mux *http.ServeMux, d *core.Deps) {
	mount(mux, func(pat string) { d.RegisterScope(pat, "*") })
	d.RegisterOpenAPI(openAPI)
}

// mount installs the GET/HEAD routes for every served file and the manifest, calling scope with each
// pattern so Register can register the "*" (public) scope and tests can mount the same routes with a
// no-op. This is the single place the route table is built.
func mount(mux *http.ServeMux, scope func(pattern string)) {
	var h handlers
	add := func(path string, body []byte, ctype string) {
		fn := h.asset(body, ctype)
		mux.HandleFunc("GET "+path, fn)
		mux.HandleFunc("HEAD "+path, fn)
		scope("GET " + path)
	}
	for _, f := range served {
		add(f.path, mustAsset(f.name), f.ctype)
	}
	add("/cx-manifest.json", manifestJSON, "application/json; charset=utf-8")
}

// assetNames lists every embedded client file name (for the grep gate and tooling), sorted.
func assetNames() []string {
	var out []string
	fs.WalkDir(assetFS, "assets", func(p string, de fs.DirEntry, err error) error {
		if err == nil && !de.IsDir() {
			out = append(out, de.Name())
		}
		return nil
	})
	sort.Strings(out)
	return out
}

var openAPI = json.RawMessage(`{"paths":{
"/cx.py":{"get":{"summary":"Zero-install cx client (Python >= 3.8 stdlib); python3 <(curl -s .../cx.py) s \"<error>\"","responses":{"200":{"description":"python source (X-Cx-Sig-Server; sha256 in /cx-manifest.json)"}}}},
"/cx.mjs":{"get":{"summary":"Zero-install cx client (Node 20+)","responses":{"200":{"description":"javascript source"}}}},
"/cx.sh":{"get":{"summary":"Zero-install cx client (POSIX sh + curl): token ops and the wait lane","responses":{"200":{"description":"shell source"}}}},
"/e2e.py":{"get":{"summary":"E2EE reference client (Python stdlib): the full DVR, cs=1, tier markers","responses":{"200":{"description":"python source"}}}},
"/e2e.mjs":{"get":{"summary":"E2EE reference client (Node 20+ native crypto): the same DVR","responses":{"200":{"description":"javascript source"}}}},
"/e2e-vectors.json":{"get":{"summary":"Cross-implementation crypto test vectors (self-test a reimplementation)","responses":{"200":{"description":"json"}}}},
"/seal.py":{"get":{"summary":"seal2: sealed-memory recipe (SPEC-v2 26.4), Python stdlib","responses":{"200":{"description":"python source"}}}},
"/seal.mjs":{"get":{"summary":"seal2: sealed-memory recipe (SPEC-v2 26.4), Node","responses":{"200":{"description":"javascript source"}}}},
"/srchash.py":{"get":{"summary":"src_hash recipe for content-blind source agreement (SPEC-v2 27.3)","responses":{"200":{"description":"python source"}}}},
"/cx-manifest.json":{"get":{"summary":"Signed {version, files:{name: sha256}, built_from}; verify a fetched client against the mirror copy","responses":{"200":{"description":"json (X-Cx-Sig-Server)"}}}}
}}`)
