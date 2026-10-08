package kb

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/know"
	"ekaii.fr/commons/internal/scrub"
)

// trace.go (SPEC-v2 27.2 "paste the whole traceback"): POST /e and POST /q take a whole traceback
// or a log chunk (text/plain or form field `text`, <= 16 KiB / 400 lines, anonymous, no PoW, cost
// 2, 60/h per IP group and 240/h per super) and reply with the error signature, the KB hits, the
// top fix and the libraries recognised in the frame paths. POST /v1/q is the body twin of GET /q/
// (a JSON/text body with q, kind, k, env). GET /ci is a descriptive page with the Actions/Make
// snippet. kb.FromTrace is the anchored, line-based recogniser the handler builds on.

const (
	traceMaxBytes = maxBody // 16 KiB
	traceMaxLines = 400
	traceEPerHour = 60 // per IP group; the super-group cap is 4x (core.UseNetQuota)
	traceFixCap   = 480
	traceRawPass  = 240 // chars of the raw error line used as the first search query
)

// RegisterTrace mounts the traceback lane next to Register's routes: POST /e, POST /q, POST /v1/q
// and the descriptive GET /ci, with the read scopes, the limiter cost and the OpenAPI fragment.
func RegisterTrace(mux *http.ServeMux, d *core.Deps) {
	h := &traceHandlers{d}
	mux.HandleFunc("POST /e", h.trace)
	mux.HandleFunc("POST /q", h.trace)
	mux.HandleFunc("POST /v1/q", h.bodyQuery)
	mux.HandleFunc("GET /ci", h.ci)
	d.RegisterScope("POST /e", "kb:r")
	d.RegisterScope("POST /q", "kb:r")
	d.RegisterScope("POST /v1/q", "kb:r")
	d.RegisterScope("GET /ci", "kb:r")
	d.RegisterCost("POST /e", 2)
	d.RegisterCost("POST /q", 2)
	d.RegisterCost("POST /v1/q", 2)
	d.RegisterOpenAPI(traceOpenAPI)
	registerDry(mux, d)
}

type traceHandlers struct{ d *core.Deps }

// --- FromTrace: the recogniser --------------------------------------------------------------------

// errShaped is the generic last-resort recogniser: a `\b\w+(Error|Exception|Panic|Fault)\b` token.
var errShaped = regexp.MustCompile(`\b\w*(?:Error|Exception|Panic|Fault)\b`)

var (
	reSitePackages = regexp.MustCompile(`site-packages/([A-Za-z0-9_][A-Za-z0-9_.-]*)/`)
	reDistPackages = regexp.MustCompile(`dist-packages/([A-Za-z0-9_][A-Za-z0-9_.-]*)/`)
	reNodeModules  = regexp.MustCompile(`node_modules/(@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)`)
	reGoMod        = regexp.MustCompile(`/pkg/mod/((?:[A-Za-z0-9_.~-]+(?:\.[A-Za-z0-9_.~-]+)+/)?[^@\s:]+)@v([0-9][0-9A-Za-z.+-]*)`)
	reCargoReg     = regexp.MustCompile(`registry/src/[^/]+/([A-Za-z0-9_][A-Za-z0-9_-]*)-([0-9][0-9A-Za-z.+-]*)/`)
	reMavenRepo    = regexp.MustCompile(`/\.m2/repository/(?:[A-Za-z0-9_.-]+/)+([A-Za-z0-9_.-]+)/([0-9][0-9A-Za-z.-]*)/`)
)

// lang recognisers are anchored to the shape of each runtime's first dump lines.
var (
	rePyTraceback  = regexp.MustCompile(`^Traceback \(most recent call last\):`)
	rePyException  = regexp.MustCompile(`^([A-Za-z_][A-Za-z0-9_.]*(?:Error|Exception|Warning|Interrupt|Exit|Flow|Iteration)):?(?:\s|$)`)
	reNodeErr      = regexp.MustCompile(`^(?:Uncaught )?(?:[A-Za-z_][A-Za-z0-9_$]*(?:Error|Exception)|Error)\b`)
	reNodeFrame    = regexp.MustCompile(`^\s+at\s`)
	reGoPanic      = regexp.MustCompile(`^(?:panic:|fatal error:)\s`)
	reGoroutine    = regexp.MustCompile(`^goroutine \d+ \[`)
	reJavaThread   = regexp.MustCompile(`^Exception in thread ".*"\s`)
	reJavaCausedBy = regexp.MustCompile(`^Caused by:\s`)
	reJavaFrame    = regexp.MustCompile(`^\s+at\s`)
	reRustPanic    = regexp.MustCompile(`^thread '.*' panicked at `)
	reDotnetHead   = regexp.MustCompile(`^Unhandled exception\.\s`)
)

// FromTrace recognises a whole traceback or log chunk (SPEC-v2 27.2): it returns the error
// signature (normalised by ErrSig), the libraries pulled from the frame paths (innermost first,
// <= 8, no DB resolution), and the detected language ("python", "node", "go", "java", "rust",
// "dotnet", or "" for the generic last-error-shaped line). It is a pure function: the handler
// resolves the raw lib names through know.ResolveLib.
func FromTrace(b []byte) (sig string, libs []LibVer, lang string) {
	text := scrub.Normalize(strings.ToValidUTF8(string(b), ""))
	lines := splitLines(text)
	sigLine, lang := recognise(lines)
	if sigLine == "" {
		// generic: the last error-shaped line (a bare log line counts).
		for i := len(lines) - 1; i >= 0; i-- {
			if errShaped.MatchString(lines[i]) {
				sigLine = strings.TrimSpace(lines[i])
				break
			}
		}
	}
	if sigLine != "" {
		sig = ErrSig(sigLine)
	}
	// Message-named modules (the culprit a `No module named 'x'` / `Cannot find module 'x'` line
	// names) are the most relevant libs, so they come before the ones pulled from frame paths.
	libs = mergeLibs(libsFromMessage(lines), extractLibs(lines, lang))
	return sig, libs, lang
}

var (
	rePyMissing   = regexp.MustCompile(`No module named ['"]([A-Za-z0-9_.]+)['"]`)
	rePyImport    = regexp.MustCompile(`cannot import name ['"][^'"]+['"] from ['"]([A-Za-z0-9_.]+)['"]`)
	reNodeMissing = regexp.MustCompile(`Cannot find module ['"](@[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+|[A-Za-z0-9_.-]+)['"]`)
)

// libsFromMessage pulls the module an import error names (Python ModuleNotFoundError / ImportError,
// Node MODULE_NOT_FOUND); the top-level package is kept (`foo.bar` -> `foo`).
func libsFromMessage(lines []string) []LibVer {
	var out []LibVer
	for _, l := range lines {
		if m := rePyMissing.FindStringSubmatch(l); m != nil {
			out = append(out, LibVer{Lib: topPkg(m[1]), Ver: ""})
		}
		if m := rePyImport.FindStringSubmatch(l); m != nil {
			out = append(out, LibVer{Lib: topPkg(m[1]), Ver: ""})
		}
		if m := reNodeMissing.FindStringSubmatch(l); m != nil && !strings.HasPrefix(m[1], ".") {
			out = append(out, LibVer{Lib: strings.ToLower(m[1]), Ver: ""})
		}
	}
	return out
}

// topPkg is the top-level package of a dotted module path (`foo.bar.baz` -> `foo`), lowercased.
func topPkg(name string) string {
	if i := strings.IndexByte(name, '.'); i > 0 {
		name = name[:i]
	}
	return strings.ToLower(name)
}

// mergeLibs concatenates lib lists, dedupes by name (first wins), caps at maxLibs.
func mergeLibs(lists ...[]LibVer) []LibVer {
	var out []LibVer
	seen := map[string]bool{}
	for _, list := range lists {
		for _, lv := range list {
			if lv.Lib == "" || seen[lv.Lib] || len(out) >= maxLibs {
				continue
			}
			seen[lv.Lib] = true
			out = append(out, lv)
		}
	}
	return out
}

// recognise finds the signature-bearing line and the language from anchored line shapes.
func recognise(lines []string) (sigLine, lang string) {
	// Python: the exception line is the last non-indented line after a Traceback header.
	tbStart := -1
	for i, l := range lines {
		if rePyTraceback.MatchString(l) {
			tbStart = i
		}
	}
	if tbStart >= 0 {
		for i := len(lines) - 1; i > tbStart; i-- {
			l := lines[i]
			if l == "" || strings.HasPrefix(l, " ") || strings.HasPrefix(l, "\t") {
				continue
			}
			if rePyException.MatchString(l) || strings.HasPrefix(l, "  File \"") {
				continue // the caret/context lines; keep scanning up
			}
			if m := rePyException.FindString(l); m != "" || errShaped.MatchString(l) {
				return strings.TrimSpace(l), "python"
			}
		}
		// fall through: a Traceble with a bare exception type line
		for i := len(lines) - 1; i > tbStart; i-- {
			if rePyException.MatchString(lines[i]) {
				return strings.TrimSpace(lines[i]), "python"
			}
		}
	}
	// Go: a panic/fatal line followed by a goroutine dump.
	for i, l := range lines {
		if reGoPanic.MatchString(l) {
			for j := i + 1; j < len(lines); j++ {
				if reGoroutine.MatchString(lines[j]) {
					return strings.TrimSpace(l), "go"
				}
			}
		}
	}
	// Rust: thread '…' panicked at '…', src/…:N:N
	for _, l := range lines {
		if reRustPanic.MatchString(l) {
			return strings.TrimSpace(l), "rust"
		}
	}
	// .NET: Unhandled exception. <Type>: <msg> then "   at …" frames.
	for _, l := range lines {
		if reDotnetHead.MatchString(l) {
			return strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(l), "Unhandled exception.")), "dotnet"
		}
	}
	// Java/Kotlin: Exception in thread "…" <Type>: <msg> or Caused by:, with "\tat …" frames.
	for i, l := range lines {
		if reJavaThread.MatchString(l) && hasFrame(lines, i, reJavaFrame) {
			return strings.TrimSpace(l), "java"
		}
	}
	for i, l := range lines {
		if reJavaCausedBy.MatchString(l) && hasFrame(lines, i, reJavaFrame) {
			return strings.TrimSpace(l), "java"
		}
	}
	// Node: an Error line with at least one "    at …" frame below it.
	for i, l := range lines {
		if reNodeErr.MatchString(l) && hasFrame(lines, i, reNodeFrame) {
			return strings.TrimSpace(l), "node"
		}
	}
	return "", ""
}

// hasFrame reports whether any line after i matches the frame pattern (within a short window).
func hasFrame(lines []string, i int, re *regexp.Regexp) bool {
	for j := i + 1; j < len(lines) && j <= i+60; j++ {
		if re.MatchString(lines[j]) {
			return true
		}
	}
	return false
}

// extractLibs pulls (name, ver) pairs from the frame paths, innermost first, deduped, capped at 8.
// For Python the deepest frame is printed last, so frames are read bottom-up; the other runtimes
// print the innermost frame first.
func extractLibs(lines []string, lang string) []LibVer {
	order := lines
	if lang == "python" {
		order = make([]string, len(lines))
		for i := range lines {
			order[i] = lines[len(lines)-1-i]
		}
	}
	var out []LibVer
	seen := map[string]bool{}
	add := func(name, ver string) {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] || len(out) >= maxLibs {
			return
		}
		seen[name] = true
		out = append(out, LibVer{Lib: strings.ToLower(name), Ver: ver})
	}
	for _, l := range order {
		if m := reGoMod.FindStringSubmatch(l); m != nil {
			add(m[1], m[2])
		}
		if m := reCargoReg.FindStringSubmatch(l); m != nil {
			add(m[1], m[2])
		}
		if m := reMavenRepo.FindStringSubmatch(l); m != nil {
			add(m[1], m[2])
		}
		if m := reSitePackages.FindStringSubmatch(l); m != nil {
			add(m[1], "")
		}
		if m := reDistPackages.FindStringSubmatch(l); m != nil {
			add(m[1], "")
		}
		if m := reNodeModules.FindStringSubmatch(l); m != nil {
			add(m[1], "")
		}
	}
	return out
}

func splitLines(text string) []string {
	sc := bufio.NewScanner(bytes.NewReader([]byte(text)))
	sc.Buffer(make([]byte, 0, 64<<10), traceMaxBytes+1<<10)
	var out []string
	for sc.Scan() {
		out = append(out, strings.TrimRight(sc.Text(), "\r"))
		if len(out) >= traceMaxLines {
			break
		}
	}
	return out
}

// --- POST /e, POST /q -----------------------------------------------------------------------------

// trace is POST /e and POST /q: read the body (capped), recognise it, search raw + sig + top-lib
// tag, and reply with the signature, hits, top fix and libs. Zero hits -> 404 + a wanted record.
func (h *traceHandlers) trace(w http.ResponseWriter, r *http.Request) {
	if h.d.Frozen("read") {
		doc.Fail(w, r, core.Frozen("read"))
		return
	}
	body, err := h.readTrace(w, r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	_, _, super := core.ClientFrom(ctx)
	root := ""
	if id, _ := h.d.AuthOpt(r); id != nil {
		root = id.Root
	}
	if err := core.UseNetQuota(ctx, h.d.DB, h.d.ClientIP(r), hourKind("e"), traceEPerHour); err != nil {
		doc.Fail(w, r, err)
		return
	}

	sig, rawLibs, lang := FromTrace(body)
	// The signature is echoed tier-2 masked; a tier-1 hit in the raw text means nothing but the
	// masked signature is ever shown. Either way the body is never stored or echoed.
	echoSig := maskSig(sig)
	rawLine := firstErrLine(body)

	res := h.runSearch(ctx, body, rawLine, sig, rawLibs)

	if len(res.hits) == 0 {
		// Record the demand (error signature + every extracted lib@ver), then 404. Nothing stored.
		if echoSig != "" {
			know.RecordMiss(ctx, h.d.DB, "e", echoSig, super, root)
		}
		for _, lv := range res.libs {
			if lv.Key != "" && lv.Ver != "" {
				know.RecordMiss(ctx, h.d.DB, "v", lv.Key+"@"+lv.Ver, super, root)
			}
		}
		h.reply404(w, r, echoSig, res.libs)
		return
	}

	h.replyHits(w, r, echoSig, lang, utf8.RuneCount(body), res)
}

// readTrace reads the POST body: text/plain (the whole body) or a form field `text`, capped at 16
// KiB and 400 lines. An empty body is a 400.
func (h *traceHandlers) readTrace(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	core.MaxBytes(w, r, traceMaxBytes)
	if isForm(r) {
		if err := r.ParseForm(); err != nil {
			return nil, core.Bad("form")
		}
		s := r.PostFormValue("text")
		if s == "" {
			s = r.PostFormValue("q")
		}
		if strings.TrimSpace(s) == "" {
			return nil, core.Bad("empty body (field text)")
		}
		return []byte(s), nil
	}
	b, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, core.Bad("empty body (text/plain traceback or form field text)")
	}
	return b, nil
}

// searchResult holds the merged hits, the resolved libs and the top entry's fix.
type searchResult struct {
	hits []Hit
	libs []resolvedLib
	fix  string
}

type resolvedLib struct {
	LibVer
	Key string // eco:name, "" when unresolved
}

// runSearch runs the three passes (raw error line, signature, top lib) and dedups by id.
func (h *traceHandlers) runSearch(ctx context.Context, body []byte, rawLine, sig string, rawLibs []LibVer) searchResult {
	libs := h.resolveLibs(ctx, rawLibs)
	seen := map[string]bool{}
	var hits []Hit
	merge := func(q string) {
		if strings.TrimSpace(q) == "" {
			return
		}
		got, err := SearchV2(ctx, h.d.DB, SearchOpts{Q: q, K: 5, Anon: true})
		if err != nil {
			return
		}
		for _, hit := range got {
			if !seen[hit.ID] {
				seen[hit.ID] = true
				hits = append(hits, hit)
			}
		}
	}
	merge(truncRunes(rawLine, traceRawPass))
	if sig != rawLine {
		merge(sig)
	}
	if len(libs) > 0 {
		merge(libs[0].Lib)
	}
	res := searchResult{hits: hits, libs: libs}
	if len(hits) > 0 {
		if e, err := GetV2(ctx, h.d.DB, hits[0].ID, GetOpts{}); err == nil {
			res.fix = truncRunes(doc.SafeLine(e.Fix), traceFixCap)
		}
	}
	return res
}

// resolveLibs resolves each raw lib name through know.ResolveLib (canonical eco:name) for the
// wanted records and the /v/ links; the bare display name is kept either way.
func (h *traceHandlers) resolveLibs(ctx context.Context, raw []LibVer) []resolvedLib {
	out := make([]resolvedLib, 0, len(raw))
	for _, lv := range raw {
		rl := resolvedLib{LibVer: lv}
		if key, ok := know.ResolveLib(ctx, h.d.DB, lv.Lib); ok {
			rl.Key = key
		}
		out = append(out, rl)
	}
	return out
}

// --- replies --------------------------------------------------------------------------------------

func (h *traceHandlers) replyHits(w http.ResponseWriter, r *http.Request, sig, lang string, rawChars int, res searchResult) {
	canon := "/e/" + sigSeg(sig)
	switch r.URL.Query().Get("f") {
	case "gha":
		h.replyGHA(w, r, res)
		return
	}
	switch doc.Negotiate(r) {
	case doc.JSON:
		h.replyJSON(w, r, sig, lang, rawChars, res, canon)
		return
	case doc.MD:
		h.replyMD(w, r, sig, rawChars, res, canon)
		return
	}
	w.Header().Add("Link", "<"+canon+`>; rel="canonical"`)
	doc.Tail(w, r, traceText(sig, rawChars, res), traceNext(sig, res.libs)...)
}

// traceText is the shared txt body of a hit reply (head, hits, top fix, libs): the HTTP txt path
// and the MCP op both render it, the op without a next: tail.
func traceText(sig string, rawChars int, res searchResult) string {
	var b strings.Builder
	b.WriteString("e: " + sig + " hits=" + strconv.Itoa(len(res.hits)) + " raw=" + strconv.Itoa(rawChars) + " chars\n")
	for _, hit := range res.hits {
		b.WriteString(hit.Line() + "\n")
	}
	if res.fix != "" {
		b.WriteString("fix: " + res.fix + "\n")
	}
	if line := libsLine(res.libs); line != "" {
		b.WriteString(line + "\n")
	}
	return b.String()
}

// replyGHA emits only the GitHub Actions `::notice` command per hit (27.2): the title is the fixed
// literal and the message is the entry title + its permalink, with %, CR and LF percent-encoded. No
// other workflow command is ever emitted.
func (h *traceHandlers) replyGHA(w http.ResponseWriter, r *http.Request, res searchResult) {
	var b strings.Builder
	for _, hit := range res.hits {
		msg := ghaEscapeData(doc.SafeLine(hit.Title) + " " + Permalink(hit.ID))
		b.WriteString("::notice title=agents.ekaii.fr::" + msg + "\n")
	}
	hd := w.Header()
	hd.Set("Content-Type", "text/plain; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	hd.Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	w.Write([]byte(b.String()))
}

func (h *traceHandlers) replyJSON(w http.ResponseWriter, r *http.Request, sig, lang string, rawChars int, res searchResult, canon string) {
	libs := make([]map[string]string, 0, len(res.libs))
	for _, lv := range res.libs {
		m := map[string]string{"lib": lv.Lib}
		if lv.Ver != "" {
			m["ver"] = lv.Ver
		}
		if lv.Key != "" {
			m["key"] = lv.Key
		}
		libs = append(libs, m)
	}
	w.Header().Add("Link", "<"+canon+`>; rel="canonical"`)
	core.JSON(w, 200, map[string]any{
		"sig": sig, "lang": lang, "raw_chars": rawChars, "hits": res.hits,
		"fix": res.fix, "libs": libs, "next": actionStrings(traceNext(sig, res.libs)),
	})
}

func (h *traceHandlers) replyMD(w http.ResponseWriter, r *http.Request, sig string, rawChars int, res searchResult, canon string) {
	var b strings.Builder
	b.WriteString("# error: " + doc.MDEscape(sig) + "\n\n")
	b.WriteString("Matched " + strconv.Itoa(len(res.hits)) + " entr" + plural(len(res.hits), "y", "ies") + " (" + strconv.Itoa(rawChars) + " chars in).\n")
	for _, hit := range res.hits {
		b.WriteString("\n- [" + doc.MDEscape(hit.Title) + "](" + Permalink(hit.ID) + ")")
	}
	if res.fix != "" {
		b.WriteString("\n\n## top fix\n\n" + res.fix + "\n")
	}
	if line := libsLine(res.libs); line != "" {
		b.WriteString("\n**" + line + "**\n")
	}
	hd := w.Header()
	hd.Add("Link", "<"+canon+`>; rel="canonical"`)
	hd.Set("Content-Type", "text/markdown; charset=utf-8")
	hd.Set("Cache-Control", "no-store")
	w.WriteHeader(200)
	w.Write([]byte(b.String()))
}

// reply404 answers a zero-hit traceback: 404 with the signature, the libs and the post/search next.
func (h *traceHandlers) reply404(w http.ResponseWriter, r *http.Request, sig string, libs []resolvedLib) {
	next := []doc.Action{doc.POST("/v1/kb", "title="+sig), doc.GET("/q/"+url.PathEscape(sig), "")}
	if len(libs) > 0 {
		next = append([]doc.Action{doc.GET("/v/"+url.PathEscape(libs[0].Lib), "")}, next...)
	}
	msg := "no entry for " + sig
	if sig == "" {
		msg = "no error signature recognised"
	}
	if line := libsLine(libs); line != "" {
		msg += " (" + line + ")"
	}
	doc.Fail(w, r, core.E(404, "notfound", msg), next...)
}

// traceNext are the next: actions of a hit reply: the canonical error page, the first lib version
// page, and a draft post.
func traceNext(sig string, libs []resolvedLib) []doc.Action {
	next := []doc.Action{doc.GET("/e/"+sigSeg(sig), "")}
	if len(libs) > 0 {
		lv := libs[0]
		seg := "/v/" + url.PathEscape(lv.Lib)
		if lv.Ver != "" {
			seg += "/" + url.PathEscape(lv.Ver)
		}
		next = append(next, doc.GET(seg, ""))
	}
	return append(next, doc.POST("/v1/kb", "title="+sig))
}

// --- POST /v1/q: the GET /q/ body twin ------------------------------------------------------------

type bodyQueryInput struct {
	Q     string `json:"q"`
	Kind  string `json:"kind"`
	K     int    `json:"k"`
	Env   string `json:"env"`
	Space string `json:"space"`
}

// bodyQuery is POST /v1/q: GET /q/ semantics carried in a JSON or text body (q, kind, k, env).
func (h *traceHandlers) bodyQuery(w http.ResponseWriter, r *http.Request) {
	id, err := h.d.AuthOpt(r)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	var in bodyQueryInput
	if err := core.Decode(w, r, 8<<10, &in); err != nil {
		doc.Fail(w, r, err)
		return
	}
	ctx := r.Context()
	if err := core.UseNetQuota(ctx, h.d.DB, h.d.ClientIP(r), hourKind("e"), traceEPerHour); err != nil {
		doc.Fail(w, r, err)
		return
	}
	o := SearchOpts{Q: in.Q, Kind: in.Kind, K: parseK(strconv.Itoa(in.K)), Env: in.Env, Space: in.Space, Anon: id == nil}
	hits, err := SearchV2(ctx, h.d.DB, o)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if TelemetryFn != nil {
		key := clientKey(ctx, id)
		for _, hit := range hits {
			TelemetryFn(ctx, hit.ID, "impression", key)
		}
	}
	if doc.Negotiate(r) == doc.JSON {
		doc.ReplyJSONArray(w, r, 200, hits)
		return
	}
	next := []doc.Action{doc.POST("/v1/kb", "token"), doc.POST("/w/kb", "+X-PoW")}
	if len(hits) > 0 {
		next = append([]doc.Action{doc.GET("/v1/kb/"+hits[0].ID, "")}, next...)
	}
	doc.Tail(w, r, hitsText(hits), next...)
}

// --- GET /ci --------------------------------------------------------------------------------------

func (h *traceHandlers) ci(w http.ResponseWriter, r *http.Request) {
	base := doc.Base()
	out := &doc.Doc{
		Head:  "ci: pipe a failing build log to " + base + "/e and get the matching fixes back",
		Title: "CI integration · agents.ekaii.fr",
		Desc:  "Pipe a failing build or test log to POST /e from GitHub Actions or a Makefile and read the matching KB entries back, as plain text, JSON, Markdown or ::notice annotations.",
		Fields: []doc.F{
			{Name: "post", Val: "POST " + base + "/e (text/plain traceback or form field text, <= 16 KiB / 400 lines, anonymous, no PoW)"},
			{Name: "curl", Val: "curl -sS --data-binary @build.log '" + base + "/e'"},
			{Name: "actions", Val: "run: curl -sS --data-binary @build.log '" + base + "/e?f=gha'  # emits ::notice annotations"},
			{Name: "make", Val: "ci-fixes: ; -@$(MAKE) build 2>&1 | tee build.log; curl -sS --data-binary @build.log '" + base + "/e'"},
			{Name: "formats", Val: "?f=gha (GitHub annotations) | ?f=json | ?f=md | default text"},
		},
		MaxAge: 3600,
		Next:   doc.Next(doc.POST("/e", "paste a traceback"), doc.GET("/q/{q}", "search"), doc.GET("/grammar", "")),
	}
	doc.Reply(w, r, 200, out)
}

// --- helpers --------------------------------------------------------------------------------------

// hourKind buckets a counter kind by the UTC hour so a daily counter enforces a per-hour cap.
func hourKind(base string) string {
	return base + strconv.Itoa(time.Now().UTC().Hour())
}

// maskSig runs tier-1 + tier-2 masking over a signature so nothing sensitive is ever echoed.
func maskSig(sig string) string {
	if sig == "" {
		return ""
	}
	out, _ := scrub.Mask(sig)
	return out
}

// firstErrLine is the first error-shaped line of the body (the raw search query); it falls back to
// the first non-empty line.
func firstErrLine(body []byte) string {
	lines := splitLines(scrub.Normalize(strings.ToValidUTF8(string(body), "")))
	for _, l := range lines {
		if errShaped.MatchString(l) {
			return strings.TrimSpace(l)
		}
	}
	for _, l := range lines {
		if strings.TrimSpace(l) != "" {
			return strings.TrimSpace(l)
		}
	}
	return ""
}

// libsLine renders `libs: name@ver name` (versions omitted when unknown); "" for no libs.
func libsLine(libs []resolvedLib) string {
	if len(libs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(libs))
	for _, lv := range libs {
		p := lv.Lib
		if lv.Ver != "" {
			p += "@" + lv.Ver
		}
		parts = append(parts, p)
	}
	return "libs: " + strings.Join(parts, " ")
}

// sigSeg is the signature as one path segment for /e/<sig> (percent-encoded).
func sigSeg(sig string) string { return url.PathEscape(sig) }

// ghaEscapeData percent-encodes %, CR and LF for a GitHub Actions command's data part.
func ghaEscapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// TraceOpMeta describes the trace op for the MCP registry (3.5); a later integration package merges
// it into the gateway's op table alongside kb.OpMeta.
var TraceOpMeta = map[string]core.OpMeta{
	"e": {Scope: "kb:r", Cost: 2},
}

// TraceOps returns the MCP ops of this file: e, the traceback lane (`cx e -` reads stdin). It runs
// the same recogniser and search as POST /e and returns the txt reply without a next: tail.
func TraceOps(d *core.Deps) map[string]Op {
	h := &traceHandlers{d}
	return map[string]Op{
		"e": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				Text string `json:"text"`
			}
			if len(a) > 0 {
				if err := json.Unmarshal(a, &in); err != nil {
					return "", core.Bad("a: " + err.Error())
				}
			}
			body := []byte(in.Text)
			if len(bytes.TrimSpace(body)) == 0 {
				return "", core.Bad("text: empty traceback")
			}
			if len(body) > traceMaxBytes {
				body = body[:traceMaxBytes]
			}
			_, _, super := core.ClientFrom(ctx)
			root := ""
			if id != nil {
				root = id.Root
			}
			sig, rawLibs, _ := FromTrace(body)
			echoSig := maskSig(sig)
			res := h.runSearch(ctx, body, firstErrLine(body), sig, rawLibs)
			if len(res.hits) == 0 {
				if echoSig != "" {
					know.RecordMiss(ctx, d.DB, "e", echoSig, super, root)
				}
				for _, lv := range res.libs {
					if lv.Key != "" && lv.Ver != "" {
						know.RecordMiss(ctx, d.DB, "v", lv.Key+"@"+lv.Ver, super, root)
					}
				}
				return "", core.E(404, "notfound", "no entry for "+echoSig)
			}
			return traceText(echoSig, utf8.RuneCount(body), res), nil
		},
	}
}

var traceOpenAPI = json.RawMessage(`{"paths":{
"/e":{"post":{"operationId":"e","summary":"Paste a whole traceback or log chunk (text/plain or form field text, <= 16 KiB / 400 lines, anonymous, no PoW): error signature + KB hits + top fix + recognised libs. ?f=gha emits GitHub ::notice lines, ?f=json, ?f=md","requestBody":{"content":{"text/plain":{"schema":{"type":"string"}},"application/x-www-form-urlencoded":{"schema":{"type":"object","properties":{"text":{"type":"string"}}}}}},"responses":{"200":{"description":"e: <sig> hits=<n> raw=<n> chars, then hits, fix:, libs:, next: and Link rel=canonical /e/<sig>"},"404":{"description":"err notfound (no entry; the signature and libs become wanted records)"},"429":{"description":"err quota"}}}},
"/q":{"post":{"operationId":"eq","summary":"Alias of POST /e (paste a traceback)","requestBody":{"content":{"text/plain":{"schema":{"type":"string"}}}},"responses":{"200":{"description":"same as POST /e"}}}},
"/v1/q":{"post":{"operationId":"qbody","summary":"GET /q/ with a body (q, kind, k, env): search the KB","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"q":{"type":"string","maxLength":1000},"kind":{"type":"string","enum":["fix","status","note","antipattern"]},"k":{"type":"integer","maximum":20},"env":{"type":"string","maxLength":200},"space":{"type":"string","maxLength":40}}}}}},"responses":{"200":{"description":"one hit per line, then next:"}}}},
"/ci":{"get":{"operationId":"ci","summary":"Descriptive CI integration page (GitHub Actions / Make snippet for POST /e)","responses":{"200":{"description":"the snippet and formats"}}}}
}}`)
