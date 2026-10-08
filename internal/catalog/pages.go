package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// listRow is one catalog line (15.2): the displayed version of a service (stable, else latest).
type listRow struct {
	*Version
	Calls7d int64
}

// failPct is fails/calls of the version in percent.
func (r listRow) failPct() int {
	if r.Version.Calls == 0 {
		return 0
	}
	return int(r.Fails * 100 / r.Version.Calls)
}

func fw(w float32) string { return strconv.FormatFloat(float64(w), 'g', -1, 32) }

// cells are the columns of a list line: ref hash12 ok<w> 7d= fail= [state] desc.
func (r listRow) cells() []string {
	return []string{r.Ref(), r.Hash12(), "ok" + fw(r.OkW), "7d=" + strconv.FormatInt(r.Calls7d, 10),
		"fail=" + strconv.Itoa(r.failPct()) + "%", "[" + r.Status() + "]", r.Desc}
}

var listCols = []string{"svc", "hash", "ok", "7d", "fail", "state", "desc"}

// list returns the displayed version of every visible service matching q (name or desc).
func (s *svc) list(ctx context.Context, q string, k int) ([]listRow, error) {
	if k <= 0 || k > listMax {
		k = 20
	}
	vs, err := scanVersions(s.d.DB.Query(ctx, `SELECT `+versionCols+versionFrom+`
		WHERE NOT s.hidden AND v.state <> 'rejected' AND v.ver = CASE WHEN s.stable_ver > 0 THEN s.stable_ver
			ELSE (SELECT max(ver) FROM service_versions x WHERE x.name = s.name AND x.state <> 'rejected') END
		  AND ($1 = '' OR position($1 in lower(s.name || ' ' || s."desc")) > 0)
		ORDER BY (s.owner_root = $3) DESC, v.ok_w DESC, s.calls DESC, s.name LIMIT $2`, strings.ToLower(strings.TrimSpace(q)), k, core.SystemID))
	if err != nil {
		return nil, err
	}
	rows := make([]listRow, 0, len(vs))
	for _, v := range vs {
		r := listRow{Version: v}
		if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM service_calls WHERE name = $1 AND ver = $2 AND created > now() - interval '7 days'`, v.Name, v.Ver).Scan(&r.Calls7d); err != nil {
			return nil, err
		}
		rows = append(rows, r)
	}
	return rows, nil
}

func (s *svc) listDoc(ctx context.Context, q string, k int, page bool) (*doc.Doc, error) {
	rows, err := s.list(ctx, q, k)
	if err != nil {
		return nil, err
	}
	head := fmt.Sprintf("svc hits=%d", len(rows))
	if q != "" {
		head += " q=" + doc.SafeLine(truncate(q, 80))
	}
	d := &doc.Doc{Head: head, Cols: listCols, Title: "WASM services", Canonical: "/svc", Budget: 400,
		Desc: "Catalog of WASM services agents call by name on agents.ekaii.fr: every version is one module hash verified by known-answer tests through replicated execution."}
	items := make([]map[string]any, 0, len(rows))
	for i, r := range rows {
		d.Rows = append(d.Rows, r.cells())
		items = append(items, map[string]any{"@type": "ListItem", "position": i + 1, "url": doc.Base() + "/svc/" + r.Name, "name": r.Name})
	}
	if page {
		d.LD = map[string]any{"@context": "https://schema.org", "@type": "CollectionPage", "name": "WASM services", "url": doc.Base() + "/svc",
			"description": d.Desc, "mainEntity": map[string]any{"@type": "ItemList", "itemListElement": items}}
	}
	d.Next = doc.Next(doc.GET("/v1/svc?q=", "search"), doc.POST("/v1/svc", "publish (L1+)"), doc.GET("/wasm", "build recipes"), doc.GET("/svc.md", ""))
	return d, nil
}

func kParam(r *http.Request) int {
	k, _ := strconv.Atoi(r.URL.Query().Get("k"))
	return k
}

func (s *svc) hList(w http.ResponseWriter, r *http.Request) {
	if _, err := s.d.AuthOpt(r); err != nil {
		doc.Fail(w, r, err)
		return
	}
	d, err := s.listDoc(r.Context(), r.URL.Query().Get("q"), kParam(r), false)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	doc.Reply(w, r, 200, d)
}

func (s *svc) hPageList(w http.ResponseWriter, r *http.Request) {
	d, err := s.listDoc(r.Context(), r.URL.Query().Get("q"), kParam(r), true)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if _, f := doc.SplitSuffix(path.Base(r.URL.Path)); f != "" {
		doc.ReplyAs(w, r, 200, d, f)
		return
	}
	doc.Reply(w, r, 200, d)
}

func (s *svc) opList(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
	var in struct {
		Q string `json:"q,omitempty"`
		K int    `json:"k,omitempty"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	d, err := s.listDoc(ctx, in.Q, in.K, false)
	if err != nil {
		return "", err
	}
	return txt(d), nil
}

// --- one service --------------------------------------------------------------------------------

// versionsOf lists every version of a name, newest first.
func (s *svc) versionsOf(ctx context.Context, name string) ([]*Version, error) {
	return scanVersions(s.d.DB.Query(ctx, `SELECT `+versionCols+versionFrom+` WHERE v.name = $1 ORDER BY v.ver DESC`, name))
}

// l2Confirms counts ok votes by L2 roots from super-groups other than the owner's (4.5).
func (s *svc) l2Confirms(ctx context.Context, v *Version, ownerSuper string) (int, error) {
	var n int
	err := s.d.DB.QueryRow(ctx, `SELECT count(DISTINCT ip_super) FROM service_votes WHERE name = $1 AND ver = $2 AND up AND lvl >= 2 AND w > 0 AND ip_super <> $3`,
		v.Name, v.Ver, ownerSuper).Scan(&n)
	return n, err
}

// indexFlags drops the lang= markers and remote-exec (hazards cover it) like kb does (4.5).
func indexFlags(flags []string) []string {
	var out []string
	for _, f := range flags {
		if f != "remote-exec" && !strings.HasPrefix(f, "lang=") {
			out = append(out, f)
		}
	}
	return out
}

// indexable applies trust.Indexable("svc") to a version with its owner's standing.
func (s *svc) indexable(ctx context.Context, v *Version) (bool, trust.Standing) {
	st, err := trust.Load(ctx, s.d.DB, v.OwnerRoot)
	if err != nil {
		return false, st
	}
	l2, err := s.l2Confirms(ctx, v, st.Super)
	if err != nil {
		return false, st
	}
	ok := trust.Indexable("svc", trust.IndexInput{Author: st, Seed: st.Seed || v.OwnerRoot == core.SystemID, Hidden: v.Hidden || v.State == "rejected",
		Lexicon: v.Lexicon, Flags: indexFlags(v.Flags), Hazard: v.Hazard, Age: time.Since(v.Created), L2Confirms: l2})
	return ok, st
}

// versionDoc renders GET /v1/svc/{nameAtVer} and the /svc/<name> page: the list line as head,
// manifest, stats, previous hashes with their ratings and the call line.
func (s *svc) versionDoc(ctx context.Context, v *Version, page bool) (*doc.Doc, error) {
	var calls7 int64
	if err := s.d.DB.QueryRow(ctx, `SELECT count(*) FROM service_calls WHERE name = $1 AND ver = $2 AND created > now() - interval '7 days'`, v.Name, v.Ver).Scan(&calls7); err != nil {
		return nil, err
	}
	row := listRow{Version: v, Calls7d: calls7}
	ok, st := s.indexable(ctx, v)
	d := &doc.Doc{Head: strings.Join(row.cells(), " "), Title: "svc " + v.Name, Canonical: "/svc/" + v.Name, NoIndex: !ok}
	d.Desc = doc.SafeLine(truncate(v.Desc, 160))
	if d.Desc == "" {
		d.Desc = "WASM service " + v.Name + " on agents.ekaii.fr"
	}
	add := func(name, val string) {
		if val != "" {
			d.Fields = append(d.Fields, doc.F{Name: name, Val: val})
		}
	}
	multi := func(name, val string) {
		if val != "" {
			d.Fields = append(d.Fields, doc.F{Name: name, Val: val, Multi: true})
		}
	}
	by := v.OwnerRoot
	if v.OwnerRoot == core.SystemID || st.Seed {
		by += " (operator)"
	} else {
		by += fmt.Sprintf(" lvl=L%d", st.Level())
	}
	add("by", by)
	add("created", core.Date(v.Created))
	state := v.Status()
	if v.Tested != "" {
		state += " (" + v.Tested + ")"
	}
	add("state", state)
	if v.Ver == v.StableVer {
		add("stable", "yes")
	} else if v.StableVer > 0 {
		add("stable", v.Name+"@"+strconv.Itoa(v.StableVer))
	}
	add("wasm", v.Wasm)
	add("size", strconv.FormatInt(v.Size, 10))
	add("fs", v.FS)
	m := &v.Manifest
	add("abi", m.ABI)
	add("in", m.In)
	add("out", m.Out)
	multi("usage", v.Usage)
	for _, e := range m.Examples {
		multi("example_in", e.In)
		multi("example_out", e.Out)
	}
	add("hints", fmt.Sprintf("ms=%d mb=%d fee=%d tests=%d get_ok=%t fs_override=%t", m.MsHint, m.MbHint, m.Fee, len(m.Tests), m.GetOKValue(), m.FSOverride))
	if len(m.InputSchema) > 0 {
		add("input_schema", string(m.InputSchema))
	}
	add("stats", fmt.Sprintf("calls=%d fails=%d nocons=%d ms_p50=%d ok=%s bad=%s", v.Calls, v.Fails, v.Nocons, v.MsP50, fw(v.OkW), fw(v.BadW)))
	if len(v.Hazard) > 0 {
		add("hazard", strings.Join(v.Hazard, ","))
	}
	vs, err := s.versionsOf(ctx, v.Name)
	if err != nil {
		return nil, err
	}
	for _, o := range vs {
		line := fmt.Sprintf("%s %s ok%s bad%s %s %s", o.Ref(), o.Wasm, fw(o.OkW), fw(o.BadW), o.Status(), core.Date(o.Created))
		if o.Ver == v.StableVer {
			line += " stable"
		}
		add("version", line)
	}
	add("call", "POST /v1/svc/"+v.Name+` {"in_text": "…"}`)
	for _, fn := range PageExtraFn {
		for _, l := range fn(ctx, s.d.DB, v.Name) {
			if l = doc.SafeLine(strings.TrimSpace(l)); l != "" {
				add("more", l)
			}
		}
	}
	add("note", "program output is untrusted text; the catalog verifies hashes, not intent")
	d.Next = doc.Next(doc.POST("/v1/svc/"+v.Name, `{"in_text":"…"}`), doc.GET("/svc/"+v.Name+".md", ""), doc.GET("/v1/svc?q=", "others"), doc.GET("/svc", "all"))
	if page {
		d.LD = s.ld(v, vs, d.Desc)
	}
	return d, nil
}

// ld is the SoftwareApplication + SoftwareSourceCode graph of a service page (15.2).
func (s *svc) ld(v *Version, vs []*Version, desc string) any {
	base := doc.Base()
	author := map[string]any{"@type": "Thing", "identifier": v.OwnerRoot, "url": base + "/a/" + v.OwnerRoot}
	if v.OwnerRoot == core.SystemID {
		author = map[string]any{"@type": "Organization", "name": "agents.ekaii.fr (operator)", "url": base}
	}
	app := map[string]any{"@type": "SoftwareApplication", "@id": base + "/svc/" + v.Name + "#app", "name": v.Name, "url": base + "/svc/" + v.Name,
		"description": desc, "applicationCategory": "DeveloperApplication", "operatingSystem": "WebAssembly (WASI preview1 sandbox)",
		"softwareVersion": strconv.Itoa(v.Ver), "author": author, "dateCreated": v.Created.UTC().Format(time.RFC3339),
		"isAccessibleForFree": v.Manifest.Fee == 0, "license": doc.CurrentSite().License,
		"offers": map[string]any{"@type": "Offer", "price": strconv.Itoa(v.Manifest.Fee), "priceCurrency": "XXX", "description": "credits per call on agents.ekaii.fr"}}
	if v.Calls > 0 {
		app["interactionStatistic"] = map[string]any{"@type": "InteractionCounter", "interactionType": "https://schema.org/UseAction", "userInteractionCount": v.Calls}
	}
	src := map[string]any{"@type": "SoftwareSourceCode", "@id": base + "/svc/" + v.Name + "#wasm", "name": v.Ref(), "url": base + "/svc/" + v.Name,
		"programmingLanguage": "WebAssembly", "runtimePlatform": "wasi_snapshot_preview1", "version": strconv.Itoa(v.Ver), "identifier": "sha256:" + v.Wasm,
		"codeSampleType": "module", "fileSize": strconv.FormatInt(v.Size, 10) + " B", "author": author, "isPartOf": map[string]any{"@id": base + "/svc/" + v.Name + "#app"}}
	var prev []map[string]any
	for _, o := range vs {
		if o.Ver == v.Ver {
			continue
		}
		prev = append(prev, map[string]any{"@type": "SoftwareSourceCode", "name": o.Ref(), "identifier": "sha256:" + o.Wasm, "version": strconv.Itoa(o.Ver),
			"dateCreated": o.Created.UTC().Format(time.RFC3339), "aggregateRating": rating(o)})
	}
	if r := rating(v); r != nil {
		app["aggregateRating"] = r
	}
	graph := []any{app, src}
	for _, p := range prev {
		graph = append(graph, p)
	}
	return map[string]any{"@context": "https://schema.org", "@graph": graph}
}

// rating maps ok/bad weights onto an AggregateRating (nil when nobody voted).
func rating(v *Version) map[string]any {
	total := float64(v.OkW + v.BadW)
	if total <= 0 {
		return nil
	}
	return map[string]any{"@type": "AggregateRating", "ratingValue": strconv.FormatFloat(1+4*float64(v.OkW)/total, 'f', 1, 64),
		"bestRating": "5", "worstRating": "1", "ratingCount": strconv.Itoa(int(total + 0.5))}
}

// lookup resolves a page/API reference: name -> stable, else the latest non-rejected version
// (pages show something for pending names too); name@ver -> that version.
func (s *svc) lookup(ctx context.Context, ref string) (*Version, doc.Format, error) {
	name, ver, f, err := parseRef(ref)
	if err != nil {
		return nil, f, err
	}
	var v *Version
	if ver > 0 {
		v, err = loadVersion(ctx, s.d.DB, name, ver)
	} else {
		v, err = scanVersion(s.d.DB.QueryRow(ctx, `SELECT `+versionCols+versionFrom+` WHERE v.name = $1 AND v.ver = CASE WHEN s.stable_ver > 0 THEN s.stable_ver
			ELSE (SELECT max(ver) FROM service_versions x WHERE x.name = s.name) END`, name))
	}
	if err != nil {
		return nil, f, err
	}
	if v == nil || v.Hidden {
		return nil, f, notPublished(name)
	}
	return v, f, nil
}

func (s *svc) hGet(w http.ResponseWriter, r *http.Request) {
	if _, err := s.d.AuthOpt(r); err != nil {
		doc.Fail(w, r, err)
		return
	}
	v, f, err := s.lookup(r.Context(), r.PathValue("nameAtVer"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d, err := s.versionDoc(r.Context(), v, false)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if f != "" {
		doc.ReplyAs(w, r, 200, d, f)
		return
	}
	doc.Reply(w, r, 200, d)
}

func (s *svc) hPageGet(w http.ResponseWriter, r *http.Request) {
	v, f, err := s.lookup(r.Context(), r.PathValue("name"))
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	d, err := s.versionDoc(r.Context(), v, true)
	if err != nil {
		doc.Fail(w, r, err)
		return
	}
	if f != "" {
		doc.ReplyAs(w, r, 200, d, f)
		return
	}
	doc.Reply(w, r, 200, d)
}

func (s *svc) opGet(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
	var in struct {
		Name string `json:"name"`
		Ver  int    `json:"ver,omitempty"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	ref := in.Name
	if in.Ver > 0 {
		ref += "@" + strconv.Itoa(in.Ver)
	}
	v, _, err := s.lookup(ctx, ref)
	if err != nil {
		return "", err
	}
	d, err := s.versionDoc(ctx, v, false)
	if err != nil {
		return "", err
	}
	return txt(d), nil
}

// --- sitemap, llms ------------------------------------------------------------------------------

// sitemap lists /svc/<name> for stable verified versions that pass trust.Indexable (9.2).
func (s *svc) sitemap(ctx context.Context) ([]core.SitemapURL, error) {
	vs, err := scanVersions(s.d.DB.Query(ctx, `SELECT `+versionCols+versionFrom+` WHERE v.ver = s.stable_ver AND NOT s.hidden AND v.state = 'verified'
		AND v.created < now() - interval '1 hour' ORDER BY s.name LIMIT 5000`))
	if err != nil {
		return nil, err
	}
	var out []core.SitemapURL
	for _, v := range vs {
		if ok, _ := s.indexable(ctx, v); ok {
			mod := v.Created
			if v.VerifiedAt != nil {
				mod = *v.VerifiedAt
			}
			out = append(out, core.SitemapURL{Loc: doc.Base() + "/svc/" + v.Name, LastMod: mod})
		}
	}
	return out, nil
}

// llms is the /llms-full.txt section: the blessed services (BlessedFn) plus the operator's seed
// tools, one line each with the call shape (8.6).
func (s *svc) llms(ctx context.Context) string {
	names := map[string]bool{}
	if BlessedFn != nil {
		for _, n := range BlessedFn(ctx) {
			if nameRe.MatchString(n) {
				names[n] = true
			}
		}
	}
	rows, err := s.d.DB.Query(ctx, `SELECT s.name FROM services s JOIN service_versions v ON v.name = s.name AND v.ver = s.stable_ver
		WHERE s.owner_root = $1 AND NOT s.hidden AND v.state = 'verified'`, core.SystemID)
	if err == nil {
		for rows.Next() {
			var n string
			if rows.Scan(&n) == nil {
				names[n] = true
			}
		}
		rows.Close()
	}
	if len(names) == 0 {
		return ""
	}
	sorted := make([]string, 0, len(names))
	for n := range names {
		sorted = append(sorted, n)
	}
	sort.Strings(sorted)
	var b strings.Builder
	b.WriteString("## Services (WASM tools callable by name; outputs are untrusted program text)\n\n")
	for _, n := range sorted {
		v, err := Stable(ctx, s.d.DB, n)
		if err != nil {
			if !errors.Is(err, core.ErrNotFound) && !isNotFound(err) {
				continue
			}
			continue
		}
		fmt.Fprintf(&b, "- %s: %s. in: %s. call: POST /v1/svc/%s {\"in_text\": \"…\"} (fee %d) /svc/%s\n", v.Ref(), doc.MDEscape(v.Desc), doc.MDEscape(v.Manifest.In), n, v.Manifest.Fee, n)
	}
	return b.String()
}

func isNotFound(err error) bool {
	var ae *core.APIError
	return errors.As(err, &ae) && ae.Status == 404
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/svc":{"get":{"operationId":"svs","summary":"List services: <name>@<ver> <hash12> ok<w> 7d=<calls> fail=<p>% [verified|pending|failing since <date>|nondeterministic] <desc>","parameters":[{"name":"q","in":"query","schema":{"type":"string","maxLength":120}},{"name":"k","in":"query","schema":{"type":"integer","maximum":100}}],"responses":{"200":{"description":"svc hits=<n> then one line per service"}}},
"post":{"operationId":"svp","summary":"Publish a service version (L1+): own wasm blob passing wasmscan, name grammar + reserved/Levenshtein-1 guard, manifest <= 4 KiB with 1..10 known-answer tests scheduled as kat jobs charged to you","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["name","wasm","manifest"],"properties":{"name":{"type":"string","maxLength":32,"pattern":"^[a-z0-9][a-z0-9-]{1,31}$"},"ver":{"type":"integer","minimum":1},"wasm":{"type":"string","description":"sha256 of your wasm blob"},"manifest":{"type":"object","description":"{desc,usage,abi,in,out,examples[<=3],ms_hint,mb_hint,fee 0..2,tests[<=10]{in|in_text,out_sha256},fs,fs_override,input_schema,get_ok}"}}}}}},"responses":{"201":{"description":"ok <name>@<ver> pending kats=<n>"},"202":{"description":"pin requested <name> <hash12> size=<n> (module over 4 MiB, L2 roots 1/week)"},"400":{"description":"err bad | err scrub module data segment <kind>"},"402":{"description":"err credits"},"403":{"description":"err auth publishing needs L1"},"409":{"description":"err taken | err dup"},"429":{"description":"err quota"}}}},
"/v1/svc/{nameAtVer}":{"get":{"operationId":"svg","summary":"Manifest, stats, versions with hashes and ratings, and the call line (name or name@ver)","parameters":[{"name":"nameAtVer","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"head line + fields"},"404":{"description":"err notfound"}}},
"post":{"operationId":"svc","summary":"Call a service: resolves name (stable) or name@ver, submits with the manifest hints and fee; done ms= out= + stdout indented (<= 16 KiB UTF-8); ?raw=1 returns the stdout bytes alone","parameters":[{"name":"nameAtVer","in":"path","required":true,"schema":{"type":"string"}},{"name":"wait","in":"query","schema":{"type":"integer","maximum":85}},{"name":"raw","in":"query","schema":{"type":"string","enum":["1"]}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"in":{"type":"string","description":"sha256 of an input blob"},"in_text":{"type":"string","maxLength":65536},"fs":{"type":"string","description":"zip blob (only when the manifest sets fs_override)"},"ms":{"type":"integer","maximum":30000},"mb":{"type":"integer","maximum":256},"wait":{"type":"integer","maximum":85},"fresh":{"type":"boolean"}}}}}},"responses":{"200":{"description":"done ms=<n> out=<hash> [code=<n>] [cached] [pinned=<hash12>] job=<id> then stdout indented by two spaces"},"202":{"description":"<id> queued|running"},"402":{"description":"err credits"},"404":{"description":"err notfound service not published yet (see /svc)"},"410":{"description":"err gone rejected"}}}},
"/v1/svc/{name}/stable":{"post":{"operationId":"svstable","summary":"Owner: move the stable pointer to a verified version that is 24 h old or was called by 3 other roots (1/h, logged)","parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["ver"],"properties":{"ver":{"type":"integer","minimum":1}}}}}},"responses":{"200":{"description":"ok <name> stable=<ver>"},"409":{"description":"err bad not verified or too new"},"429":{"description":"err rate once per hour"}}}},
"/v1/svc/{nameAtVer}/ok":{"post":{"operationId":"svok","summary":"Vote that this version worked (roots with a finalised job on it within 30 d, one per version, weight trust.Weight)","parameters":[{"name":"nameAtVer","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"note":{"type":"string","maxLength":200}}}}}},"responses":{"200":{"description":"ok <name>@<ver> ok<w> bad<w>"},"403":{"description":"err auth vote needs a finalised job"},"409":{"description":"err dup already voted"}}}},
"/v1/svc/{nameAtVer}/bad":{"post":{"operationId":"svbad","summary":"Vote that this version failed (same rules as ok)","parameters":[{"name":"nameAtVer","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"note":{"type":"string","maxLength":200}}}}}},"responses":{"200":{"description":"ok <name>@<ver> ok<w> bad<w>"}}}},
"/v1/run":{"post":{"operationId":"run","summary":"Submit + wait + inline output; code/stdin build the interpreter framing {code,stdin} (py=cxpy js=cxjs lua=cxlua)","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["svc"],"properties":{"svc":{"type":"string","description":"name or name@ver"},"in_text":{"type":"string","maxLength":65536},"code":{"type":"string","maxLength":65536},"stdin":{"type":"string","maxLength":65536},"fs":{"type":"string"},"ms":{"type":"integer","maximum":30000},"mb":{"type":"integer","maximum":256},"wait":{"type":"integer","maximum":85}}}}}},"responses":{"200":{"description":"done ms= out= job= + stdout indented"},"202":{"description":"<id> queued"},"404":{"description":"err notfound service not published yet (see /svc)"}}}},
"/svc":{"get":{"operationId":"svcPage","summary":"Catalog page (HTML, .md, .json, .txt): one line per service, CollectionPage JSON-LD","responses":{"200":{"description":"page"}}}},
"/svc/{name}":{"get":{"operationId":"svcNamePage","summary":"Service page (HTML, .md, .json, .txt): manifest, hashes, ratings, SoftwareApplication + SoftwareSourceCode JSON-LD; indexable per trust.Indexable","parameters":[{"name":"name","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"page"},"404":{"description":"err notfound"}}}},
"/admin/svc":{"post":{"operationId":"adminSvc","summary":"Admin token: publish under the system root with reserved names allowed (interpreters, cx-*); KATs run as system jobs; the first version becomes stable","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["name","wasm","manifest"],"properties":{"name":{"type":"string"},"ver":{"type":"integer"},"wasm":{"type":"string"},"manifest":{"type":"object"}}}}}},"responses":{"201":{"description":"ok <name>@<ver> pending kats=<n>"},"401":{"description":"err auth admin"}}}}
}}`)
