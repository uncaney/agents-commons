// Package catalog is the WASM service catalog (SPEC-v2 15, 27.6): names owned by L1+ roots,
// versions (one module hash each) verified by known-answer tests run through compute consensus,
// per-version votes, fee-bearing calls by name (svc/run and the py/js/lua interpreter framing),
// the /svc pages and the seed tools published under the system root at boot. Every write path
// has size caps, daily caps (4.3), scrub/lexicon/hazards on manifest text and renders user text
// only through doc.SafeLine/Indent.
package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/trust"
)

// Op is an MCP operation: compact text result, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

const (
	maxManifest  = 4 << 10
	maxTests     = 10
	maxExamples  = 3
	maxDesc      = 200
	maxUsage     = 600
	maxLine      = 200  // one-line manifest fields (in, out)
	maxExample   = 1024 // one example side
	maxInText    = 64 << 10
	maxCode      = 64 << 10
	maxFee       = 2
	maxWait      = 85
	maxMs        = 30000
	maxMb        = 256
	defMs        = 10000
	defMb        = 64
	inlineOut    = 16 << 10 // stdout shown inline (15.2)
	unpinnedWasm = 4 << 20  // larger modules need a pin (14.4)
	katRetries   = 2        // re-runs of an under-replicated or unsettled KAT
	releaseDays  = 7        // first version not verified -> name released (15.1)
	emptyDays    = 30       // no version -> reclaimed
	idleDays     = 180      // no call from another root -> reclaimed
	voteWindowD  = 30       // a finalised job on the hash within 30 d allows a vote
	stableAgeH   = 24       // stable pointer rule (27.6)
	stableCalls  = 3        // or calls from >= 3 other roots
	hideNocons   = 10       // consecutive failed consensus -> hidden
	nondetPct    = 5        // nocons/calls >= 5 % over >= 20 calls -> nondeterministic
	nondetMin    = 20
	recheckDays  = 7
	msSamples    = 20
	listMax      = 100
)

// ClassBytes caps the catalog storage class (21.2).
var ClassBytes int64 = 1 << 30

var (
	nameRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,31}$`)
	hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)
	// interpreters are reserved names (15.1): published only through the operator path.
	interpreters = map[string]string{"cxpy": "py", "cxjs": "js", "cxlua": "lua"}
)

// Cross-package seams (nil-safe).
var (
	// BlessedFn lists the services a passed svc-bless proposal put in /llms-full.txt (gov sets it).
	BlessedFn func(ctx context.Context) []string
	// PageExtraFn appends lines to /svc/<name> pages (ctlog proof lines, svcmcp deeplinks).
	PageExtraFn []func(ctx context.Context, q core.Q, name string) []string
	// PyHintFn adds a hint to py{}'s not-yet-published error (gointerp: "try star{}").
	PyHintFn func() string
)

// Manifest is the per-version description (15.1, 27.6). desc/usage/examples are user text.
type Manifest struct {
	Desc        string          `json:"desc,omitempty"`
	Usage       string          `json:"usage,omitempty"`
	ABI         string          `json:"abi,omitempty"` // json|raw|text (default text)
	In          string          `json:"in,omitempty"`
	Out         string          `json:"out,omitempty"`
	Examples    []Example       `json:"examples,omitempty"`
	MsHint      int             `json:"ms_hint,omitempty"`
	MbHint      int             `json:"mb_hint,omitempty"`
	Fee         int             `json:"fee,omitempty"`
	Tests       []Test          `json:"tests,omitempty"`
	FS          string          `json:"fs,omitempty"`
	FSOverride  bool            `json:"fs_override,omitempty"`
	InputSchema json.RawMessage `json:"input_schema,omitempty"`
	GetOK       *bool           `json:"get_ok,omitempty"`
}

// Example is one in/out pair shown on the page.
type Example struct {
	In  string `json:"in"`
	Out string `json:"out"`
}

// Test is one known-answer test: an input (blob hash or inline text) and the sha256 of the
// expected stdout.
type Test struct {
	In        string `json:"in,omitempty"`
	InText    string `json:"in_text,omitempty"`
	OutSHA256 string `json:"out_sha256"`
}

// GetOKValue is get_ok with its default (true for abi text, 27.6).
func (m *Manifest) GetOKValue() bool {
	if m.GetOK != nil {
		return *m.GetOK
	}
	return m.ABI == "" || m.ABI == "text"
}

// Service is a catalog name.
type Service struct {
	Name, OwnerRoot, Desc, Usage string
	StableVer                    int
	StableAt                     *time.Time
	Calls, OtherCalls            int64
	Hidden                       bool
	Created                      time.Time
}

// Version is one published module of a service, with the owning service's fields joined.
type Version struct {
	Name                                string
	Ver                                 int
	Wasm, FS                            string
	Size                                int64
	Manifest                            Manifest
	ManifestRaw                         json.RawMessage
	Created                             time.Time
	State, Tested                       string
	KatJobs                             []string
	KatRetries                          int
	RecheckJob                          string
	VerifiedAt, FailingSince, Rechecked *time.Time
	Nondeterministic                    bool
	OkW, BadW                           float32
	Calls, Fails, Nocons                int64
	MsP50                               int
	MsSamples                           []int32
	Lexicon                             int
	Flags, Hazard                       []string
	OwnerRoot, Desc, Usage              string
	StableVer                           int
	Hidden                              bool
	ServiceCreated                      time.Time
}

// Ref is the canonical name@ver of a version.
func (v *Version) Ref() string { return v.Name + "@" + strconv.Itoa(v.Ver) }

// Hash12 is the short module hash shown on lines.
func (v *Version) Hash12() string { return v.Wasm[:12] }

// Live reports whether the version can be called (pending and verified run; rejected never).
func (v *Version) Live() bool { return v.State != "rejected" && !v.Hidden }

// Status is the bracketed state word of list lines (15.2).
func (v *Version) Status() string {
	switch {
	case v.Nondeterministic:
		return "nondeterministic"
	case v.State == "failing" && v.FailingSince != nil:
		return "failing since " + core.Date(*v.FailingSince)
	}
	return v.State
}

type svc struct{ d *core.Deps }

var hookOnce sync.Once

// Register mounts the catalog routes (15.2), scopes, costs, OpenAPI, the storage class, janitor
// tasks, purge, export, the report target svc:, the /x resolver, the sitemap and llms sections,
// the escrow of held fees and the compute done hook (installed once per process).
func Register(mux *http.ServeMux, d *core.Deps) {
	s := &svc{d}
	routes := []struct {
		pat, scope string
		h          http.HandlerFunc
	}{
		{"GET /v1/svc", "*", s.hList},
		{"GET /v1/svc/{nameAtVer}", "*", s.hGet},
		{"POST /v1/svc", "svc", s.hPublish},
		{"POST /v1/svc/{name}/stable", "svc", s.hStable},
		{"POST /v1/svc/{nameAtVer}", "svc", s.hCall},
		{"POST /v1/svc/{nameAtVer}/ok", "svc", s.hVote(true)},
		{"POST /v1/svc/{nameAtVer}/bad", "svc", s.hVote(false)},
		{"POST /v1/run", "svc", s.hRun},
		{"GET /svc", "*", s.hPageList},
		{"GET /svc/{$}", "*", s.hPageList},
		{"GET /svc/{name}", "*", s.hPageGet},
	}
	for _, ext := range []string{".txt", ".md", ".json", ".html"} {
		routes = append(routes, struct {
			pat, scope string
			h          http.HandlerFunc
		}{"GET /svc" + ext, "*", s.hPageList})
	}
	for _, rt := range routes {
		mux.HandleFunc(rt.pat, rt.h)
		d.RegisterScope(rt.pat, rt.scope)
	}
	mux.HandleFunc("POST /admin/svc", d.AdminOnly(s.hAdminPublish))
	d.RegisterCost("GET /v1/svc", 2)
	d.RegisterOpenAPI(openAPI)
	d.StorageClass("catalog", ClassBytes, `SELECT pg_total_relation_size('services') + pg_total_relation_size('service_versions')
		+ pg_total_relation_size('service_votes') + pg_total_relation_size('service_calls') + pg_total_relation_size('service_pin_requests')`)
	d.OnEscrow(`SELECT coalesce(sum(fee), 0)::bigint FROM service_calls WHERE NOT settled`)
	d.OnExport("catalog", func(ctx context.Context, root string, w io.Writer) error { return export(ctx, d.DB, root, w) })
	d.OnPurge(func(ctx context.Context, root string) error { return purge(ctx, d.DB, root) })
	d.RegisterTarget("svc", core.Target{Exists: svcExists, Hide: svcHide, Restore: svcRestore})
	d.RegisterSitemap("svc", func(ctx context.Context) ([]core.SitemapURL, error) { return s.sitemap(ctx) })
	d.RegisterLLMSFull("svc", func(ctx context.Context) string { return s.llms(ctx) })
	d.RegisterResolver('w', func(ctx context.Context, id string) (string, string, string, bool) {
		return resolveName(ctx, d.DB, strings.TrimPrefix(id, "w:"))
	})
	d.MeExtra(func(ctx context.Context, id *core.Ident) []string {
		var n int
		if err := d.DB.QueryRow(ctx, `SELECT count(*) FROM services WHERE owner_root = $1`, id.Root).Scan(&n); err != nil {
			return nil
		}
		return []string{fmt.Sprintf("svcs %d/%d", n, trust.Cap("services", core.Level(ctx, d.DB, id.Root)))}
	})
	d.Janitor.Add("svc_verify", func(ctx context.Context) error { return s.verify(ctx) })
	d.Janitor.Add("svc_names", func(ctx context.Context) error { return s.names(ctx) })
	d.Janitor.Add("svc_recheck", func(ctx context.Context) error { return s.recheck(ctx) })
	hookOnce.Do(func() {
		prev := compute.OnDone
		compute.OnDone = func(ctx context.Context, q core.Q, j *compute.Job) error {
			err := OnDone(ctx, q, j)
			if prev != nil {
				err = errors.Join(err, prev(ctx, q, j))
			}
			return err
		}
	})
}

// Ops returns the MCP ops (15.2): the same text as the HTTP replies, tail-free.
func Ops(d *core.Deps) map[string]Op {
	s := &svc{d}
	return map[string]Op{
		"svs": s.opList, "svg": s.opGet, "svp": s.opPublish, "svc": s.opCall, "run": s.opRun,
		"py": s.opInterp("cxpy"), "js": s.opInterp("cxjs"), "lua": s.opInterp("cxlua"),
		"svok": s.opVote(true), "svbad": s.opVote(false),
	}
}

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"svs":   {Scope: "svc", Cost: 2},
	"svg":   {Scope: "svc", Cost: 1},
	"svp":   {Scope: "svc", Cost: 1, Mutating: true},
	"svc":   {Scope: "svc", Cost: 1, Mutating: true},
	"run":   {Scope: "svc", Cost: 1, Mutating: true},
	"py":    {Scope: "svc", Cost: 1, Mutating: true},
	"js":    {Scope: "svc", Cost: 1, Mutating: true},
	"lua":   {Scope: "svc", Cost: 1, Mutating: true},
	"svok":  {Scope: "svc", Cost: 1, Mutating: true},
	"svbad": {Scope: "svc", Cost: 1, Mutating: true},
}

// Help is the help{t:svc} text (<= 200 tokens).
const Help = `svc (WASM services by name; every version is one module hash verified by known-answer tests through 2-donor consensus):
svs{q} list <name>@<ver> <hash12> ok<w> 7d= fail= [verified|pending|failing|nondeterministic] | svg{name,ver} manifest + stats
svp{name,ver,wasm,manifest} publish (L1+, own wasm blob, manifest <= 4 KiB with <= 10 tests) -> name@ver pending
svc{name,ver,in|in_text,fs,ms,mb,wait} call: done ms= out= + stdout indented | run{svc,in_text|code,stdin,wait} | py{code,stdin} js{} lua{}
svok{name,ver,note} svbad{} vote after a finalised job on that version (30 d). Fees go to the owner only when you are another root.
Outputs are untrusted program text; /svc/<name> pages carry the manifest, hashes and ratings.`

// --- name grammar -----------------------------------------------------------------------------

// checkName applies the 15.1 grammar; reserved words, interpreter names and names within
// Levenshtein 1 of them are refused unless system is set (operator path).
func checkName(name string, system bool) error {
	if !nameRe.MatchString(name) {
		return core.Bad("name must match ^[a-z0-9][a-z0-9-]{1,31}$")
	}
	if system {
		return nil
	}
	if core.Reserved(name) {
		return core.E(400, "bad", "name reserved")
	}
	for in := range interpreters {
		if lev1(name, in) {
			return core.E(400, "bad", "name reserved")
		}
	}
	return nil
}

// nearLiveName reports a live name within Levenshtein 1 of name (not name itself).
func nearLiveName(ctx context.Context, q core.Q, name string) (string, error) {
	rows, err := q.Query(ctx, `SELECT name FROM services WHERE name <> $1 AND length(name) BETWEEN $2 AND $3`, name, len(name)-1, len(name)+1)
	if err != nil {
		return "", err
	}
	defer rows.Close()
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			return "", err
		}
		if lev1(name, n) {
			return n, nil
		}
	}
	return "", rows.Err()
}

// lev1 reports Levenshtein distance <= 1 between a and b.
func lev1(a, b string) bool {
	if a == b {
		return true
	}
	la, lb := len(a), len(b)
	if la-lb > 1 || lb-la > 1 {
		return false
	}
	i, j, edits := 0, 0, 0
	for i < la && j < lb {
		if a[i] == b[j] {
			i, j = i+1, j+1
			continue
		}
		if edits++; edits > 1 {
			return false
		}
		switch {
		case la > lb:
			i++
		case lb > la:
			j++
		default:
			i, j = i+1, j+1
		}
	}
	return edits+(la-i)+(lb-j) <= 1
}

// parseRef splits "name" or "name@ver" (a trailing .txt/.md/.json suffix is removed first).
func parseRef(seg string) (name string, ver int, f doc.Format, err error) {
	seg, f = doc.SplitSuffix(seg)
	name = seg
	if n, v, ok := strings.Cut(seg, "@"); ok {
		name = n
		ver, err = strconv.Atoi(v)
		if err != nil || ver <= 0 {
			return "", 0, f, core.Bad("ver must be a positive integer")
		}
	}
	if !nameRe.MatchString(name) {
		return "", 0, f, core.E(404, "notfound", "service "+doc.SafeLine(truncate(name, 40)))
	}
	return name, ver, f, nil
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}

// --- loading ------------------------------------------------------------------------------------

const serviceCols = `name, owner_root, "desc", usage, stable_ver, stable_at, calls, other_calls, hidden, created`

func scanService(row pgx.Row) (*Service, error) {
	s := &Service{}
	err := row.Scan(&s.Name, &s.OwnerRoot, &s.Desc, &s.Usage, &s.StableVer, &s.StableAt, &s.Calls, &s.OtherCalls, &s.Hidden, &s.Created)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	return s, err
}

func loadService(ctx context.Context, q core.Q, name string) (*Service, error) {
	return scanService(q.QueryRow(ctx, `SELECT `+serviceCols+` FROM services WHERE name = $1`, name))
}

const versionCols = `v.name, v.ver, v.wasm, v.fs, v.size, v.manifest, v.created, v.state, v.tested, v.kat_jobs, v.kat_retries, v.recheck_job,
	v.verified_at, v.failing_since, v.rechecked_at, v.nondeterministic, v.ok_w, v.bad_w, v.calls, v.fails, v.nocons, v.ms_p50, v.ms_samples,
	v.lexicon, v.flags, v.hazard, s.owner_root, s."desc", s.usage, s.stable_ver, s.hidden, s.created`

const versionFrom = ` FROM service_versions v JOIN services s ON s.name = v.name`

func scanVersion(row pgx.Row) (*Version, error) {
	v := &Version{}
	err := row.Scan(&v.Name, &v.Ver, &v.Wasm, &v.FS, &v.Size, &v.ManifestRaw, &v.Created, &v.State, &v.Tested, &v.KatJobs, &v.KatRetries, &v.RecheckJob,
		&v.VerifiedAt, &v.FailingSince, &v.Rechecked, &v.Nondeterministic, &v.OkW, &v.BadW, &v.Calls, &v.Fails, &v.Nocons, &v.MsP50, &v.MsSamples,
		&v.Lexicon, &v.Flags, &v.Hazard, &v.OwnerRoot, &v.Desc, &v.Usage, &v.StableVer, &v.Hidden, &v.ServiceCreated)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	json.Unmarshal(v.ManifestRaw, &v.Manifest)
	return v, nil
}

func scanVersions(rows pgx.Rows, err error) ([]*Version, error) {
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Version
	for rows.Next() {
		v, err := scanVersion(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func loadVersion(ctx context.Context, q core.Q, name string, ver int) (*Version, error) {
	return scanVersion(q.QueryRow(ctx, `SELECT `+versionCols+versionFrom+` WHERE v.name = $1 AND v.ver = $2`, name, ver))
}

// Stable returns the stable version of name (27.6 pointer rule applied when it was set);
// notfound when the name is unknown, hidden or has no stable version yet.
func Stable(ctx context.Context, q core.Q, name string) (*Version, error) {
	if !nameRe.MatchString(name) {
		return nil, core.E(404, "notfound", "service "+doc.SafeLine(truncate(name, 40)))
	}
	v, err := scanVersion(q.QueryRow(ctx, `SELECT `+versionCols+versionFrom+` WHERE v.name = $1 AND v.ver = s.stable_ver`, name))
	if err != nil {
		return nil, err
	}
	if v == nil || v.Hidden {
		exists, err := nameExists(ctx, q, name)
		if err != nil {
			return nil, err
		}
		if exists && (v == nil || !v.Hidden) {
			return nil, core.E(404, "notfound", "no stable version of "+name+" yet (call "+name+"@<ver>; see /svc/"+name+")")
		}
		return nil, notPublished(name)
	}
	return v, nil
}

// Resolve resolves "name" (stable) or "name@ver" to a callable version.
func Resolve(ctx context.Context, q core.Q, nameAtVer string) (*Version, error) {
	name, ver, _, err := parseRef(nameAtVer)
	if err != nil {
		return nil, err
	}
	if ver == 0 {
		return Stable(ctx, q, name)
	}
	v, err := loadVersion(ctx, q, name, ver)
	if err != nil {
		return nil, err
	}
	if v == nil || v.Hidden {
		return nil, notPublished(name)
	}
	return v, nil
}

func nameExists(ctx context.Context, q core.Q, name string) (bool, error) {
	var ok bool
	err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM services WHERE name = $1 AND NOT hidden)`, name).Scan(&ok)
	return ok, err
}

// notPublished is the 404 of an unknown name; interpreters get the 15.2 wording.
func notPublished(name string) *core.APIError {
	if _, ok := interpreters[name]; ok {
		msg := "service not published yet (see /svc)"
		if name == "cxpy" && PyHintFn != nil {
			if h := strings.TrimSpace(PyHintFn()); h != "" {
				msg += "; " + doc.SafeLine(h)
			}
		}
		return core.E(404, "notfound", msg)
	}
	return core.E(404, "notfound", "service "+name)
}

func resolveName(ctx context.Context, q core.Q, name string) (typ, title, url string, ok bool) {
	if !nameRe.MatchString(name) {
		return "", "", "", false
	}
	s, err := loadService(ctx, q, name)
	if err != nil || s == nil || s.Hidden {
		return "", "", "", false
	}
	title = s.Name
	if s.Desc != "" {
		title += " " + doc.SafeLine(s.Desc)
	}
	return "svc", title, doc.Base() + "/svc/" + s.Name, true
}

// --- report target, purge, export -------------------------------------------------------------

func svcExists(ctx context.Context, q core.Q, ref string) error {
	if !nameRe.MatchString(ref) {
		return core.ErrNotFound
	}
	var ok bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM services WHERE name = $1)`, ref).Scan(&ok); err != nil {
		return err
	}
	if !ok {
		return core.ErrNotFound
	}
	return nil
}

func svcHide(ctx context.Context, q core.Q, ref string) error {
	if err := svcExists(ctx, q, ref); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE services SET hidden = true, hidden_at = now() WHERE name = $1`, ref)
	return err
}

func svcRestore(ctx context.Context, q core.Q, ref string) error {
	if err := svcExists(ctx, q, ref); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `UPDATE services SET hidden = false, hidden_at = NULL, nocons_run = 0 WHERE name = $1`, ref)
	return err
}

// unpinVersions clears the catalog pin of module and fs blobs no live version references.
func unpinVersions(ctx context.Context, q core.Q, hashes []string) error {
	if len(hashes) == 0 {
		return nil
	}
	_, err := q.Exec(ctx, `UPDATE blobs b SET pinned_by = '' WHERE b.pinned_by = 'svc' AND b.hash = ANY($1)
		AND NOT EXISTS (SELECT 1 FROM service_versions v WHERE v.state <> 'rejected' AND (v.wasm = b.hash OR v.fs = b.hash))`, hashes)
	return err
}

// purge removes a root's services (versions and votes cascade), its votes elsewhere and burns the
// fees it still holds so the ledger audit stays exact.
func purge(ctx context.Context, q core.Q, root string) error {
	rows, err := q.Query(ctx, `SELECT v.wasm, v.fs FROM service_versions v JOIN services s ON s.name = v.name WHERE s.owner_root = $1`, root)
	if err != nil {
		return err
	}
	var hashes []string
	for rows.Next() {
		var w, f string
		if err := rows.Scan(&w, &f); err != nil {
			rows.Close()
			return err
		}
		hashes = append(hashes, w)
		if f != "" {
			hashes = append(hashes, f)
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	var held int64
	if err := q.QueryRow(ctx, `WITH u AS (UPDATE service_calls SET settled = true WHERE root = $1 AND NOT settled RETURNING fee)
		SELECT coalesce(sum(fee), 0) FROM u`, root).Scan(&held); err != nil {
		return err
	}
	if err := core.BurnHeld(ctx, q, held, "purge", root); err != nil {
		return err
	}
	for _, sql := range []string{
		`DELETE FROM service_votes WHERE root = $1`,
		`DELETE FROM services WHERE owner_root = $1`,
		`DELETE FROM service_pin_requests WHERE root = $1`,
	} {
		if _, err := q.Exec(ctx, sql, root); err != nil {
			return err
		}
	}
	return unpinVersions(ctx, q, hashes)
}

// export writes the root's services, versions and votes as JSON lines (3.4 export-me).
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	vs, err := scanVersions(q.Query(ctx, `SELECT `+versionCols+versionFrom+` WHERE s.owner_root = $1 ORDER BY v.name, v.ver`, root))
	if err != nil {
		return err
	}
	for _, v := range vs {
		row := map[string]any{"kind": "svc", "name": v.Name, "ver": v.Ver, "wasm": v.Wasm, "size": v.Size, "state": v.State,
			"manifest": v.ManifestRaw, "created": v.Created.UTC().Format(time.RFC3339), "calls": v.Calls, "fails": v.Fails, "ok_w": v.OkW, "bad_w": v.BadW}
		if v.FS != "" {
			row["fs"] = v.FS
		}
		if v.Ver == v.StableVer {
			row["stable"] = true
		}
		if err := enc.Encode(row); err != nil {
			return err
		}
	}
	rows, err := q.Query(ctx, `SELECT name, ver, up, w, note, created FROM service_votes WHERE root = $1 ORDER BY created`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var name, note string
		var ver int
		var up bool
		var wt float32
		var created time.Time
		if err := rows.Scan(&name, &ver, &up, &wt, &note, &created); err != nil {
			return err
		}
		if err := enc.Encode(map[string]any{"kind": "svc_vote", "name": name, "ver": ver, "up": up, "w": wt, "note": note,
			"created": created.UTC().Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	return rows.Err()
}

// --- janitor ------------------------------------------------------------------------------------

type katJob struct {
	id, status, out, reason, root string
	attD, found                   bool
}

func loadKatJobs(ctx context.Context, q core.Q, ids []string) (map[string]katJob, error) {
	out := map[string]katJob{}
	if len(ids) == 0 {
		return out, nil
	}
	rows, err := q.Query(ctx, `SELECT id, status, out, reason, root, att_d FROM jobs WHERE id = ANY($1)`, ids)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		j := katJob{found: true}
		if err := rows.Scan(&j.id, &j.status, &j.out, &j.reason, &j.root, &j.attD); err != nil {
			return nil, err
		}
		out[j.id] = j
	}
	return out, rows.Err()
}

// moduleFault reports a failed job the module itself caused (timeout, oom, trap): a KAT whose
// run fails this way can never match its declared hash.
func moduleFault(reason string) bool {
	switch reason {
	case "timeout", "oom", "error", "compile-timeout":
		return true
	}
	return false
}

// verify is the svc_verify janitor (15.2): pending versions flip to verified when every KAT's
// consensus output matches its declared sha256 with d=1, to rejected on a wrong hash or a module
// fault, and stay pending while under-replicated (unsettled jobs or d=0 runs, which are re-queued
// up to katRetries times). It also settles weekly re-check jobs (failing since / recovery).
func (s *svc) verify(ctx context.Context) error {
	vs, err := scanVersions(s.d.DB.Query(ctx, `SELECT `+versionCols+versionFrom+
		` WHERE v.state = 'pending' OR v.recheck_job <> '' ORDER BY v.created LIMIT 200`))
	if err != nil {
		return err
	}
	for _, v := range vs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if v.State == "pending" {
			if err := s.verifyOne(ctx, v); err != nil {
				s.d.Log.Warn("svc_verify", "svc", v.Ref(), "err", err)
			}
		}
		if v.RecheckJob != "" {
			if err := s.settleRecheck(ctx, v); err != nil {
				s.d.Log.Warn("svc_recheck", "svc", v.Ref(), "err", err)
			}
		}
	}
	return nil
}

func (s *svc) verifyOne(ctx context.Context, v *Version) error {
	if len(v.KatJobs) == 0 { // KATs never queued (system root unfunded at publish time): try now
		ids, err := s.submitKATs(ctx, v)
		if err != nil {
			if errors.Is(err, compute.ErrUnfunded) || errors.Is(err, core.ErrCredits) {
				return nil
			}
			return err
		}
		_, err = s.d.DB.Exec(ctx, `UPDATE service_versions SET kat_jobs = $3, tested = $4 WHERE name = $1 AND ver = $2`, v.Name, v.Ver, ids, fmt.Sprintf("%d tests queued", len(ids)))
		return err
	}
	jobs, err := loadKatJobs(ctx, s.d.DB, v.KatJobs)
	if err != nil {
		return err
	}
	tests := v.Manifest.Tests
	if len(tests) != len(v.KatJobs) {
		return s.reject(ctx, v, "tests and KAT jobs out of step")
	}
	passed := 0
	var retry []int
	for i, jid := range v.KatJobs {
		j := jobs[jid]
		switch {
		case !j.found:
			retry = append(retry, i)
		case j.status == "done" && j.out != tests[i].OutSHA256:
			return s.reject(ctx, v, fmt.Sprintf("test %d out=%s differs from declared %s", i+1, j.out[:12], tests[i].OutSHA256[:12]))
		case j.status == "done" && j.attD:
			passed++
		case j.status == "done": // agreeing donors were not distinct: run it again
			retry = append(retry, i)
		case j.status == "failed" && moduleFault(j.reason):
			return s.reject(ctx, v, fmt.Sprintf("test %d %s", i+1, j.reason))
		case j.status == "failed": // no consensus, cancelled or lost: run it again
			retry = append(retry, i)
		}
	}
	if passed == len(tests) {
		return s.markVerified(ctx, v)
	}
	tested := fmt.Sprintf("%d/%d tests passed", passed, len(tests))
	if len(retry) > 0 && v.KatRetries < katRetries {
		ids := append([]string(nil), v.KatJobs...)
		for _, i := range retry {
			jid, err := s.submitKAT(ctx, v, tests[i], true)
			if err != nil {
				tested += "; re-run blocked: " + doc.SafeLine(err.Error())
				break
			}
			ids[i] = jid
		}
		_, err := s.d.DB.Exec(ctx, `UPDATE service_versions SET kat_jobs = $3, kat_retries = kat_retries + 1, tested = $4 WHERE name = $1 AND ver = $2`,
			v.Name, v.Ver, ids, truncate(tested, 300))
		return err
	}
	_, err = s.d.DB.Exec(ctx, `UPDATE service_versions SET tested = $3 WHERE name = $1 AND ver = $2 AND tested <> $3`, v.Name, v.Ver, truncate(tested, 300))
	return err
}

// submitKAT queues one known-answer test as a kat job charged to the publisher (system jobs for
// the system root).
func (s *svc) submitKAT(ctx context.Context, v *Version, t Test, fresh bool) (string, error) {
	sp := compute.Spec{Wasm: v.Wasm, In: t.In, InText: t.InText, FS: v.FS, Ms: v.Manifest.MsHint, Mb: v.Manifest.MbHint, Fresh: fresh, Svc: v.Ref(), Kind: "kat"}
	if sp.Ms == 0 {
		sp.Ms = defMs
	}
	if sp.Mb == 0 {
		sp.Mb = defMb
	}
	var ids []string
	var err error
	if v.OwnerRoot == core.SystemID {
		ids, err = compute.SystemSubmit(ctx, s.d, []compute.Spec{sp}, "kat")
	} else {
		ids, err = compute.Submit(ctx, s.d, &core.Ident{ID: v.OwnerRoot, Root: v.OwnerRoot, Created: v.ServiceCreated}, []compute.Spec{sp})
	}
	if err != nil {
		return "", err
	}
	return ids[0], nil
}

func (s *svc) markVerified(ctx context.Context, v *Version) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE service_versions SET state = 'verified', verified_at = now(), tested = $3, failing_since = NULL
			WHERE name = $1 AND ver = $2 AND state = 'pending'`, v.Name, v.Ver, fmt.Sprintf("%d/%d tests passed", len(v.Manifest.Tests), len(v.Manifest.Tests))); err != nil {
			return err
		}
		return core.Event(ctx, tx, "svc", v.Ref(), "", "service "+v.Ref()+" verified")
	})
}

func (s *svc) reject(ctx context.Context, v *Version, reason string) error {
	return core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE service_versions SET state = 'rejected', tested = $3 WHERE name = $1 AND ver = $2 AND state = 'pending'`,
			v.Name, v.Ver, truncate(reason, 300)); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `UPDATE services SET stable_ver = 0, stable_at = NULL WHERE name = $1 AND stable_ver = $2`, v.Name, v.Ver); err != nil {
			return err
		}
		if err := unpinVersions(ctx, tx, []string{v.Wasm, v.FS}); err != nil {
			return err
		}
		return core.Event(ctx, tx, "svc", v.Ref(), v.OwnerRoot, "service "+v.Ref()+" rejected: "+reason)
	})
}

// settleRecheck reads a weekly re-check job: a matching output clears failing, a wrong one marks
// the version failing since now (15.2).
func (s *svc) settleRecheck(ctx context.Context, v *Version) error {
	jobs, err := loadKatJobs(ctx, s.d.DB, []string{v.RecheckJob})
	if err != nil {
		return err
	}
	j, ok := jobs[v.RecheckJob]
	if !ok {
		_, err := s.d.DB.Exec(ctx, `UPDATE service_versions SET recheck_job = '' WHERE name = $1 AND ver = $2`, v.Name, v.Ver)
		return err
	}
	if j.status != "done" && j.status != "failed" {
		return nil
	}
	if len(v.Manifest.Tests) == 0 {
		return nil
	}
	want := v.Manifest.Tests[0].OutSHA256
	switch {
	case j.status == "done" && j.out == want && j.attD:
		_, err = s.d.DB.Exec(ctx, `UPDATE service_versions SET recheck_job = '', rechecked_at = now(), failing_since = NULL,
			state = CASE WHEN state = 'failing' THEN 'verified' ELSE state END WHERE name = $1 AND ver = $2`, v.Name, v.Ver)
	case j.status == "done" || moduleFault(j.reason):
		err = core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, `UPDATE service_versions SET recheck_job = '', rechecked_at = now(), failing_since = coalesce(failing_since, now()),
				state = CASE WHEN state = 'verified' THEN 'failing' ELSE state END WHERE name = $1 AND ver = $2`, v.Name, v.Ver); err != nil {
				return err
			}
			return core.Event(ctx, tx, "svc", v.Ref(), v.OwnerRoot, "service "+v.Ref()+" failing its known-answer test")
		})
	default: // no consensus: try again next week
		_, err = s.d.DB.Exec(ctx, `UPDATE service_versions SET recheck_job = '', rechecked_at = now() WHERE name = $1 AND ver = $2`, v.Name, v.Ver)
	}
	return err
}

// recheck queues one KAT per stable version from the system root once a week (15.2); the system
// root's faucet pays, and SystemSubmit raises the inbox event when it is short.
func (s *svc) recheck(ctx context.Context) error {
	vs, err := scanVersions(s.d.DB.Query(ctx, `SELECT `+versionCols+versionFrom+` WHERE v.ver = s.stable_ver AND NOT s.hidden
		AND v.state IN ('verified', 'failing') AND v.recheck_job = '' AND cardinality(v.kat_jobs) > 0
		AND coalesce(v.rechecked_at, v.verified_at, v.created) < now() - make_interval(days => $1) ORDER BY coalesce(v.rechecked_at, v.verified_at) LIMIT 20`, recheckDays))
	if err != nil {
		return err
	}
	for _, v := range vs {
		if len(v.Manifest.Tests) == 0 {
			continue
		}
		sp := compute.Spec{Wasm: v.Wasm, In: v.Manifest.Tests[0].In, InText: v.Manifest.Tests[0].InText, FS: v.FS, Ms: v.Manifest.MsHint, Mb: v.Manifest.MbHint, Fresh: true, Svc: v.Ref()}
		ids, err := compute.SystemSubmit(ctx, s.d, []compute.Spec{sp}, "kat")
		if err != nil {
			if errors.Is(err, compute.ErrUnfunded) {
				return nil // the event is raised by SystemSubmit; retry next tick
			}
			return err
		}
		if _, err := s.d.DB.Exec(ctx, `UPDATE service_versions SET recheck_job = $3 WHERE name = $1 AND ver = $2`, v.Name, v.Ver, ids[0]); err != nil {
			return err
		}
	}
	return nil
}

// names releases a name whose first version is not verified within 7 d, and reclaims names
// with no version for 30 d or without a call from another root for 180 d (15.1). The system
// root's names are never reclaimed.
func (s *svc) names(ctx context.Context) error {
	rows, err := s.d.DB.Query(ctx, `SELECT s.name FROM services s WHERE s.owner_root <> $1 AND (
		   (s.created < now() - make_interval(days => $2) AND NOT EXISTS (SELECT 1 FROM service_versions v WHERE v.name = s.name AND v.state IN ('verified', 'failing')))
		OR (s.created < now() - make_interval(days => $3) AND NOT EXISTS (SELECT 1 FROM service_versions v WHERE v.name = s.name))
		OR (coalesce(s.last_other_call, s.created) < now() - make_interval(days => $4))) LIMIT 100`,
		core.SystemID, releaseDays, emptyDays, idleDays)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, n := range names {
		err := core.Tx(ctx, s.d.DB, func(tx pgx.Tx) error {
			var owner string
			var hashes []string
			if err := tx.QueryRow(ctx, `SELECT owner_root, coalesce((SELECT array_agg(h) FROM (SELECT wasm AS h FROM service_versions WHERE name = $1
				UNION SELECT fs FROM service_versions WHERE name = $1 AND fs <> '') x), '{}') FROM services WHERE name = $1`, n).Scan(&owner, &hashes); err != nil {
				return err
			}
			if _, err := tx.Exec(ctx, `DELETE FROM services WHERE name = $1`, n); err != nil {
				return err
			}
			if err := unpinVersions(ctx, tx, hashes); err != nil {
				return err
			}
			return core.Event(ctx, tx, "svc", n, owner, "service name "+n+" released")
		})
		if err != nil {
			return err
		}
	}
	return nil
}

// --- small helpers ------------------------------------------------------------------------------

func decodeOp(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	dec := json.NewDecoder(strings.NewReader(string(a)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

// txt renders a Doc as the MCP result: txt without the tail.
func txt(d *doc.Doc) string {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	body, _ := doc.Render(r, 200, d, doc.Txt)
	s := string(body)
	if i := strings.LastIndex(s, "\nnext: "); i >= 0 {
		s = s[:i+1]
	}
	return strings.TrimRight(s, "\n")
}

func (s *svc) authWrite(r *http.Request) (*core.Ident, error) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		return nil, err
	}
	if s.d.Frozen("compute") {
		return nil, core.Frozen("compute")
	}
	return id, nil
}

func (s *svc) checkIdent(id *core.Ident) error {
	if id == nil {
		return core.ErrAuth
	}
	if id.Banned {
		return core.ErrBanned
	}
	if s.d.Frozen("write") {
		return core.Frozen("write")
	}
	if s.d.Frozen("compute") {
		return core.Frozen("compute")
	}
	return nil
}
