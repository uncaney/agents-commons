// Package compute implements blobs, jobs, worker leases, consensus and the compute janitor
// (SPEC-v2 14, 27.6): the scoped result cache, signed attestations, cancel/delete/info, worker
// stats and caps/pins negotiation, private lanes, donor diagnostics and blob tenure. HTTP handlers
// and MCP ops share the same service methods; other packages use the exported Submit / Status /
// Output / SystemSubmit / PutBlobBytes / CacheLookup and the nil-safe hook vars below.
package compute

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"sync"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/sign"
)

// Op is an MCP operation: same compact text as the HTTP handler, errors as *core.APIError.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

const (
	maxBlob      = 16 << 20
	maxWasm      = 4 << 20 // unpinned job modules: compile cost/memory grows with size (review #4c)
	maxText      = 1 << 20 // text kind / publishable text (27.6)
	blobQuota    = 256 << 20
	opaqueQuota  = 64 << 20 // live opaque bytes for L0/L1 roots (27.6 tenure)
	defMaxBytes  = 20 << 30 // global blob budget, env MAX_BLOB_BYTES (review #8)
	maxInText    = 64 << 10
	maxJobWait   = 85
	maxLeaseAit  = 55
	maxBatch     = 100
	maxMs        = 30000
	defMs        = 10000
	maxMb        = 256
	defMb        = 64
	maxWaitS     = 24 * 3600
	blobTTLDays  = 7
	tenureHours  = 24 // opaque blobs never used by a job, and private blobs
	maxTouches   = 3  // re-uploads of an opaque hash per week (err quota blob tenure)
	stuckHours   = 24
	retentionD   = 30 // finished jobs kept (14.6), also the cache window (14.1)
	leaseWindow  = 50 // random pick among the oldest N queued replicas (review #1)
	maxLeases    = 4  // live leases per worker root (review #7)
	maxPins      = 32 // pins a lease body may list (14.4)
	minPaidMs    = 50 // agreed timeout/oom below this earns nothing (review #1)
	expireRepCap = 5  // max rep lost per root per day from expired leases (review #7)
	workRepCap   = 20 // rep:work per root per day (4.2)
	probationOK  = 3  // runs_ok before a module leaves probation (27.6)
	bombDonors   = 3  // distinct donors reporting compile-timeout -> banned compile-bomb
	trustedDaily = 100
	leaseVer     = 2
	leaseSunset  = "2027-01-01"
)

var hashRe = regexp.MustCompile(`^[0-9a-f]{64}$`)

type svc struct {
	d        *core.Deps
	maxBytes int64 // global blob budget
	signer   *sign.Signer
	stats    *donorStats
}

var (
	svcMu sync.Mutex
	svcs  = map[*core.Deps]*svc{}
)

// svcFor returns the one service of a Deps so Register, Ops and the exported functions share the
// in-memory donor presence (w/stats, eta).
func svcFor(d *core.Deps) *svc {
	svcMu.Lock()
	defer svcMu.Unlock()
	if s, ok := svcs[d]; ok {
		return s
	}
	s := newSvc(d)
	svcs[d] = s
	return s
}

func newSvc(d *core.Deps) *svc {
	s := &svc{d: d, maxBytes: defMaxBytes, stats: newDonorStats()}
	if v, err := strconv.ParseInt(os.Getenv("MAX_BLOB_BYTES"), 10, 64); err == nil && v > 0 {
		s.maxBytes = v
	}
	// The statement key derives from the server secret (17.1); without one no att line is written.
	s.signer, _ = sign.New(d.Cfg)
	return s
}

// Register mounts compute routes, janitor tasks, the purge hook and the core registries.
func Register(mux *http.ServeMux, d *core.Deps) { svcFor(d).register(mux) }

func (s *svc) register(mux *http.ServeMux) {
	d := s.d
	s.registerJanitor()
	mux.HandleFunc("POST /v1/b", s.hPutBlob)
	mux.HandleFunc("GET /v1/b/{hash}", s.hGetBlob)
	mux.HandleFunc("DELETE /v1/b/{hash}", s.hDeleteBlob)
	mux.HandleFunc("GET /v1/b/{hash}/info", s.hBlobInfo)
	mux.HandleFunc("POST /v1/b/{hash}/publish", s.hPublishBlob)
	mux.HandleFunc("POST /v1/j", s.hSubmit)
	mux.HandleFunc("GET /v1/j/{id}", s.hJob)
	mux.HandleFunc("DELETE /v1/j/{id}", s.hCancel)
	mux.HandleFunc("POST /v1/w/lease", s.hLease)
	mux.HandleFunc("POST /v1/w/done", s.hDone)
	mux.HandleFunc("GET /v1/w/stats", s.hStats)
	mux.HandleFunc("GET /v1/pins", s.hPins)
	mux.HandleFunc("POST /admin/pin", d.AdminOnly(s.hPin))
	mux.HandleFunc("POST /admin/unpin", d.AdminOnly(s.hUnpin))
	// Blob routes serve submitters (j) and donors (w): they check the scope per call.
	for _, p := range []string{"POST /v1/b", "GET /v1/b/{hash}"} {
		d.RegisterScope(p, "*")
	}
	for _, p := range []string{"DELETE /v1/b/{hash}", "GET /v1/b/{hash}/info", "POST /v1/b/{hash}/publish", "POST /v1/j", "GET /v1/j/{id}", "DELETE /v1/j/{id}"} {
		d.RegisterScope(p, "j")
	}
	d.RegisterScope("POST /v1/w/lease", "w")
	d.RegisterScope("POST /v1/w/done", "w")
	d.RegisterCost("GET /v1/j/{id}", 0.2)
	d.RegisterCost("GET /v1/w/stats", 0.2)
	d.StorageClass("blobs", s.maxBytes, `SELECT coalesce(sum(size), 0) FROM blobs`)
	d.StorageClass("blobs_opaque", s.maxBytes/4, `SELECT coalesce(sum(size), 0) FROM blobs WHERE kind = 'opaque'`)
	d.OnExport("compute", func(ctx context.Context, root string, w io.Writer) error { return s.export(ctx, root, w) })
	d.MeExtra(s.meLines)
	d.RegisterResolver('j', s.resolve)
	d.RegisterOpenAPI(openAPI)
}

// Ops returns the MCP ops owned by this package (janitor/purge hooks are registered by Register).
func Ops(d *core.Deps) map[string]Op {
	s := svcFor(d)
	return map[string]Op{"j": s.opJ, "jw": s.opJW, "jo": s.opJO, "jc": s.opJC, "jatt": s.opJAtt,
		"bd": s.opBD, "binfo": s.opBInfo, "wstats": s.opWStats}
}

// OpMeta describes the ops for the MCP registry (3.5).
var OpMeta = map[string]core.OpMeta{
	"j":      {Scope: "j", Cost: 1, Mutating: true},
	"jw":     {Scope: "j", Cost: 0.2},
	"jo":     {Scope: "j", Cost: 1},
	"jc":     {Scope: "j", Cost: 1, Mutating: true},
	"jatt":   {Scope: "j", Cost: 0.2},
	"bd":     {Scope: "j", Cost: 1, Mutating: true},
	"binfo":  {Scope: "j", Cost: 1},
	"wstats": {Scope: "", Cost: 0.2},
}

// Help is the help{t:compute} text of this package (<= 200 tokens).
const Help = `compute (donated WASI preview1 sandboxes, 2-replica consensus, results cached 30 d per (wasm,in,fs,mb)):
j{wasm,in|in_text,ms,mb,fs,fresh,max_wait_s,lane:public|own|trusted} submit (or jobs[]); reply id lines + eta_s= | jw{id,wait} status (done out=<hash> ms= [cached]) | jo{id} small text output inline
jc{id} cancel with refund | jatt{id} signed att1 receipt line + sig | bd{hash} delete own unused blob | binfo{hash} wasm/zip/text facts, scrub=, runs_ok= | wstats{} donors_online= slots= queued= p50_wait_s=
Blobs: POST /v1/b (<=16 MiB, ?private=1 own lane only), GET /v1/b/<hash>/info, POST /v1/b/<hash>/publish (clean text or wasm). Donors see inputs: never send secrets.`

// Cross-package seams (nil-safe; each fails closed or neutral when unset).
var (
	// CacheJobFn mirrors a finalized, attested result into the free-text result cache (16.4);
	// key = hex(sha256(wasm || input || fs)).
	CacheJobFn func(ctx context.Context, q core.Q, key, jobID, out string, cost int) error
	// RevokedFn reports whether (wasm, input) was revoked by an audit (14.5); nil = not revoked.
	RevokedFn func(ctx context.Context, q core.Q, wasm, input string) (bool, error)
	// OnDone runs inside finalize's transaction after a job settles (P60a sets a chain); errors are
	// logged and never roll a settled job back.
	OnDone func(ctx context.Context, q core.Q, j *Job) error
	// NondeterministicFn flags a module whose results legitimately differ between runs (14.5).
	NondeterministicFn func(ctx context.Context, q core.Q, wasm string) bool
	// PriorityAuditFn enqueues a priority audit of a root-scoped result another root asked for
	// (14.1); nil = a row in audit_queue.
	PriorityAuditFn func(ctx context.Context, q core.Q, jobID, reason string) error
	// InfoExtraFn appends lines to GET /v1/b/{hash}/info (P105: compile_ms_p50, mem_p50, hints).
	InfoExtraFn func(ctx context.Context, q core.Q, hash string) []string
	// RevokeFn records a revocation line for /att/revoked.txt (P45); nil = an ops event only.
	RevokeFn func(ctx context.Context, q core.Q, wasm, input, reason string) error
)

// ErrUnfunded: SystemSubmit found the system root short of credits (16.1).
var ErrUnfunded = core.E(402, "credits", "system root unfunded")

// Submit creates jobs for id (or serves them from the result cache) and returns their ids.
func Submit(ctx context.Context, d *core.Deps, id *core.Ident, specs []Spec) ([]string, error) {
	res, err := svcFor(d).submit(ctx, id, specs)
	if err != nil {
		return nil, err
	}
	return res.ids, nil
}

// Status returns a job view of id's job, long-polling up to wait seconds for a final state.
func Status(ctx context.Context, d *core.Deps, id *core.Ident, jid string, wait int) (*JobView, error) {
	return svcFor(d).status(ctx, id, jid, clampWait(wait, maxJobWait))
}

// Output returns the output bytes of id's done job; false when the job is not done yet.
func Output(ctx context.Context, d *core.Deps, id *core.Ident, jid string) ([]byte, bool, error) {
	return svcFor(d).output(ctx, id, jid)
}

// CacheLookup serves a globally scoped cached result for (wasm, input, fs, mb) (27.6 svcget).
func CacheLookup(ctx context.Context, q core.Q, wasm, input, fs string, mb int) (*JobView, bool, error) {
	return cacheLookupGlobal(ctx, q, wasm, input, fs, mb)
}

// authCompute: token, not banned, neither write nor compute frozen.
func (s *svc) authCompute(r *http.Request) (*core.Ident, error) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		return nil, err
	}
	if s.d.Frozen("compute") {
		return nil, core.Frozen("compute")
	}
	return id, nil
}

// needScope is the per-call scope check of the shared blob routes (registered "*").
func needScope(id *core.Ident, scopes ...string) error {
	if id == nil || id.Scopes == nil {
		return nil
	}
	for _, sc := range scopes {
		if core.ScopeAllowed(id.Scopes, sc) {
			return nil
		}
	}
	return core.E(403, "scope", scopes[0])
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

// waitParam parses ?wait= (seconds), clamped to max.
func waitParam(r *http.Request, max int) (int, error) {
	v := r.URL.Query().Get("wait")
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, core.Bad("wait must be 0.." + strconv.Itoa(max))
	}
	if n > max {
		n = max
	}
	return n, nil
}

func clampWait(n, max int) int {
	if n < 0 {
		return 0
	}
	if n > max {
		return max
	}
	return n
}

// bumpDaily adds delta to today's counter (scope, kind) and returns the new value.
// Same table/semantics as core's quota counters; used for the negative rep cap on
// expired leases, which core.AddRep (positive caps only) does not cover.
func bumpDaily(ctx context.Context, q core.Q, scope, kind string, delta int) (int, error) {
	var n int
	err := q.QueryRow(ctx, `INSERT INTO counters (scope, kind, day, n) VALUES ($1, $2, current_date, $3)
		ON CONFLICT (scope, kind, day) DO UPDATE SET n = counters.n + EXCLUDED.n RETURNING n`, scope, kind, delta).Scan(&n)
	return n, err
}

func decodeOp(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/b":{"post":{"operationId":"putBlob","summary":"Upload a blob (raw body <= 16 MiB, sha256-addressed; ?private=1 owner-only 24 h; X-Lease: donor output)","parameters":[{"name":"private","in":"query","schema":{"type":"string","enum":["1"]}},{"name":"X-Lease","in":"header","schema":{"type":"string"}}],"requestBody":{"content":{"application/octet-stream":{"schema":{"type":"string","format":"binary"}}}},"responses":{"200":{"description":"<hash> exp=<date> kind=wasm|text|opaque [scrub=<kinds>]"},"413":{"description":"err size"},"429":{"description":"err quota"}}}},
"/v1/b/{hash}":{"get":{"operationId":"getBlob","summary":"Download a blob: owner root, public, pinned, or a live lease (X-Lease) referencing it; else 404","parameters":[{"name":"hash","in":"path","required":true,"schema":{"type":"string","pattern":"^[0-9a-f]{64}$"}}],"responses":{"200":{"description":"raw bytes, immutable"},"404":{"description":"err notfound"}}},"delete":{"operationId":"bd","summary":"Delete an own blob no active job references","parameters":[{"name":"hash","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok deleted <hash>"},"409":{"description":"err taken referenced or pinned"}}}},
"/v1/b/{hash}/info":{"get":{"operationId":"binfo","summary":"Static facts: wasm size= imports= memory= funcs= has_start= producers= | zip entries= unpacked= fs_ok= | text|opaque size=; scrub=, runs_ok=","parameters":[{"name":"hash","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"one line per fact group"}}}},
"/v1/b/{hash}/publish":{"post":{"operationId":"bpub","summary":"Make an own blob world-readable: clean UTF-8 text <= 1 MiB (no tier-1/2 findings) or a scanned wasm module","parameters":[{"name":"hash","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok public <hash>"},"400":{"description":"err bad no media or archive hosting | err scrub <kinds>"}}}},
"/v1/j":{"post":{"operationId":"j","summary":"Submit jobs (2-replica consensus; cached results answer done immediately)","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"wasm":{"type":"string","description":"sha256 of a wasm blob"},"in":{"type":"string","description":"sha256 of an input blob"},"in_text":{"type":"string","maxLength":65536},"fs":{"type":"string","description":"sha256 of a zip blob mounted read-only at /"},"ms":{"type":"integer","minimum":1,"maximum":30000,"default":10000},"mb":{"type":"integer","minimum":1,"maximum":256,"default":64},"fresh":{"type":"boolean"},"max_wait_s":{"type":"integer"},"lane":{"type":"string","enum":["public","own","trusted"]},"jobs":{"type":"array","items":{"type":"object"}}}}}}},"responses":{"200":{"description":"one job id per line, then eta_s=~<n> [probation …]"},"202":{"description":"queued eta=unknown (no donors online) | <id> warn scrub <kind>: donors are strangers"},"402":{"description":"err credits"}}}},
"/v1/j/{id}":{"get":{"operationId":"jw","summary":"Job status, long-poll ?wait<=85; ?att=1 adds the signed att1 line","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},{"name":"wait","in":"query","schema":{"type":"integer"}},{"name":"att","in":"query","schema":{"type":"string"}}],"responses":{"200":{"description":"<id> queued|running | <id> done out=<hash> ms=<n> [code=<n>] [cached] | <id> failed <reason>"}}},"delete":{"operationId":"jc","summary":"Cancel a queued/running job with full refund","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"<id> cancelled refund=<n>"}}}},
"/v1/w/lease":{"post":{"operationId":"wlease","summary":"Donor: lease one replica (long-poll ?wait<=55); ver 2 negotiates caps (pin, new, l0) and pins","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"max_ms":{"type":"integer"},"max_mb":{"type":"integer"},"ver":{"type":"integer"},"caps":{"type":"array","items":{"type":"string"}},"pins":{"type":"array","items":{"type":"string"},"maxItems":32}}}}}},"responses":{"200":{"description":"{lease, job, wasm, in, fs, ms, mb, lane, deadline}"},"204":{"description":"nothing eligible"}}}},
"/v1/w/done":{"post":{"operationId":"wdone","summary":"Donor: report a lease {lease, status: ok|exit|timeout|oom|error, out, code, ms, diag, dsig}","responses":{"200":{"description":"{ok:true}"},"400":{"description":"err badsig (lease requeued)"},"410":{"description":"err gone job cancelled"}}}},
"/v1/w/stats":{"get":{"operationId":"wstats","summary":"Anonymous donor/queue stats (15 s cache, coarse buckets)","responses":{"200":{"description":"donors_online= slots= queued= leased= p50_wait_s= max_ms= max_mb= caps= donors_new= donors_l0="}}}},
"/v1/pins":{"get":{"operationId":"pins","summary":"Pinned modules donors may warm: <hash> <name>@<ver> <size> [by=seed]","responses":{"200":{"description":"one pin per line"}}}}
}}`)
