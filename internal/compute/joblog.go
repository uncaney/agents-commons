package compute

// Per-replica failure diagnostics (SPEC-v2 27.6, P105 joblog): GET /v1/j/{id}/log / op jlog shows
// the submitter one block per reported replica, then the donor's stderr (secrets masked) and the
// WASM stack trace, so a failing module can be debugged without exposing the diagnostics to anyone
// else or to the index. The diag rows are never fingerprinted and drop with the replica rows.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
	"ekaii.fr/commons/internal/wasmscan"
)

// maxLogBytes bounds one replica's rendered stderr+trace block (27.6: 6 KiB per replica).
const maxLogBytes = 6 << 10

// BlobBytes returns the stored bytes of a blob by hash so svcget can serve a global cached result's
// stdout (27.6); ok=false when no such blob row or file exists. It reads only; it never computes.
func BlobBytes(ctx context.Context, d *core.Deps, hash string) ([]byte, bool, error) {
	if !hashRe.MatchString(hash) {
		return nil, false, nil
	}
	s := svcFor(d)
	if _, ok, err := blobSize(ctx, s.d.DB, hash); err != nil || !ok {
		return nil, false, err
	}
	b, err := os.ReadFile(s.blobPath(hash))
	if err != nil {
		return nil, false, nil
	}
	return b, true, nil
}

// PutSystemBlob stores bytes as a system-owned blob, skipping the per-root quota, so an anonymous
// service input survives (as its sha256 address) until a system precompute references it by hash
// (svcget demand-driven precomputation, 27.6). It stores only; it never runs compute.
func PutSystemBlob(ctx context.Context, d *core.Deps, b []byte, max int64) (string, error) {
	if max <= 0 || max > maxBlob {
		max = maxBlob
	}
	if int64(len(b)) > max {
		return "", core.ErrSize
	}
	row, _, err := svcFor(d).putBlob(ctx, core.SystemID, bytes.NewReader(b), putOpts{max: max, exempt: true})
	if err != nil {
		return "", err
	}
	return row.hash, nil
}

// RegisterJobLog mounts the failure-diagnostics route (27.6). Register (P13) runs on the same Deps
// first; cmd/gateway wires this and OpsJobLog through the integration package.
func RegisterJobLog(mux *http.ServeMux, d *core.Deps) { svcFor(d).registerJobLog(mux) }

func (s *svc) registerJobLog(mux *http.ServeMux) {
	d := s.d
	mux.HandleFunc("GET /v1/j/{id}/log", s.hJobLog)
	d.RegisterScope("GET /v1/j/{id}/log", "j")
	d.RegisterCost("GET /v1/j/{id}/log", 0.2)
	d.RegisterOpenAPI(openAPIJobLog)
}

// OpsJobLog returns the MCP op of this file (merged next to Ops by the integration package).
func OpsJobLog(d *core.Deps) map[string]Op {
	s := svcFor(d)
	return map[string]Op{"jlog": s.opJLog}
}

// OpMetaJobLog describes OpsJobLog for the registry (3.5).
var OpMetaJobLog = map[string]core.OpMeta{"jlog": {Scope: "j", Cost: 0.2}}

// HelpJobLog is the help{t:jlog} text (<= 200 tokens).
const HelpJobLog = `jlog{id} (submitter only) per-replica failure diagnostics of your job: one block per reported replica
'replica N by <root> status=exit code=1 ms=812 compile_ms=3900 mem=41/64MiB', then the donor's stderr as '| ' lines (secrets masked) and the wasm stack trace as '# ' lines. Never indexed; dropped when the job's rows age out. GET /v1/j/<id>/log for the same.`

var openAPIJobLog = json.RawMessage(`{"paths":{
"/v1/j/{id}/log":{"get":{"operationId":"jlog","summary":"Submitter-only per-replica failure diagnostics: status/ms/compile_ms/mem line then masked stderr (| ) and wasm trace (# ) lines; never indexed","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"one block per reported replica"},"404":{"description":"err notfound (not the submitter or no such job)"}}}}
}}`)

func (s *svc) hJobLog(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	text, j, err := s.jobLog(r.Context(), id, r.PathValue("id"))
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	core.OK(w, r, text, j)
}

func (s *svc) opJLog(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeOp(a, &in); err != nil {
		return "", err
	}
	text, _, err := s.jobLog(ctx, id, in.ID)
	return text, err
}

// replicaDiag is one reported replica as the log surface reads it.
type replicaDiag struct {
	root, status string
	code, ms     int
	diag         []byte
}

// jobLog renders the per-replica diagnostics of id's own job (submitter only). A job owned by
// another root answers the same ErrNotFound as an unknown id (14.6, 24.§).
func (s *svc) jobLog(ctx context.Context, id *core.Ident, jid string) (string, map[string]any, error) {
	if id == nil {
		return "", nil, core.ErrAuth
	}
	if !core.ValidID(jid) {
		return "", nil, core.ErrNotFound
	}
	var mb int
	err := s.d.DB.QueryRow(ctx, `SELECT mb FROM jobs WHERE id = $1 AND root = $2`, jid, id.Root).Scan(&mb)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", nil, core.ErrNotFound
	}
	if err != nil {
		return "", nil, err
	}
	rows, err := s.d.DB.Query(ctx, `SELECT coalesce(worker_root, ''), coalesce(status, ''), coalesce(code, 0), coalesce(ms, 0), diag
		FROM replicas WHERE job = $1 AND state = 'reported' ORDER BY id`, jid)
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	var reps []replicaDiag
	for rows.Next() {
		var rd replicaDiag
		if err := rows.Scan(&rd.root, &rd.status, &rd.code, &rd.ms, &rd.diag); err != nil {
			return "", nil, err
		}
		reps = append(reps, rd)
	}
	if err := rows.Err(); err != nil {
		return "", nil, err
	}
	var lines []string
	blocks := make([]map[string]any, 0, len(reps))
	for i, rd := range reps {
		head, jblock := rd.headLine(i+1, mb)
		lines = append(lines, head)
		body, jb := renderDiag(rd.diag)
		lines = append(lines, body...)
		for k, v := range jb {
			jblock[k] = v
		}
		blocks = append(blocks, jblock)
	}
	if len(reps) == 0 {
		lines = append(lines, jid+" no replica diagnostics")
	}
	return strings.Join(lines, "\n"), map[string]any{"id": jid, "replicas": blocks}, nil
}

// headLine is the 'replica N by <root> status= code= ms= [compile_ms=] [mem=]' line.
func (rd *replicaDiag) headLine(n, mb int) (string, map[string]any) {
	d := decodeDiag(rd.diag)
	j := map[string]any{"replica": n, "by": rd.root, "status": rd.status, "code": rd.code, "ms": rd.ms}
	b := fmt.Sprintf("replica %d by %s status=%s code=%d ms=%d", n, doc.SafeLine(rd.root), rd.status, rd.code, rd.ms)
	if d != nil && d.CompileMs > 0 {
		b += fmt.Sprintf(" compile_ms=%d", d.CompileMs)
		j["compile_ms"] = d.CompileMs
	}
	if d != nil && d.MemPages > 0 {
		used := (int64(d.MemPages)*wasmscan.PageSize + (1<<20 - 1)) >> 20
		b += fmt.Sprintf(" mem=%d/%dMiB", used, mb)
		j["mem_mib"], j["mb"] = used, mb
	}
	return b, j
}

// decodeDiag unmarshals the stored replicas.diag (never fingerprinted); nil when absent or invalid.
func decodeDiag(raw []byte) *diagIn {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var d diagIn
	if json.Unmarshal(raw, &d) != nil {
		return nil
	}
	return &d
}

// renderDiag turns one replica's stored diag into the '| ' stderr and '# ' trace lines: stderr is
// base64-decoded, both are normalised, masked (tier 1 and 2) and made line-injection-safe, and the
// whole block is capped at 6 KiB (27.6). Secrets a donor's output might carry never leak here.
func renderDiag(raw []byte) ([]string, map[string]any) {
	d := decodeDiag(raw)
	if d == nil {
		return nil, nil
	}
	var lines []string
	j := map[string]any{}
	budget := maxLogBytes
	emit := func(prefix, text string) {
		masked, _ := scrub.Mask(scrub.Normalize(text))
		for _, ln := range strings.Split(masked, "\n") {
			if budget <= 0 {
				return
			}
			s := prefix + doc.SafeLine(ln)
			if len(s) > budget {
				s = s[:budget]
			}
			budget -= len(s) + 1
			lines = append(lines, s)
		}
	}
	if d.Stderr != "" {
		if raw, err := base64.RawURLEncoding.DecodeString(d.Stderr); err == nil && len(raw) > 0 {
			j["stderr"] = true
			emit("| ", string(raw))
		}
	}
	if d.Trace != "" {
		j["trace"] = true
		emit("# ", d.Trace)
	}
	if len(lines) == 0 {
		return nil, nil
	}
	return lines, j
}
