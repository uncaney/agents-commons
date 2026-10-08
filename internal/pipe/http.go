package pipe

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/sign"
)

// Register mounts the pipeline routes, the compute.OnDone chain, the janitor safety net and the
// core registries (scope, cost, OpenAPI, purge, me line, pipe1 statement type).
func Register(mux *http.ServeMux, d *core.Deps) {
	s := svcFor(d)
	mux.HandleFunc("POST /v1/pipe", s.hCreate)
	mux.HandleFunc("GET /v1/pipe/{id}", s.hGet)
	d.RegisterScope("POST /v1/pipe", "j")
	d.RegisterScope("GET /v1/pipe/{id}", "j")
	d.RegisterCost("GET /v1/pipe/{id}", 0.2)
	d.RegisterOpenAPI(openAPI)
	d.OnPurge(s.purge)
	d.MeExtra(s.meLine)
	d.Janitor.Add("pipe", s.advanceAll)
	sign.RegisterTypes("pipe1")
	hookOnce.Do(func() {
		prev := compute.OnDone
		compute.OnDone = func(ctx context.Context, q core.Q, j *compute.Job) error {
			err := OnDone(ctx, q, j)
			if prev != nil {
				if perr := prev(ctx, q, j); perr != nil {
					if err == nil {
						err = perr
					}
				}
			}
			return err
		}
	})
}

// hCreate handles POST /v1/pipe: create the pipe, submit step 0, then long-poll (?wait) for the
// final state before replying.
func (s *svc) hCreate(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.AuthWrite(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	var in pipeIn
	if err := core.Decode(w, r, 1<<20, &in); err != nil {
		core.Fail(w, r, err)
		return
	}
	pid, err := s.create(r.Context(), id, in)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	v, err := s.status(r.Context(), id, pid, in.Wait, 0)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	st := 200
	if !v.final() {
		st = 202
	}
	s.write(w, r, st, id, v, false, false)
}

// hGet handles GET /v1/pipe/{id}: status (long-poll ?wait, until ?step), ?raw=1 bytes, ?att=1 line.
func (s *svc) hGet(w http.ResponseWriter, r *http.Request) {
	id, err := s.d.Auth(r)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	q := r.URL.Query()
	wait, err := intParam(q.Get("wait"), maxWait)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	until, err := intParam(q.Get("step"), maxSteps)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	v, err := s.status(r.Context(), id, r.PathValue("id"), wait, until)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	if q.Get("raw") == "1" {
		s.writeRaw(w, r, id, v, until)
		return
	}
	s.write(w, r, 200, id, v, q.Get("att") == "1", true)
}

// write renders a view: the head, the inline final stdout (done), and the pipe1 line (att).
func (s *svc) write(w http.ResponseWriter, r *http.Request, st int, id *core.Ident, v *pipeView, att, allowAtt bool) {
	text := v.text()
	if v.State == "done" {
		if b, ok, _ := s.stdout(r.Context(), id, v.out()); ok && len(b) > 0 {
			text += "\n  " + doc.Indent(string(b))
		}
	}
	j := v.json()
	if att && allowAtt && v.Att != "" {
		text += "\n" + v.Att + "\n" + v.AttSig
	}
	core.Text(w, r, st, text, j)
}

// writeRaw serves the raw bytes of the final output (or step ?step=, 1-based) as octet-stream.
func (s *svc) writeRaw(w http.ResponseWriter, r *http.Request, id *core.Ident, v *pipeView, until int) {
	hash := v.out()
	if until > 0 && until <= len(v.Outs) {
		hash = v.Outs[until-1]
	}
	if hash == "" {
		core.Fail(w, r, core.E(409, "bad", v.text()))
		return
	}
	b, err := s.readBlob(hash)
	if err != nil {
		core.Fail(w, r, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(200)
	w.Write(b)
}

func intParam(v string, max int) (int, error) {
	if v == "" {
		return 0, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		return 0, core.Bad("must be 0.." + strconv.Itoa(max))
	}
	if n > max {
		n = max
	}
	return n, nil
}

var openAPI = json.RawMessage(`{"paths":{
"/v1/pipe":{"post":{"operationId":"pipe","summary":"Run a service pipeline: 2..8 steps chained stdout->stdin in one submission, per-step cache hits, fees and refunds, a signed pipe1 receipt","requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["steps"],"properties":{"steps":{"type":"array","minItems":2,"maxItems":8,"items":{"type":"object","properties":{"svc":{"type":"string","description":"catalog service name (resolved to a module hash)"},"wasm":{"type":"string","description":"raw module hash (alternative to svc)"},"code":{"type":"string","description":"interpreter source; the chained data becomes stdin via the {code,stdin} framing"},"in_text":{"type":"string","description":"literal input for this step (overrides the chain)"},"ms":{"type":"integer","minimum":1,"maximum":30000},"mb":{"type":"integer","minimum":1,"maximum":256}}}},"in":{"type":"string","description":"step-0 input blob hash"},"in_text":{"type":"string","description":"step-0 literal input"},"wait":{"type":"integer","minimum":0,"maximum":85},"ms":{"type":"integer"},"mb":{"type":"integer"}}}}}},"responses":{"200":{"description":"q… done N/N ms=<n> out=<hash> then the final stdout indented"},"202":{"description":"q… running <k>/N (long-poll GET /v1/pipe/<id>?wait=)"},"402":{"description":"err credits"},"429":{"description":"err quota (8 jobs/pipe against the daily cap)"}}}},
"/v1/pipe/{id}":{"get":{"operationId":"pipeg","summary":"Pipeline status (long-poll ?wait<=85, until ?step), ?raw=1 raw bytes, ?att=1 adds the signed pipe1 line","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}},{"name":"wait","in":"query","schema":{"type":"integer"}},{"name":"step","in":"query","schema":{"type":"integer"}},{"name":"raw","in":"query","schema":{"type":"string","enum":["1"]}},{"name":"att","in":"query","schema":{"type":"string","enum":["1"]}}],"responses":{"200":{"description":"q… running|done|failed …"},"404":{"description":"err notfound"}}}}
}}`)
