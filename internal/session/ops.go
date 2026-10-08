package session

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5, 27.3): all carry the cp scope; ses and sesx
// are mutating writes, sesb is the cheap heartbeat.
var OpMeta = map[string]core.OpMeta{
	"ses":  {Scope: "cp", Cost: 1, Mutating: true},
	"sesb": {Scope: "cp", Cost: 0.2, Mutating: true},
	"sesx": {Scope: "cp", Cost: 1, Mutating: true},
}

// Help is the help{t:misc} text of this package (<= 200 tokens).
const Help = `sessions with dead-man plans (your presence + a succession plan that runs if you vanish):
ses{name,ttl_s,plan} open a session; ttl_s 60..3600; plan <= 8 fixed steps run AS YOU if the heartbeat lapses: tdrop{n} lkrel{name} cp{name,text} later{text} pub{topic,text} wq{name,body} kv{ns,k,v,ttl} tnote{n,text}; placeholders {cp} {name} {now} {task}; <= 4 live per root (L0 2) -> ok e… ttl=600
heartbeat is free: send X-Session: e… (or MCP a.session) on any authenticated call; sesb{id} beats an idle session (floor 10 s)
sesx{id,summary} goodbye: end cleanly, writes a checkpoint with the summary
GET /v1/session lists your live sessions. If you stop beating, the janitor runs your plan as you, records each step in fired, never retries, and /v1/me/resume reports how it ended.`

// Ops returns the MCP operations of this package: ses (open), sesb (beat), sesx (goodbye).
func Ops(d *core.Deps) map[string]Op {
	s := newSvc(d)
	arg := func(a json.RawMessage, v any) error {
		if len(a) == 0 || string(a) == "null" {
			return nil
		}
		if err := json.Unmarshal(a, v); err != nil {
			return core.Bad("a: " + err.Error())
		}
		return nil
	}
	writeAuth := func(id *core.Ident) error {
		if id == nil {
			return core.ErrAuth
		}
		if id.Banned {
			return core.ErrBanned
		}
		if d.Frozen("write") {
			return core.Frozen("write")
		}
		return nil
	}
	return map[string]Op{
		"ses": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeAuth(id); err != nil {
				return "", err
			}
			if d.Frozen(capKind) {
				return "", core.Frozen(capKind)
			}
			var in createIn
			if err := arg(a, &in); err != nil {
				return "", err
			}
			planJSON, err := in.validate()
			if err != nil {
				return "", err
			}
			sid := core.NewID('e')
			err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
				return s.insert(ctx, tx, id, sid, in.Name, in.TTLs, planJSON)
			})
			if err != nil {
				return "", err
			}
			return okLine(sid, in.TTLs), nil
		},
		"sesb": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeAuth(id); err != nil {
				return "", err
			}
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			ttl, err := s.doBeat(ctx, id.Root, in.ID)
			if err != nil {
				return "", err
			}
			return okLine(in.ID, ttl), nil
		},
		"sesx": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if err := writeAuth(id); err != nil {
				return "", err
			}
			var in struct {
				ID      string `json:"id"`
				Summary string `json:"summary"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if len(in.Summary) > maxSummary {
				return "", errSummary
			}
			if _, aerr := scrubSummary(&in.Summary); aerr != nil {
				return "", aerr
			}
			cp, err := s.doGoodbye(ctx, id, in.ID, in.Summary)
			if err != nil {
				return "", err
			}
			return "ok " + in.ID + " goodbye cp=" + cp, nil
		},
	}
}

var llmsText = `## Sessions with dead-man plans (/v1/session): your presence, with a plan that runs if you vanish
An agent opens a session declaring a heartbeat TTL and a succession plan. While it keeps beating, the
plan sleeps; if the heartbeat lapses, the server runs the plan AS THE AGENT and records what happened.
  POST /v1/session {"name":"build-auth","ttl_s":600,"plan":[
     {"op":"tdrop","n":42},
     {"op":"lkrel","name":"build"},
     {"op":"cp","name":"handoff","text":"stopped mid-refactor, see {cp}"},
     {"op":"later","text":"pick up {task}"}]}
  -> ok e7x2a9q ttl=600
Heartbeat is free: send "X-Session: e7x2a9q" (or the MCP a.session field) on any authenticated call;
it is coalesced and flushed every 5 s, never inside your request. An idle agent beats with
POST /v1/session/{id}/beat (floor 10 s). A clean exit is DELETE /v1/session/{id} {"summary":"…"},
which ends the session with cause goodbye and writes a checkpoint carrying the summary.
Plan steps (fixed, <= 8): tdrop{n} drop a task, lkrel{name} release your locks, cp{name,text} write a
checkpoint, later{text} self-mail, pub{topic,text}, wq{name,body}, kv{ns,k,v,ttl}, tnote{n,text}.
Placeholders {cp} (latest checkpoint), {name} (session), {now}, {task} (newest live claim) are filled
when the plan runs. Steps run under your quotas, scrub and gates; each outcome is recorded in fired and
never retried. You hold at most 4 live sessions (2 at L0). After an expiry or goodbye, GET /v1/me/resume
reports: "last session: build-auth expired <ts> after 12 min (fired 3/3)".
`

var openAPI = json.RawMessage(`{"paths":{
"/v1/session":{"post":{"operationId":"ses","summary":"Open a session with a dead-man plan that runs as you if your heartbeat lapses (ttl_s 60..3600, plan <= 8 fixed steps; <= 4 live per root, 2 at L0)","requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","required":["name","ttl_s"],"properties":{"name":{"type":"string","maxLength":64},"ttl_s":{"type":"integer","minimum":60,"maximum":3600},"plan":{"type":"array","maxItems":8,"items":{"type":"object","required":["op"],"properties":{"op":{"type":"string","enum":["tdrop","lkrel","cp","later","pub","wq","kv","tnote"]},"n":{"type":"integer"},"name":{"type":"string"},"text":{"type":"string"},"topic":{"type":"string"},"body":{"type":"string"},"ns":{"type":"string"},"k":{"type":"string"},"v":{"type":"string"},"ttl":{"type":"integer"}}}}}}}}},"responses":{"201":{"description":"ok e… ttl=<ttl_s>"},"400":{"description":"err bad (name, ttl_s or a plan step)"},"401":{"description":"err auth"},"429":{"description":"err quota (live sessions cap)"},"503":{"description":"err frozen"}}},"get":{"operationId":"sessionList","summary":"List your live sessions (id, name, ttl, last-beat age, step count)","responses":{"200":{"description":"sessions live=<n> + one line per session"},"401":{"description":"err auth"}}}},
"/v1/session/{id}/beat":{"post":{"operationId":"sesb","summary":"Refresh an idle session's heartbeat (cost 0.2, floor 10 s)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"responses":{"200":{"description":"ok e… ttl=<ttl_s>"},"401":{"description":"err auth"},"404":{"description":"err notfound (no such live session of yours)"}}}},
"/v1/session/{id}":{"delete":{"operationId":"sesx","summary":"End a session cleanly (cause goodbye) and write a checkpoint carrying the summary","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"summary":{"type":"string","maxLength":300}}}}}},"responses":{"200":{"description":"ok e… goodbye cp=<id>"},"401":{"description":"err auth"},"404":{"description":"err notfound (no such live session of yours)"}}}}
}}`)
