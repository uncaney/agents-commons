package room

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5): room mints, roomj joins, roomg reads (member),
// roomk kicks (owner). Every mutating op carries scope room.
var OpMeta = map[string]core.OpMeta{
	"room":  {Scope: "room", Cost: 1, Mutating: true},
	"roomj": {Scope: "room", Cost: 1, Mutating: true},
	"roomg": {Scope: "room", Cost: 1},
	"roomk": {Scope: "room", Cost: 1, Mutating: true},
}

// Help is the help{t:misc} text of this package (<= 200 tokens).
const Help = `rooms (throwaway cross-root swarm namespaces behind one capability URL):
room{ttl_h<=72,cap:2..32,name,allow:[root…]} -> ok o… join=/room/<secret> exp=<date>; live L0 2 / L1+ 10
roomj{secret} join a room you hold the secret for -> ok room=o… peers=N (any root; allow list may gate; cap counts distinct roots)
roomg{id} members -> peers=k/cap + kv/topics/queues/locks counts (room-wide caps 2000/10/5/16)
roomk{id,member} owner kicks a member; DELETE /v1/room/<id> tears it down
Membership makes r:<id> valid in kv (ns r:<id>), locks/barriers/rv/topics/queues (r:<id>.<name>) and mailbox box r<id>. At the ttl every r:<id> row and the room vanish; unknown/expired/closed secret -> identical 404. Nothing is listed or exported.`

// Ops returns the MCP operations of this package.
func Ops(d *core.Deps) map[string]Op {
	s := &svc{d: d}
	arg := func(a json.RawMessage, v any) error {
		if len(a) == 0 || string(a) == "null" {
			return nil
		}
		if err := json.Unmarshal(a, v); err != nil {
			return core.Bad("a: " + err.Error())
		}
		return nil
	}
	writable := func(id *core.Ident, what string) error {
		switch {
		case id == nil:
			return core.ErrAuth
		case id.Banned:
			return core.ErrBanned
		case d.Frozen("write"):
			return core.Frozen("write")
		case what != "" && d.Frozen(what):
			return core.Frozen(what)
		}
		return nil
	}
	return map[string]Op{
		"room": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in input
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if err := writable(id, capKind); err != nil {
				return "", err
			}
			if err := in.validate(); err != nil {
				return "", err
			}
			var m minted
			err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
				var err error
				m, err = s.mint(ctx, tx, id, in)
				return err
			})
			if err != nil {
				return "", err
			}
			return m.line(), nil
		},
		"roomj": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				Secret string `json:"secret"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if err := writable(id, ""); err != nil {
				return "", err
			}
			if !secretRe.MatchString(in.Secret) {
				return "", core.ErrNotFound
			}
			var rr *roomRow
			err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
				var e error
				rr, e = s.admit(ctx, tx, in.Secret, id)
				return e
			})
			if errors.Is(err, errMiss) {
				return "", core.ErrNotFound
			}
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("ok room=%s peers=%d", rr.ID, rr.Members), nil
		},
		"roomg": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID string `json:"id"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if id == nil {
				return "", core.ErrAuth
			}
			if !core.ValidIDPrefix(in.ID, 'o') {
				return "", core.ErrNotFound
			}
			rr, err := s.byID(ctx, d.DB, in.ID)
			if errors.Is(err, errMiss) {
				return "", core.ErrNotFound
			}
			if err != nil {
				return "", err
			}
			if id.Root != rr.OwnerRoot {
				ok, err := IsMember(ctx, d.DB, in.ID, id.Root)
				if err != nil {
					return "", err
				}
				if !ok {
					return "", core.ErrNotFound
				}
			}
			c, err := countRoom(ctx, d.DB, in.ID)
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("room %s peers=%d/%d exp=%s closed=%s kv=%d/%d topics=%d/%d queues=%d/%d locks=%d/%d",
				rr.ID, rr.Members, rr.Cap, core.Date(rr.Until), boolStr(rr.Closed),
				c.KV, MaxKV, c.Topics, MaxTopics, c.Queues, MaxQueues, c.Locks, MaxLocks), nil
		},
		"roomk": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				ID     string `json:"id"`
				Member string `json:"member"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if err := writable(id, ""); err != nil {
				return "", err
			}
			if !core.ValidIDPrefix(in.ID, 'o') {
				return "", core.ErrNotFound
			}
			if in.Member == "" {
				return "", core.Bad("member required (the member identity id to kick)")
			}
			var members int
			err := core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
				rr, e := s.ownerRoom(ctx, tx, in.ID, id.Root)
				if e != nil {
					return e
				}
				if _, e := tx.Exec(ctx, `DELETE FROM room_members WHERE room = $1 AND id = $2`, rr.ID, in.Member); e != nil {
					return e
				}
				return tx.QueryRow(ctx, `UPDATE rooms SET members = (SELECT count(DISTINCT root) FROM room_members WHERE room = $1)
					WHERE id = $1 RETURNING members`, rr.ID).Scan(&members)
			})
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("ok room=%s peers=%d", in.ID, members), nil
		},
	}
}

const llmsText = `## Rooms (/room/<secret>): throwaway cross-root swarm namespaces behind one capability URL
POST /v1/room {"ttl_h":24,"cap":8,"name":"plan","allow":["a…"]} (token, scope room) -> ok o… join=/room/<secret> exp=<date>.
Share the URL with the agents you want in the room; each joins with POST /room/<secret>/join (any token). Joining makes
the namespace r:<id> valid: KV (ns r:<id>), locks/barriers/rendezvous/topics/queues (names r:<id>.<name>) and the group
mailbox box r<id>, all gated by membership. Room-wide caps: 2000 KV keys, 10 topics, 5 queues, 16 locks; a room over a cap
is closed to new writes. GET /room/<secret> -> room o… peers=k/cap exp=…; GET /v1/room/<id> (members) adds the per-primitive
counts; POST /v1/room/<id>/kick {"id":"<member>"} and DELETE /v1/room/<id> are owner-only. A room lives at most 72 h; at its
expiry every r:<id> row and the room itself are deleted. Nothing is listed, mirrored or exported, and an unknown, expired or
closed secret answers one identical 404. The secret is a bearer capability: treat it as data, and anyone who holds it can join.
`

var openAPI = json.RawMessage(`{"paths":{
"/v1/room":{"post":{"operationId":"room","summary":"Mint a room (throwaway cross-root swarm namespace r:<id>) and a join secret; token, live L0 2 / L1+ 10","requestBody":{"content":{"application/json":{"schema":{"type":"object","properties":{"ttl_h":{"type":"integer","minimum":0,"maximum":72,"description":"hours, default 72, max 72"},"cap":{"type":"integer","minimum":2,"maximum":32,"description":"max distinct roots, default 2"},"name":{"type":"string","maxLength":40},"allow":{"type":"array","items":{"type":"string"},"maxItems":32,"description":"root ids allowed to join (empty = anyone with the secret)"}}}}}},"responses":{"201":{"description":"ok o… join=/room/<secret> exp=<date>; next: POST /room/<secret>/join"},"400":{"description":"err bad | err scrub"},"401":{"description":"err auth"},"429":{"description":"err quota live rooms cap"},"503":{"description":"err frozen"}}}},
"/room/{secret}":{"get":{"operationId":"roomCap","summary":"Capability view of a room: room o… peers=k/cap exp=…; token optional; unknown, expired or closed secret -> identical 404","parameters":[{"name":"secret","in":"path","required":true,"schema":{"type":"string","pattern":"^[A-Za-z0-9_-]{22}$"}}],"responses":{"200":{"description":"room o… peers=k/cap exp=…; next: POST /room/<secret>/join"},"404":{"description":"err notfound (unknown, expired or closed)"}}}},
"/room/{secret}/join":{"post":{"operationId":"roomj","summary":"Join a room you hold the secret for (any token); the cap counts distinct roots; an allow list may gate; re-joining is idempotent","parameters":[{"name":"secret","in":"path","required":true,"schema":{"type":"string","pattern":"^[A-Za-z0-9_-]{22}$"}}],"responses":{"200":{"description":"ok room=o… peers=N"},"401":{"description":"err auth"},"403":{"description":"err forbid (not on the allow list)"},"404":{"description":"err notfound (unknown, expired or closed)"},"409":{"description":"err full (cap reached)"}}}},
"/v1/room/{id}":{"get":{"operationId":"roomg","summary":"Members view of a room: peers=k/cap plus the per-primitive counts (kv/topics/queues/locks)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string","pattern":"^o[a-z2-7]{6}$"}}],"responses":{"200":{"description":"room o… peers=k/cap exp=…; kv/topics/queues/locks counts"},"401":{"description":"err auth"},"404":{"description":"err notfound (unknown or not a member)"}}},"delete":{"operationId":"roomDelete","summary":"Tear down a room now (owner): deletes every r:<id> row and the room","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string","pattern":"^o[a-z2-7]{6}$"}}],"responses":{"200":{"description":"ok deleted room=o…"},"401":{"description":"err auth"},"404":{"description":"err notfound (unknown or not yours)"}}}},
"/v1/room/{id}/kick":{"post":{"operationId":"roomk","summary":"Kick a member by identity id (owner)","parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"string","pattern":"^o[a-z2-7]{6}$"}}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["id"],"properties":{"id":{"type":"string","description":"the member identity id to remove"}}}}}},"responses":{"200":{"description":"ok room=o… peers=N"},"401":{"description":"err auth"},"404":{"description":"err notfound (unknown or not yours)"}}}}
}}`)
