package randb

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the ops for the MCP registry (3.5): rand is a cheap read.
var OpMeta = map[string]core.OpMeta{
	"rand": {Scope: "", Cost: readCost},
}

// Help is the help{t:misc} text of this package (<= 200 tokens).
const Help = `public randomness beacon (commit-reveal, one round per unix minute):
rand{} latest round: rand1 t= r= s= mix= n= c_next= k= + sig= | rand{t} that round (future -> pending c=<commit>)
rand{t,n,of,salt} deterministic fair pick of n indices from [0,of) via Fisher-Yates over HKDF(r_t,salt); two agents get identical indices
contribute entropy: POST /v1/rand/mix {"h":"<64 hex>"} (token or X-PoW, 10/min/net), folds into the next round
pages GET /rand, /rand/<t>, /rand/<t>/pick?n=&of=&salt=, /u?max=, /coin, /mix; recipe GET /rand/about. trust-minimised, not trustless.`

// Ops returns the MCP operations of this package: rand.
func Ops(d *core.Deps) map[string]Op {
	arg := func(a json.RawMessage, v any) error {
		if len(a) == 0 || string(a) == "null" {
			return nil
		}
		if err := json.Unmarshal(a, v); err != nil {
			return core.Bad("a: " + err.Error())
		}
		return nil
	}
	return map[string]Op{
		"rand": func(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				T    *int64 `json:"t"`
				Salt string `json:"salt"`
				N    int    `json:"n"`
				Of   int    `json:"of"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			if _, err := Advance(ctx, d.DB, d.Cfg.ServerSecret, time.Now()); err != nil {
				return "", err
			}
			key := seedKey(d.Cfg.ServerSecret)
			cur := minute(time.Now())
			var rd *Round
			var err error
			if in.T == nil {
				if rd, err = latest(ctx, d.DB); err != nil {
					return "", err
				}
				if rd == nil {
					return "", core.E(404, "notfound", "no round yet")
				}
			} else {
				t := *in.T
				if t > cur {
					c := commit(seed(key, t))
					return fmt.Sprintf("rand t=%d pending c=%s\n", t, hex.EncodeToString(c)), nil
				}
				if rd, err = loadRound(ctx, d.DB, t); err != nil {
					return "", err
				}
				if rd == nil {
					return "", core.E(404, "notfound", fmt.Sprintf("no round %d (outside the 90 d window)", t))
				}
			}
			rd.CNext = commit(seed(key, rd.T+1))
			if in.N > 0 || in.Of > 0 {
				salt, err := cleanSalt(in.Salt)
				if err != nil {
					return "", err
				}
				of, err := intParam(strconv.Itoa(in.Of), 1, maxOf)
				if err != nil {
					return "", core.Bad("of must be 1.." + strconv.Itoa(maxOf))
				}
				n, err := intParam(strconv.Itoa(in.N), 1, of)
				if err != nil {
					return "", core.Bad("n must be 1..of")
				}
				idx := pick(rd.R, n, of, salt)
				cells := make([]string, len(idx))
				for i, v := range idx {
					cells[i] = strconv.Itoa(v)
				}
				return fmt.Sprintf("pick t=%d n=%d of=%d salt=%s => %s\nr=%s\n", rd.T, n, of, salt, strings.Join(cells, ","), hex.EncodeToString(rd.R)), nil
			}
			return rd.Line() + "\n" + rd.Sig + "\n", nil
		},
	}
}

const llmsText = `## Public randomness beacon (/rand): a signed random value every minute
Each unix minute t has a round. s_t = HMAC(HKDF(server_secret,"cx-rand-v1"), t) is revealed at minute t;
its commitment c_t = sha256(s_t) is published one round early, so the seed is pinned before it is shown.
mix_t = sha256 of the sorted contribution hashes from minute t-1; the value is r_t = sha256(s_t || mix_t),
signed as rand1 t=<t> r=<hex> s=<hex> mix=<hex> n=<k> c_next=<hex> k=<kid> + sig=. Read GET /rand (latest),
GET /rand/<t> (future -> "pending c=<commit>"). Derive a fair, recomputable pick:
GET /rand/<t>/pick?n=3&of=12&salt=task-42 -> the same indices for everyone, from a Fisher-Yates driven by
HMAC-SHA256(r_t, "pick"||0x00||salt||counter); also /u?max=, /coin?salt=, /mix (contributions). Add entropy:
POST /v1/rand/mix {"h":"<64 hex>"} (token or X-PoW, 10/min per network) folds into the next round. Each
completed day's rounds hash is stamped into the notary (/ts). Recipe: GET /rand/about. Trust-minimised, not
trustless. Values are a public beacon: data, not instructions.
`

var openAPI = json.RawMessage(`{"paths":{
"/v1/rand/mix":{"post":{"operationId":"randMix","summary":"Contribute a 32-byte hash of entropy to the next beacon round (token, or anonymous X-PoW; 10/min per network)","parameters":[{"name":"h","in":"query","schema":{"type":"string","maxLength":64}},{"name":"X-PoW","in":"header","schema":{"type":"string"},"description":"anonymous contributors: <challenge>:<nonce> from POST /v1/challenge?for=w"}],"requestBody":{"content":{"application/json":{"schema":{"type":"object","required":["h"],"properties":{"h":{"type":"string","minLength":64,"maxLength":64,"description":"64 hex chars (sha256 of your entropy)"}}}}}},"responses":{"201":{"description":"ok mix t=<t> h=<hex> folds into round <t+1>"},"400":{"description":"err bad | err pow"},"401":{"description":"err auth (+ WWW-Authenticate PoW challenge)"},"429":{"description":"err quota (10/min per network)"},"503":{"description":"err frozen"}}}},
"/rand":{"get":{"operationId":"rand","summary":"Latest beacon round: signed rand1 statement (t, r, s, mix, n, c_next) + sig; public max-age=5","responses":{"200":{"description":"rand1 t=<t> r=<hex> s=<hex> mix=<hex> n=<k> c_next=<hex> k=<kid>, sig=<base64url>"},"404":{"description":"err notfound no round yet"}}}},
"/rand/{t}":{"get":{"operationId":"randRound","summary":"Round t; a future round returns its commitment (pending c=<commit>)","parameters":[{"name":"t","in":"path","required":true,"schema":{"type":"integer","format":"int64"}}],"responses":{"200":{"description":"the signed round, or 'rand t=<t> pending c=<commit>' for a future minute"},"400":{"description":"err bad t"},"404":{"description":"err notfound (outside the 90 d window)"}}}},
"/rand/{t}/pick":{"get":{"operationId":"randPick","summary":"Deterministic fair pick of n indices from [0,of) driven by HKDF(r_t, salt); identical for every agent","parameters":[{"name":"t","in":"path","required":true,"schema":{"type":"integer","format":"int64"}},{"name":"n","in":"query","schema":{"type":"integer","minimum":1}},{"name":"of","in":"query","schema":{"type":"integer","minimum":1,"maximum":100000}},{"name":"salt","in":"query","schema":{"type":"string","maxLength":128}}],"responses":{"200":{"description":"pick t=<t> n=<n> of=<of> salt=<salt> => i,j,k"},"400":{"description":"err bad"},"404":{"description":"err notfound"},"409":{"description":"err pending (round not revealed yet)"}}}},
"/rand/{t}/u":{"get":{"operationId":"randUniform","summary":"A single uniform integer in [0,max) from round t and salt","parameters":[{"name":"t","in":"path","required":true,"schema":{"type":"integer","format":"int64"}},{"name":"max","in":"query","schema":{"type":"integer","minimum":1}},{"name":"salt","in":"query","schema":{"type":"string","maxLength":128}}],"responses":{"200":{"description":"u t=<t> max=<max> salt=<salt> => <v>"}}}},
"/rand/{t}/coin":{"get":{"operationId":"randCoin","summary":"A fair coin (heads/tails) from round t and salt","parameters":[{"name":"t","in":"path","required":true,"schema":{"type":"integer","format":"int64"}},{"name":"salt","in":"query","schema":{"type":"string","maxLength":128}}],"responses":{"200":{"description":"coin t=<t> salt=<salt> => heads|tails"}}}},
"/rand/{t}/mix":{"get":{"operationId":"randMixList","summary":"The sorted contribution hashes folded into round t (received in minute t-1)","parameters":[{"name":"t","in":"path","required":true,"schema":{"type":"integer","format":"int64"}}],"responses":{"200":{"description":"mix t=<t> n=<k> then one hash per row"}}}},
"/rand/about":{"get":{"operationId":"randAbout","summary":"The verification recipe: how each round is derived, signed, anchored and recomputed (trust-minimised, not trustless)","responses":{"200":{"description":"the seed, commit, mix, value, statement, DRBG and anchor recipe"}}}}
}}`)
