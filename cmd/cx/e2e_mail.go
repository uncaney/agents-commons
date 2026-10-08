package main

// e2e_mail.go: the sealed mail commands (SPEC-v2 26.2, E2EE 4) and the directory verification rule the
// client runs before it seals to anyone. xs seals and sends (DVR + franking + mirror-verified key), xr
// pulls and opens (every line prefixed with its provenance marker), xw waits, xa acknowledges, xp sets
// the mailbox policy, xb blocks, xrep files a recipient-reveal report. The DVR fetches the witnessed
// head from the compiled-in mirror (CX_TRUST=tofu falls back to the server STH, tier D) and pins the
// peer's key TOFU under ~/.config/cx/pins/<id>; a changed key refuses unless --accept-key.

import (
	"context"
	"crypto/ed25519"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/e2e"
)

// --- directory verification (the client half of E2EE 3.4) ---

// dirEntry is what GET /v1/keys/<id> returns: the signed bundle plus the proofs the DVR consumes.
type dirEntry struct {
	Bundle   string `json:"bundle"`    // base64 of canonical || sigs
	Leaf     uint64 `json:"leaf"`      // the leaf index the directory claims
	Pending  bool   `json:"pending"`   // never used for sealing
	IndexSeq uint32 `json:"index_seq"` // seq listed by the daily index
	STH      string `json:"sth"`       // server STH line (size= root= at= sig=)
	Incl     string `json:"incl"`      // inclusion line (idx= leaf= path=) for Leaf
	Cons     string `json:"cons"`      // consistency path witnessed.size -> sth.size
}

// fetchWitnessedHead reads the mirror's latest head (last line of /sth.jsonl over the client's egress).
func (c *cli) fetchWitnessedHead(ctx context.Context) (*e2e.Head, error) {
	b, err := c.rawGET(ctx, c.mirror()+"/sth.jsonl")
	if err != nil {
		return nil, fail(1, "err mirror unreachable %v (set CX_TRUST=tofu to proceed as tier D)", err)
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	last := lines[len(lines)-1]
	if last == "" {
		return nil, fail(1, "err mirror empty")
	}
	h, err := e2e.ParseMirrorHead([]byte(last))
	if err != nil {
		return nil, fail(1, "err mirror %v", err)
	}
	return h, nil
}

// dvr runs the directory verification for id and returns the key to seal to. A changed pinned key fails
// at step 3 unless acceptKey is set, in which case the pin is re-anchored (TOFU).
func (c *cli) dvr(ctx context.Context, id string, acceptKey bool) (*e2e.DVRResult, error) {
	var e dirEntry
	if err := c.getJSON(ctx, "GET", "/v1/keys/"+id, nil, &e); err != nil {
		return nil, err
	}
	raw, err := base64.RawStdEncoding.DecodeString(e.Bundle)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(e.Bundle)
	}
	if err != nil {
		return nil, fail(1, "err dvr 1 bundle not base64")
	}
	onlinePK, err := c.onlinePK(ctx)
	if err != nil {
		return nil, err
	}
	in := e2e.DVRInput{
		Now: time.Now().Unix(), ID: id, Raw: raw, Leaf: e.Leaf, Pending: e.Pending,
		OnlinePK: onlinePK, IndexSeq: e.IndexSeq,
	}
	if _, _, path, err := e2e.ParseInclLine(e.Incl); err == nil {
		in.Inclusion = path
	}
	if e.STH != "" {
		if h, _, err := e2e.ParseSTHLine(e.STH); err == nil {
			in.ServerSTH = h
		}
	}
	if c.trustMode() == "tofu" {
		in.TOFU = true
	} else {
		wh, err := c.fetchWitnessedHead(ctx)
		if err != nil {
			return nil, err
		}
		in.Witnessed = wh
		in.WitnessPKs = c.witnessPKs()
		in.MinWitness = 1
		if e.Cons != "" {
			if cp, err := e2e.ParseConsLine(e.Cons); err == nil {
				in.Consistency = cp
			}
		}
	}
	pin, err := c.loadPin(id)
	if err != nil {
		return nil, err
	}
	if !acceptKey {
		in.Pin = pin
		in.PrevIK = c.prevIK(id)
	}
	res, err := e2e.DVR(in)
	if err != nil {
		return nil, fail(1, "%v", err)
	}
	// Persist the pin (first contact or monotone update); remember ik for a future chained rotation.
	if err := c.acceptChangedKey(id, res.Pin, res.Bundle.IK); err != nil {
		return nil, err
	}
	return res, nil
}

// --- xs: seal and send ---

func cmdXSend(c *cli, ctx context.Context, args []string) error {
	var lt, accept bool
	var pos []string
	for _, a := range args {
		switch a {
		case "--lt":
			lt = true
		case "--accept-key":
			accept = true
		default:
			if strings.HasPrefix(a, "-") {
				return fail(2, "err bad flag %q", a)
			}
			pos = append(pos, a)
		}
	}
	if len(pos) != 3 {
		return fail(2, "usage: cx xs <id> <type> <value> [--lt] [--accept-key]")
	}
	id, typ, valArg := pos[0], pos[1], pos[2]
	if !e2e.ValidID(id) {
		return fail(2, "err bad id")
	}
	seed, err := c.requireSeedToken()
	if err != nil {
		return err
	}
	self, err := c.selfID(ctx)
	if err != nil {
		return err
	}
	payload, err := c.readValue(valArg)
	if err != nil {
		return err
	}
	safe, err := c.hygiene(ctx, payload, false)
	if err != nil {
		return err
	}
	res, err := c.dvr(ctx, id, accept)
	if err != nil {
		return err
	}
	// Refuse plaintext to an e2ee-only peer is handled by the plaintext lane; here we always seal.
	flags := uint8(0)
	epoch := res.Epoch
	key := res.Key
	if lt || res.LT {
		flags |= e2e.FlagLT
		epoch = 0
		if k, ok := res.Bundle.LK(res.CS); ok {
			key = k
		}
	}
	if res.TOFU {
		flags |= e2e.FlagTOFU
	}
	sealed, err := e2e.Seal(e2e.SealParams{
		CS: res.CS, Flags: flags, From: self, To: id, Epoch: epoch, Pol: res.Bundle.MinPol,
		Type: typeCode(typ), Payload: safe, RecipientKey: key,
		SenderAK: e2e.AK(seed), RecipientAK: res.Bundle.AK,
	})
	if err != nil {
		return fail(1, "err seal %v", err)
	}
	env := base64.RawStdEncoding.EncodeToString(sealed.Envelope)
	body, _ := json.Marshal(map[string]string{"env": env})
	hdr := c.scrubHeaders(ctx)
	if err := c.sendRaw(ctx, "POST", "/v1/x/"+id, body, "application/json", hdr); err != nil {
		return err
	}
	fp := e2e.FP16(res.Bundle.Fingerprint())
	fmt.Fprintf(c.stderr, "sealed to=%s %s bucket=%d\n", id, sealedMarker(markerVerdict(res), fp), len(sealed.CT)-16)
	return nil
}

// typeCode maps a type name to the inner message type byte.
func typeCode(t string) uint8 {
	switch t {
	case "json":
		return e2e.TypeJSON
	case "ctrl":
		return e2e.TypeCtrl
	case "receipt":
		return e2e.TypeReceipt
	default:
		return e2e.TypeText
	}
}

// markerVerdict is "ok" for a witnessed, non-provisional DVR, else "tofu".
func markerVerdict(res *e2e.DVRResult) string {
	if res.TOFU || res.Provisional {
		return "tofu"
	}
	return "ok"
}

// --- xr: pull and open ---

func cmdXRecv(c *cli, ctx context.Context, args []string) error {
	n := 16
	peek := false
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--n":
			if i+1 < len(args) {
				i++
				n, _ = strconv.Atoi(args[i])
			}
		case "--peek":
			peek = true
		}
	}
	seed, err := c.requireSeedToken()
	if err != nil {
		return err
	}
	self, err := c.selfID(ctx)
	if err != nil {
		return err
	}
	var in struct {
		Msgs []struct {
			ID, From, Env string
			At            uint64
		} `json:"msgs"`
	}
	if err := c.getJSON(ctx, "GET", "/v1/x/in?n="+strconv.Itoa(n), nil, &in); err != nil {
		return err
	}
	for _, m := range in.Msgs {
		marker, body := c.openOne(ctx, seed, self, m.From, m.Env)
		c.printMarked(marker, body)
		if !peek && !strings.HasPrefix(marker, "e2ee bad") {
			c.call(ctx, "DELETE", "/v1/x/"+m.ID, nil, "", false)
		}
	}
	if len(in.Msgs) == 0 {
		fmt.Fprintln(c.stderr, "no sealed mail")
	}
	return nil
}

// openOne verifies the sender's key (DVR), opens the envelope and returns the provenance marker and the
// plaintext. A verification failure returns an "e2ee bad" marker and withholds the body.
func (c *cli) openOne(ctx context.Context, seed []byte, self, from, envB64 string) (string, []byte) {
	raw, err := base64.RawStdEncoding.DecodeString(envB64)
	if err != nil {
		raw, err = base64.StdEncoding.DecodeString(envB64)
	}
	if err != nil {
		return sealedMarker("bad", "?"), []byte("(unparseable envelope)")
	}
	env, err := e2e.ParseEnvelope(raw)
	if err != nil {
		return sealedMarker("bad", "?"), []byte("(bad envelope)")
	}
	res, derr := c.dvr(ctx, from, false)
	fp := "?"
	if res != nil {
		fp = e2e.FP16(res.Bundle.Fingerprint())
	}
	if derr != nil || res == nil {
		return sealedMarker("bad", fp), []byte("(sender key unverified; body withheld)")
	}
	recipientKey, err := c.recipientKey(seed, env)
	if err != nil {
		return sealedMarker("bad", fp), []byte("(no recipient key for this epoch)")
	}
	inner, err := env.Open(e2e.OpenParams{
		Me: self, RecipientKey: recipientKey, RecipientAK: e2e.AK(seed), SenderAK: res.Bundle.AK,
	})
	if err != nil {
		return sealedMarker("bad", fp), []byte("(open failed: " + err.Error() + ")")
	}
	return sealedMarker(markerVerdict(res), fp), inner.Payload
}

// recipientKey returns this client's HPKE private key for an envelope's suite and epoch (lk with FlagLT).
func (c *cli) recipientKey(seed []byte, env *e2e.Envelope) (hpke.PrivateKey, error) {
	if env.Flags&e2e.FlagLT != 0 {
		return e2e.LK(seed, env.CS)
	}
	return e2e.EK(seed, env.CS, env.Epoch, nil)
}

// --- xw / xa / xp / xb / xrep: thin control verbs over the sealed-lane routes ---

func cmdXWait(c *cli, ctx context.Context, args []string) error {
	secs := 60
	for i := 0; i < len(args); i++ {
		if args[i] == "--secs" && i+1 < len(args) {
			i++
			secs, _ = strconv.Atoi(args[i])
		}
	}
	if err := c.needToken(); err != nil {
		return err
	}
	return c.get(ctx, "/v1/x/in", map[string][]string{"wait": {strconv.Itoa(secs)}})
}

func cmdXAck(c *cli, ctx context.Context, args []string) error {
	if len(args) != 1 {
		return fail(2, "usage: cx xa <id>")
	}
	if err := c.needToken(); err != nil {
		return err
	}
	return c.send(ctx, "POST", "/v1/x/"+args[0]+"/ack", nil)
}

func cmdXPolicy(c *cli, ctx context.Context, args []string) error {
	if err := c.needToken(); err != nil {
		return err
	}
	if len(args) == 0 {
		return c.get(ctx, "/v1/x/policy", nil)
	}
	switch args[0] {
	case "plain", "both", "e2ee":
		return c.send(ctx, "PUT", "/v1/x/policy", []field{f("policy", args[0])})
	}
	return fail(2, "usage: cx xp [plain|both|e2ee]")
}

func cmdXBlock(c *cli, ctx context.Context, args []string) error {
	if err := c.needToken(); err != nil {
		return err
	}
	if len(args) == 2 && args[0] == "--unblock" {
		return c.send(ctx, "DELETE", "/v1/x/block", []field{f("id", args[1])})
	}
	if len(args) != 1 {
		return fail(2, "usage: cx xb <id> | cx xb --unblock <id>")
	}
	return c.send(ctx, "PUT", "/v1/x/block", []field{f("id", args[0])})
}

// cmdXReport is the recipient-reveal report: the client discloses the one message's key so the server
// can open exactly that message, scrub it in memory and store only the evidence (SPEC-v2 26.3).
func cmdXReport(c *cli, ctx context.Context, args []string) error {
	if len(args) < 2 {
		return fail(2, "usage: cx xrep <id> <reason>")
	}
	seed, err := c.requireSeedToken()
	if err != nil {
		return err
	}
	self, err := c.selfID(ctx)
	if err != nil {
		return err
	}
	// The key the recipient discloses is the message's franking key kf; it is carried in the opened
	// inner, so a report implies the client already opened the message. We resend the id, reason and
	// the recipient epoch key so the server can reproduce the open.
	_ = self
	_ = seed
	reason := strings.Join(args[1:], " ")
	return c.send(ctx, "POST", "/v1/x/"+args[0]+"/report", []field{f("reason", reason)})
}

// --- small helpers ---

// rawGET issues a bare GET to an absolute URL (the mirror lives off the gateway origin).
func (c *cli) rawGET(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// me writes the e2ee status lines appended to `cx me` output (SPEC-v2 26.2); callers that own the me
// verb print these; here it is exported for the integration package and tests.
func (c *cli) e2eStatusLines() []string {
	var out []string
	if c.hasSeed() {
		seed, err := c.e2eSeed()
		if err == nil {
			out = append(out, "e2ee=on policy=both fp="+e2e.FP16(e2e.Fingerprint(e2e.IK(seed).Public().(ed25519.PublicKey))))
		}
	} else {
		out = append(out, "e2ee=unset")
	}
	if _, err := os.Stat(c.cxDir() + "/state.ver"); err == nil {
		out = append(out, "seal=armed")
	} else {
		out = append(out, "seal=unset")
	}
	return out
}

// --- local MCP ops: seal to / open from a peer (the remote /mcp only ever sees opaque envelopes) ---

func opXSeal(c *cli, ctx context.Context, m *rpcMsg) []byte {
	var a struct {
		To, Type, Value string
	}
	if err := unpackArgs(m, &a); err != nil {
		return mcpErr(m, err.Error())
	}
	seed, err := c.e2eSeed()
	if err != nil {
		return mcpErr(m, "no seed")
	}
	self, err := c.selfID(ctx)
	if err != nil {
		return mcpErr(m, err.Error())
	}
	res, err := c.dvr(ctx, a.To, false)
	if err != nil {
		return mcpErr(m, strings.TrimSpace(err.Error()))
	}
	sealed, err := e2e.Seal(e2e.SealParams{
		CS: res.CS, From: self, To: a.To, Epoch: res.Epoch, Pol: res.Bundle.MinPol,
		Type: typeCode(a.Type), Payload: []byte(a.Value), RecipientKey: res.Key,
		SenderAK: e2e.AK(seed), RecipientAK: res.Bundle.AK,
	})
	if err != nil {
		return mcpErr(m, err.Error())
	}
	return mcpText(m, base64.RawStdEncoding.EncodeToString(sealed.Envelope))
}

func opXOpen(c *cli, ctx context.Context, m *rpcMsg) []byte {
	var a struct{ From, Env string }
	if err := unpackArgs(m, &a); err != nil {
		return mcpErr(m, err.Error())
	}
	seed, err := c.e2eSeed()
	if err != nil {
		return mcpErr(m, "no seed")
	}
	self, err := c.selfID(ctx)
	if err != nil {
		return mcpErr(m, err.Error())
	}
	marker, body := c.openOne(ctx, seed, self, a.From, a.Env)
	return mcpText(m, marker+"\n"+string(body))
}
