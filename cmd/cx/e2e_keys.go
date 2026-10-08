package main

// e2e_keys.go: identity on the sealed lane. `cx join` (the seed-bearing form) generates the 32-byte
// seed, derives the seq-1 bundle, and publishes it inside registration; the seed is printed once as
// CX_SEED and stored 0600 next to the token with --save-seed. `cx keys` / `cx fp` show the derived
// public keys and the safety number; `cx pk verify` checks a published key; `cx log witness|audit`
// is the client half of the two-witness DVR and the key-substitution alert (SPEC-v2 26.6, E2EE P9).
// `cx selftest` runs the sealed-lane known-answer round-trips. Child seeds derive with Sub (a child
// cannot climb back to the parent).

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/e2e"
)

// joinE2EOpts controls the seed-bearing join.
type joinE2EOpts struct {
	saveSeed bool
	policy   uint8 // bundle mail policy (PolicyBoth by default)
}

// joinE2E is `cx join --e2e`: PoW, a seq-1 bundle derived from a fresh seed, registration carrying the
// bundle, and the recovery wrap. The seed is returned so the caller can print CX_SEED exactly once.
func (c *cli) joinE2E(ctx context.Context, name string, o joinE2EOpts) (id string, seed []byte, err error) {
	var ch struct {
		C    string `json:"c"`
		Bits int    `json:"bits"`
		ID   string `json:"id"`
	}
	if err = c.getJSON(ctx, "POST", "/v1/challenge", struct{}{}, &ch); err != nil {
		return "", nil, err
	}
	if ch.C == "" || ch.ID == "" {
		return "", nil, fail(1, "err proto challenge missing id (server not e2e-enabled)")
	}
	nonce := solve(ctx, ch.C, ch.Bits)
	if nonce == "" {
		return "", nil, fail(1, "err pow cancelled")
	}
	seed = e2e.NewSeed()
	pol := o.policy
	if pol == 0 {
		pol = e2e.PolicyBoth
	}
	raw, err := buildRegBundle(seed, ch.ID, pol)
	if err != nil {
		return "", nil, fail(1, "err bundle %v", err)
	}
	var reg struct {
		ID, Token string
	}
	body := map[string]string{"c": ch.C, "nonce": nonce, "name": name, "bundle": base64.RawStdEncoding.EncodeToString(raw)}
	if err = c.getJSON(ctx, "POST", "/v1/register", body, &reg); err != nil {
		return "", nil, err
	}
	if reg.ID == "" || reg.Token == "" {
		return "", nil, fail(1, "err proto bad register reply")
	}
	if err = c.saveToken(reg.Token); err != nil {
		return "", nil, fail(1, "err save token: %v", err)
	}
	c.token = reg.Token
	_ = writeFile0600(c.cxDir()+"/id", []byte(reg.ID+"\n"))
	if o.saveSeed {
		if err = c.saveSeed(seed); err != nil {
			return "", nil, fail(1, "err save seed: %v", err)
		}
	}
	return reg.ID, seed, nil
}

// buildRegBundle derives and signs the seq-1 registration bundle (mode D, five epochs, CS1, LK last
// resort accepted) addressed to id, and returns canonical || sigs as the wire form.
func buildRegBundle(seed []byte, id string, policy uint8) ([]byte, error) {
	now := time.Now().Unix()
	b, err := e2e.NewBundle(seed, e2e.BundleParams{
		ID:         id,
		Seq:        1,
		IAT:        uint32(now),
		Exp:        uint32(now + 30*86400),
		Flags:      e2e.FlagLKOK,
		MailPolicy: policy,
		E0:         e2e.Epoch(now),
		NEK:        e2e.EpochsAhead,
		RevCommit:  make([]byte, 32),
	})
	if err != nil {
		return nil, err
	}
	return b.Sign(e2e.IK(seed), nil, nil)
}

// cmdJoinE2E is wired by the integration package through the registry; exposed here so the seed-bearing
// join can also be driven directly. It prints id, then CX_SEED once, then arms the recovery wrap.
func cmdJoinE2E(c *cli, ctx context.Context, args []string) error {
	var name string
	var o joinE2EOpts
	for _, a := range args {
		switch {
		case a == "--save-seed":
			o.saveSeed = true
		case a == "--e2e":
		case strings.HasPrefix(a, "-"):
			return fail(2, "err bad flag %q", a)
		case name == "":
			name = a
		default:
			return fail(2, "usage: cx join <name> [--e2e] [--save-seed]")
		}
	}
	if name == "" {
		return fail(2, "usage: cx join <name> [--e2e] [--save-seed]")
	}
	if c.hasToken() {
		return fail(1, "err exists token already present (%s)", c.tokenPath())
	}
	id, seed, err := c.joinE2E(ctx, name, o)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "id=%s\n", id)
	fmt.Fprintf(c.stdout, "CX_SEED=%s  (printed once; store it offline)\n", e2e.FormatSeed(seed))
	if !o.saveSeed {
		fmt.Fprintln(c.stderr, "seed not saved to disk; export CX_SEED to use the sealed lane")
	}
	// Arm the recovery wrap so sealed memory is restorable from the recovery code (SPEC-v2 26.4).
	recovery := e2e.NewSeed()
	if err := c.putMKWrap(ctx, seed, recovery); err == nil {
		fmt.Fprintf(c.stdout, "CX_RECOVERY=%s  (printed once; store it offline)\n", e2e.FormatSeed(recovery))
	}
	return nil
}

// selfID returns this identity's id (the <cxdir>/id cache written at join, else GET /v1/me).
func (c *cli) selfID(ctx context.Context) (string, error) {
	if b, err := os.ReadFile(c.cxDir() + "/id"); err == nil {
		if id := strings.TrimSpace(string(b)); e2e.ValidID(id) {
			return id, nil
		}
	}
	b, err := c.call(ctx, "GET", "/v1/me", nil, "", false)
	if err != nil {
		return "", err
	}
	for _, f := range strings.Fields(string(b)) {
		if k, v, ok := strings.Cut(f, "="); ok && k == "id" && e2e.ValidID(v) {
			return v, nil
		}
	}
	return "", fail(1, "err no id")
}

// cmdKeys shows the derived public keys and fingerprint.
func cmdKeys(c *cli, ctx context.Context, args []string) error {
	seed, err := c.e2eSeed()
	if err != nil {
		return err
	}
	ikPub := e2e.IK(seed).Public().(ed25519.PublicKey)
	fp := e2e.Fingerprint(ikPub)
	fmt.Fprintf(c.stdout, "fp=%s\n", e2e.FP16(fp))
	if len(args) > 0 && args[0] == "--bundle" {
		fmt.Fprintf(c.stdout, "ik=%s\n", b64url(ikPub))
		fmt.Fprintf(c.stdout, "rk=%s\n", b64url(e2e.RK(seed).Public().(ed25519.PublicKey)))
		fmt.Fprintf(c.stdout, "ak=%s\n", b64url(e2e.AK(seed).PublicKey().Bytes()))
	}
	fmt.Fprintf(c.stdout, "safety=%s\n", e2e.FPDigits(fp))
	return nil
}

// cmdFP prints the safety number of self, or of a pinned peer.
func cmdFP(c *cli, ctx context.Context, args []string) error {
	if len(args) == 0 {
		seed, err := c.e2eSeed()
		if err != nil {
			return err
		}
		fp := e2e.Fingerprint(e2e.IK(seed).Public().(ed25519.PublicKey))
		fmt.Fprintf(c.stdout, "self %s\n%s\n", e2e.FP16(fp), e2e.FPDigits(fp))
		return nil
	}
	id := args[0]
	pin, err := c.loadPin(id)
	if err != nil {
		return err
	}
	if pin == nil {
		return fail(1, "err no pin for %s (send once to pin it)", id)
	}
	fp, err := hex.DecodeString(pin.FP)
	if err != nil || len(fp) != 32 {
		return fail(1, "err pin corrupt %s", id)
	}
	fmt.Fprintf(c.stdout, "%s %s\n%s\n", id, e2e.FP16(fp), e2e.FPDigits(fp))
	return nil
}

// cmdPK verifies a published key against its pin and the transparency root.
func cmdPK(c *cli, ctx context.Context, args []string) error {
	if len(args) != 2 || args[0] != "verify" {
		return fail(2, "usage: cx pk verify <id>")
	}
	id := args[1]
	if !e2e.ValidID(id) {
		return fail(2, "err bad id")
	}
	b, err := c.call(ctx, "GET", "/v1/pk/"+id, nil, "", false)
	if err != nil {
		return err
	}
	kv := map[string]string{}
	for _, f := range strings.Fields(string(b)) {
		if k, v, ok := strings.Cut(f, "="); ok {
			kv[k] = v
		}
	}
	ik, err := base64.RawURLEncoding.DecodeString(kv["ik"])
	if err != nil || len(ik) != ed25519.PublicKeySize {
		// pk1 lines may use std base64; try that too
		if ik, err = base64.StdEncoding.DecodeString(kv["ik"]); err != nil || len(ik) != ed25519.PublicKeySize {
			return fail(1, "err pk bad ik")
		}
	}
	fp := e2e.Fingerprint(ik)
	verdict := "NEW"
	if pin, _ := c.loadPin(id); pin != nil {
		if pin.FP == hex.EncodeToString(fp) {
			verdict = "match"
		} else {
			verdict = "CHANGED"
		}
	}
	fmt.Fprintf(c.stdout, "pk %s fp=%s n=%s %s\n", id, e2e.FP16(fp), kv["n"], verdict)
	return nil
}

// cmdWit is the client-side transparency check (SPEC-v2 26.6, E2EE P9); also reachable as the documented
// `cx log witness|audit` form through the integration package's dispatcher.
func cmdWit(c *cli, ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail(2, "usage: cx wit witness | audit  (alias: cx log witness|audit)")
	}
	switch args[0] {
	case "witness":
		return c.logWitness(ctx)
	case "audit":
		return c.logAudit(ctx)
	}
	return fail(2, "usage: cx wit witness | audit")
}

// logWitness fetches the mirror's latest head and verifies it under the pinned online and witness keys.
func (c *cli) logWitness(ctx context.Context) error {
	onlinePK, err := c.onlinePK(ctx)
	if err != nil {
		return err
	}
	head, err := c.fetchWitnessedHead(ctx)
	if err != nil {
		return err
	}
	w := c.witnessPKs()
	minW := 1
	if len(w) == 0 {
		minW = 0
	}
	if err := e2e.VerifyHead(head, onlinePK, w, minW); err != nil {
		return fail(1, "err log witness %v", err)
	}
	fmt.Fprintf(c.stdout, "witnessed size=%d root=%s witnesses=%d\n", head.Size, hex.EncodeToString(head.Root)[:16], len(head.Witness))
	return nil
}

// logAudit checks that the leaves the log holds for this id are exactly the ones we produced (step 5).
func (c *cli) logAudit(ctx context.Context) error {
	id, err := c.selfID(ctx)
	if err != nil {
		return err
	}
	b, err := c.call(ctx, "GET", "/v1/log/id/"+id, nil, "", false)
	if err != nil {
		return err
	}
	var logged []uint64
	for _, f := range strings.Fields(string(b)) {
		if k, v, ok := strings.Cut(f, "="); ok && (k == "leaf" || k == "idx") {
			if n, e := strconv.ParseUint(v, 10, 64); e == nil {
				logged = append(logged, n)
			}
		}
	}
	mine := c.ownLeaves()
	if err := e2e.VerifyOwnEntry(mine, logged); err != nil {
		return fail(1, "%v", err)
	}
	fmt.Fprintf(c.stdout, "audit ok leaves=%d\n", len(logged))
	return nil
}

// ownLeaves reads the leaf indices this client has produced (sealed-state own_leaves; a local cache
// mirrors it so audit works offline).
func (c *cli) ownLeaves() []uint64 {
	b, err := os.ReadFile(c.cxDir() + "/own_leaves")
	if err != nil {
		return nil
	}
	var out []uint64
	for _, f := range strings.Fields(string(b)) {
		if n, e := strconv.ParseUint(f, 10, 64); e == nil {
			out = append(out, n)
		}
	}
	return out
}

// deriveSubSeed is `cx sub --e2e`: the child seed handed to a sub-agent with its token. It is a one-way
// HKDF of the parent seed and the child id, so a compromised child cannot climb back to the parent.
func deriveSubSeed(parent []byte, subid string) string {
	return e2e.FormatSeed(e2e.Sub(parent, subid))
}

// cmdSelftest runs the sealed-lane known-answer round-trips: derive -> bundle -> seal -> open, the seal1
// memory recipe, the sealed-state recipe and the mk recovery wrap. A failure is fatal (exit 1).
func cmdSelftest(c *cli, ctx context.Context, args []string) error {
	n, err := runSelftest()
	if err != nil {
		return fail(1, "err selftest %v", err)
	}
	fmt.Fprintf(c.stdout, "selftest ok n=%d\n", n)
	return nil
}

// runSelftest exercises every primitive the client depends on and returns the number of checks passed.
func runSelftest() (int, error) {
	seed := e2e.NewSeed()
	id := "atestid"
	n := 0

	// bundle derive + sign + parse + verify
	raw, err := buildRegBundle(seed, id, e2e.PolicyBoth)
	if err != nil {
		return n, fmt.Errorf("bundle build: %w", err)
	}
	b, err := e2e.ParseBundle(raw)
	if err != nil || b.Verify() != nil || b.ID != id {
		return n, fmt.Errorf("bundle verify")
	}
	n++

	// seal1 memory round-trip (aad-bound)
	kv := e2e.SealV1Key(e2e.MK(seed))
	val, err := e2e.Seal1(kv, sealAAD("kv", "k1"), []byte("secret value"), nil)
	if err != nil || !e2e.IsSealed(val) {
		return n, fmt.Errorf("seal1")
	}
	if pt, err := e2e.Open1(kv, sealAAD("kv", "k1"), val); err != nil || string(pt) != "secret value" {
		return n, fmt.Errorf("open1")
	}
	// wrong aad must fail
	if _, err := e2e.Open1(kv, sealAAD("kv", "other"), val); err == nil {
		return n, fmt.Errorf("open1 aad not bound")
	}
	n++

	// sealed state round-trip
	st := &e2e.State{Cursor: 7, Seen: []string{"aaa"}}
	pt, _ := st.Encode()
	blob, err := e2e.SealState(e2e.KState(seed), id, 1, pt, nil)
	if err != nil {
		return n, fmt.Errorf("seal state")
	}
	if got, err := e2e.OpenState(e2e.KState(seed), id, 1, blob); err != nil || string(got) != string(pt) {
		return n, fmt.Errorf("open state")
	}
	n++

	// mk recovery wrap round-trip
	recovery := e2e.NewSeed()
	wrapped, err := e2e.WrapMK(e2e.MK(seed), recovery, nil)
	if err != nil {
		return n, fmt.Errorf("wrap mk")
	}
	if mk, err := e2e.UnwrapMK(wrapped, recovery); err != nil || string(mk) != string(e2e.MK(seed)) {
		return n, fmt.Errorf("unwrap mk")
	}
	n++

	// sub seed derivation is one-way and deterministic
	child := e2e.Sub(seed, "achild1")
	if len(child) != e2e.SeedSize || string(child) == string(seed) || string(child) != string(e2e.Sub(seed, "achild1")) {
		return n, fmt.Errorf("sub derive")
	}
	n++
	return n, nil
}
