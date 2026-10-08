package main

// e2e_state.go: the TOFU pin store (~/.config/cx/pins/<id>), the sealed-state cache (keyed from the
// seed via KState, the one thing a stateless agent cannot re-derive), and the client-side policy-pack
// hygiene gate (SPEC-v2 26.5): fetch /scrub/rules, pin rules_v, and refuse or mask tier-1 secrets
// before anything is sealed. A changed pinned key refuses unless --accept-key is given.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/e2e"
)

// --- TOFU pins ---

// loadPin reads the pin for id; (nil,nil) on first contact.
func (c *cli) loadPin(id string) (*e2e.Pin, error) {
	b, err := os.ReadFile(c.pinPath(id))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var p e2e.Pin
	if json.Unmarshal(b, &p) != nil {
		return nil, fail(1, "err pin corrupt %s", id)
	}
	return &p, nil
}

// savePin writes the pin 0600 (atomic).
func (c *cli) savePin(id string, p e2e.Pin) error {
	b, _ := json.Marshal(p)
	return writeFile0600(c.pinPath(id), b)
}

// prevIKForRotation returns the pinned ik bytes when a chained rotation may be accepted. The pin stores
// the fingerprint, not the key, so a rotation proof (sig_prev) is what the DVR checks; absent the raw
// previous ik we pass nil and a changed key is refused unless --accept-key.
func (c *cli) prevIK(id string) []byte {
	b, err := os.ReadFile(c.pinPath(id) + ".ik")
	if err != nil {
		return nil
	}
	ik, _ := base64.RawURLEncoding.DecodeString(strings.TrimSpace(string(b)))
	if len(ik) == 32 {
		return ik
	}
	return nil
}

// acceptChangedKey overwrites the pin and remembers the new ik (TOFU re-anchor under --accept-key).
func (c *cli) acceptChangedKey(id string, p e2e.Pin, ik []byte) error {
	if err := c.savePin(id, p); err != nil {
		return err
	}
	return writeFile0600(c.pinPath(id)+".ik", []byte(base64.RawURLEncoding.EncodeToString(ik)))
}

// --- policy-pack hygiene (client-side scrub, SPEC-v2 26.5) ---

// hygiene is the gate every write path runs before sealing: a tier-1 secret refuses the write
// (`err scrub <kind>`) unless mask is set, in which case the matching spans are redacted. tier-2 PII
// is left to the server's franking path. Returns the (possibly masked) bytes to seal.
func (c *cli) hygiene(ctx context.Context, pt []byte, mask bool) ([]byte, error) {
	r := c.scrubRules(ctx)
	if r == nil {
		return pt, nil // rules unreachable: franking remains the enforcement path (26.5)
	}
	kind := r.hit(string(pt))
	if kind == "" {
		return pt, nil
	}
	if !mask {
		return nil, fail(1, "err scrub %s (use --mask to redact, or --plain only for non-secret text)", kind)
	}
	return maskTier1(r, pt), nil
}

// maskTier1 replaces every tier-1 match with [REDACTED:<kind>].
func maskTier1(r *scrubRules, pt []byte) []byte {
	s := string(pt)
	for i, rx := range r.tier1 {
		s = rx.ReplaceAllString(s, "[REDACTED:"+r.kinds[i]+"]")
	}
	return []byte(s)
}

// scrubVersion returns the rules_v the client pins and sends as X-Scrub-V on sealed writes.
func (c *cli) scrubVersion(ctx context.Context) string {
	_, _, b, err := c.callH(ctx, "GET", "/scrub/rules", nil, "", false, nil)
	if err != nil {
		return ""
	}
	line, _, _ := strings.Cut(string(b), "\n")
	for _, kv := range strings.Fields(line) {
		if k, v, ok := strings.Cut(kv, "="); ok && k == "rules_v" {
			return v
		}
	}
	return ""
}

// scrubHeaders returns the X-Scrub-V header map for a sealed write (scrub=client recorded server-side).
func (c *cli) scrubHeaders(ctx context.Context) map[string]string {
	if v := c.scrubVersion(ctx); v != "" {
		return map[string]string{"X-Scrub-V": v}
	}
	return nil
}

// --- sealed-state cache (E2EE 7.2): the agent's pins/cursor/seen window, sealed under KState ---

// stateVer is the monotone version the server stores alongside the blob; we keep it in a tiny local
// counter file so a rollback (served ver < our ver) is detectable (StateStale).
func (c *cli) stateVerPath() string { return c.cxDir() + "/state.ver" }

func (c *cli) readStateVer() uint64 {
	b, _ := os.ReadFile(c.stateVerPath())
	n, _ := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	return n
}

func (c *cli) writeStateVer(v uint64) error {
	return writeFile0600(c.stateVerPath(), []byte(strconv.FormatUint(v, 10)))
}

// putSealedState seals st for (id,ver+1) and writes it with PUT /v1/x/state; the server stores it
// opaque and returns it only to the owner.
func (c *cli) putSealedState(ctx context.Context, seed []byte, id string, st *e2e.State) error {
	pt, err := st.Encode()
	if err != nil {
		return fail(1, "err state %v", err)
	}
	ver := c.readStateVer() + 1
	blob, err := e2e.SealState(e2e.KState(seed), id, ver, pt, nil)
	if err != nil {
		return fail(1, "err state seal %v", err)
	}
	body, _ := json.Marshal(map[string]any{"ver": ver, "blob": base64.RawStdEncoding.EncodeToString(blob)})
	if err := c.sendRaw(ctx, "PUT", "/v1/x/state", body, "application/json", nil); err != nil {
		return err
	}
	return c.writeStateVer(ver)
}

// getSealedState fetches and opens the sealed-state blob for id; (nil,nil) when none exists. A served
// version older than the local one is a rollback and is refused.
func (c *cli) getSealedState(ctx context.Context, seed []byte, id string) (*e2e.State, error) {
	b, err := c.call(ctx, "GET", "/v1/x/state", nil, "", true)
	if err != nil {
		return nil, nil // no blob yet
	}
	var sv struct {
		Ver  uint64 `json:"ver"`
		Blob string `json:"blob"`
	}
	if json.Unmarshal(b, &sv) != nil || sv.Blob == "" {
		return nil, nil
	}
	if e2e.StateStale(sv.Ver, c.readStateVer()) {
		return nil, fail(1, "err state stale served ver=%d < local ver=%d (rollback)", sv.Ver, c.readStateVer())
	}
	blob, err := base64.RawStdEncoding.DecodeString(sv.Blob)
	if err != nil {
		return nil, fail(1, "err state bad blob")
	}
	pt, err := e2e.OpenState(e2e.KState(seed), id, sv.Ver, blob)
	if err != nil {
		return nil, fail(1, "err state open %v", err)
	}
	return e2e.DecodeState(pt)
}
