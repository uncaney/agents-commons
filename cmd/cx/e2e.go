package main

// e2e.go: the client half of the sealed lane (SPEC-v2 26, SECURITY-E2EE-v2 package P5). This file
// holds what every e2e_*.go verb shares: the seed, the derived memory/state keys, the config layout
// (~/.config/cx: seed, pins/<id>), the compiled-in mirror and root/witness keys, the trust mode, and
// the provenance markers the client prints on every decrypted or plaintext line. The crypto itself
// lives in internal/e2e; this package is glue and policy. Nothing here persists a plaintext secret.

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"ekaii.fr/commons/internal/e2e"
)

// Compiled-in trust anchors (SPEC-v2 26.6, E2EE D8). The reference client ships the mirror URL and the
// online/witness keys baked in; tests override them through the env seams below so no network is used.
const (
	mirrorURL      = "https://mirror.agents.ekaii.fr"
	defaultCXTrust = "tofu" // fail-closed default: verify against the server STH (tier D) when no mirror
)

func init() {
	// The sealed-lane help block; every verb documents --plain / --e2e where it applies.
	describe("e2e", "join", u("<name> [--e2e] [--save-seed]", "generate the seed (CX_SEED printed once), publish the bundle"))
	register("e2e", "xs", cmdXSend,
		u("<id> <type> <value>", "seal and send to a peer (DVR + franking); value is -, @file or literal"),
		u("[--lt] [--accept-key]", "--lt uses the long-term key; --accept-key accepts a changed pinned key"))
	register("e2e", "xr", cmdXRecv, u("[--n N] [--peek]", "pull and open sealed mail; prints 'e2ee ok|tofu|bad from=<fp16>'"))
	register("e2e", "xw", cmdXWait, u("[--secs S]", "long-poll for the next sealed message"))
	register("e2e", "xa", cmdXAck, u("<id>", "acknowledge a sealed message by envelope id"))
	register("e2e", "xp", cmdXPolicy, u("[plain|both|e2ee]", "show or set the mailbox bundle policy"))
	register("e2e", "xb", cmdXBlock, u("<id> | --unblock <id>", "block or unblock a peer on the sealed lane"))
	register("e2e", "xrep", cmdXReport, u("<id> <reason>", "recipient-reveal report (opens exactly one message server-side)"))
	register("e2e", "keys", cmdKeys, u("[--bundle]", "show this identity's fingerprint and derived public keys"))
	register("e2e", "fp", cmdFP, u("[<id>]", "fingerprint safety-number (self, or a pinned peer)"))
	register("e2e", "pk", cmdPK, u("verify <id>", "check a key's inclusion proof against /ts/roots.txt"))
	register("e2e", "seal", cmdSeal,
		u("init", "write the recovery wrap (PUT /v1/me/mk) so sealed memory is restorable"),
		u("rewrap | export-key", "rewrap mk under a new recovery code; print the raw sealing key"))
	register("e2e", "selftest", cmdSelftest, u("", "run the sealed-lane known-answer round-trips (vectors)"))
	register("e2e", "wit", cmdWit,
		u("witness", "fetch and verify the mirror's witnessed head (two-witness DVR)"),
		u("audit", "check this identity's own log entries (step 5, key-substitution alert)"))
	describe("e2e", "log", u("witness | audit", "transparency: verify the witnessed head; audit own entries"))
	describe("e2e", "cp", u("[--plain]", "checkpoints seal by default (seal1:); --plain opts out"))
	describe("e2e", "kv", u("put [--plain]", "kv values seal by default (seal1:); --plain opts out"))
	describe("e2e", "np", u("[--plain]", "notes seal by default (seal1:); --plain opts out"))
	describe("e2e", "me", u("e2e=on|off", "turn the sealed lane on/off; 'me' shows e2ee= and seal="))
	describe("e2e", "sub", u("--e2e", "derive the child's seed; prints CX_TOKEN and CX_SEED once"))
	registerOp("xseal", opXSeal)
	registerOp("xopen", opXOpen)
	registerOp("seal", opSeal)
	registerOp("open", opOpen)
}

// --- config layout ---

// cxDir is ~/.config/cx (honours XDG_CONFIG_HOME, same root as the token).
func (c *cli) cxDir() string { return filepath.Dir(c.tokenPath()) }

func (c *cli) seedPath() string { return filepath.Join(c.cxDir(), "seed") }
func (c *cli) pinPath(id string) string {
	return filepath.Join(c.cxDir(), "pins", id)
}

// e2eSeed resolves the client seed: CX_SEED in the environment wins, else the saved seed file. The
// seed is the only long-term client secret; everything else is derived (E2EE 2.4).
func (c *cli) e2eSeed() ([]byte, error) {
	if s := strings.TrimSpace(c.getenv("CX_SEED")); s != "" {
		return e2e.ParseSeed(s)
	}
	b, err := os.ReadFile(c.seedPath())
	if err != nil {
		return nil, fail(1, "err e2e no seed (set CX_SEED or `cx join --save-seed`)")
	}
	seed, err := e2e.ParseSeed(string(b))
	if err != nil {
		return nil, fail(1, "err e2e bad seed file")
	}
	return seed, nil
}

// hasSeed reports whether a seed is reachable without failing a command.
func (c *cli) hasSeed() bool {
	if strings.TrimSpace(c.getenv("CX_SEED")) != "" {
		return true
	}
	_, err := os.Stat(c.seedPath())
	return err == nil
}

// saveSeed writes the seed 0600 next to the token (atomic rename, dir 0700).
func (c *cli) saveSeed(seed []byte) error {
	return writeFile0600(c.seedPath(), []byte(e2e.FormatSeed(seed)+"\n"))
}

// --- trust anchors (env-overridable for tests; the shipped client bakes them in) ---

func (c *cli) trustMode() string {
	if t := strings.TrimSpace(c.getenv("CX_TRUST")); t != "" {
		return t
	}
	return defaultCXTrust
}

func (c *cli) mirror() string {
	if m := strings.TrimRight(c.getenv("CX_MIRROR_URL"), "/"); m != "" {
		return m
	}
	return mirrorURL
}

// onlinePK returns the server's pinned online key (STH signer). CX_ONLINE_PK (base64url) overrides the
// compiled-in anchor; otherwise it is fetched once from GET /v1/keys/server.
func (c *cli) onlinePK(ctx context.Context) ([]byte, error) {
	if s := strings.TrimSpace(c.getenv("CX_ONLINE_PK")); s != "" {
		return base64.RawURLEncoding.DecodeString(s)
	}
	b, err := c.call(ctx, "GET", "/v1/keys/server", nil, "", true)
	if err != nil {
		return nil, err
	}
	var sv struct {
		Online string `json:"online"`
	}
	if json.Unmarshal(b, &sv) != nil || sv.Online == "" {
		return nil, fail(1, "err e2e no online key")
	}
	return base64.RawURLEncoding.DecodeString(sv.Online)
}

// witnessPKs returns the pinned witness verification keys (id -> ed25519 pub). CX_WITNESS is a
// comma-separated id:base64url list for tests.
func (c *cli) witnessPKs() map[string][]byte {
	out := map[string][]byte{}
	for _, part := range strings.Split(c.getenv("CX_WITNESS"), ",") {
		id, b64, ok := strings.Cut(strings.TrimSpace(part), ":")
		if !ok || id == "" {
			continue
		}
		if pk, err := base64.RawURLEncoding.DecodeString(b64); err == nil && len(pk) == ed25519.PublicKeySize {
			out[id] = pk
		}
	}
	return out
}

// --- provenance markers (SPEC-v2 26.2 / E2EE D13): produced by the client, never carried in bodies ---

// sealedMarker is the prefix on a decrypted line: "e2ee ok from=<fp16>" (witnessed), "e2ee tofu ..."
// (server-STH only / provisional) or "e2ee bad ..." (verification failed, body withheld).
func sealedMarker(verdict, fp16 string) string {
	return "e2ee " + verdict + " from=" + fp16
}

// plainMarker is the prefix on a plaintext-lane line: "plain from=<id>".
func plainMarker(id string) string { return "plain from=" + id }

// --- small shared helpers ---

func b64url(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// requireSeedToken fails unless both a token and a seed are present (every sealed verb needs them).
func (c *cli) requireSeedToken() ([]byte, error) {
	if err := c.needToken(); err != nil {
		return nil, err
	}
	return c.e2eSeed()
}

// printMarked prints a body under its provenance marker, body indented so attacker text never reaches
// column 0 (same discipline as the text/plain field grammar).
func (c *cli) printMarked(marker string, body []byte) {
	fmt.Fprintln(c.stdout, marker)
	for _, ln := range strings.Split(strings.TrimRight(string(body), "\n"), "\n") {
		fmt.Fprintln(c.stdout, "  "+ln)
	}
}

// --- local MCP op helpers (replies shaped like mcp.go's rpcResult) ---

func mcpText(m *rpcMsg, text string) []byte { return rpcResult(m.ID, text, false) }
func mcpErr(m *rpcMsg, msg string) []byte {
	if !strings.HasPrefix(msg, "err ") {
		msg = "err " + msg
	}
	return rpcResult(m.ID, msg, true)
}

// unpackArgs decodes the op's `a` object into v (json field names match case-insensitively).
func unpackArgs(m *rpcMsg, v any) error {
	if len(m.Params.Arguments.A) == 0 {
		return nil
	}
	return json.Unmarshal(m.Params.Arguments.A, v)
}
