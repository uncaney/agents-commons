package main

// e2e_seal.go: sealed memory (SPEC-v2 26.4). Checkpoints, kv values and notes seal by default with
// seal1: keyed from mk = HKDF(seed,"cx-mk"); --plain opts out. The recovery wrap (mk encrypted under the
// recovery code) is written with PUT /v1/me/mk at join and after recover, so a lost seed is restorable
// from the recovery code alone. Local MCP ops (cx mcp) seal/open on the client side; the remote /mcp
// only ever sees opaque seal1: bodies. Every value passes the policy-pack hygiene gate before sealing.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"

	"ekaii.fr/commons/internal/e2e"
)

// sealAAD builds the seal1 aad: the namespace/key, checkpoint name or note name (SPEC-v2 26.4).
func sealAAD(kind, name string) string { return kind + "|" + name }

// sealValue seals pt for (kind,name) under mk, after the tier-1 hygiene gate. plain returns the bytes
// unchanged but still line-injection-safe. The returned value is a seal1: string or the plaintext.
func (c *cli) sealValue(ctx context.Context, seed []byte, kind, name string, pt []byte, plain, mask bool) (string, error) {
	safe, err := c.hygiene(ctx, pt, mask)
	if err != nil {
		return "", err
	}
	if plain {
		return string(safe), nil
	}
	kv := e2e.SealV1Key(e2e.MK(seed))
	return e2e.Seal1(kv, sealAAD(kind, name), safe, nil)
}

// openValue opens a seal1:/seal2: value bound to (kind,name) under mk; a plaintext value is returned
// verbatim. The second return reports whether the value was sealed (for the [sealed] rendering the
// server also does). seal2's tag key is now aad-bound (Security Review 2 #11), so the (kind|name) aad
// must be threaded in exactly as seal1 carries it.
func (c *cli) openValue(seed []byte, kind, name, value string) ([]byte, bool, error) {
	if !e2e.IsSealed(value) {
		return []byte(value), false, nil
	}
	kv := e2e.SealV1Key(e2e.MK(seed))
	if strings.HasPrefix(value, "seal2:") {
		pt, err := e2e.Open2(kv, sealAAD(kind, name), value)
		return pt, true, err
	}
	// seal1 is opened through openValueAAD, which supplies the same (kind|name) aad.
	return nil, true, fmt.Errorf("err sealed need aad")
}

// openValueAAD opens a seal1: value bound to (kind,name).
func (c *cli) openValueAAD(seed []byte, kind, name, value string) ([]byte, error) {
	kv := e2e.SealV1Key(e2e.MK(seed))
	return e2e.Open1(kv, sealAAD(kind, name), value)
}

// --- recovery wrap (mk_wrapped) ---

// cmdSeal: `cx seal init | rewrap | export-key`.
func cmdSeal(c *cli, ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail(2, "usage: cx seal init | rewrap | export-key")
	}
	seed, err := c.requireSeedToken()
	if err != nil {
		return err
	}
	switch args[0] {
	case "init", "rewrap":
		return c.sealInit(ctx, seed, args[0] == "rewrap", args[1:])
	case "export-key":
		// The raw sealing key, for an external tool that must open sealed memory. Printed, never stored.
		fmt.Fprintln(c.stdout, "seal-key="+base64.RawURLEncoding.EncodeToString(e2e.SealV1Key(e2e.MK(seed))))
		return nil
	}
	return fail(2, "usage: cx seal init | rewrap | export-key")
}

// sealInit derives a recovery code (or takes --code), wraps mk under it and writes it with
// PUT /v1/me/mk. The recovery code is printed once; it is never stored.
func (c *cli) sealInit(ctx context.Context, seed []byte, rewrap bool, args []string) error {
	var code string
	for i := 0; i < len(args); i++ {
		if args[i] == "--code" && i+1 < len(args) {
			i++
			code = args[i]
		}
	}
	recovery := []byte(code)
	if code == "" {
		recovery = e2e.NewSeed() // 32 bytes of entropy as the recovery code
		code = e2e.FormatSeed(recovery)
	}
	if err := c.putMKWrap(ctx, seed, recovery); err != nil {
		return err
	}
	verb := "sealed memory armed"
	if rewrap {
		verb = "recovery code rotated"
	}
	fmt.Fprintf(c.stdout, "%s\nCX_RECOVERY=%s  (printed once; store it offline)\n", verb, code)
	return nil
}

// putMKWrap wraps mk under the recovery code and writes it to PUT /v1/me/mk {"wrapped":<b64>}.
func (c *cli) putMKWrap(ctx context.Context, seed, recovery []byte) error {
	wrapped, err := e2e.WrapMK(e2e.MK(seed), recovery, nil)
	if err != nil {
		return fail(1, "err seal wrap %v", err)
	}
	body, _ := json.Marshal(map[string]string{"wrapped": base64.RawStdEncoding.EncodeToString(wrapped)})
	return c.sendRaw(ctx, "PUT", "/v1/me/mk", body, "application/json", nil)
}

// recoverMK unwraps mk_wrapped (from GET /v1/me/mk or the recover reply) with the recovery code and
// returns mk; a successful unwrap proves the recovery code and lets sealed memory be reopened.
func recoverMK(wrappedB64 string, recovery []byte) ([]byte, error) {
	wrapped, err := base64.RawStdEncoding.DecodeString(strings.TrimSpace(wrappedB64))
	if err != nil {
		wrapped, err = base64.StdEncoding.DecodeString(strings.TrimSpace(wrappedB64))
	}
	if err != nil {
		return nil, fmt.Errorf("err recover bad wrap")
	}
	mk, err := e2e.UnwrapMK(wrapped, recovery)
	if err != nil {
		return nil, fmt.Errorf("err recover wrong code")
	}
	return mk, nil
}

// --- local MCP ops: sealing happens here, the remote /mcp sees only opaque bodies (SPEC-v2 26.2) ---

func opSeal(c *cli, ctx context.Context, m *rpcMsg) []byte {
	var a struct {
		Kind, Name, Value string
		Plain             bool
	}
	if err := unpackArgs(m, &a); err != nil {
		return mcpErr(m, err.Error())
	}
	seed, err := c.e2eSeed()
	if err != nil {
		return mcpErr(m, "no seed")
	}
	v, err := c.sealValue(ctx, seed, a.Kind, a.Name, []byte(a.Value), a.Plain, false)
	if err != nil {
		return mcpErr(m, err.Error())
	}
	return mcpText(m, v)
}

func opOpen(c *cli, ctx context.Context, m *rpcMsg) []byte {
	var a struct{ Kind, Name, Value string }
	if err := unpackArgs(m, &a); err != nil {
		return mcpErr(m, err.Error())
	}
	seed, err := c.e2eSeed()
	if err != nil {
		return mcpErr(m, "no seed")
	}
	pt, err := c.openValueAAD(seed, a.Kind, a.Name, a.Value)
	if err != nil {
		return mcpErr(m, err.Error())
	}
	return mcpText(m, string(pt))
}
