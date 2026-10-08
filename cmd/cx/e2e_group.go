package main

// e2e_group.go: the sealed-group verbs (SPEC-v2 26, groups wave P73). The commands compile against the
// internal/e2e group formats and the /v1/g routes; the heavy ratchet lives in internal/e2e. These are
// the client entry points: create a group, send a sealed group message, pull and open the roster's
// messages. Group epoch secrets are kept in the sealed state (GroupState), never on disk in the clear.

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"strconv"

	"ekaii.fr/commons/internal/e2e"
)

func init() {
	register("e2e", "grp", cmdGroup,
		u("new <name>", "create a sealed group (you become the first member)"),
		u("send <gid> <value>", "seal a message to the group roster"),
		u("recv <gid> [--n N]", "pull and open the group's sealed messages"),
		u("ls", "list the groups you belong to"))
}

func cmdGroup(c *cli, ctx context.Context, args []string) error {
	if len(args) == 0 {
		return fail(2, "usage: cx grp new|send|recv|ls ...")
	}
	seed, err := c.requireSeedToken()
	if err != nil {
		return err
	}
	switch args[0] {
	case "ls":
		return c.get(ctx, "/v1/g", nil)
	case "new":
		if len(args) != 2 {
			return fail(2, "usage: cx grp new <name>")
		}
		return c.send(ctx, "POST", "/v1/g", []field{f("name", args[1])})
	case "send":
		if len(args) != 3 {
			return fail(2, "usage: cx grp send <gid> <value>")
		}
		return c.groupSend(ctx, seed, args[1], args[2])
	case "recv":
		if len(args) < 2 {
			return fail(2, "usage: cx grp recv <gid> [--n N]")
		}
		return c.groupRecv(ctx, seed, args[1], args[2:])
	}
	return fail(2, "usage: cx grp new|send|recv|ls ...")
}

// groupState loads this group's epoch secrets from the sealed state (nil when not a member).
func (c *cli) groupState(ctx context.Context, seed []byte, gid string) (*e2e.GroupState, error) {
	self, err := c.selfID(ctx)
	if err != nil {
		return nil, err
	}
	st, err := c.getSealedState(ctx, seed, self)
	if err != nil || st == nil {
		return nil, err
	}
	if gs, ok := st.Groups[gid]; ok {
		return &gs, nil
	}
	return nil, nil
}

// groupSend seals a value for the group roster at the current epoch and posts it to /v1/g/<gid>.
func (c *cli) groupSend(ctx context.Context, seed []byte, gid, valArg string) error {
	gs, err := c.groupState(ctx, seed, gid)
	if err != nil {
		return err
	}
	if gs == nil {
		return fail(1, "err group not a member of %s", gid)
	}
	payload, err := c.readValue(valArg)
	if err != nil {
		return err
	}
	safe, err := c.hygiene(ctx, payload, false)
	if err != nil {
		return err
	}
	msgRoot, err := base64.RawURLEncoding.DecodeString(gs.Secret)
	if err != nil {
		return fail(1, "err group state")
	}
	app, err := e2e.SealApp(e2e.AppParams{
		GID: gid, Epoch: gs.Epoch, Idx: gs.Idx, Gen: gs.Gen,
		MsgRoot: msgRoot, IK: e2e.IK(seed), Payload: safe,
	})
	if err != nil {
		return fail(1, "err group seal %v", err)
	}
	body, _ := json.Marshal(map[string]string{"row": base64.RawStdEncoding.EncodeToString(app.Row)})
	return c.sendRaw(ctx, "POST", "/v1/g/"+gid, body, "application/json", nil)
}

// groupRecv pulls the group's sealed rows and opens each against the current message root.
func (c *cli) groupRecv(ctx context.Context, seed []byte, gid string, args []string) error {
	n := 32
	for i := 0; i < len(args); i++ {
		if args[i] == "--n" && i+1 < len(args) {
			i++
			n, _ = strconv.Atoi(args[i])
		}
	}
	gs, err := c.groupState(ctx, seed, gid)
	if err != nil {
		return err
	}
	if gs == nil {
		return fail(1, "err group not a member of %s", gid)
	}
	msgRoot, err := base64.RawURLEncoding.DecodeString(gs.Secret)
	if err != nil {
		return fail(1, "err group state")
	}
	var in struct {
		Rows []struct{ From, Row string } `json:"rows"`
	}
	if err := c.getJSON(ctx, "GET", "/v1/g/"+gid+"/in?n="+strconv.Itoa(n), nil, &in); err != nil {
		return err
	}
	for _, r := range in.Rows {
		raw, err := base64.RawStdEncoding.DecodeString(r.Row)
		if err != nil {
			continue
		}
		msg, err := e2e.ParseApp(raw)
		if err != nil {
			c.printMarked(sealedMarker("bad", "?"), []byte("(bad group row)"))
			continue
		}
		inner, err := msg.Open(msgRoot)
		if err != nil {
			c.printMarked(sealedMarker("bad", r.From), []byte("(group open failed)"))
			continue
		}
		c.printMarked(plainMarker(r.From), inner.Payload)
	}
	return nil
}

// groupSecretB64 is the base64url of a group's epoch secret, for the sealed GroupState.
func groupSecretB64(secret []byte) string { return base64.RawURLEncoding.EncodeToString(secret) }
