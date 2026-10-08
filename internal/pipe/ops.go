package pipe

import (
	"bytes"
	"context"
	"encoding/json"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// arg decodes an op argument object (empty = zero value), refusing unknown fields.
func arg(a json.RawMessage, v any) error {
	a = bytes.TrimSpace(a)
	if len(a) == 0 || bytes.Equal(a, []byte("null")) {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(a))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return core.Bad("args: " + err.Error())
	}
	return nil
}

// Ops returns the MCP operations: the same compact text as the HTTP handlers.
func Ops(d *core.Deps) map[string]Op {
	s := svcFor(d)
	return map[string]Op{
		"pipe":  s.opPipe,
		"pipeg": s.opPipeG,
	}
}

// OpMeta describes the ops for the MCP registry (3.5). A pipe mutates (it reserves and submits);
// the read op is cheap.
var OpMeta = map[string]core.OpMeta{
	"pipe":  {Scope: "j", Cost: 1, Mutating: true},
	"pipeg": {Scope: "j", Cost: 0.2},
}

func (s *svc) opPipe(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	var in pipeIn
	if err := arg(a, &in); err != nil {
		return "", err
	}
	pid, err := s.create(ctx, id, in)
	if err != nil {
		return "", err
	}
	v, err := s.status(ctx, id, pid, in.Wait, 0)
	if err != nil {
		return "", err
	}
	return s.opText(ctx, id, v), nil
}

func (s *svc) opPipeG(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
	if id == nil {
		return "", core.ErrAuth
	}
	var in struct {
		ID   string `json:"id"`
		Wait int    `json:"wait,omitempty"`
		Step int    `json:"step,omitempty"`
		Att  bool   `json:"att,omitempty"`
	}
	if err := arg(a, &in); err != nil {
		return "", err
	}
	until := in.Step
	if until < 0 || until > maxSteps {
		until = 0
	}
	v, err := s.status(ctx, id, in.ID, clampWait(in.Wait), until)
	if err != nil {
		return "", err
	}
	t := s.opText(ctx, id, v)
	if in.Att && v.Att != "" {
		t += "\n" + v.Att + "\n" + v.AttSig
	}
	return t, nil
}

// opText renders the head plus the inline final stdout (done), for the tail-free MCP reply.
func (s *svc) opText(ctx context.Context, id *core.Ident, v *pipeView) string {
	t := v.text()
	if v.State == "done" {
		if b, ok, _ := s.stdout(ctx, id, v.out()); ok && len(b) > 0 {
			t += "\n  " + doc.Indent(string(b))
		}
	}
	return t
}
