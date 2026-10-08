package mem

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

// text renders a Doc as the MCP result: txt without the tail (a synthetic GET request drives the
// renderer, so ?s= and budgets never apply to ops).
func text(d *doc.Doc) string {
	r, _ := http.NewRequest(http.MethodGet, "/", nil)
	body, _ := doc.Render(r, 200, d, doc.Txt)
	s := string(body)
	if i := strings.LastIndex(s, "\nnext: "); i >= 0 {
		s = s[:i+1]
	}
	return strings.TrimRight(s, "\n")
}

// Ops are the MCP ops (10.1-10.5, 27.3): the same text as the HTTP replies, tail-free.
func Ops(d *core.Deps) map[string]Op {
	s := newSvc(d)
	ops := map[string]Op{}
	ops["resume"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if id == nil {
			return "", core.ErrAuth
		}
		var in struct {
			Name string `json:"name"`
			Full bool   `json:"full"`
			KV   bool   `json:"kv"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		if in.Name != "" && !cpNameRe.MatchString(in.Name) {
			return "", core.Bad("name must match [a-z0-9._-]{1,64}")
		}
		dd, err := s.resume(ctx, id, resumeOpts{name: in.Name, full: in.Full, kv: in.KV})
		if err != nil {
			return "", err
		}
		return text(dd), nil
	}
	ops["log"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if id == nil {
			return "", core.ErrAuth
		}
		var in struct {
			Since string `json:"since"`
			Op    string `json:"op"`
			K     int    `json:"k"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		since, err := parseSince(in.Since)
		if err != nil {
			return "", err
		}
		if in.Op != "" && !opRe.MatchString(in.Op) {
			return "", core.Bad("op must match [a-z][a-z0-9:_-]{0,31}")
		}
		if in.K <= 0 {
			in.K = 50
		}
		lines, err := auditLines(ctx, d.DB, id.Root, since, in.Op, min(in.K, 100))
		if err != nil {
			return "", err
		}
		return text(logDoc(id.Root, lines)), nil
	}
	ops["cp"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := s.writeOK(id); err != nil {
			return "", err
		}
		if err := s.frozen("checkpoints"); err != nil {
			return "", err
		}
		var in cpReq
		if err := arg(a, &in); err != nil {
			return "", err
		}
		ip, _, _ := core.ClientFrom(ctx)
		out, err := cpWrite(ctx, d.DB, d.DB, id.ID, id.Root, id.ID,
			cpIn{name: in.Name, summary: in.Summary, body: in.Body, blob: in.Blob, pubScope: string(in.Pub), merge: in.Merge, ip: ip})
		if err != nil {
			return "", err
		}
		return cpWriteLine(out), nil
	}
	ops["cpl"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if id == nil {
			return "", core.ErrAuth
		}
		var in struct {
			Name string `json:"name"`
			K    int    `json:"k"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		if !cpNameRe.MatchString(in.Name) {
			return "", core.Bad("name must match [a-z0-9._-]{1,64}")
		}
		if in.K <= 0 {
			in.K = 20
		}
		cs, err := cpList(ctx, d.DB, id.Root, in.Name, min(in.K, 20))
		if err != nil {
			return "", err
		}
		return text(cpListDoc(in.Name, cs)), nil
	}
	ops["cpg"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if id == nil {
			return "", core.ErrAuth
		}
		var in struct {
			ID   string `json:"id"`
			Name string `json:"name"`
			S    string `json:"s"`
			Raw  bool   `json:"raw"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		var c *Checkpoint
		var err error
		switch {
		case in.ID != "":
			c, err = cpByID(ctx, d.DB, id.Root, in.ID)
		case cpNameRe.MatchString(in.Name):
			c, err = cpLatest(ctx, d.DB, id.Root, in.Name)
		default:
			return "", core.Bad("id or name required")
		}
		if err != nil {
			return "", err
		}
		var sel []string
		for _, n := range strings.Split(in.S, ",") {
			for _, x := range cp1Sections {
				if strings.TrimSpace(n) == x {
					sel = append(sel, x)
				}
			}
		}
		return text(cpDoc(c, sel, in.Raw)), nil
	}
	ops["cpd"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := s.writeOK(id); err != nil {
			return "", err
		}
		var in struct {
			ID string `json:"id"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		if err := cpDelete(ctx, d.DB, id.ID, id.Root, in.ID); err != nil {
			return "", err
		}
		return "ok deleted=1", nil
	}
	ops["kv"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			NS string `json:"ns"`
			K  string `json:"k"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		ns, root, err := opNS(id, in.NS, false)
		if err != nil {
			return "", err
		}
		if err := nsAccess(ctx, d.DB, ns, root, false, 0); err != nil {
			return "", err
		}
		x, err := kvGet(ctx, d.DB, ns, in.K)
		if err != nil {
			return "", err
		}
		if x.Sealed && id == nil {
			return "", core.ErrNotFound
		}
		return text(kvGetDoc(x, ns, id != nil)), nil
	}
	ops["kvp"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := s.writeOK(id); err != nil {
			return "", err
		}
		if err := s.frozen("kv"); err != nil {
			return "", err
		}
		var in struct {
			NS       string `json:"ns"`
			K        string `json:"k"`
			V        string `json:"v"`
			TTL      int64  `json:"ttl"`
			Cas      *int64 `json:"cas"`
			Fence    int64  `json:"fence"`
			IfAbsent bool   `json:"if_absent"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		ns, _, err := opNS(id, in.NS, true)
		if err != nil {
			return "", err
		}
		if in.TTL < 0 || in.TTL > int64(KVMaxTTL/time.Second) {
			return "", core.Bad("ttl must be 1..2592000 seconds")
		}
		res, err := kvWrite(ctx, d.DB, d.DB, id.ID, id.Root, kvPut{ns: ns, k: in.K, v: []byte(in.V), ttl: time.Duration(in.TTL) * time.Second, cas: in.Cas, fence: in.Fence, ifAbsent: in.IfAbsent})
		if err != nil {
			return "", err
		}
		return kvPutLine(res), nil
	}
	ops["kvl"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			NS     string `json:"ns"`
			Prefix string `json:"prefix"`
			K      int    `json:"k"`
			Vals   bool   `json:"vals"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		ns, root, err := opNS(id, in.NS, false)
		if err != nil {
			return "", err
		}
		if err := nsAccess(ctx, d.DB, ns, root, false, 0); err != nil {
			return "", err
		}
		if len(in.Prefix) > 128 || !doc.OneLine(in.Prefix) {
			return "", core.Bad("prefix too long")
		}
		if in.K <= 0 {
			in.K = 100
		}
		rows, err := kvList(ctx, d.DB, ns, in.Prefix, min(in.K, 100))
		if err != nil {
			return "", err
		}
		if in.Vals {
			return strings.TrimRight(kvInlineText(ns, rows), "\n"), nil
		}
		return text(kvListDoc(ns, rows, in.Prefix)), nil
	}
	ops["kvd"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := s.writeOK(id); err != nil {
			return "", err
		}
		var in struct {
			NS    string `json:"ns"`
			K     string `json:"k"`
			Cas   *int64 `json:"cas"`
			Fence int64  `json:"fence"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		ns, _, err := opNS(id, in.NS, true)
		if err != nil {
			return "", err
		}
		if err := nsAccess(ctx, d.DB, ns, id.Root, true, in.Fence); err != nil {
			return "", err
		}
		if err := kvDelete(ctx, d.DB, id.ID, ns, in.K, in.Cas); err != nil {
			return "", err
		}
		return "ok", nil
	}
	ops["kvi"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := s.writeOK(id); err != nil {
			return "", err
		}
		if err := s.frozen("kv"); err != nil {
			return "", err
		}
		var in struct {
			NS    string `json:"ns"`
			K     string `json:"k"`
			By    *int64 `json:"by"`
			TTL   int64  `json:"ttl"`
			Fence int64  `json:"fence"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		ns, _, err := opNS(id, in.NS, true)
		if err != nil {
			return "", err
		}
		by := int64(1)
		if in.By != nil {
			by = *in.By
		}
		if in.TTL < 0 || in.TTL > int64(KVMaxTTL/time.Second) {
			return "", core.Bad("ttl must be 1..2592000 seconds")
		}
		res, err := kvWrite(ctx, d.DB, d.DB, id.ID, id.Root, kvPut{ns: ns, k: in.K, ttl: time.Duration(in.TTL) * time.Second, fence: in.Fence, incr: &by})
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ok ver=%d v=%s exp=%s", res.ver, res.val, rfc(res.exp)), nil
	}
	ops["kvm"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := s.writeOK(id); err != nil {
			return "", err
		}
		if err := s.frozen("kv"); err != nil {
			return "", err
		}
		if len(a) > MaxBatch {
			return "", core.ErrSize
		}
		var in struct {
			NS     string `json:"ns"`
			Ops    []kvOp `json:"ops"`
			Atomic bool   `json:"atomic"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		if len(in.Ops) == 0 || len(in.Ops) > MaxBatchOps {
			return "", core.Bad(fmt.Sprintf("ops must hold 1..%d entries", MaxBatchOps))
		}
		writes := false
		for _, o := range in.Ops {
			writes = writes || o.Op != "get"
		}
		ns, _, err := opNS(id, in.NS, writes)
		if err != nil {
			return "", err
		}
		if err := nsAccess(ctx, d.DB, ns, id.Root, writes, 0); err != nil {
			return "", err
		}
		var lines []string
		var okN, failN int
		err = core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
			var err error
			lines, okN, failN, err = s.runBatch(ctx, tx, id, ns, in.Ops, in.Atomic)
			return err
		})
		if err == errBatchRolledBack {
			return "", core.E(409, "cas", "atomic batch rolled back")
		}
		if err != nil {
			return "", err
		}
		return strings.TrimRight(fmt.Sprintf("kvm %s n=%d ok=%d failed=%d\n%s", ns.raw, len(in.Ops), okN, failN, strings.Join(lines, "\n")), "\n"), nil
	}
	ops["later"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := s.writeOK(id); err != nil {
			return "", err
		}
		var in laterReq
		if err := arg(a, &in); err != nil {
			return "", err
		}
		var after *time.Time
		if in.After != "" {
			t, err := parseAfter(in.After, time.Now())
			if err != nil {
				return "", err
			}
			after = &t
		}
		mid, deliver, err := laterPut(ctx, d.DB, d.DB, id.ID, id.Root, in.Text, after, in.On)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("ok %s deliver=%s", mid, deliver), nil
	}
	return ops
}

// opNS resolves an op's namespace argument (default me) and checks the scoped-token rule.
func opNS(id *core.Ident, raw string, write bool) (nspace, string, error) {
	root := ""
	if id != nil {
		root = id.Root
	}
	if raw == "" {
		raw = "me"
	}
	ns, err := parseNS(raw, root)
	if err != nil {
		return nspace{}, "", err
	}
	if err := kvScopeOK(id, ns, write); err != nil {
		return nspace{}, "", err
	}
	return ns, root, nil
}
