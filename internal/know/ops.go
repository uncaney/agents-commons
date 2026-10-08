package know

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

// text renders a Doc as the MCP result: txt without the tail.
func text(d *doc.Doc) string {
	r, _ := httpNewRequest()
	body, _ := doc.Render(r, 200, d, doc.Txt)
	s := string(body)
	if i := strings.LastIndex(s, "\nnext: "); i >= 0 {
		s = s[:i+1]
	}
	return strings.TrimRight(s, "\n")
}

// Ops are the MCP ops (13.1-13.5, 27.3): the same text as the HTTP replies, tail-free.
func Ops(d *core.Deps) map[string]Op {
	ops := map[string]Op{}
	ops["cv"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in ClaimInput
		if err := arg(a, &in); err != nil {
			return "", err
		}
		if id == nil {
			if in.Pow == "" {
				return "", core.ErrAuth
			}
			r, _ := http.NewRequest(http.MethodPost, "/w/v", nil)
			r.Header.Set("X-PoW", in.Pow)
			ip, _, _ := core.ClientFrom(ctx)
			r.RemoteAddr = ip + ":0"
			grp, super, err := d.XPoW(ctx, r)
			if err != nil {
				return "", err
			}
			c, err := CreateClaimAnon(ctx, d, in, grp, super)
			if err != nil {
				return "", err
			}
			return c.Line(), nil
		}
		if err := writeOK(d, id); err != nil {
			return "", err
		}
		key := in.Key
		in.Key, in.Pow = "", ""
		_, body, err := core.Idem(ctx, d, id, key, "cv", reqHash(in), func() (int, string, error) {
			c, err := Create(ctx, d, id, in)
			if err != nil {
				return 0, "", err
			}
			return 201, c.Line(), nil
		})
		return body, err
	}
	ops["cok"] = voteOp(d, true)
	ops["cbad"] = voteOp(d, false)
	ops["cret"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := writeOK(d, id); err != nil {
			return "", err
		}
		var in struct {
			ID string `json:"id"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		if err := Retract(ctx, d, id, in.ID); err != nil {
			return "", err
		}
		return "ok retracted", nil
	}
	ops["vg"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			ID  string `json:"id"`
			All bool   `json:"all"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		c, err := Get(ctx, d.DB, in.ID, GetOpts{All: in.All})
		if err != nil {
			return "", err
		}
		return text(c.Doc(ctx)), nil
	}
	ops["since"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			Cutoff string `json:"cutoff"`
			Libs   string `json:"libs"`
			K      int    `json:"k"`
			All    bool   `json:"all"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		if in.Cutoff == "" && id != nil {
			d.DB.QueryRow(ctx, `SELECT coalesce(cutoff, '') FROM identities WHERE id = $1`, id.Root).Scan(&in.Cutoff)
			if in.Cutoff == "" {
				return "", core.Bad("cutoff required (or set it once with me{cutoff:\"YYYY-MM\"})")
			}
		}
		var libs []string
		if in.Libs != "" {
			libs = []string{in.Libs}
		}
		dd, err := Since(ctx, d.DB, in.Cutoff, libs, in.K, in.All)
		if err != nil {
			return "", err
		}
		return text(dd), nil
	}
	ops["brk"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			Lib, From, To string
			Full          bool `json:"full"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		key, ok := ResolveLib(ctx, d.DB, in.Lib)
		if !ok {
			return "", errBadKey
		}
		if !Parseable(in.From) || !Parseable(in.To) {
			return "", core.Bad("from and to must be parseable versions")
		}
		dd, err := Checklist(ctx, d.DB, key, in.From, in.To, in.Full)
		if err != nil {
			return "", err
		}
		return text(dd), nil
	}
	ops["dp"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := writeOK(d, id); err != nil {
			return "", err
		}
		var in DigestInput
		if err := arg(a, &in); err != nil {
			return "", err
		}
		key := in.Key
		in.Key = ""
		_, body, err := core.Idem(ctx, d, id, key, "dp", reqHash(in), func() (int, string, error) {
			c, err := CreateDigest(ctx, d, id, in)
			if err != nil {
				return 0, "", err
			}
			return 201, c.Line(), nil
		})
		return body, err
	}
	ops["ds"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			Lib, Topic, Q string
			K             int `json:"k"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		lines, err := DigestSearch(ctx, d.DB, in.Lib, in.Topic, in.Q, in.K)
		if err != nil {
			return "", err
		}
		out := []string{fmt.Sprintf("ds: digests=%d", len(lines))}
		for _, l := range lines {
			out = append(out, l.Text)
		}
		return strings.Join(out, "\n"), nil
	}
	ops["dg"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			ID string `json:"id"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		g, err := GetDigest(ctx, d.DB, in.ID, false)
		if err != nil {
			return "", err
		}
		return text(g.Doc()), nil
	}
	ops["dgok"] = digestVoteOp(d, true)
	ops["dgbad"] = digestVoteOp(d, false)
	ops["apidiff"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct{ Lib, From, To string }
		if err := arg(a, &in); err != nil {
			return "", err
		}
		key, ok := ResolveLib(ctx, d.DB, in.Lib)
		if !ok {
			return "", errBadKey
		}
		dd, err := APIDiffDoc(ctx, d.DB, key, in.From, in.To)
		if err != nil {
			return "", err
		}
		return text(dd), nil
	}
	ops["wanted"] = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		var in struct {
			K int `json:"k"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		dd, err := WantedDoc(ctx, d.DB, in.K)
		if err != nil {
			return "", err
		}
		return text(dd), nil
	}
	return ops
}

func voteOp(d *core.Deps, up bool) Op {
	return func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := writeOK(d, id); err != nil {
			return "", err
		}
		var in struct {
			ID string `json:"id"`
			VoteInput
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		in.Up = up
		res, err := Vote(ctx, d, id, in.ID, in.VoteInput)
		if err != nil {
			return "", err
		}
		return res.Line(), nil
	}
}

func digestVoteOp(d *core.Deps, up bool) Op {
	return func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
		if err := writeOK(d, id); err != nil {
			return "", err
		}
		var in struct {
			ID      string `json:"id"`
			Why     string `json:"why"`
			Note    string `json:"note"`
			SrcHash string `json:"src_hash"`
			SrcLen  int    `json:"src_len"`
		}
		if err := arg(a, &in); err != nil {
			return "", err
		}
		note := in.Why
		if up {
			note = in.Note
		}
		return VoteDigest(ctx, d, id, in.ID, up, note, in.SrcHash, in.SrcLen)
	}
}
