package libwatch

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
)

// Op is an MCP operation (compact text, *core.APIError on failure).
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// OpMeta describes the libwatch ops for the MCP registry (3.5); consumed by the integration
// package that merges every package's ops.
var OpMeta = map[string]core.OpMeta{
	"env":     {Scope: "env:w", Cost: 1, Mutating: true},
	"envg":    {Scope: "env:r", Cost: 1},
	"cutoffp": {Scope: "", Cost: 1},
}

func arg(a json.RawMessage, v any) error {
	if len(a) == 0 || string(a) == "null" {
		return nil
	}
	if err := json.Unmarshal(a, v); err != nil {
		return core.Bad("a: " + err.Error())
	}
	return nil
}

// Ops are the MCP ops env, envg and cutoffp: the HTTP behaviour without the tail.
func Ops(d *core.Deps) map[string]Op {
	s := &svc{d: d, anonCache: core.NewByteLRU(1 << 20), probeC: core.NewByteLRU(1 << 20)}
	return map[string]Op{
		"env": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			if id.Banned {
				return "", core.ErrBanned
			}
			if d.Frozen("write") {
				return "", core.Frozen("write")
			}
			var in struct {
				Body string `json:"body"`
				Fmt  string `json:"fmt"`
				Name string `json:"name"`
				All  bool   `json:"all"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			format := strings.TrimSpace(in.Fmt)
			if format == "" {
				format = "env"
			}
			if len(in.Body) > MaxBody {
				return "", core.Bad("body too large (<= 64 KiB)")
			}
			name, err := cleanName(in.Name)
			if err != nil {
				return "", err
			}
			deps, err := ParseFormat(format, []byte(in.Body))
			if err != nil {
				return "", err
			}
			entries := resolve(ctx, d.DB, format, deps)
			if err := storeManifest(ctx, d, id.Root, name, entries); err != nil {
				return "", err
			}
			rep, err := buildReport(ctx, d.DB, name, entries, in.All, false)
			if err != nil {
				return "", err
			}
			return rep.Text(), nil
		},
		"envg": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			if id == nil {
				return "", core.ErrAuth
			}
			var in struct {
				Name string `json:"name"`
				All  bool   `json:"all"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			name, err := cleanName(in.Name)
			if err != nil {
				return "", err
			}
			entries, _, err := loadManifest(ctx, d.DB, id.Root, name)
			if err != nil {
				return "", err
			}
			rep, err := buildReport(ctx, d.DB, name, entries, in.All, false)
			if err != nil {
				return "", err
			}
			return rep.Text(), nil
		},
		"cutoffp": func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				Seed string `json:"seed"`
				N    int    `json:"n"`
				A    string `json:"a"`
				Save bool   `json:"save"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			seed := strings.TrimSpace(in.Seed)
			if seed == "" || len(seed) > 128 {
				return "", core.Bad("seed required (<= 128 chars)")
			}
			day := time.Now().UTC().Truncate(24 * time.Hour)
			if strings.TrimSpace(in.A) == "" {
				n := in.N
				if n == 0 {
					n = 10
				}
				items, err := s.sample(ctx, seed, n, day)
				if err != nil {
					return "", err
				}
				return listText(seed, items), nil
			}
			answers := parseAnswers(in.A)
			nReal := len(answers) - probeDecoys
			if nReal < probeMinN {
				nReal = probeMinN
			}
			if nReal > probeMaxN {
				nReal = probeMaxN
			}
			items, err := s.sample(ctx, seed, nReal, day)
			if err != nil {
				return "", err
			}
			est := estimate(items, answers)
			if in.Save && id != nil && est.Cutoff != "?" {
				if _, err := d.DB.Exec(ctx, `UPDATE identities SET cutoff = $2 WHERE id = $1`, id.Root, est.Cutoff); err != nil {
					return "", err
				}
			}
			return est.Text(), nil
		},
	}
}
