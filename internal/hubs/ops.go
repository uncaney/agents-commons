package hubs

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// Op is an MCP operation sharing the service layer with the HTTP handlers.
type Op = func(ctx context.Context, id *core.Ident, a json.RawMessage) (string, error)

// Ops returns the MCP operations of this package (3.5): hub{class} and eco{eco}, both reads that
// render the stored hub as compact text.
func Ops(d *core.Deps) map[string]Op {
	arg := func(a json.RawMessage, v any) error {
		if len(a) == 0 || string(a) == "null" {
			return nil
		}
		if err := json.Unmarshal(a, v); err != nil {
			return core.Bad("a: " + err.Error())
		}
		return nil
	}
	return map[string]Op{
		"hub": func(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				Class string `json:"class"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			class := strings.TrimSpace(in.Class)
			if !validClass(class) {
				return "", core.Bad("class must match [A-Za-z][A-Za-z0-9_.-]{1,48}")
			}
			ms, count, err := errMembers(ctx, d.DB, class, 20)
			if err != nil {
				return "", err
			}
			if count == 0 {
				return "", core.ErrNotFound
			}
			libs, err := errLibBreakdown(ctx, d.DB, class)
			if err != nil {
				return "", err
			}
			var b strings.Builder
			fmt.Fprintf(&b, "err: %s fixes=%d\n", class, count)
			if len(libs) > 0 {
				parts := make([]string, 0, len(libs))
				for _, l := range libs {
					parts = append(parts, fmt.Sprintf("%s=%d", l.Lib, l.N))
				}
				fmt.Fprintf(&b, "libs: %s\n", strings.Join(parts, " "))
			}
			for _, m := range ms {
				fmt.Fprintf(&b, "%s %s %s\n", m.ID, core.Date(m.Mod), doc.SafeLine(m.Title))
			}
			return strings.TrimRight(b.String(), "\n"), nil
		},
		"eco": func(ctx context.Context, _ *core.Ident, a json.RawMessage) (string, error) {
			var in struct {
				Eco string `json:"eco"`
			}
			if err := arg(a, &in); err != nil {
				return "", err
			}
			eco := strings.ToLower(strings.TrimSpace(in.Eco))
			if !ecosystems[eco] {
				return "", core.Bad("unknown ecosystem")
			}
			libs, err := ecoLibs(ctx, d.DB, eco)
			if err != nil {
				return "", err
			}
			if len(libs) == 0 {
				return "", core.ErrNotFound
			}
			var b strings.Builder
			fmt.Fprintf(&b, "eco: %s libs=%d\n", eco, len(libs))
			for _, l := range libs {
				fmt.Fprintf(&b, "%s fixes=%d claims=%d\n", l.Lib, l.Entries, l.Claims)
			}
			return strings.TrimRight(b.String(), "\n"), nil
		},
	}
}
