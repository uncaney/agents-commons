package machineclaims

import (
	"context"
	"encoding/json"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/know"
)

// Registry metadata to claims (27.9): know.ApplyLibMeta calls LibMetaHook with every libmeta result
// it stores. The latest version yields a verified `release` claim (registry publish time); each
// version npm marks deprecated yields a `deprecated` claim and each PyPI/crates yanked version a
// `removed` claim. Versions are untrusted; only known single-token versions with a buildable
// registry permalink become claims, and the number of flag claims per result is bounded.

// hookDeps is the Deps LibMetaHook writes claims through; set by Register (the hook signature carries
// only the tx). Writing a machine claim needs core.Tx on the pool, which know.CreateClaim owns.
var hookDeps *core.Deps

const maxFlagClaims = 50

// libMeta mirrors the courier/know libmeta result shape (courier-produced: re-validated here).
type libMeta struct {
	Key      string `json:"key"`
	Display  string `json:"display"`
	Latest   string `json:"latest"`
	LatestAt string `json:"latest_at"`
	Versions []struct {
		V          string `json:"v"`
		At         string `json:"at"`
		Yanked     bool   `json:"yanked"`
		Deprecated bool   `json:"deprecated"`
	} `json:"versions"`
	Err string `json:"err"`
}

// LibMetaHook is know.LibMetaHookFn: it derives release/deprecated/removed machine claims from a
// stored libmeta result. A nil hookDeps (not wired) or an errored result is a no-op.
func LibMetaHook(ctx context.Context, q core.Q, key string, meta json.RawMessage) error {
	d := hookDeps
	if d == nil || len(meta) == 0 {
		return nil
	}
	var m libMeta
	if err := json.Unmarshal(meta, &m); err != nil {
		return nil
	}
	if m.Err != "" {
		return nil
	}
	key, err := know.ParseKey(key)
	if err != nil {
		return nil
	}
	eco, name := know.Eco(key)
	disp := oneLine(m.Display, 80)
	if disp == "" {
		disp = name
	}
	// release claim for the latest version (registry publish time).
	if versionToken(m.Latest) {
		if src := versionURL(eco, name, m.Latest); src != "" {
			in := know.ClaimInput{Lib: key, Kind: "release", VTo: m.Latest, Effective: eolDate(m.LatestAt),
				Title: cut(disp+" "+m.Latest+" released", know.MaxTitle), SourceURL: src,
				Src: "machine", SourceTier: "official", SourceState: "ok", Status: "verified"}
			if _, err := know.CreateClaim(ctx, d, systemAuthor(), in); err != nil && !skippable(err) {
				return err
			}
		}
	}
	flags := 0
	for i := len(m.Versions) - 1; i >= 0 && flags < maxFlagClaims; i-- {
		v := m.Versions[i]
		if !versionToken(v.V) || (!v.Deprecated && !v.Yanked) {
			continue
		}
		kind, word := "deprecated", "deprecated"
		if v.Yanked {
			kind, word = "removed", "yanked"
		}
		src := versionURL(eco, name, v.V)
		if src == "" {
			continue
		}
		in := know.ClaimInput{Lib: key, Kind: kind, VTo: v.V, Effective: eolDate(v.At),
			Title: cut(disp+" "+v.V+" "+word, know.MaxTitle), SourceURL: src,
			Src: "machine", SourceTier: "official", SourceState: "ok", Status: "verified"}
		if _, err := know.CreateClaim(ctx, d, systemAuthor(), in); err != nil && !skippable(err) {
			return err
		}
		flags++
	}
	return nil
}

// versionURL builds the canonical registry permalink for one version (used as the per-version dedup
// key); "" when the ecosystem has no stable per-version page.
func versionURL(eco, name, version string) string {
	v := strings.TrimSpace(version)
	if !versionToken(v) {
		return ""
	}
	switch eco {
	case "pypi":
		return "https://pypi.org/project/" + name + "/" + v + "/"
	case "npm":
		return "https://www.npmjs.com/package/" + name + "/v/" + v
	case "crates":
		return "https://crates.io/crates/" + name + "/" + v
	case "gem":
		return "https://rubygems.org/gems/" + name + "/versions/" + v
	case "go":
		return "https://pkg.go.dev/" + name + "@" + v
	}
	return ""
}
