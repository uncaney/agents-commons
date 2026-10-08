package catalog

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"ekaii.fr/commons/internal/compute"
	"ekaii.fr/commons/internal/core"
)

// SeedSystem publishes the seed modules of dir under the system root (15.3): every <name>.wasm
// with a <name>.json manifest next to it (the build script copies internal/catalog/seed/<name>/
// manifest.json there) that no live version already carries. Blobs are stored directly with
// pinned_by = seed (quota-exempt); modules above 4 MiB are inserted into pins (note 'seed') in
// the same transaction as their version so donor eligibility and the warm phase pick them up
// (27.6); KATs run as system jobs (pending until the faucet funds them). Returns the number of
// versions published. A missing or empty dir publishes nothing and is not an error.
func SeedSystem(ctx context.Context, d *core.Deps, dir string) (int, error) {
	if dir == "" {
		return 0, nil
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	var names []string
	for _, e := range ents {
		if n, ok := strings.CutSuffix(e.Name(), ".wasm"); ok && !e.IsDir() && nameRe.MatchString(n) {
			names = append(names, n)
		}
	}
	sort.Strings(names)
	s := &svc{d}
	n := 0
	for _, name := range names {
		if ctx.Err() != nil {
			return n, ctx.Err()
		}
		published, err := s.seedOne(ctx, dir, name)
		if err != nil {
			d.Log.Warn("seed module", "name", name, "err", err)
			continue
		}
		if published {
			n++
		}
	}
	if n > 0 {
		d.Log.Info("seed modules", "published", n, "dir", dir)
	}
	return n, nil
}

// seedOne publishes <dir>/<name>.wasm when its hash is not a live version of name yet.
func (s *svc) seedOne(ctx context.Context, dir, name string) (bool, error) {
	wasm, err := os.ReadFile(filepath.Join(dir, name+".wasm"))
	if err != nil {
		return false, err
	}
	manifest, err := os.ReadFile(filepath.Join(dir, name+".json"))
	if err != nil {
		manifest, err = os.ReadFile(filepath.Join(dir, name+".manifest.json"))
		if err != nil {
			return false, fmt.Errorf("manifest: %w", err)
		}
	}
	sum := sha256.Sum256(wasm)
	hash := hex.EncodeToString(sum[:])
	var live bool
	if err := s.d.DB.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM service_versions WHERE name = $1 AND wasm = $2 AND state <> 'rejected')`, name, hash).Scan(&live); err != nil {
		return false, err
	}
	if live {
		return false, nil
	}
	var owner string
	if err := s.d.DB.QueryRow(ctx, `SELECT owner_root FROM services WHERE name = $1`, name).Scan(&owner); err == nil && owner != core.SystemID {
		return false, fmt.Errorf("name %s owned by %s", name, owner)
	}
	stored, err := compute.PutBlobBytes(ctx, s.d, core.SystemID, wasm, "seed")
	if err != nil {
		return false, err
	}
	if stored != hash {
		return false, fmt.Errorf("blob hash mismatch")
	}
	v, _, err := s.publish(ctx, systemIdent(), publishIn{Name: name, Wasm: hash, Manifest: json.RawMessage(manifest)}, publishOpts{system: true, pinSeed: true})
	if err != nil {
		return false, err
	}
	s.d.Log.Info("seed module", "svc", v.Ref(), "hash", hash[:12], "size", len(wasm), "state", v.State)
	return true, nil
}
