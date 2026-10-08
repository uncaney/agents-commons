package libwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/know"
)

var errNoManifest = core.E(404, "notfound", "no such manifest")

// cleanName normalises a manifest name (default when empty, [a-z0-9._-], <= 32).
func cleanName(name string) (string, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return "default", nil
	}
	if len(name) > MaxName || !core.ValidName(name) {
		return "", core.Bad("name must match [a-zA-Z0-9._-]{1,32}")
	}
	return name, nil
}

// storeManifest upserts a root's manifest and (at L1+ only) enqueues libmeta for every key, then
// returns the stored entries. The per-root manifest cap is enforced for a new name. The whole
// write is one transaction.
func storeManifest(ctx context.Context, d *core.Deps, root, name string, entries []entry) error {
	libs, err := json.Marshal(entries)
	if err != nil {
		return err
	}
	lvl := core.Level(ctx, d.DB, root)
	return core.Tx(ctx, d.DB, func(tx pgx.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM env_manifests WHERE root = $1 AND name = $2)`, root, name).Scan(&exists); err != nil {
			return err
		}
		if !exists {
			var n int
			if err := tx.QueryRow(ctx, `SELECT count(*) FROM env_manifests WHERE root = $1`, root).Scan(&n); err != nil {
				return err
			}
			if n >= manifestCap(lvl) {
				return core.E(409, "quota", fmt.Sprintf("at most %d manifests per root", manifestCap(lvl)))
			}
		}
		if _, err := tx.Exec(ctx, `INSERT INTO env_manifests (root, name, libs, updated) VALUES ($1, $2, $3::jsonb, now())
			ON CONFLICT (root, name) DO UPDATE SET libs = EXCLUDED.libs, updated = now()`, root, name, string(libs)); err != nil {
			return err
		}
		if lvl >= 1 {
			for _, e := range entries {
				if err := know.RequestLibMeta(ctx, tx, e.Key, root); err != nil {
					return err
				}
			}
		}
		return core.Audit(ctx, tx, root, "env", name, len(entries))
	})
}

// loadManifest returns a root's stored entries and the alerts flag.
func loadManifest(ctx context.Context, q core.Q, root, name string) ([]entry, bool, error) {
	var raw []byte
	var alerts bool
	err := q.QueryRow(ctx, `SELECT libs, alerts FROM env_manifests WHERE root = $1 AND name = $2`, root, name).Scan(&raw, &alerts)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, false, errNoManifest
	}
	if err != nil {
		return nil, false, err
	}
	var entries []entry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, false, err
	}
	return entries, alerts, nil
}

// setAlerts toggles a manifest's alert subscription.
func setAlerts(ctx context.Context, q core.Q, root, name string, on bool) error {
	ct, err := q.Exec(ctx, `UPDATE env_manifests SET alerts = $3 WHERE root = $1 AND name = $2`, root, name, on)
	if err != nil {
		return err
	}
	if ct.RowsAffected() == 0 {
		return errNoManifest
	}
	return nil
}

// purge removes every manifest of a root (export-me erase, 3.4).
func purge(ctx context.Context, q core.Q, root string) error {
	_, err := q.Exec(ctx, `DELETE FROM env_manifests WHERE root = $1`, root)
	return err
}

// export writes a root's manifests as newline-delimited JSON (export-me, 3.4). Nothing else in
// libwatch is root-owned: lib_releases is a public pool.
func export(ctx context.Context, q core.Q, root string, w io.Writer) error {
	rows, err := q.Query(ctx, `SELECT name, libs, updated, alerts FROM env_manifests WHERE root = $1 ORDER BY name`, root)
	if err != nil {
		return err
	}
	defer rows.Close()
	enc := json.NewEncoder(w)
	for rows.Next() {
		var name string
		var libs []byte
		var upd time.Time
		var alerts bool
		if err := rows.Scan(&name, &libs, &upd, &alerts); err != nil {
			return err
		}
		rec := struct {
			Kind    string          `json:"kind"`
			Name    string          `json:"name"`
			Libs    json.RawMessage `json:"libs"`
			Updated string          `json:"updated"`
			Alerts  bool            `json:"alerts"`
		}{"env_manifest", name, json.RawMessage(libs), upd.UTC().Format(time.RFC3339), alerts}
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return rows.Err()
}

// resumeLines adds the drift summary to GET /v1/me/resume (27.3:
// `env: 4 drifts (1 security: pypi:requests)`).
func resumeLines(ctx context.Context, q core.Q, root string) []string {
	rows, err := q.Query(ctx, `SELECT libs FROM env_manifests WHERE root = $1`, root)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var all []entry
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil
		}
		var es []entry
		if json.Unmarshal(raw, &es) != nil {
			continue
		}
		for _, e := range es {
			if !seen[e.Key] {
				seen[e.Key] = true
				all = append(all, e)
			}
		}
	}
	if len(all) == 0 {
		return nil
	}
	rep, err := buildReport(ctx, q, "", all, false, false)
	if err != nil || rep.cnt == 0 {
		return nil
	}
	secN := 0
	secLibs := make([]string, 0)
	for _, l := range rep.lines {
		if l.Sec > 0 {
			secN += l.Sec
			secLibs = append(secLibs, l.Key)
		}
	}
	line := fmt.Sprintf("env: %d drifts", rep.cnt)
	if secN > 0 {
		sort.Strings(secLibs)
		line += fmt.Sprintf(" (%d security: %s)", secN, secLibs[0])
	}
	return []string{line}
}
