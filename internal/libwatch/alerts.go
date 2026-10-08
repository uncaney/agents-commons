package libwatch

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
)

// alertKinds are the claim kinds that raise a manifest alert (27.3).
var alertKinds = []string{"breaking", "security", "eol"}

// AlertJanitor is the hourly digest janitor (27.3): for every root with alert-subscribed
// manifests, verified breaking/security/eol claims of its libs confirmed after last_alert are
// gathered into one mail.SendSys digest, at most once per root per day. last_alert then advances
// so the same claims never alert twice.
func AlertJanitor(ctx context.Context, q core.Q) error {
	rows, err := q.Query(ctx, `SELECT root, coalesce(max(last_alert), 'epoch'::timestamptz)
		FROM env_manifests WHERE alerts GROUP BY root
		HAVING max(last_alert) IS NULL OR max(last_alert)::date < current_date`)
	if err != nil {
		return err
	}
	type cand struct {
		root  string
		after time.Time
	}
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.root, &c.after); err != nil {
			rows.Close()
			return err
		}
		cands = append(cands, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, c := range cands {
		if err := alertRoot(ctx, q, c.root, c.after); err != nil {
			return err
		}
	}
	return nil
}

// alertRoot builds and sends one root's digest, then advances last_alert on its alert manifests.
func alertRoot(ctx context.Context, q core.Q, root string, after time.Time) error {
	keys, err := rootKeys(ctx, q, root)
	if err != nil || len(keys) == 0 {
		return err
	}
	drows, err := q.Query(ctx, `SELECT c.kind, c.lib, c.v_to, c.title FROM claims c
		WHERE c.lib = ANY($1) AND c.kind = ANY($2) AND c.status = 'verified' AND NOT c.hidden
		AND c.expires_at > now() AND c.confirmed_at > $3
		ORDER BY (c.kind = 'security') DESC, (c.kind = 'breaking') DESC, c.confirmed_at DESC LIMIT 50`,
		keys, alertKinds, after)
	if err != nil {
		return err
	}
	var lines []string
	secN := 0
	for drows.Next() {
		var kind, lib, vto, title string
		if err := drows.Scan(&kind, &lib, &vto, &title); err != nil {
			drows.Close()
			return err
		}
		if kind == "security" {
			secN++
		}
		lines = append(lines, fmt.Sprintf("%s %s %s %s", kind, lib, orDash(vto), doc.SafeLine(title)))
	}
	drows.Close()
	if err := drows.Err(); err != nil {
		return err
	}
	if len(lines) == 0 {
		return nil
	}
	subject := fmt.Sprintf("env drift: %d new claim(s)", len(lines))
	if secN > 0 {
		subject = fmt.Sprintf("env drift: %d new (%d security)", len(lines), secN)
	}
	body := "Verified changes to libraries in your manifests:\n" + strings.Join(lines, "\n") +
		"\nGET /v1/env to review; PUT /v1/env/{name} {\"alerts\":false} to mute."
	if err := core.SysMail(ctx, q, root, subject, body); err != nil {
		return err
	}
	_, err = q.Exec(ctx, `UPDATE env_manifests SET last_alert = now() WHERE root = $1 AND alerts`, root)
	return err
}

// rootKeys collects the distinct lib keys across a root's alert-subscribed manifests.
func rootKeys(ctx context.Context, q core.Q, root string) ([]string, error) {
	rows, err := q.Query(ctx, `SELECT libs FROM env_manifests WHERE root = $1 AND alerts`, root)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var keys []string
	for rows.Next() {
		var raw []byte
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var es []entry
		if json.Unmarshal(raw, &es) != nil {
			continue
		}
		for _, e := range es {
			if !seen[e.Key] {
				seen[e.Key] = true
				keys = append(keys, e.Key)
			}
		}
	}
	return keys, rows.Err()
}

// FillLibReleases rebuilds the public release pool from confirmed `release` claims (authoritative)
// and the registry version times carried in libs.versions (27.3). Claim rows win a (key, ver)
// collision; both sources are idempotent.
func FillLibReleases(ctx context.Context, q core.Q) error {
	if _, err := q.Exec(ctx, `INSERT INTO lib_releases (key, ver, released, src)
		SELECT c.lib, c.v_to, coalesce(c.effective, c.confirmed_at::date), 'claim'
		FROM claims c
		WHERE c.kind = 'release' AND c.status = 'verified' AND NOT c.hidden AND c.expires_at > now()
		AND c.v_to <> '' AND coalesce(c.effective, c.confirmed_at::date) IS NOT NULL
		ON CONFLICT (key, ver) DO NOTHING`); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `INSERT INTO lib_releases (key, ver, released, src)
		SELECT l.key, e->>'v', (e->>'at')::timestamptz::date, 'registry'
		FROM libs l, jsonb_array_elements(l.versions) e
		WHERE coalesce(e->>'at', '') <> '' AND left(e->>'at', 4) BETWEEN '1990' AND '9999'
		AND coalesce(e->>'v', '') <> ''
		ON CONFLICT (key, ver) DO NOTHING`)
	return err
}
