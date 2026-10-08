package catalog

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/gov"
)

// transferIdleDays is the inactivity a service must show before a passed svc-transfer proposal may
// move its owner_root (15.2, "svc-transfer after 90 d inactivity").
const transferIdleDays = 90

// RegisterVerify wires the catalog's verification extensions (SPEC-v2 15.2, 18.1). The weekly
// re-verification itself runs from catalog.Register's svc_recheck / svc_verify janitors (one KAT
// per stable version from the system root through compute.SystemSubmit, skipped with an inbox
// event when the system root is unfunded; a wrong hash flips the version failing-since, a matching
// one clears it). This step adds what the governance surface needs on top: the blessed-services
// feed for /llms-full.txt, the KAT run history recorder (svc_kat_runs), and the svc-bless /
// svc-transfer gov appliers. The appliers are also exported so P60a can register them directly.
func RegisterVerify(d *core.Deps) {
	if BlessedFn == nil {
		BlessedFn = func(ctx context.Context) []string { return blessedNames(ctx, d) }
	}
	d.Janitor.Add("svc_kat_history", func(ctx context.Context) error { return recordKATRuns(ctx, d) })
	gov.RegisterKind("svc-bless", nil, BlessApplier(d))
	gov.RegisterKind("svc-transfer", nil, TransferApplier(d))
}

// blessedNames lists the visible services a passed svc-bless proposal blessed (blessed_at set on
// an operator yes). Names match nameRe by construction (the services table CHECK), so llms accepts
// them directly.
func blessedNames(ctx context.Context, d *core.Deps) []string {
	rows, err := d.DB.Query(ctx, `SELECT name FROM services WHERE blessed_at IS NOT NULL AND NOT hidden ORDER BY name`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var n string
		if rows.Scan(&n) == nil {
			out = append(out, n)
		}
	}
	return out
}

// recordKATRuns is the svc_kat_history janitor: it appends one row per newly-finished KAT job
// (publish verification and the weekly re-check) to svc_kat_runs, keyed by job id so it is
// idempotent. The history makes the failing-since / recovery verdicts auditable without re-reading
// the (retained-then-pruned) jobs table.
func recordKATRuns(ctx context.Context, d *core.Deps) error {
	rows, err := d.DB.Query(ctx, `SELECT j.id, j.svc, j.status, coalesce(j.out, ''), j.att_d, coalesce(j.reason, '')
		FROM jobs j WHERE j.kind = 'kat' AND j.svc <> '' AND j.status IN ('done', 'failed')
		  AND NOT EXISTS (SELECT 1 FROM svc_kat_runs r WHERE r.job = j.id) ORDER BY j.finished_at LIMIT 500`)
	if err != nil {
		return err
	}
	type run struct {
		job, svc, status, out, reason string
		attD                          bool
	}
	var runs []run
	for rows.Next() {
		var r run
		if err := rows.Scan(&r.job, &r.svc, &r.status, &r.out, &r.attD, &r.reason); err != nil {
			rows.Close()
			return err
		}
		runs = append(runs, r)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for _, r := range runs {
		name, ver, ok := splitRef(r.svc)
		if !ok {
			continue
		}
		ok = r.status == "done" && r.attD
		if _, err := d.DB.Exec(ctx, `INSERT INTO svc_kat_runs (job, name, ver, status, ok, out, att_d, reason)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (job) DO NOTHING`,
			r.job, name, ver, r.status, ok, r.out, r.attD, truncate(r.reason, 300)); err != nil {
			return err
		}
	}
	return nil
}

// splitRef parses a name@ver reference into its parts.
func splitRef(ref string) (name string, ver int, ok bool) {
	i := strings.LastIndexByte(ref, '@')
	if i < 0 {
		return "", 0, false
	}
	v, err := strconv.Atoi(ref[i+1:])
	if err != nil || v <= 0 || !nameRe.MatchString(ref[:i]) {
		return "", 0, false
	}
	return ref[:i], v, true
}

// --- governance appliers (18.1) -----------------------------------------------------------------

// BlessApplier is the gov.Applier for a passed svc-bless proposal. svc-bless is an await-operator
// kind, so gov only runs this applier on an explicit operator yes (18.1): it lists the service in
// /llms-full.txt by stamping blessed_at. prev records whether it was already blessed, so a revert
// re-proposal can un-bless it.
func BlessApplier(d *core.Deps) gov.Applier {
	return func(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
		name := blessName(p)
		if name == "" {
			return nil, core.Bad("svc-bless: name must be a service name")
		}
		var existed bool
		switch err := tx.QueryRow(ctx, `SELECT blessed_at IS NOT NULL FROM services WHERE name = $1`, name).Scan(&existed); {
		case errors.Is(err, pgx.ErrNoRows):
			return nil, core.E(404, "notfound", "service "+name+" not found")
		case err != nil:
			return nil, err
		}
		if _, err := tx.Exec(ctx, `UPDATE services SET blessed_at = now() WHERE name = $1 AND blessed_at IS NULL`, name); err != nil {
			return nil, err
		}
		if err := gov.ChangelogNote(ctx, tx, "", p.ID+" svc-bless "+name); err != nil {
			return nil, err
		}
		if err := core.Event(ctx, tx, "svc", name, "", "service "+name+" blessed (listed in /llms-full.txt)"); err != nil {
			return nil, err
		}
		prev, _ := json.Marshal(map[string]bool{"blessed": existed})
		return prev, nil
	}
}

// blessName is the service name a svc-bless proposal targets: its patch {name} (a name or name@ver)
// or, failing that, its target; the @ver and any svc: prefix are dropped.
func blessName(p *gov.Proposal) string {
	var pt struct {
		Name string `json:"name"`
	}
	_ = json.Unmarshal(p.Patch, &pt)
	n := pt.Name
	if n == "" {
		n = p.Target
	}
	n = strings.TrimPrefix(n, "svc:")
	if i := strings.IndexByte(n, '@'); i >= 0 {
		n = n[:i]
	}
	if !nameRe.MatchString(n) {
		return ""
	}
	return n
}

// TransferApplier is the gov.Applier for a passed svc-transfer proposal: it moves a service's
// owner_root to the patch's {to}, but only once the service has been inactive for transferIdleDays
// (15.2). An active service fails the apply (the proposal ends failed). prev is the former owner
// for revert.
func TransferApplier(d *core.Deps) gov.Applier {
	return func(ctx context.Context, tx core.Q, p *gov.Proposal) (json.RawMessage, error) {
		name := strings.TrimPrefix(p.Target, "svc:")
		if i := strings.IndexByte(name, '@'); i >= 0 {
			name = name[:i]
		}
		if !nameRe.MatchString(name) {
			return nil, core.Bad("svc-transfer: target must be a service name")
		}
		var pt struct {
			To string `json:"to"`
		}
		if err := json.Unmarshal(p.Patch, &pt); err != nil || !core.ValidIDPrefix(pt.To, 'a') {
			return nil, core.Bad("svc-transfer: to must be a root id")
		}
		var owner string
		var inactive bool
		switch err := tx.QueryRow(ctx, `SELECT owner_root, coalesce(last_other_call, created) < now() - make_interval(days => $2)
			FROM services WHERE name = $1`, name, transferIdleDays).Scan(&owner, &inactive); {
		case errors.Is(err, pgx.ErrNoRows):
			return nil, core.E(404, "notfound", "service "+name+" not found")
		case err != nil:
			return nil, err
		}
		if owner == core.SystemID {
			return nil, core.Bad("svc-transfer: system services are not transferable")
		}
		if !inactive {
			return nil, core.Bad("svc-transfer: " + name + " active within " + strconv.Itoa(transferIdleDays) + " d")
		}
		if owner == pt.To {
			return nil, core.Bad("svc-transfer: already owned by " + doc.SafeLine(pt.To))
		}
		if _, err := tx.Exec(ctx, `UPDATE services SET owner_root = $2 WHERE name = $1`, name, pt.To); err != nil {
			return nil, err
		}
		if err := gov.ChangelogNote(ctx, tx, "", p.ID+" svc-transfer "+name+" "+owner+" -> "+pt.To); err != nil {
			return nil, err
		}
		if err := core.Event(ctx, tx, "svc", name, owner, "service "+name+" transferred to "+pt.To); err != nil {
			return nil, err
		}
		prev, _ := json.Marshal(map[string]string{"owner_root": owner})
		return prev, nil
	}
}
