package core

import (
	"context"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"
)

// v1 freeze vocabulary (bare keys); v2 adds freeze:<class>, shed:<level> and any key matching flagKeyRe.
var freezeKinds = map[string]bool{"reg": true, "write": true, "compute": true, "all": true}

// flagKeyRe is the v2 key grammar (a superset of ^[a-z][a-z:-]{0,40}$ so that maintenance_until
// and edgekv:<path> rows fit, SPEC 27.1/27.7).
var flagKeyRe = regexp.MustCompile(`^[a-z][a-z0-9:_./-]{0,80}$`)

// ValidFlagKey reports whether k may be stored in flags.
func ValidFlagKey(k string) bool { return flagKeyRe.MatchString(k) }

// maintenanceUntil mirrors the maintenance_until flag for reply.Err's Retry-After (27.7).
var maintenanceUntil atomic.Pointer[time.Time]

// MaintenanceUntil returns the active maintenance deadline, if any.
func MaintenanceUntil() (time.Time, bool) {
	t := maintenanceUntil.Load()
	if t == nil || !t.After(time.Now()) {
		return time.Time{}, false
	}
	return *t, true
}

// Flag returns the raw boolean value of a flag key from the in-memory cache.
func (d *Deps) Flag(k string) bool {
	m := d.flags.Load()
	return m != nil && (*m)[k]
}

// FlagStr returns the string value of a flag key ("" when unset).
func (d *Deps) FlagStr(k string) string {
	m := d.flagStrs.Load()
	if m == nil {
		return ""
	}
	return (*m)[k]
}

// Frozen reports whether `what` (a v1 kind reg|write|compute or a storage class) is frozen: by the
// bare key, by freeze:<what>, or by all / freeze:all.
func (d *Deps) Frozen(what string) bool {
	m := d.flags.Load()
	if m == nil {
		return false
	}
	n := strings.TrimPrefix(what, "freeze:")
	return (*m)["all"] || (*m)["freeze:all"] || (*m)[n] || (*m)["freeze:"+n]
}

// SetFreeze persists a freeze/shed flag (v1 kinds, freeze:<class>, shed:<level>) and refreshes the cache.
func (d *Deps) SetFreeze(ctx context.Context, what string, on bool) error {
	if !freezeKinds[what] && !strings.HasPrefix(what, "freeze:") && !strings.HasPrefix(what, "shed:") {
		return Bad("what must be reg|write|compute|all, freeze:<class> or shed:<level>")
	}
	return d.SetFlag(ctx, what, on, "")
}

// SetFlag persists any flag (key per ValidFlagKey, boolean + optional string value) and refreshes.
func (d *Deps) SetFlag(ctx context.Context, k string, on bool, s string) error {
	if !ValidFlagKey(k) {
		return Bad("flag key")
	}
	if len(s) > 200 {
		return Bad("flag value too long")
	}
	_, err := d.DB.Exec(ctx, `INSERT INTO flags (k, v, s) VALUES ($1, $2, $3)
		ON CONFLICT (k) DO UPDATE SET v = EXCLUDED.v, s = EXCLUDED.s, updated = now()`, k, on, s)
	if err != nil {
		return err
	}
	return d.RefreshFlags(ctx)
}

// RefreshFlags reloads the flag cache from the DB (janitor calls this every tick).
func (d *Deps) RefreshFlags(ctx context.Context) error {
	rows, err := d.DB.Query(ctx, `SELECT k, v, s FROM flags`)
	if err != nil {
		return err
	}
	defer rows.Close()
	m := map[string]bool{}
	ms := map[string]string{}
	for rows.Next() {
		var k, s string
		var v bool
		if err := rows.Scan(&k, &v, &s); err != nil {
			return err
		}
		m[k] = v
		if s != "" {
			ms[k] = s
		}
	}
	if rows.Err() != nil {
		return rows.Err()
	}
	d.flags.Store(&m)
	d.flagStrs.Store(&ms)
	if t, err := time.Parse(time.RFC3339, ms["maintenance_until"]); err == nil && m["maintenance_until"] {
		maintenanceUntil.Store(&t)
	} else {
		maintenanceUntil.Store(nil)
	}
	return nil
}

// CheckFrozen is a handler-side shortcut: writes err frozen and returns false when frozen.
func (d *Deps) CheckFrozen(w http.ResponseWriter, r *http.Request, what string) bool {
	if d.Frozen(what) {
		Fail(w, r, Frozen(what))
		return false
	}
	return true
}

// Shed reports whether the shed rung `level` (feeds, anon-search, longpoll, anon-write, compute)
// applies to this request: verified crawlers (27.1) are exempt from feeds and anon-search on reads.
func (d *Deps) Shed(r *http.Request, level string) bool {
	if !d.Flag("shed:" + level) {
		return false
	}
	if r != nil && (r.Method == http.MethodGet || r.Method == http.MethodHead) && (level == "feeds" || level == "anon-search") {
		if ok, _ := BotLane(r.Context()); ok {
			return false
		}
	}
	return true
}

// ErrBusy is the shed reply (21.1): 503 + Retry-After.
func ErrBusy(level string) *APIError { return E(503, "busy", "retry shed:"+level) }
