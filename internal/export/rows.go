package export

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strconv"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/scrub"
)

// Row shapes (9.5, 27.1). Text fields pass scrub.Mask again at export time (rows below the current
// scrub version), seed rows carry author "seed", every URL is server-built, dates are RFC 3339 UTC.

var spaceRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,39}$`)

type emitFn func(row map[string]any) error

func mask(s string) string {
	out, _ := scrub.Mask(s)
	return out
}

func ts(t time.Time) string { return t.UTC().Format(time.RFC3339) }

func tsp(t *time.Time) any {
	if t == nil {
		return nil
	}
	return ts(*t)
}

func author(seed bool, id string) string {
	if seed {
		return "seed"
	}
	return id
}

func strs(xs []string) []string {
	if xs == nil {
		return []string{}
	}
	return xs
}

// license returns the configured content license (CC0-1.0 before Register).
func license() string {
	if s := cur.Load(); s != nil {
		return s.lic
	}
	return "CC0-1.0"
}

// kbRow is the kb shard row: the 9.5 fields plus rev and md_sha256 (sha256 of the Markdown
// rendition served at /kb/<id>.md); hazard families when present.
func kbRow(e *kb.Entry, lic string) map[string]any {
	libs := make([]map[string]string, 0, len(e.Libs))
	for _, lv := range e.Libs {
		libs = append(libs, map[string]string{"lib": lv.Lib, "ver": lv.Ver})
	}
	if e.License != "" {
		lic = e.License
	}
	sum := sha256.Sum256([]byte(e.Markdown()))
	row := map[string]any{
		"id": e.ID, "kind": e.Kind, "title": mask(e.Title), "symptom": mask(e.Symptom), "cause": mask(e.Cause),
		"fix": mask(e.Fix), "versions": mask(e.Versions), "libs": libs, "tags": strs(e.Tags), "ok_w": e.OkW, "bad_w": e.BadW,
		"created": ts(e.Created), "confirmed_at": tsp(e.ConfirmedAt), "url": kb.Permalink(e.ID),
		"author": author(e.Seed, e.Author), "license": lic, "rev": max(e.Rev, 1), "md_sha256": hex.EncodeToString(sum[:]),
	}
	if len(e.Applies) > 0 {
		row["applies"] = e.Applies
	}
	if len(e.Hazard) > 0 {
		row["hazard"] = e.Hazard
	}
	return row
}

// kbRows streams the visible, non-quarantined entries (optionally of one space) newest first,
// one page at a time with the page's libs loaded in bulk. Entries with votes are reloaded through
// GetV2 so the works/fails lines (and md_sha256) match the page.
func kbRows(ctx context.Context, q core.Q, space, lic string, emit emitFn) error {
	after := ""
	for page := 0; page < 1<<20; page++ {
		es, cursor, err := kb.Latest(ctx, q, kb.LatestOpts{Space: space, N: pageSize, After: after})
		if err != nil {
			return err
		}
		if err := loadLibs(ctx, q, es); err != nil {
			return err
		}
		for _, e := range es {
			if e.OkW != 0 || e.BadW != 0 {
				full, err := kb.GetV2(ctx, q, e.ID, kb.GetOpts{})
				if err == nil {
					e = full
				} else if !errors.Is(err, core.ErrNotFound) {
					return err
				}
			}
			if err := emit(kbRow(e, lic)); err != nil {
				return err
			}
		}
		if cursor == "" {
			return nil
		}
		after = cursor
	}
	return nil
}

// loadLibs attaches the kb_versions pairs of a page of entries (Latest leaves them empty).
func loadLibs(ctx context.Context, q core.Q, es []*kb.Entry) error {
	if len(es) == 0 {
		return nil
	}
	byID := make(map[string]*kb.Entry, len(es))
	ids := make([]string, 0, len(es))
	for _, e := range es {
		byID[e.ID] = e
		ids = append(ids, e.ID)
	}
	rows, err := q.Query(ctx, `SELECT kb_id, lib, ver FROM kb_versions WHERE kb_id = ANY($1) ORDER BY kb_id, lib, ver`, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var lv kb.LibVer
		if err := rows.Scan(&id, &lv.Lib, &lv.Ver); err != nil {
			return err
		}
		if e := byID[id]; e != nil {
			e.Libs = append(e.Libs, lv)
		}
	}
	return rows.Err()
}

// taskRows streams visible, non-quarantined board tasks (one when n > 0; one space when set).
func taskRows(ctx context.Context, q core.Q, n int64, space, lic string, emit emitFn) error {
	rows, err := q.Query(ctx, `SELECT t.n, t.id, t.title, t.body, t.tags, t.state, t.space, t.created, t.closed_at, t.confirmed_at,
		t.ok_w, t.bad_w, t.hazard, coalesce(r.seed, false), (SELECT count(*) FROM task_notes tn WHERE tn.n = t.n)
		FROM tasks t LEFT JOIN identities r ON r.id = t.root
		WHERE t.state <> 'hidden' AND NOT t.quarantine AND t.title <> '' AND ($1 = 0 OR t.n = $1) AND ($2 = '' OR t.space = $2)
		ORDER BY t.n`, n, space)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			tn, notes                  int64
			id, title, body, state, sp string
			tags, hazard               []string
			created                    time.Time
			closed, confirmed          *time.Time
			okW, badW                  float32
			seed                       bool
		)
		if err := rows.Scan(&tn, &id, &title, &body, &tags, &state, &sp, &created, &closed, &confirmed, &okW, &badW, &hazard, &seed, &notes); err != nil {
			return err
		}
		row := map[string]any{
			"id": strconv.FormatInt(tn, 10), "n": tn, "title": mask(title), "body": mask(body), "tags": strs(tags), "state": state,
			"space": sp, "created": ts(created), "closed_at": tsp(closed), "confirmed_at": tsp(confirmed), "ok_w": okW, "bad_w": badW,
			"notes": notes, "url": doc.Base() + "/t/" + strconv.FormatInt(tn, 10), "author": author(seed, id), "license": lic,
		}
		if len(hazard) > 0 {
			row["hazard"] = hazard
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return rows.Err()
}

// claimRows streams visible claims (verified/unverified, not hidden, not expired; one when id set).
func claimRows(ctx context.Context, q core.Q, id, lic string, emit emitFn) error {
	rows, err := q.Query(ctx, `SELECT c.id, c.lib, c.kind, c.v_from, c.v_to, c.effective, c.title, c.detail, c.migrate, c.scope, c.sev,
		c.source_url, c.source_quote, c.source_tier, c.status, c.conf_w, c.disp_w, c.created, c.confirmed_at, c.author,
		c.seed OR coalesce(r.seed, false)
		FROM claims c LEFT JOIN identities r ON r.id = c.author_root AND c.author_root <> ''
		WHERE NOT c.hidden AND c.status IN ('verified', 'unverified') AND c.expires_at > now() AND ($1 = '' OR c.id = $1)
		ORDER BY c.created, c.id`, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			cid, lib, kind, vFrom, vTo, title, detail, migrate, scope string
			srcURL, srcQuote, srcTier, status, auth                   string
			effective, confirmed                                      *time.Time
			sev                                                       int
			confW, dispW                                              float32
			created                                                   time.Time
			seed                                                      bool
		)
		if err := rows.Scan(&cid, &lib, &kind, &vFrom, &vTo, &effective, &title, &detail, &migrate, &scope, &sev, &srcURL, &srcQuote,
			&srcTier, &status, &confW, &dispW, &created, &confirmed, &auth, &seed); err != nil {
			return err
		}
		var eff any
		if effective != nil {
			eff = effective.UTC().Format(dateFmt)
		}
		row := map[string]any{
			"id": cid, "lib": lib, "kind": kind, "v_from": vFrom, "v_to": vTo, "effective": eff, "title": mask(title), "detail": mask(detail),
			"migrate": mask(migrate), "scope": scope, "sev": sev, "source_url": srcURL, "source_quote": mask(srcQuote), "source_tier": srcTier,
			"status": status, "conf_w": confW, "disp_w": dispW, "created": ts(created), "confirmed_at": tsp(confirmed),
			"url": doc.Base() + "/v1/v/" + cid, "author": author(seed, auth), "license": lic,
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return rows.Err()
}

// digestRows streams live, visible digests (one when id set).
func digestRows(ctx context.Context, q core.Q, id, lic string, emit emitFn) error {
	rows, err := q.Query(ctx, `SELECT g.id, g.lib, g.v_from, g.v_to, g.topic, g.body, g.source_url, g.tokens_est, g.ok_w, g.bad_w,
		g.created, g.confirmed_at, g.author, coalesce(r.seed, false)
		FROM digests g LEFT JOIN identities r ON r.id = g.author_root AND g.author_root <> ''
		WHERE NOT g.hidden AND g.status = 'live' AND g.expires_at > now() AND ($1 = '' OR g.id = $1)
		ORDER BY g.created, g.id`, id)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var (
			did, lib, vFrom, vTo, topic, body, srcURL, auth string
			tokens                                          int
			okW, badW                                       float32
			created                                         time.Time
			confirmed                                       *time.Time
			seed                                            bool
		)
		if err := rows.Scan(&did, &lib, &vFrom, &vTo, &topic, &body, &srcURL, &tokens, &okW, &badW, &created, &confirmed, &auth, &seed); err != nil {
			return err
		}
		row := map[string]any{
			"id": did, "lib": lib, "v_from": vFrom, "v_to": vTo, "topic": topic, "body": mask(body), "source_url": srcURL, "tokens_est": tokens,
			"ok_w": okW, "bad_w": badW, "created": ts(created), "confirmed_at": tsp(confirmed), "url": doc.Base() + "/v1/dg/" + did,
			"author": author(seed, auth), "license": lic,
		}
		if err := emit(row); err != nil {
			return err
		}
	}
	return rows.Err()
}

// Row returns the export row of one visible, non-quarantined object (kind kb|task|claim|digest; a
// task id is its number) and false when the object is unknown or not exportable (27.7 sync).
func Row(ctx context.Context, q core.Q, kind, id string) (map[string]any, bool, error) {
	lic := license()
	var out map[string]any
	emit := func(r map[string]any) error { out = r; return nil }
	var err error
	switch kind {
	case "kb":
		if !core.ValidIDPrefix(id, 'k') {
			return nil, false, nil
		}
		e, err := kb.GetV2(ctx, q, id, kb.GetOpts{})
		if errors.Is(err, core.ErrNotFound) {
			return nil, false, nil
		}
		if err != nil {
			return nil, false, err
		}
		if e.Quarantine || !e.Visible() {
			return nil, false, nil
		}
		return kbRow(e, lic), true, nil
	case "task":
		n, perr := strconv.ParseInt(id, 10, 64)
		if perr != nil || n <= 0 {
			return nil, false, nil
		}
		err = taskRows(ctx, q, n, "", lic, emit)
	case "claim":
		if !core.ValidIDPrefix(id, 'v') {
			return nil, false, nil
		}
		err = claimRows(ctx, q, id, lic, emit)
	case "digest":
		if !core.ValidIDPrefix(id, 'd') {
			return nil, false, nil
		}
		err = digestRows(ctx, q, id, lic, emit)
	default:
		return nil, false, core.Bad("export kind")
	}
	if err != nil {
		return nil, false, err
	}
	return out, out != nil, nil
}

var errFull = errors.New("export: size cap")

// SpaceJSONL writes the visible, non-quarantined rows of one space as JSONL (<= 2 MiB, 27.5): src
// selects kb ("kb"), tasks ("t"/"tasks") or both ("" / "all"). The output stops at the cap.
func SpaceJSONL(ctx context.Context, q core.Q, slug, src string, w io.Writer) error {
	if !spaceRe.MatchString(slug) {
		return core.Bad("space")
	}
	var kbOn, tasksOn bool
	switch src {
	case "", "all":
		kbOn, tasksOn = true, true
	case "kb":
		kbOn = true
	case "t", "tasks":
		tasksOn = true
	default:
		return core.Bad("src must be kb, t or all")
	}
	lic := license()
	var n int64
	emit := func(row map[string]any) error {
		var b bytes.Buffer
		enc := json.NewEncoder(&b)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(row); err != nil {
			return err
		}
		if n+int64(b.Len()) > spaceJSONLMax {
			return errFull
		}
		k, err := w.Write(b.Bytes())
		n += int64(k)
		return err
	}
	if kbOn {
		if err := kbRows(ctx, q, slug, lic, emit); err != nil {
			if errors.Is(err, errFull) {
				return nil
			}
			return err
		}
	}
	if tasksOn {
		if err := taskRows(ctx, q, 0, slug, lic, emit); err != nil && !errors.Is(err, errFull) {
			return err
		}
	}
	return nil
}
