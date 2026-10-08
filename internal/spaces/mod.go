package spaces

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/forge"
	"ekaii.fr/commons/internal/kb"
	"ekaii.fr/commons/internal/scrub"
)

// Steward moderation (SPEC-v2 18.3): POST /v1/s/{slug}/hide|unhide {target, why}. Reversible,
// logged in mod_log (public on /s/<slug>/log) and bound by the scope rule: the target must belong
// to the space (kb.space = slug, tasks.space = slug, the space's own docs, its group box g<slug>,
// topic messages under s:<slug>.); anything else answers `403 err scope target not in space`.

// ErrScope is the scope rule's refusal.
var ErrScope = core.E(403, "scope", "target not in space")

var (
	psRefRe   = regexp.MustCompile(`^(s:[a-z0-9][a-z0-9_-]{0,39}\.[a-z0-9._-]{1,64}|[a-z]:[a-z0-9._-]{1,120})/([1-9][0-9]{0,17})$`)
	targetRe  = regexp.MustCompile(`^(kb|t|d|m|ps):(.{1,160})$`)
	errTarget = core.Bad("target must be kb:<id> | t:<n> | d:<name> | m:<id> | ps:<topic>/<seq>")
)

// parseTarget splits and shape-checks a moderation target.
func parseTarget(target string) (kind, ref string, err error) {
	m := targetRe.FindStringSubmatch(strings.TrimSpace(target))
	if m == nil {
		return "", "", errTarget
	}
	kind, ref = m[1], m[2]
	switch kind {
	case "kb":
		if !core.ValidIDPrefix(ref, 'k') {
			return "", "", errTarget
		}
	case "t":
		if n, err := strconv.ParseInt(ref, 10, 64); err != nil || n <= 0 {
			return "", "", errTarget
		}
	case "d":
		if !docNameRe.MatchString(ref) {
			return "", "", errTarget
		}
	case "m":
		if !core.ValidIDPrefix(ref, 'm') {
			return "", "", errTarget
		}
	case "ps":
		if !psRefRe.MatchString(ref) {
			return "", "", errTarget
		}
	}
	return kind, ref, nil
}

// TargetInSpace applies the scope rule: it returns the target's kind and ref when the row exists
// and belongs to slug, core.ErrNotFound when it does not exist, ErrScope when it lives elsewhere.
func TargetInSpace(ctx context.Context, q core.Q, slug, target string) (kind, ref string, err error) {
	kind, ref, err = parseTarget(target)
	if err != nil {
		return "", "", err
	}
	var owner string
	switch kind {
	case "kb":
		err = q.QueryRow(ctx, `SELECT space FROM kb WHERE id = $1`, ref).Scan(&owner)
	case "t":
		n, _ := strconv.ParseInt(ref, 10, 64)
		err = q.QueryRow(ctx, `SELECT space FROM tasks WHERE n = $1`, n).Scan(&owner)
	case "d":
		err = q.QueryRow(ctx, `SELECT space FROM space_docs WHERE space = $1 AND name = $2`, slug, ref).Scan(&owner)
	case "m":
		err = q.QueryRow(ctx, `SELECT box FROM mail WHERE id = $1`, ref).Scan(&owner)
		owner = strings.TrimPrefix(owner, "g")
	case "ps":
		topic := ref[:strings.LastIndexByte(ref, '/')]
		if !strings.HasPrefix(topic, "s:"+slug+".") {
			return "", "", ErrScope
		}
		seq, _ := strconv.ParseInt(ref[len(topic)+1:], 10, 64)
		var ok bool
		if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM topic_msgs WHERE topic = $1 AND seq = $2)`, topic, seq).Scan(&ok); err != nil {
			return "", "", err
		}
		if !ok {
			return "", "", core.ErrNotFound
		}
		return kind, ref, nil
	}
	if errors.Is(err, errNoRows) {
		return "", "", core.ErrNotFound
	}
	if err != nil {
		return "", "", err
	}
	if owner != slug {
		return "", "", ErrScope
	}
	return kind, ref, nil
}

// Moderate hides (or restores) target in slug on behalf of steward id: scope rule, the kind's own
// hide function (kb report-hide without rep penalty, forge task hide, doc hide, the registered m:
// and ps: targets with a direct fallback), then a mod_log row and an event.
func Moderate(ctx context.Context, d *core.Deps, id *core.Ident, slug, target, why string, hide bool) error {
	if _, err := stewardOnly(ctx, d.DB, slug, id.Root); err != nil {
		return err
	}
	why = strings.TrimSpace(why)
	if !doc.OneLine(why) || utf8.RuneCountInString(why) > MaxWhy {
		return core.Bad(fmt.Sprintf("why must be one line of <= %d chars", MaxWhy))
	}
	if _, aerr := scrub.RejectOrMask(map[string]*string{"why": &why}); aerr != nil {
		return aerr
	}
	kind, ref, err := TargetInSpace(ctx, d.DB, slug, target)
	if err != nil {
		return err
	}
	q := d.DB
	switch kind {
	case "kb":
		if hide {
			if err := kb.HideBy(ctx, q, ref, "report"); err != nil {
				return err
			}
			var hidden bool
			if err := q.QueryRow(ctx, `SELECT hidden FROM kb WHERE id = $1`, ref).Scan(&hidden); err != nil {
				return err
			}
			if !hidden {
				return core.E(409, "bad", "target immune (restored by appeal within 30 d)")
			}
		} else if err := kb.Restore(ctx, q, ref); err != nil {
			return err
		}
	case "t":
		n, _ := strconv.ParseInt(ref, 10, 64)
		if hide {
			err = forge.HideTask(ctx, d, int(n))
		} else {
			err = forge.RestoreTask(ctx, d, n)
		}
		if err != nil {
			return err
		}
	case "d":
		if err := SetDocHidden(ctx, q, slug, ref, hide); err != nil {
			return err
		}
	case "m", "ps":
		if err := hideRegistered(ctx, d, kind, ref, hide); err != nil {
			return err
		}
	}
	action := "hide"
	if !hide {
		action = "unhide"
	}
	return inTx(ctx, q, func(tx core.Q) error {
		if err := modLog(ctx, tx, slug, id.Root, kind+":"+ref, action, why); err != nil {
			return err
		}
		if err := core.Audit(ctx, tx, id.ID, "sh", kind+":"+ref, 0); err != nil {
			return err
		}
		return core.Event(ctx, tx, "space", "s:"+slug, "", "space "+slug+" "+action+" "+kind+":"+ref)
	})
}

// hideRegistered uses the kind's report target when its package is wired, else the row's hidden
// column directly (both tables exist from the shared migrations).
func hideRegistered(ctx context.Context, d *core.Deps, kind, ref string, hide bool) error {
	if t, ok := d.Target(kind); ok {
		if hide && t.Hide != nil {
			return t.Hide(ctx, d.DB, ref)
		}
		if !hide && t.Restore != nil {
			return t.Restore(ctx, d.DB, ref)
		}
	}
	switch kind {
	case "m":
		_, err := d.DB.Exec(ctx, `UPDATE mail SET hidden = $2 WHERE id = $1`, ref, hide)
		return err
	case "ps":
		i := strings.LastIndexByte(ref, '/')
		seq, _ := strconv.ParseInt(ref[i+1:], 10, 64)
		_, err := d.DB.Exec(ctx, `UPDATE topic_msgs SET hidden = $3 WHERE topic = $1 AND seq = $2`, ref[:i], seq, hide)
		return err
	}
	return nil
}

func moderateLine(target string, hide bool) string {
	if hide {
		return "ok hidden " + doc.SafeLine(target)
	}
	return "ok restored " + doc.SafeLine(target)
}
