package drop

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/jackc/pgx/v5"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/scrub"
)

var (
	// sealedRe is an opaque client-sealed body (SPEC-v2 26.1 D10, 26.4): stored as is, no scan.
	sealedRe = regexp.MustCompile(`^(?:cxs1|seal[12]):[A-Za-z0-9_-]+\n?$`)
	tokenRe  = regexp.MustCompile(`cx_[A-Za-z0-9_-]{43}`)
)

// refusedHazards are rejected from anonymous and L0 writers (4.5).
var refusedHazards = map[string]bool{"exec-remote": true, "obfuscated-exec": true}

// sealed reports whether a body is an opaque sealed value.
func sealed(text string) bool { return sealedRe.MatchString(text) }

// check runs the drop write order on an already normalised body: tier 1 rejects unless every secret
// in the finding is a cx_ token of an identity below the writer (subkey handoff), tier 2 masks in
// place, hazards refuse exec-remote/obfuscated-exec from anonymous and L0 writers. Returns the number
// of masked findings. tx is the write transaction (rolled back on rejection); the leak link (3.4)
// runs on the pool so a rotation or revocation outlives the refused write.
func (s *svc) check(ctx context.Context, tx core.Q, text *string, writer *core.Ident, level int) (int, error) {
	if sealed(*text) {
		return 0, nil
	}
	fs := scrub.Scan("body", *text)
	var masks []scrub.Finding
	for _, f := range fs {
		if f.Tier != 1 {
			masks = append(masks, f)
			continue
		}
		span := (*text)[f.Off : f.Off+f.Len]
		toks := tokenRe.FindAllString(span, -1)
		if len(toks) == 0 {
			return 0, core.E(400, "scrub", fmt.Sprintf("%s body@%d", f.Kind, f.Off))
		}
		for _, tok := range toks {
			ok, err := handoff(ctx, tx, writer, tok)
			if err != nil {
				return 0, err
			}
			if ok {
				continue
			}
			msg := fmt.Sprintf("%s body@%d", f.Kind, f.Off)
			if action, _ := core.LeakedToken(ctx, s.d.DB, tok); action != "" {
				msg += " (" + action + ")"
			}
			return 0, core.E(400, "scrub", msg)
		}
	}
	if len(masks) > 0 {
		*text = mask(*text, masks)
	}
	if writer == nil || level <= 0 {
		for _, h := range scrub.Hazards(*text) {
			if refusedHazards[h] {
				return 0, core.E(400, "hazard", h)
			}
		}
	}
	return len(masks), nil
}

// handoff: tok is the live or revoked token of an identity strictly below the writer's identity.
func handoff(ctx context.Context, q core.Q, writer *core.Ident, tok string) (bool, error) {
	if writer == nil {
		return false, nil
	}
	var id string
	err := q.QueryRow(ctx, `SELECT id FROM identities WHERE token_hash = $1`, core.HashToken(tok)).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if id == writer.ID {
		return false, nil
	}
	return core.IsAncestor(ctx, q, writer.ID, id)
}

// mask replaces tier-2 spans with scrub's placeholders (findings are non-overlapping, any order).
func mask(text string, fs []scrub.Finding) string {
	sort.Slice(fs, func(i, j int) bool { return fs[i].Off > fs[j].Off })
	for _, f := range fs {
		text = text[:f.Off] + placeholder(f.Kind) + text[f.Off+f.Len:]
	}
	return text
}

func placeholder(kind string) string {
	switch kind {
	case "path":
		return "/<user>"
	case "arn":
		return "<acct>"
	}
	return "<" + strings.ToLower(kind) + ">"
}
