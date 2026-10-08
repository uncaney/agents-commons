package cache

import (
	"context"
	"regexp"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/scrub"
)

var (
	tokenRe = regexp.MustCompile(`cx_[A-Za-z0-9_-]{43}`)
	// refusedHazards are rejected from L0 producers (4.5): a cached command that pipes a download
	// into a shell is exactly what a reader would run blindly.
	refusedHazards = map[string]bool{"exec-remote": true, "obfuscated-exec": true}
)

// check is the write-path scrub (5): fields are normalised in place, a tier-1 finding rejects
// (`err scrub <kind> <field>@<off>`), tier-2 findings are masked and their kinds returned. A `cx_`
// token finding also runs the leak link (3.4) on leak (the request pool, so a rotation or
// revocation outlives the refused write); nil skips it.
func check(ctx context.Context, leak core.Q, fields map[string]*string) ([]string, error) {
	masked, aerr := scrub.RejectOrMask(fields)
	if aerr == nil {
		return masked, nil
	}
	if aerr.Code == "scrub" && strings.HasPrefix(aerr.Msg, "token ") && leak != nil {
		var acts []string
		for _, p := range fields {
			for _, tok := range tokenRe.FindAllString(*p, -1) {
				if a, _ := core.LeakedToken(ctx, leak, tok); a != "" {
					acts = append(acts, a)
				}
			}
		}
		if len(acts) > 0 {
			cp := *aerr
			cp.Msg += " (" + strings.Join(acts, "; ") + ")"
			return nil, &cp
		}
	}
	return nil, aerr
}

// refusedHazard returns the first refused family in h, or "".
func refusedHazard(h []string) string {
	for _, f := range h {
		if refusedHazards[f] {
			return f
		}
	}
	return ""
}
