package mem

import (
	"context"
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/scrub"
)

var (
	// sealedRe is a client-sealed value (26.4): stored opaque, no scan, never shared.
	sealedRe = regexp.MustCompile(`^seal([12]):([A-Za-z0-9_-]+)$`)
	tokenRe  = regexp.MustCompile(`cx_[A-Za-z0-9_-]{43}`)
	// refusedHazards are rejected on public checkpoints of L0 owners (4.5).
	refusedHazards = map[string]bool{"exec-remote": true, "obfuscated-exec": true}
)

// sealed reports whether a body or value is an opaque sealed value (one trailing newline allowed).
func sealed(s string) bool { return sealedRe.MatchString(strings.TrimSuffix(s, "\n")) }

// sealNonce returns "<scheme>:<nonce chars>" of a sealed value: 12 bytes (16 base64url chars) for
// seal1, the first 126 bits of the 16-byte nonce (21 whole chars) for seal2; "" when the value is
// too short to carry one.
func sealNonce(s string) string {
	m := sealedRe.FindStringSubmatch(strings.TrimSuffix(s, "\n"))
	if m == nil {
		return ""
	}
	n := 16
	if m[1] == "2" {
		n = 21
	}
	if len(m[2]) < n {
		return ""
	}
	return m[1] + ":" + m[2][:n]
}

// check is the write-path scrub (5): fields are normalised in place, a tier-1 finding rejects
// (`err scrub <kind> <field>@<off>`), tier-2 findings are masked and their kinds returned. A `cx_`
// token finding also runs the leak link (3.4) on leak (the request pool, so a rotation or
// revocation outlives the refused write); nil skips it (service calls).
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

// hazards classifies the concatenated texts (4.5).
func hazards(texts ...string) []string { return scrub.Hazards(strings.Join(texts, "\n")) }

// refusedHazard returns the first refused family in h, or "".
func refusedHazard(h []string) string {
	for _, f := range h {
		if refusedHazards[f] {
			return f
		}
	}
	return ""
}

// precond carries the HTTP preconditions of a cp or KV write (27.3): If-None-Match: * (create
// only) and If-Match: <rev> (replace that revision only).
type precond struct {
	ifMatch     *int64
	ifNoneMatch bool
}

var errBadIfMatch = core.Bad("If-Match must be a revision number")

// preconds parses the two headers; "*" on If-Match means "must exist".
func preconds(r *http.Request) (precond, error) {
	var p precond
	if v := strings.TrimSpace(r.Header.Get("If-None-Match")); v != "" {
		if v != "*" {
			return p, core.Bad("If-None-Match: * is the only supported form")
		}
		p.ifNoneMatch = true
	}
	if v := strings.TrimSpace(r.Header.Get("If-Match")); v != "" {
		if v == "*" {
			n := int64(-1)
			p.ifMatch = &n
			return p, nil
		}
		v = strings.Trim(strings.TrimPrefix(v, "W/"), `"`)
		n, err := strconv.ParseInt(v, 10, 64)
		if err != nil || n < 0 {
			return p, errBadIfMatch
		}
		p.ifMatch = &n
	}
	return p, nil
}

// check applies the preconditions to the current revision (0 when the object does not exist).
func (p precond) check(cur int64, exists bool) error {
	switch {
	case p.ifNoneMatch && exists:
		return core.E(412, "cas", "rev="+strconv.FormatInt(cur, 10))
	case p.ifMatch != nil && !exists, p.ifMatch != nil && *p.ifMatch >= 0 && *p.ifMatch != cur:
		return core.E(412, "cas", "rev="+strconv.FormatInt(cur, 10))
	}
	return nil
}

// isAPIErr reports whether err is an *core.APIError with the given code.
func isAPIErr(err error, code string) bool {
	var ae *core.APIError
	return errors.As(err, &ae) && ae.Code == code
}
