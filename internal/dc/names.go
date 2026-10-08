package dc

import (
	"context"
	"regexp"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// Name grammar (SPEC-v2 12): `[a-z0-9._-]{1,64}` in a namespace: g:<name> (global, public read),
// a:<root>.<name> (own tree; shorthand ~<name>), s:<slug>.<name> (space members). No '/', so
// every name is one path segment. dc does not import swarm; the grammar is restated here.
var (
	shortRe = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	slugRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
)

const maxName = 128

// MemberFn answers space membership for s: names (spaces.IsMember-shaped, the same shape as
// swarm.MemberFn); nil = deny.
var MemberFn func(ctx context.Context, q core.Q, slug, root string) (bool, error)

type name struct {
	full  string // canonical form: g:x | a:<root>.x | s:<slug>.x
	ns    byte
	owner string // root id or slug; "" for g:
	short string
}

var (
	errName    = core.Bad("name: g:<name> | ~<name> | a:<root>.<name> | s:<slug>.<name> with name [a-z0-9._-]{1,64}")
	errMembers = core.E(403, "auth", "members only")
)

// parseName canonicalises raw; callerRoot resolves the ~ shorthand (anonymous ~ is an auth error).
func parseName(raw, callerRoot string) (name, error) {
	if strings.HasPrefix(raw, "~") {
		if callerRoot == "" {
			return name{}, core.ErrAuth
		}
		raw = "a:" + callerRoot + "." + raw[1:]
	}
	if len(raw) > maxName || len(raw) < 3 || raw[1] != ':' {
		return name{}, errName
	}
	n := name{full: raw, ns: raw[0]}
	rest := raw[2:]
	switch n.ns {
	case 'g':
		n.short = rest
	case 'a', 's':
		i := strings.IndexByte(rest, '.')
		if i <= 0 || i == len(rest)-1 {
			return name{}, errName
		}
		n.owner, n.short = rest[:i], rest[i+1:]
		ok := slugRe.MatchString(n.owner)
		if n.ns == 'a' {
			ok = core.ValidIDPrefix(n.owner, 'a')
		}
		if !ok {
			return name{}, errName
		}
	default:
		return name{}, errName
	}
	if !shortRe.MatchString(n.short) {
		return name{}, errName
	}
	return n, nil
}

// access checks that id may read (or write) the decision: writes need a token everywhere, g:
// reads are public, a: is the owner tree, s: goes through MemberFn (nil = deny).
func access(ctx context.Context, q core.Q, id *core.Ident, n name, write bool) error {
	if id == nil {
		if n.ns == 'g' && !write {
			return nil
		}
		return core.ErrAuth
	}
	switch n.ns {
	case 'g':
		return nil
	case 'a':
		if id.Root == n.owner {
			return nil
		}
		return core.ErrForbid
	case 's':
		if MemberFn == nil {
			return errMembers
		}
		ok, err := MemberFn(ctx, q, n.owner, id.Root)
		if err != nil {
			return err
		}
		if !ok {
			return errMembers
		}
		return nil
	}
	return errName
}

// rootOf is the caller's root or "" for anonymous requests.
func rootOf(id *core.Ident) string {
	if id == nil {
		return ""
	}
	return id.Root
}
