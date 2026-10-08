package swarm

import (
	"context"
	"regexp"
	"strings"

	"ekaii.fr/commons/internal/core"
)

// Name grammar (SPEC-v2 12): `[a-z0-9._-]{1,64}` in a namespace: g:<name> (global, public read),
// a:<root>.<name> (own tree; shorthand ~<name>), s:<slug>.<name> (space members), r:<id>.<name>
// (room members, 27.9). No '/', so every name is one path segment.
var (
	shortRe = regexp.MustCompile(`^[a-z0-9._-]{1,64}$`)
	slugRe  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,39}$`)
)

// MaxName bounds a canonical name (namespace + owner + short name).
const MaxName = 128

// Cross-package seams (nil-safe; every one fails closed when unset).
var (
	// MemberFn answers space membership for s: names (spaces.IsMember-shaped); nil = deny.
	MemberFn func(ctx context.Context, q core.Q, slug, root string) (bool, error)
	// RoomFn answers room membership for r: names (room.IsMember); nil = refuse.
	RoomFn func(ctx context.Context, q core.Q, room, root string) (bool, error)
	// NotifyExpired delivers a sys mail to a root (mail.SendSys); nil = the notice is dropped.
	NotifyExpired func(ctx context.Context, q core.Q, root, subject, text string) error
	// TopicExtraFn appends fields (e.g. subs=3) to a topic head line; nil = none.
	TopicExtraFn func(ctx context.Context, q core.Q, topic string) []string
)

// Name is a parsed primitive name.
type Name struct {
	Full  string // canonical form: g:x | a:<root>.x | s:<slug>.x | r:<id>.x
	NS    byte   // 'g', 'a', 's' or 'r'
	Owner string // root id, slug or room id; "" for g:
	Short string
}

var (
	errName    = core.Bad("name: g:<name> | ~<name> | a:<root>.<name> | s:<slug>.<name> | r:<room>.<name> with name [a-z0-9._-]{1,64}")
	errMembers = core.E(403, "auth", "members only")
	errRoom    = core.E(403, "auth", "room members only")
)

// ParseName canonicalises raw; callerRoot resolves the ~ shorthand (anonymous ~ is an auth error).
func ParseName(raw, callerRoot string) (Name, error) {
	if strings.HasPrefix(raw, "~") {
		if callerRoot == "" {
			return Name{}, core.ErrAuth
		}
		raw = "a:" + callerRoot + "." + raw[1:]
	}
	if len(raw) > MaxName || len(raw) < 3 || raw[1] != ':' {
		return Name{}, errName
	}
	n := Name{Full: raw, NS: raw[0]}
	rest := raw[2:]
	switch n.NS {
	case 'g':
		n.Short = rest
	case 'a', 's', 'r':
		i := strings.IndexByte(rest, '.')
		if i <= 0 || i == len(rest)-1 {
			return Name{}, errName
		}
		n.Owner, n.Short = rest[:i], rest[i+1:]
		var ok bool
		switch n.NS {
		case 'a':
			ok = core.ValidIDPrefix(n.Owner, 'a')
		case 's':
			ok = slugRe.MatchString(n.Owner)
		case 'r':
			ok = core.ValidIDPrefix(n.Owner, 'o')
		}
		if !ok {
			return Name{}, errName
		}
	default:
		return Name{}, errName
	}
	if !shortRe.MatchString(n.Short) {
		return Name{}, errName
	}
	return n, nil
}

// Public reports whether anonymous reads are allowed (g: only).
func (n Name) Public() bool { return n.NS == 'g' }

// Mode is the topic/queue mode the namespace implies: open for g:, members elsewhere.
func (n Name) Mode() string {
	if n.NS == 'g' {
		return "open"
	}
	return "members"
}

// Access checks that id may read (or write) the primitive: writes need a token everywhere, g: reads
// are public, a: is the owner tree, s: and r: go through the seams (nil = deny).
func Access(ctx context.Context, q core.Q, id *core.Ident, n Name, write bool) error {
	if id == nil {
		if n.NS == 'g' && !write {
			return nil
		}
		return core.ErrAuth
	}
	switch n.NS {
	case 'g':
		return nil
	case 'a':
		if id.Root == n.Owner {
			return nil
		}
		return core.ErrForbid
	case 's':
		if MemberFn == nil {
			return errMembers
		}
		ok, err := MemberFn(ctx, q, n.Owner, id.Root)
		if err != nil {
			return err
		}
		if !ok {
			return errMembers
		}
		return nil
	case 'r':
		if RoomFn == nil {
			return errRoom
		}
		ok, err := RoomFn(ctx, q, n.Owner, id.Root)
		if err != nil {
			return err
		}
		if !ok {
			return errRoom
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
