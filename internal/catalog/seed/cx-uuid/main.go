// cx-uuid: UUID checks and deterministic generation. Text protocol, one command:
//
//	check <uuid>               -> "valid version=4 variant=rfc4122" | "invalid <reason>"
//	v4 <seed...>               -> a v4-shaped UUID derived from sha256(seed) (deterministic)
//	v5 <namespace> <name...>   -> RFC 4122 v5 (SHA-1); namespace dns|url|oid|x500 or a UUID
//	v3 <namespace> <name...>   -> RFC 4122 v3 (MD5)
//	nil                        -> 00000000-0000-0000-0000-000000000000
//
// JSON form: {"op":"v5","args":["dns","example.com"]}.
package main

import (
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

var namespaces = map[string]string{
	"dns":  "6ba7b810-9dad-11d1-80b4-00c04fd430c8",
	"url":  "6ba7b811-9dad-11d1-80b4-00c04fd430c8",
	"oid":  "6ba7b812-9dad-11d1-80b4-00c04fd430c8",
	"x500": "6ba7b814-9dad-11d1-80b4-00c04fd430c8",
}

// parse accepts 8-4-4-4-12 hex groups (dashes optional, braces allowed).
func parse(s string) ([16]byte, bool) {
	var u [16]byte
	s = strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(s), "{"), "}")
	if strings.Count(s, "-") == 4 {
		parts := strings.Split(s, "-")
		if len(parts[0]) != 8 || len(parts[1]) != 4 || len(parts[2]) != 4 || len(parts[3]) != 4 || len(parts[4]) != 12 {
			return u, false
		}
		s = strings.Join(parts, "")
	}
	if len(s) != 32 {
		return u, false
	}
	b, err := hex.DecodeString(strings.ToLower(s))
	if err != nil {
		return u, false
	}
	copy(u[:], b)
	return u, true
}

func format(u [16]byte) string {
	h := hex.EncodeToString(u[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

func stamp(u []byte, version byte) [16]byte {
	var out [16]byte
	copy(out[:], u[:16])
	out[6] = (out[6] & 0x0f) | (version << 4)
	out[8] = (out[8] & 0x3f) | 0x80
	return out
}

func variant(u [16]byte) string {
	switch {
	case u[8]&0x80 == 0:
		return "ncs"
	case u[8]&0xc0 == 0x80:
		return "rfc4122"
	case u[8]&0xe0 == 0xc0:
		return "microsoft"
	}
	return "future"
}

func namespace(s string) [16]byte {
	if ns, ok := namespaces[strings.ToLower(s)]; ok {
		u, _ := parse(ns)
		return u
	}
	u, ok := parse(s)
	if !ok {
		sio.Fail("namespace must be dns|url|oid|x500 or a UUID")
	}
	return u
}

func main() {
	in := sio.Read()
	var op string
	var args []string
	if m, ok := sio.Object(in); ok {
		op, args = sio.Str(m, "op"), sio.Strs(m, "args")
	} else {
		line, _ := sio.Line(in)
		f := strings.Fields(line)
		if len(f) == 0 {
			sio.Fail("usage: check <uuid> | v4 <seed> | v5 <ns> <name> | v3 <ns> <name> | nil")
		}
		op, args = f[0], f[1:]
	}
	switch op {
	case "check":
		if len(args) != 1 {
			sio.Fail("check needs one uuid")
		}
		u, ok := parse(args[0])
		if !ok {
			sio.Outln("invalid not 32 hex digits in 8-4-4-4-12 groups")
			return
		}
		ver := u[6] >> 4
		if u == [16]byte{} {
			sio.Outln("valid nil")
			return
		}
		if ver < 1 || ver > 8 {
			sio.Outln("invalid version nibble " + strconv.FormatUint(uint64(ver), 16))
			return
		}
		sio.Outln("valid version=" + strconv.Itoa(int(ver)) + " variant=" + variant(u))
	case "v4":
		seed := strings.Join(args, " ")
		if seed == "" {
			sio.Fail("v4 needs a seed (deterministic sandbox: no randomness)")
		}
		h := sha256.Sum256([]byte("cx-uuid-v4\x00" + seed))
		sio.Outln(format(stamp(h[:], 4)))
	case "v5", "v3":
		if len(args) < 2 {
			sio.Fail(op + " needs a namespace and a name")
		}
		ns := namespace(args[0])
		name := strings.Join(args[1:], " ")
		if op == "v5" {
			h := sha1.Sum(append(ns[:], name...))
			sio.Outln(format(stamp(h[:], 5)))
		} else {
			h := md5.Sum(append(ns[:], name...))
			sio.Outln(format(stamp(h[:], 3)))
		}
	case "nil":
		sio.Outln(format([16]byte{}))
	default:
		sio.Fail("unknown command " + strconv.Quote(op))
	}
}
