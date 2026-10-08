// cx-tz: time zone conversion with the embedded tz database (no clock: the time is an input).
// Text protocol: "<time> <to-zone>" or "<time> <from-zone> <to-zone>"; JSON form
// {"time":"2026-10-07T12:00:00Z","from":"UTC","to":"Europe/Paris"}. Accepted times: RFC 3339,
// "2006-01-02 15:04[:05]", "2006-01-02T15:04", "2006-01-02", unix seconds. Output:
//
//	2026-10-07T14:00:00+02:00 CEST offset=+02:00 dst=true zone=Europe/Paris
//	unix=1791374400 utc=2026-10-07T12:00:00Z weekday=Wednesday
package main

import (
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

var layouts = []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05", "2006-01-02 15:04:05", "2006-01-02T15:04", "2006-01-02 15:04", "2006-01-02"}

func parseTime(s string, loc *time.Location) (time.Time, bool) {
	s = strings.TrimSpace(s)
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		return time.Unix(n, 0).UTC(), true
	}
	for _, l := range layouts {
		if t, err := time.ParseInLocation(l, s, loc); err == nil {
			return t, true
		}
	}
	return time.Time{}, false
}

func zone(name string) *time.Location {
	switch strings.ToLower(name) {
	case "", "utc", "z":
		return time.UTC
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		sio.Fail("unknown zone " + strconv.Quote(name) + " (IANA names such as Europe/Paris)")
	}
	return loc
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

func main() {
	in := sio.Read()
	var ts, from, to string
	if m, ok := sio.Object(in); ok {
		ts, from, to = sio.Str(m, "time"), sio.Str(m, "from"), sio.Str(m, "to")
	} else {
		line, _ := sio.Line(in)
		f := strings.Fields(line)
		switch len(f) {
		case 2:
			ts, to = f[0], f[1]
		case 3:
			ts, from, to = f[0], f[1], f[2]
		case 4: // "2026-10-07 12:00 Europe/Paris Asia/Tokyo" style
			ts, from, to = f[0]+" "+f[1], f[2], f[3]
		default:
			sio.Fail("usage: <time> [from-zone] <to-zone>")
		}
	}
	t, ok := parseTime(ts, zone(from))
	if !ok {
		sio.Fail("cannot parse time " + strconv.Quote(ts))
	}
	loc := zone(to)
	out := t.In(loc)
	abbr, off := out.Zone()
	sign := "+"
	if off < 0 {
		sign, off = "-", -off
	}
	sio.Outln(out.Format(time.RFC3339) + " " + abbr + " offset=" + sign + pad2(off/3600) + ":" + pad2(off%3600/60) + " dst=" + strconv.FormatBool(out.IsDST()) + " zone=" + loc.String())
	sio.Outln("unix=" + strconv.FormatInt(t.Unix(), 10) + " utc=" + t.UTC().Format(time.RFC3339) + " weekday=" + out.Weekday().String())
}
