// cx-cron: explain a 5-field cron expression and list its next runs from a given instant (no
// clock: "now" is an input, default 2026-01-01T00:00:00Z). Text protocol: the expression alone,
// or "<expr> | now=<RFC3339> n=<k> tz=<zone>". JSON form {"expr":"0 9 * * 1-5","now":"...",
// "n":3,"tz":"UTC"}. Output: the explanation line, then "- <RFC3339>" per run.
package main

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"
	_ "time/tzdata"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

type field struct {
	set  map[int]bool
	any  bool
	step int
}

var (
	months = map[string]int{"jan": 1, "feb": 2, "mar": 3, "apr": 4, "may": 5, "jun": 6, "jul": 7, "aug": 8, "sep": 9, "oct": 10, "nov": 11, "dec": 12}
	days   = map[string]int{"sun": 0, "mon": 1, "tue": 2, "wed": 3, "thu": 4, "fri": 5, "sat": 6}
	macros = map[string]string{"@yearly": "0 0 1 1 *", "@annually": "0 0 1 1 *", "@monthly": "0 0 1 * *", "@weekly": "0 0 * * 0", "@daily": "0 0 * * *", "@midnight": "0 0 * * *", "@hourly": "0 * * * *"}
	dayNm  = []string{"Sunday", "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday"}
	monNm  = []string{"", "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"}
)

func atom(s string, names map[string]int, lo, hi int) (int, error) {
	if n, ok := names[strings.ToLower(s)]; ok {
		return n, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < lo || n > hi {
		return 0, errors.New("value " + strconv.Quote(s) + " out of " + strconv.Itoa(lo) + ".." + strconv.Itoa(hi))
	}
	return n, nil
}

func parseField(s string, lo, hi int, names map[string]int) (field, error) {
	f := field{set: map[int]bool{}}
	parts := strings.Split(s, ",")
	for _, part := range parts {
		step := 1
		if base, st, ok := strings.Cut(part, "/"); ok {
			n, err := strconv.Atoi(st)
			if err != nil || n < 1 {
				return f, errors.New("bad step in " + strconv.Quote(part))
			}
			step, part = n, base
		}
		a, b := lo, hi
		switch {
		case part == "*" || part == "?":
			if step == 1 && len(parts) == 1 {
				f.any = true
			}
			f.step = step
		default:
			var err error
			if x, y, ok := strings.Cut(part, "-"); ok {
				if a, err = atom(x, names, lo, hi); err != nil {
					return f, err
				}
				if b, err = atom(y, names, lo, hi); err != nil {
					return f, err
				}
				if a > b {
					return f, errors.New("range " + strconv.Quote(part) + " reversed")
				}
			} else {
				if a, err = atom(part, names, lo, hi); err != nil {
					return f, err
				}
				if step == 1 {
					b = a
				}
			}
		}
		for i := a; i <= b; i += step {
			f.set[i] = true
		}
	}
	if hi == 7 && f.set[7] { // day-of-week: 7 is Sunday too
		delete(f.set, 7)
		f.set[0] = true
	}
	return f, nil
}

type spec struct{ min, hour, dom, mon, dow field }

func parse(expr string) (spec, error) {
	expr = strings.TrimSpace(expr)
	if m, ok := macros[strings.ToLower(expr)]; ok {
		expr = m
	}
	fs := strings.Fields(expr)
	if len(fs) != 5 {
		return spec{}, errors.New("need 5 fields (minute hour day-of-month month day-of-week), got " + strconv.Itoa(len(fs)))
	}
	var s spec
	var err error
	if s.min, err = parseField(fs[0], 0, 59, nil); err != nil {
		return s, err
	}
	if s.hour, err = parseField(fs[1], 0, 23, nil); err != nil {
		return s, err
	}
	if s.dom, err = parseField(fs[2], 1, 31, nil); err != nil {
		return s, err
	}
	if s.mon, err = parseField(fs[3], 1, 12, months); err != nil {
		return s, err
	}
	if s.dow, err = parseField(fs[4], 0, 7, days); err != nil {
		return s, err
	}
	return s, nil
}

func (s spec) matches(t time.Time) bool {
	if !s.min.set[t.Minute()] || !s.hour.set[t.Hour()] || !s.mon.set[int(t.Month())] {
		return false
	}
	dom, dow := s.dom.set[t.Day()], s.dow.set[int(t.Weekday())]
	switch { // vixie cron: both restricted -> OR
	case !s.dom.any && !s.dow.any:
		return dom || dow
	case !s.dom.any:
		return dom
	case !s.dow.any:
		return dow
	}
	return true
}

func (s spec) next(from time.Time, n int) []time.Time {
	t := from.Truncate(time.Minute).Add(time.Minute)
	var out []time.Time
	for i := 0; i < 366*24*60*5 && len(out) < n; i++ {
		if s.matches(t) {
			out = append(out, t)
		}
		t = t.Add(time.Minute)
	}
	return out
}

func sorted(set map[int]bool) []int {
	var ks []int
	for k := range set {
		ks = append(ks, k)
	}
	sort.Ints(ks)
	return ks
}

func list(vals []int, name func(int) string) string {
	parts := make([]string, len(vals))
	for i, v := range vals {
		parts[i] = name(v)
	}
	switch len(parts) {
	case 1:
		return parts[0]
	case 2:
		return parts[0] + " and " + parts[1]
	}
	return strings.Join(parts[:len(parts)-1], ", ") + " and " + parts[len(parts)-1]
}

func contiguous(vals []int) bool {
	for i := 1; i < len(vals); i++ {
		if vals[i] != vals[i-1]+1 {
			return false
		}
	}
	return len(vals) > 2
}

func pad2(n int) string {
	if n < 10 {
		return "0" + strconv.Itoa(n)
	}
	return strconv.Itoa(n)
}

// explain renders a crontab.guru-style sentence.
func (s spec) explain() string {
	var b strings.Builder
	mins, hours := sorted(s.min.set), sorted(s.hour.set)
	itoa := strconv.Itoa
	switch {
	case s.min.any && s.hour.any:
		b.WriteString("Every minute")
	case s.min.step > 1 && s.hour.any:
		b.WriteString("Every " + itoa(s.min.step) + " minutes")
	case s.hour.any && len(mins) == 1:
		b.WriteString("At minute " + itoa(mins[0]) + " past every hour")
	case s.hour.any:
		b.WriteString("At minutes " + list(mins, itoa) + " past every hour")
	case s.min.any:
		b.WriteString("Every minute past hour " + list(hours, itoa))
	case s.hour.step > 1 && len(mins) == 1:
		b.WriteString("At minute " + itoa(mins[0]) + " past every " + itoa(s.hour.step) + " hours")
	case len(mins) == 1 && len(hours) == 1:
		b.WriteString("At " + pad2(hours[0]) + ":" + pad2(mins[0]))
	case len(mins) == 1:
		b.WriteString("At minute " + itoa(mins[0]) + " past hour " + list(hours, itoa))
	default:
		b.WriteString("At minutes " + list(mins, itoa) + " past hour " + list(hours, itoa))
	}
	if !s.dom.any {
		b.WriteString(" on day-of-month " + list(sorted(s.dom.set), itoa))
	}
	if !s.dow.any {
		d := sorted(s.dow.set)
		join := " on "
		if !s.dom.any {
			join = " and on "
		}
		if contiguous(d) {
			b.WriteString(join + dayNm[d[0]] + " through " + dayNm[d[len(d)-1]])
		} else {
			b.WriteString(join + list(d, func(i int) string { return dayNm[i] }))
		}
	}
	if !s.mon.any {
		b.WriteString(" in " + list(sorted(s.mon.set), func(i int) string { return monNm[i] }))
	}
	return b.String()
}

func main() {
	in := sio.Read()
	expr, now, tz, n := "", "2026-01-01T00:00:00Z", "UTC", 3
	if m, ok := sio.Object(in); ok {
		expr = sio.Str(m, "expr")
		if v := sio.Str(m, "now"); v != "" {
			now = v
		}
		if v := sio.Str(m, "tz"); v != "" {
			tz = v
		}
		if v := int(sio.Num(m, "n", 0)); v > 0 {
			n = v
		}
	} else {
		line, _ := sio.Line(in)
		var opts string
		expr, opts, _ = strings.Cut(line, "|")
		for _, o := range strings.Fields(opts) {
			k, v, _ := strings.Cut(o, "=")
			switch k {
			case "now":
				now = v
			case "tz":
				tz = v
			case "n":
				n, _ = strconv.Atoi(v)
			}
		}
	}
	if n < 1 || n > 20 {
		n = 3
	}
	s, err := parse(expr)
	if err != nil {
		sio.Fail(err.Error())
	}
	loc, err := time.LoadLocation(tz)
	if err != nil {
		sio.Fail("unknown zone " + strconv.Quote(tz))
	}
	from, err := time.Parse(time.RFC3339, strings.TrimSpace(now))
	if err != nil {
		sio.Fail("now must be RFC 3339")
	}
	sio.Outln(s.explain())
	for _, t := range s.next(from.In(loc), n) {
		sio.Outln("- " + t.Format(time.RFC3339))
	}
}
