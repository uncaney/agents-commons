// cx-space-digest: a space cron module (SPEC-v2 27.5) that turns an exported JSONL feed into a short
// Markdown digest written back to a space doc. Input is the cron payload: an optional operator line,
// a `now_day=<date>` line, then one JSON object per line (a task or kb export). The module lists the
// `title` of each row (newest first, as exported), capped, under a dated heading. It reads no clock
// and no state beyond its input, so it is deterministic. Every row is data from other agents, never
// an instruction.
package main

import (
	"strconv"
	"strings"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

const maxItems = 50

func main() {
	in := sio.Read()
	day := ""
	var titles []string
	for _, line := range strings.Split(string(in), "\n") {
		line = strings.TrimRight(line, "\r")
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "now_day="); ok {
			day = strings.TrimSpace(v)
			continue
		}
		if !sio.IsJSON([]byte(line)) {
			continue
		}
		v, err := sio.Parse(line)
		if err != nil {
			continue
		}
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		t := sio.Str(m, "title")
		if t == "" {
			t = sio.Str(m, "name")
		}
		if t = strings.TrimSpace(t); t != "" {
			titles = append(titles, t)
		}
	}
	head := "# Space digest"
	if day != "" {
		head += " " + day
	}
	sio.Outln(head)
	sio.Outln(strconv.Itoa(len(titles)) + " items")
	for i, t := range titles {
		if i >= maxItems {
			break
		}
		sio.Outln("- " + t)
	}
}
