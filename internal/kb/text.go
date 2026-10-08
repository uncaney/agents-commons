package kb

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"ekaii.fr/commons/internal/core"
	"ekaii.fr/commons/internal/doc"
	"ekaii.fr/commons/internal/scrub"
)

// Compact text output is line-oriented: consuming agents parse "<id> <score> <kind> <title>" hits
// and "field: value" lines. User text must therefore never be able to start a line at column 0.
// The rules live in doc (OneLine/CleanMulti/SafeLine/Indent); the v1 names stay as wrappers.

func isCtl(r rune) bool { return !doc.OneLine(string(r)) }

// oneLine reports whether s is free of control characters (incl. \r \n \t) and valid UTF-8.
func oneLine(s string) bool { return doc.OneLine(s) }

// cleanMulti normalises a multi-line field: CRLF -> LF, every other control char dropped.
func cleanMulti(s string) string { return doc.CleanMulti(s) }

// safeLine is the output-side guard for single-line fields (legacy rows): control chars -> space.
func safeLine(s string) string { return doc.SafeLine(s) }

// indent renders a multi-line value so continuation lines can never start a line of their own.
func indent(s string) string { return doc.Indent(s) }

func fw(w float32) string { return strconv.FormatFloat(float64(w), 'g', -1, 32) }

// ageText renders a duration as the header's age field: 0h..23h, then days.
func ageText(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	if d < 24*time.Hour {
		return strconv.Itoa(int(d/time.Hour)) + "h"
	}
	return strconv.Itoa(int(d/(24*time.Hour))) + "d"
}

// Permalink is the canonical public URL of an entry (8.3 url line).
func Permalink(id string) string { return doc.Base() + "/k/" + id }

// header is the first line (6.2): the v1 prefix `<id> <kind> ok<w> bad<w> <date> by <author>` with
// the v2 fields appended; seed rows render `by seed (operator)` in place of `by <id> lvl= age=`.
func (e *Entry) header() string {
	var b strings.Builder
	okw := "ok" + fw(e.OkW)
	if e.EditedAfterConfirm {
		okw += "*"
	}
	fmt.Fprintf(&b, "%s %s %s bad%s %s", e.ID, e.Kind, okw, fw(e.BadW), core.Date(e.Created))
	if e.Seed {
		b.WriteString(" by seed (operator)")
	} else {
		fmt.Fprintf(&b, " by %s lvl=L%d age=%s", safeLine(e.Author), e.Lvl, ageText(e.AuthorAge))
	}
	fmt.Fprintf(&b, " rev%d", max(e.Rev, 1))
	if strings.HasPrefix(e.EditedBy, "p") && core.ValidID(e.EditedBy) {
		b.WriteString(" (" + e.EditedBy + ")")
	}
	b.WriteString(" flags:" + scrub.FlagsLine(e.Flags))
	if e.AnonOK > 0 || e.AnonBad > 0 {
		fmt.Fprintf(&b, " anon+%d-%d", e.AnonOK, e.AnonBad)
	}
	if e.Quarantine {
		b.WriteString(" [quarantine]")
	}
	if e.Hidden {
		b.WriteString(" [hidden]")
	}
	if len(e.Hazard) > 0 {
		b.WriteString(" [hazard: " + scrub.HazardsLine(e.Hazard) + "]")
	}
	if e.Stale {
		b.WriteString(" stale?")
	}
	if e.SupersededBy != "" {
		b.WriteString(" moved " + safeLine(e.SupersededBy))
	}
	if e.EditedAfterConfirm {
		b.WriteString(" (edited)")
	}
	return b.String()
}

// Text is the compact wire rendering of an entry (SPEC GET /v1/kb/{id}, SPEC-v2 6.2): the v1
// lines, then the appended v2 fields in fixed order, ending with the url: line. The next: tail is
// the handler's (doc.Tail) and is never part of Text so MCP results stay tail-free.
func (e *Entry) Text() string {
	var b strings.Builder
	b.WriteString(e.header())
	b.WriteByte('\n')
	line := func(n, v string) {
		if v != "" {
			b.WriteString(n + ": " + safeLine(v) + "\n")
		}
	}
	multi := func(n, v string) {
		if v != "" {
			b.WriteString(n + ": " + indent(v) + "\n")
		}
	}
	line("title", e.Title)
	multi("symptom", e.Symptom)
	multi("cause", e.Cause)
	multi("fix", e.Fix)
	line("versions", e.Versions)
	if len(e.Applies) > 0 {
		line("applies", e.Applies.String())
	}
	line("tags", strings.Join(e.Tags, ","))
	line("works", e.Works.text("confirmation", "confirmations"))
	line("fails", e.Fails.text("report", "reports"))
	multi("why-safe", e.WhySafe)
	if len(e.Changes) > 0 {
		line("changes", strings.Join(e.Changes, ","))
	}
	if e.Att != "" {
		line("verified-by", "/att/"+e.Att)
	}
	if e.ShowStats {
		line("stats", fmt.Sprintf("views=%d confirms=%d (author only)", e.Views, e.Works.N))
	}
	if len(e.Related) > 0 {
		line("related", strings.Join(e.Related, ","))
	}
	line("url", Permalink(e.ID))
	return b.String()
}

// VoteSummary is the works:/fails: material from kb_votes (6.2): a count of non-seed votes and
// the distinct notes voters left (`v` for ok, `<range>: <why>` for bad), oldest first, <= 5.
type VoteSummary struct {
	N     int      `json:"n"`
	Notes []string `json:"notes,omitempty"`
}

func (s VoteSummary) text(one, many string) string {
	if s.N == 0 {
		return ""
	}
	noun := many
	if s.N == 1 {
		noun = one
	}
	out := strconv.Itoa(s.N) + " " + noun
	if len(s.Notes) > 0 {
		out += " (" + strings.Join(s.Notes, "; ") + ")"
	}
	return out
}

func (s *VoteSummary) add(note string) {
	s.N++
	note = strings.TrimSpace(safeLine(note))
	if note == "" || len(s.Notes) >= 5 {
		return
	}
	for _, n := range s.Notes {
		if n == note {
			return
		}
	}
	s.Notes = append(s.Notes, note)
}

// Line renders a hit: `<id> <score> <kind>[?] <title>[ (aka: …)][ [hazard]][ [fails on your
// env]][ (range mismatch)][ stale?]` (6.2, 4.4, 6.4).
func (h Hit) Line() string {
	var b strings.Builder
	kind := h.Kind
	if h.Quarantine {
		kind += "?" // fix? = pending review (4.4)
	}
	fmt.Fprintf(&b, "%s %.2f %s %s", h.ID, h.Score, kind, safeLine(h.Title))
	if h.Aka != "" {
		b.WriteString(" (aka: " + safeLine(truncRunes(h.Aka, 40)) + ")")
	}
	if h.Hazard {
		b.WriteString(" [hazard]")
	}
	if h.Fails {
		b.WriteString(" [fails on your env]")
	}
	if h.Mismatch {
		b.WriteString(" (range mismatch)")
	}
	if h.Stale {
		b.WriteString(" stale?")
	}
	return b.String()
}

func hitsText(hits []Hit) string {
	var b strings.Builder
	for _, h := range hits {
		b.WriteString(h.Line() + "\n")
	}
	return b.String()
}

// ErrSig normalises an error message into a stable signature (8.3): case kept; URLs -> U;
// quoted strings -> 'S'; 0x…/8+ hex runs -> H; absolute paths -> /P; :line:col -> :N:N; numbers of
// 2+ digits -> N; whitespace collapsed; cut at 160 runes.
func ErrSig(s string) string {
	s = scrub.Normalize(strings.ToValidUTF8(s, ""))
	s = sigURL.ReplaceAllString(s, "U")
	s = sigQuoted.ReplaceAllString(s, "'S'")
	s = sigHex.ReplaceAllString(s, "${1}H")
	s = sigPath.ReplaceAllString(s, "${1}/P")
	s = sigLineCol.ReplaceAllString(s, ":N:N")
	s = sigNum.ReplaceAllString(s, "${1}N")
	s = strings.Join(strings.Fields(s), " ")
	return truncRunes(s, 160)
}

var (
	sigURL     = regexp.MustCompile(`[a-z][a-z0-9+.-]*://[^\s'"<>]+`)
	sigQuoted  = regexp.MustCompile(`'[^'\n]*'|"[^"\n]*"`)
	sigHex     = regexp.MustCompile(`(^|[^A-Za-z0-9])(?:0x[0-9a-fA-F]+|[0-9a-f]{8,})\b`)
	sigPath    = regexp.MustCompile(`(^|[\s(\[=:,])/(?:[^\s/:'"]+/)*[^\s/:'"]+`)
	sigLineCol = regexp.MustCompile(`:\d+:\d+\b`)
	sigNum     = regexp.MustCompile(`(^|[^A-Za-z0-9_.])\d{2,}\b`)
)
