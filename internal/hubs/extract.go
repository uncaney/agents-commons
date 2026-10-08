package hubs

import (
	"regexp"
	"strings"
)

// Error-class extraction (SPEC-v2 27.1): the Go regex families the janitor runs over an entry's
// title to fill kb.err_class. Each family is tried in order; the first match that passes the
// validation shape wins, spaces folded to '-'. "exit status <n>" is never a class.

var (
	// errClassFamilies are the ordered extraction families of 27.1.
	errClassFamilies = []*regexp.Regexp{
		// Typed error/exception/warning/fault names at the head of the title.
		regexp.MustCompile(`^[A-Z][A-Za-z0-9_.]*(?:Error|Exception|Warning|Fault)\b`),
		// errno-style all-caps codes: ENOENT, ECONNREFUSED, EADDRINUSE…
		regexp.MustCompile(`\bE[A-Z]{4,}\b`),
		// compiler diagnostic codes: TS2345, CS1002, E0432, RUSTC…
		regexp.MustCompile(`\b(?:TS|CS|E|RUSTC)\d{3,5}\b`),
		// Oracle error codes.
		regexp.MustCompile(`\bORA-\d{5}\b`),
		// SQLSTATE class codes.
		regexp.MustCompile(`\bSQLSTATE \w{5}\b`),
	}
	// errClassOK is the validation shape every extracted class must satisfy (27.1).
	errClassOK = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{1,48}$`)
	// exitStatusRe matches the one phrasing 27.1 explicitly excludes.
	exitStatusRe = regexp.MustCompile(`(?i)\bexit status \d+`)
)

// ErrClass extracts the error class of a title for its /err/ hub, or "" when none of the families
// match (or the match fails the validation shape). The result is safe as a URL path segment and
// as a stored err_class value.
func ErrClass(title string) string {
	// "exit status 1" and friends are build-tool exit codes, never an error class.
	title = exitStatusRe.ReplaceAllString(title, " ")
	for _, re := range errClassFamilies {
		m := strings.ReplaceAll(re.FindString(title), " ", "-")
		if m != "" && errClassOK.MatchString(m) {
			return m
		}
	}
	return ""
}

// validClass reports whether a path-supplied class is well formed (the hub 404s otherwise).
func validClass(s string) bool { return errClassOK.MatchString(s) }
