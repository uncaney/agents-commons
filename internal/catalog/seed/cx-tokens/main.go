// cx-tokens: deterministic token-count estimate for LLM budgeting. Input: the text (or
// {"text":"..."}). Output: one line
//
//	tokens=~N chars=N words=N lines=N bytes=N method=heuristic-v1
//
// The heuristic counts ~1 token per 4 letters of a word (minimum 1), one per digit group of up
// to 3 digits, one per punctuation or symbol character, and ignores whitespace except newlines
// (1 each). It is model-agnostic and within about 15 % of BPE tokenizers on English and code.
package main

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"ekaii.fr/commons/internal/catalog/seed/sio"
)

func estimate(s string) (tokens, words, lines int) {
	runLetters, runDigits := 0, 0
	flush := func() {
		if runLetters > 0 {
			tokens += (runLetters + 3) / 4
			words++
			runLetters = 0
		}
		if runDigits > 0 {
			tokens += (runDigits + 2) / 3
			words++
			runDigits = 0
		}
	}
	for _, r := range s {
		switch {
		case unicode.IsLetter(r) || r == '\'' || r == '_':
			if runDigits > 0 {
				flush()
			}
			if r > 0x2FF { // non-Latin scripts tokenise closer to one token per character
				flush()
				tokens++
				words++
				continue
			}
			runLetters++
		case unicode.IsDigit(r):
			if runLetters > 0 {
				flush()
			}
			runDigits++
		case r == '\n':
			flush()
			lines++
			tokens++
		case unicode.IsSpace(r):
			flush()
		default:
			flush()
			tokens++
		}
	}
	flush()
	if len(s) > 0 && !strings.HasSuffix(s, "\n") {
		lines++
	}
	return
}

func main() {
	in := sio.Read()
	text := string(in)
	if m, ok := sio.Object(in); ok {
		text = sio.Str(m, "text")
	}
	tokens, words, lines := estimate(text)
	sio.Outln("tokens=~" + strconv.Itoa(tokens) + " chars=" + strconv.Itoa(utf8.RuneCountInString(text)) + " words=" + strconv.Itoa(words) +
		" lines=" + strconv.Itoa(lines) + " bytes=" + strconv.Itoa(len(text)) + " method=heuristic-v1")
}
