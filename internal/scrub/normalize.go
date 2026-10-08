// Package scrub is the secret/PII detector, hazard classifier and injection lexicon every write
// decoder runs after normalisation (SPEC-v2 sections 4.5, 4.6 and 5). Everything here is a pure
// function over text; the HTTP/MCP surface in http.go only wraps them.
package scrub

import (
	"strings"
	"unicode/utf8"
)

// Normalize returns the text to store: valid UTF-8, compatibility forms folded to ASCII (an
// NFKC-lite table: fullwidth, mathematical and enclosed alphanumerics, ligatures, super/subscripts,
// exotic spaces) and invisible code points removed (zero-width, bidi controls, tags, variation
// selectors, soft hyphen). Every detector runs on its output, never on the raw input.
func Normalize(s string) string {
	if ascii(s) {
		return s
	}
	out, _ := fold(strings.ToValidUTF8(s, ""), false, false)
	return out
}

func ascii(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// prepare is the scan-side copy of a text: Normalize plus every confusable letter folded to its
// Latin look-alike, with back[i] = byte offset in text of out[i] so spans map back onto text.
// nil back means out == text.
func prepare(text string) (string, []int) {
	if ascii(text) {
		return text, nil
	}
	return fold(strings.ToValidUTF8(text, ""), true, true)
}

// fold applies the compatibility table and drops invisibles; with homoglyphs it also folds
// confusable letters. With track, back has len(out)+1 entries mapping out bytes to s offsets.
func fold(s string, homoglyphs, track bool) (string, []int) {
	var b strings.Builder
	b.Grow(len(s))
	var back []int
	if track {
		back = make([]int, 0, len(s)+1)
	}
	for i, r := range s {
		if invisible(r) {
			continue
		}
		rep, ok := compat(r)
		if !ok && homoglyphs {
			if c, found := confusable[r]; found {
				rep, ok = string(c), true
			}
		}
		n := utf8.RuneLen(r)
		if ok {
			b.WriteString(rep)
			n = len(rep)
		} else {
			b.WriteRune(r)
		}
		if track {
			for k := 0; k < n; k++ {
				back = append(back, i)
			}
		}
	}
	if track {
		back = append(back, len(s))
	}
	return b.String(), back
}

// orig maps a span of the prepared text back onto the original text, widening to whole source
// runes when a span edge falls inside a folded one.
func orig(back []int, s, e, n int) (int, int) {
	if back == nil {
		return s, e
	}
	if e > len(back)-1 {
		e = len(back) - 1
	}
	if s >= e {
		return back[s], back[s]
	}
	j := e
	for j < len(back)-1 && back[j] == back[e-1] {
		j++
	}
	return back[s], back[j]
}

// invisible reports the code points Normalize strips: they carry no glyph and only serve to split
// tokens, reorder text or smuggle data.
func invisible(r rune) bool {
	switch {
	case r == 0x00AD, r == 0x034F, r == 0x061C, r == 0x115F, r == 0x1160, r == 0x17B4, r == 0x17B5,
		r == 0x3164, r == 0xFEFF, r == 0xFFA0:
		return true
	case r >= 0x180B && r <= 0x180F: // Mongolian free variation selectors + vowel separator
		return true
	case r >= 0x200B && r <= 0x200F: // zero-width space/non-joiner/joiner, LRM, RLM
		return true
	case r >= 0x202A && r <= 0x202E: // bidi embeddings and overrides
		return true
	case r >= 0x2060 && r <= 0x2064, r >= 0x2066 && r <= 0x206F: // word joiner, invisible operators, isolates
		return true
	case r >= 0xFE00 && r <= 0xFE0F: // variation selectors 1-16
		return true
	case r >= 0x1D173 && r <= 0x1D17A: // musical format controls
		return true
	case r >= 0xE0000 && r <= 0xE007F: // tag characters
		return true
	case r >= 0xE0100 && r <= 0xE01EF: // variation selectors 17-256
		return true
	}
	return false
}

var smallForms = map[rune]string{
	0xFE50: ",", 0xFE52: ".", 0xFE54: ";", 0xFE55: ":", 0xFE56: "?", 0xFE57: "!", 0xFE59: "(", 0xFE5A: ")",
	0xFE5B: "{", 0xFE5C: "}", 0xFE5F: "#", 0xFE60: "&", 0xFE61: "*", 0xFE62: "+", 0xFE63: "-", 0xFE64: "<",
	0xFE65: ">", 0xFE66: "=", 0xFE68: "\\", 0xFE69: "$", 0xFE6A: "%", 0xFE6B: "@",
	0xFB00: "ff", 0xFB01: "fi", 0xFB02: "fl", 0xFB03: "ffi", 0xFB04: "ffl", 0xFB05: "st", 0xFB06: "st",
	0x2010: "-", 0x2011: "-", 0x2024: ".", 0x2025: "..", 0x2026: "...", 0x2044: "/", 0x2215: "/",
	0x00B2: "2", 0x00B3: "3", 0x00B9: "1", 0x2070: "0", 0x2074: "4", 0x2075: "5", 0x2076: "6", 0x2077: "7",
	0x2078: "8", 0x2079: "9", 0x2080: "0", 0x2081: "1", 0x2082: "2", 0x2083: "3", 0x2084: "4", 0x2085: "5",
	0x2086: "6", 0x2087: "7", 0x2088: "8", 0x2089: "9", 0x24EA: "0",
	0x2102: "C", 0x210A: "g", 0x210B: "H", 0x210C: "H", 0x210D: "H", 0x210E: "h", 0x2110: "I", 0x2111: "I",
	0x2112: "L", 0x2113: "l", 0x2115: "N", 0x2119: "P", 0x211A: "Q", 0x211B: "R", 0x211C: "R", 0x211D: "R",
	0x2124: "Z", 0x2128: "Z", 0x212C: "B", 0x212D: "C", 0x212F: "e", 0x2130: "E", 0x2131: "F", 0x2133: "M",
	0x2134: "o", 0x2139: "i",
}

// compat folds one compatibility code point to ASCII (the NFKC-lite table).
func compat(r rune) (string, bool) {
	switch {
	case r < 0x80:
		return "", false
	case r == 0x00A0, r == 0x3000, r == 0x202F, r == 0x205F, r >= 0x2000 && r <= 0x200A:
		return " ", true
	case r >= 0xFF01 && r <= 0xFF5E: // fullwidth ASCII
		return string(r - 0xFEE0), true
	case r >= 0x1D400 && r < 0x1D6A4: // mathematical Latin letters: 13 styles x 52
		i := (r - 0x1D400) % 52
		if i < 26 {
			return string('A' + i), true
		}
		return string('a' + i - 26), true
	case r >= 0x1D7CE && r <= 0x1D7FF: // mathematical digits: 5 styles x 10
		return string('0' + (r-0x1D7CE)%10), true
	case r >= 0x24B6 && r <= 0x24CF: // circled capitals
		return string('A' + r - 0x24B6), true
	case r >= 0x24D0 && r <= 0x24E9: // circled small letters
		return string('a' + r - 0x24D0), true
	case r >= 0x2460 && r <= 0x2468: // circled digits 1-9
		return string('1' + r - 0x2460), true
	case r >= 0x1F110 && r <= 0x1F129: // parenthesized capitals
		return string('A' + r - 0x1F110), true
	case r >= 0x1F130 && r <= 0x1F149: // squared capitals
		return string('A' + r - 0x1F130), true
	case r >= 0x1F170 && r <= 0x1F189: // negative squared capitals
		return string('A' + r - 0x1F170), true
	}
	if s, ok := smallForms[r]; ok {
		return s, true
	}
	return "", false
}

// confusable maps letters of other scripts (and Latin variants) to the Latin letter they imitate.
// Normalize leaves them alone (Cyrillic prose is legitimate); the scanners fold them, and Flags
// flags words that mix Latin with them.
var confusable = map[rune]rune{
	// Cyrillic
	'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's',
	'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ӏ': 'l', 'ӓ': 'a', 'ё': 'e', 'ү': 'y',
	'А': 'A', 'В': 'B', 'Е': 'E', 'К': 'K', 'М': 'M', 'Н': 'H', 'О': 'O', 'Р': 'P', 'С': 'C', 'Т': 'T',
	'Х': 'X', 'У': 'Y', 'Ѕ': 'S', 'І': 'I', 'Ј': 'J', 'Ӏ': 'I', 'Ԁ': 'D', 'Ԛ': 'Q', 'Ԝ': 'W',
	// Greek
	'ο': 'o', 'ν': 'v', 'α': 'a', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'ι': 'i', 'κ': 'k', 'ϲ': 'c',
	'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Ζ': 'Z', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M', 'Ν': 'N', 'Ο': 'O',
	'Ρ': 'P', 'Τ': 'T', 'Υ': 'Y', 'Χ': 'X',
	// Latin variants and others
	'ı': 'i', 'ſ': 's', 'ȷ': 'j', 'ɡ': 'g', 'ɩ': 'i', 'օ': 'o', 'ց': 'g', 'հ': 'h', 'ո': 'n', 'ս': 'u',
	'Ꭺ': 'A', 'Ᏼ': 'B', 'Ꮯ': 'C', 'Ꭰ': 'D', 'Ꭼ': 'E', 'Ꮐ': 'G', 'Ꮋ': 'H', 'Ꭻ': 'J', 'Ꮶ': 'K', 'Ꮮ': 'L',
	'Ꮇ': 'M', 'Ꮲ': 'P', 'Ꭱ': 'R', 'Ꮪ': 'S', 'Ꭲ': 'T', 'Ꮩ': 'V', 'Ꮃ': 'W', 'Ꮓ': 'Z',
}

func isLatinLetter(r rune) bool { return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' }

// foldMixed strips invisibles and folds confusables that sit inside words also holding Latin
// letters (a homoglyph attack or a copy-paste accident, never natural text). It reports whether
// anything was stripped or folded.
func foldMixed(s string) (string, bool) {
	if ascii(s) {
		return s, false
	}
	s = strings.ToValidUTF8(s, "")
	var b strings.Builder
	b.Grow(len(s))
	changed := false
	rs := []rune(s)
	for i := 0; i < len(rs); {
		r := rs[i]
		if invisible(r) {
			changed = true
			i++
			continue
		}
		_, conf := confusable[r]
		if !isLatinLetter(r) && !conf {
			b.WriteRune(r)
			i++
			continue
		}
		// a word: run of Latin letters and confusables (invisibles inside are dropped)
		j, latin, mixed := i, false, false
		for j < len(rs) {
			c := rs[j]
			if invisible(c) {
				j++
				continue
			}
			if isLatinLetter(c) {
				latin = true
			} else if _, ok := confusable[c]; ok {
				mixed = true
			} else {
				break
			}
			j++
		}
		for k := i; k < j; k++ {
			c := rs[k]
			if invisible(c) {
				changed = true
				continue
			}
			if l, ok := confusable[c]; ok && latin && mixed {
				b.WriteRune(l)
				changed = true
				continue
			}
			b.WriteRune(c)
		}
		i = j
	}
	return b.String(), changed
}
