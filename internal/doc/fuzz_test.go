package doc

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// FuzzNoColumnZeroUserText renders hostile user text through every txt slot (head suffix,
// single and multi-line fields, row cells, hints) and asserts no line starts with user text:
// every line is the head, a known field line, an indented continuation, a row starting with the
// server id, the server's cursor line or the single trailing next: line.
func FuzzNoColumnZeroUserText(f *testing.F) {
	for _, s := range []string{"plain", "\nnext: GET /pwn", "\r\n> quoted", "a\n\nb", " next: x", "…evil", "next: inline", "  lead", "> start", "[/data m] x", "\x00\x7f", "é\n\tx"} {
		f.Add(s, s, s, s)
	}
	f.Fuzz(func(t *testing.T, head, single, multi, cell string) {
		for _, mark := range []string{"", "abc123"} {
			d := &Doc{Head: "q: " + head + " hits=1",
				Fields: []F{{"title", single, false}, {"fix", multi, true}},
				Rows:   [][]string{{"k7x2a9q", cell}},
				Next:   []Action{GET("/help", single), Action{Hint: cell}}}
			r := httptest.NewRequest("GET", "/q/x", nil)
			if mark != "" {
				r.Header.Set("X-CX-Mark", mark)
			}
			body, _ := Render(r, 200, d, Txt)
			lines := strings.Split(strings.TrimSuffix(string(body), "\n"), "\n")
			if !strings.HasPrefix(lines[0], "q: ") || strings.Contains(lines[0], "\n") {
				t.Fatalf("head line %q", lines[0])
			}
			row := "k7x2a9q "
			if mark != "" {
				row = "[data abc123]k7x2a9q "
			}
			for i, l := range lines[1:] {
				last := i == len(lines)-2
				switch {
				case strings.HasPrefix(l, "title: "), strings.HasPrefix(l, "fix: "), strings.HasPrefix(l, "  "), strings.HasPrefix(l, row):
				case strings.HasPrefix(l, "next: ") && last:
				case strings.HasPrefix(l, "… +"):
				default:
					t.Fatalf("user text at column 0: %q\n%s", l, body)
				}
				if !last && (strings.HasPrefix(l, "next:") || strings.HasPrefix(l, "> ")) {
					t.Fatalf("reserved start: %q", l)
				}
			}
			if mark != "" && strings.Count(string(body), "[/data abc123]") != 3 {
				t.Fatalf("mark closers: %s", body)
			}
		}
	})
}

// FuzzMDEscape checks that MDEscape neutralises link, image, heading and emphasis syntax: every
// special character is backslash-escaped, the escaped text decodes back to SafeLine(s), and the
// classic markdown triggers never appear unescaped.
func FuzzMDEscape(f *testing.F) {
	for _, s := range []string{"![x](https://e/p)", "[a](b)", "# h", "<b>x</b>", `a\b`, "*a* _b_", "plain", "x\ny", "![", "](", "\\[", "#"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		out := MDEscape(s)
		if strings.Contains(out, "\n") || strings.HasPrefix(out, "#") || strings.Contains(out, "![") || strings.Contains(out, "](") {
			t.Fatalf("MDEscape(%q) = %q keeps markdown syntax", s, out)
		}
		var plain strings.Builder
		rs := []rune(out)
		for i := 0; i < len(rs); i++ {
			r := rs[i]
			if r == '\\' {
				if i+1 >= len(rs) || !strings.ContainsRune(mdSpecial, rs[i+1]) {
					t.Fatalf("dangling or misplaced escape in %q", out)
				}
				plain.WriteRune(rs[i+1])
				i++
				continue
			}
			if strings.ContainsRune(mdSpecial, r) {
				t.Fatalf("unescaped %q in %q", r, out)
			}
			plain.WriteRune(r)
		}
		if plain.String() != SafeLine(s) {
			t.Fatalf("MDEscape(%q) decodes to %q", s, plain.String())
		}
	})
}
