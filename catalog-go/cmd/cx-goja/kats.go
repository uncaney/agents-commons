package main

import "ekaii.fr/commons/catalog-go/internal/kat"

// kats are the 20 known-answer tests for cx-goja: arithmetic, strings, json,
// regex, dates under the fake clock (plus the constant Math.random) and an
// error path (27.6).
var kats = []kat.KAT{
	// arithmetic
	{Name: "precedence", Cat: "arithmetic", Code: `print(1 + 2 * 3)`},
	{Name: "for-sum", Cat: "arithmetic", Code: `var s=0; for(var i=0;i<10;i++) s+=i; print(s)`},
	{Name: "math-max", Cat: "arithmetic", Code: `print(Math.max(3, 7, 2))`},
	{Name: "mod", Cat: "arithmetic", Code: `print(10 % 3)`},
	{Name: "to-fixed", Cat: "arithmetic", Code: `print((0.1 + 0.2).toFixed(2))`},
	// strings
	{Name: "upper", Cat: "strings", Code: `print("hello".toUpperCase())`},
	{Name: "join", Cat: "strings", Code: `print(["a","b","c"].join("-"))`},
	{Name: "lower", Cat: "strings", Code: `print("MixedCase".toLowerCase())`},
	{Name: "slice", Cat: "strings", Code: `print("starlight".slice(0, 4))`},
	{Name: "stdin-echo", Cat: "strings", Code: `print(stdin.trim())`, Stdin: "  padded  "},
	// json
	{Name: "stringify", Cat: "json", Code: `print(JSON.stringify({a: 1, b: [2, 3]}))`},
	{Name: "parse-index", Cat: "json", Code: `print(JSON.parse("[1,2,3]")[2])`},
	{Name: "parse-field", Cat: "json", Code: `var o=JSON.parse('{"x":5}'); print(o.x * 2)`},
	// regex
	{Name: "test", Cat: "regex", Code: `print(/\d+/.test("abc123"))`},
	{Name: "match", Cat: "regex", Code: `print("2026-01-02".match(/\d{4}/)[0])`},
	{Name: "replace-g", Cat: "regex", Code: `print("abcabc".replace(/a/g, "X"))`},
	// dates under the fake clock
	{Name: "epoch-year", Cat: "dates", Code: `print(new Date(0).getUTCFullYear())`},
	{Name: "now-year", Cat: "dates", Code: `print(new Date().getUTCFullYear())`},
	{Name: "random-type", Cat: "dates", Code: `print(typeof Math.random())`},
	// error path
	{Name: "throw", Cat: "error", Code: `throw new Error("boom")`, Err: true},
}
