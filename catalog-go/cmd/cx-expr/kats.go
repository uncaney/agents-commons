package main

import "ekaii.fr/commons/catalog-go/internal/kat"

// kats are the 20 known-answer tests for cx-expr: arithmetic, strings, json,
// regex (the matches operator), dates under the fake clock (the injected clock)
// and error paths (27.6). Each program is a single expression.
var kats = []kat.KAT{
	// arithmetic
	{Name: "precedence", Cat: "arithmetic", Code: `1 + 2 * 3`},
	{Name: "sum-range", Cat: "arithmetic", Code: `sum(1..10)`},
	{Name: "max", Cat: "arithmetic", Code: `max(3, 7, 2)`},
	{Name: "mod", Cat: "arithmetic", Code: `17 % 5`},
	{Name: "range-len", Cat: "arithmetic", Code: `len(1..100)`},
	// strings
	{Name: "upper", Cat: "strings", Code: `upper("hello")`},
	{Name: "join", Cat: "strings", Code: `join(["a", "b", "c"], "-")`},
	{Name: "len", Cat: "strings", Code: `len("expr")`},
	{Name: "trim-stdin", Cat: "strings", Code: `trim(stdin)`, Stdin: "  hi  "},
	{Name: "lower", Cat: "strings", Code: `lower("MixED")`},
	// json
	{Name: "map-render", Cat: "json", Code: `{a: 1, b: 2}`},
	{Name: "fromjson-index", Cat: "json", Code: `fromJSON("[1,2,3]")[1]`},
	{Name: "fromjson-field", Cat: "json", Code: `fromJSON('{"x":5}').x * 2`},
	// regex (matches operator)
	{Name: "has-prefix", Cat: "regex", Code: `hasPrefix("foobar", "foo")`},
	{Name: "matches", Cat: "regex", Code: `"abc123" matches "^[a-z]+[0-9]+$"`},
	{Name: "split", Cat: "regex", Code: `split("a,b,c", ",")`},
	// dates under the fake clock
	{Name: "clock-year", Cat: "dates", Code: `clock.Year()`},
	{Name: "date-year", Cat: "dates", Code: `date("2020-05-15").Year()`},
	// error paths
	{Name: "bad-int", Cat: "error", Code: `int("abc")`, Err: true},
	{Name: "bad-json", Cat: "error", Code: `fromJSON("not json")`, Err: true},
}
