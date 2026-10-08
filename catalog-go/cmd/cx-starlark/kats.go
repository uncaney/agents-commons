package main

import "ekaii.fr/commons/catalog-go/internal/kat"

// kats are the 20 known-answer tests for cx-starlark: arithmetic, strings, json,
// regex-ish string matching, dates under the fake clock and error paths (27.6).
var kats = []kat.KAT{
	// arithmetic
	{Name: "sum-range", Cat: "arithmetic", Code: `print(sum(range(10)))`},
	{Name: "mul", Cat: "arithmetic", Code: `print(7 * 6)`},
	{Name: "mod", Cat: "arithmetic", Code: `print(17 % 5)`},
	{Name: "floordiv", Cat: "arithmetic", Code: `print(10 // 3)`},
	{Name: "comprehension", Cat: "arithmetic", Code: `print(sum([x * x for x in range(5)]))`},
	// strings
	{Name: "upper", Cat: "strings", Code: `print("hello".upper())`},
	{Name: "join", Cat: "strings", Code: `print(", ".join(["a", "b", "c"]))`},
	{Name: "len", Cat: "strings", Code: `print(len("starlark"))`},
	{Name: "replace", Cat: "strings", Code: `print("abcabc".replace("a", "X"))`},
	{Name: "stdin-echo", Cat: "strings", Code: `print(stdin.strip())`, Stdin: "  padded  "},
	// json
	{Name: "json-encode", Cat: "json", Code: `print(json.encode({"a": 1, "b": [2, 3]}))`},
	{Name: "json-decode", Cat: "json", Code: `print(json.decode('[1,2,3]')[1])`},
	{Name: "json-roundtrip", Cat: "json", Code: `d = json.decode('{"x":10,"y":20}'); print(d["x"] + d["y"])`},
	// regex-ish (string matching)
	{Name: "startswith", Cat: "regex", Code: `print("foo123bar".startswith("foo"))`},
	{Name: "split", Cat: "regex", Code: `print(json.encode("a,b,c".split(",")))`},
	{Name: "find", Cat: "regex", Code: `print("hello world".find("world"))`},
	// dates under the fake clock
	{Name: "now-year", Cat: "dates", Code: `print(time.now().year)`},
	{Name: "from-timestamp", Cat: "dates", Code: `print(time.from_timestamp(0).unix)`},
	// error paths
	{Name: "fail", Cat: "error", Code: `fail("boom")`, Err: true},
	{Name: "div-zero", Cat: "error", Code: `print(1 // 0)`, Err: true},
}
