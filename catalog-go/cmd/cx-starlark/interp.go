// Command cx-starlark is a go.starlark.net launcher (Python dialect,
// deterministic by design) implementing the 15.4 contract. It predeclares the
// time/json/math modules, a Python-compatible sum(), and stdin/argv; time.now()
// rides the fake clock so dates are reproducible.
package main

import (
	"fmt"
	"io"

	"go.starlark.net/lib/json"
	"go.starlark.net/lib/math"
	startime "go.starlark.net/lib/time"
	"go.starlark.net/starlark"
	"go.starlark.net/syntax"

	"ekaii.fr/commons/catalog-go/internal/launch"
)

func main() { launch.Main(Eval) }

// Eval runs one starlark program, routing print() to out and surfacing an
// EvalError as its backtrace (the compact traceback of 15.4).
func Eval(in launch.Input, out io.Writer) error {
	startime.NowFunc = launch.FakeNow
	thread := &starlark.Thread{
		Name:  "main",
		Print: func(_ *starlark.Thread, msg string) { fmt.Fprintln(out, msg) },
	}
	argv := make([]starlark.Value, len(in.Argv))
	for i, a := range in.Argv {
		argv[i] = starlark.String(a)
	}
	predeclared := starlark.StringDict{
		"time":  startime.Module,
		"json":  json.Module,
		"math":  math.Module,
		"sum":   starlark.NewBuiltin("sum", sumBuiltin),
		"stdin": starlark.String(in.Stdin),
		"argv":  starlark.NewList(argv),
	}
	_, err := starlark.ExecFile(thread, "main.star", in.Code, predeclared)
	if err != nil {
		if ev, ok := err.(*starlark.EvalError); ok {
			return backtraceErr(ev.Backtrace())
		}
		return err
	}
	return nil
}

// backtraceErr wraps a starlark backtrace string as an error.
type backtraceErr string

func (b backtraceErr) Error() string { return string(b) }

// sumBuiltin is a Python-compatible sum(iterable, start=0) so programs such as
// sum(range(10)) work (starlark's universe omits it).
func sumBuiltin(thread *starlark.Thread, b *starlark.Builtin, args starlark.Tuple, kwargs []starlark.Tuple) (starlark.Value, error) {
	var iterable starlark.Value
	var start starlark.Value = starlark.MakeInt(0)
	if err := starlark.UnpackPositionalArgs("sum", args, kwargs, 1, &iterable, &start); err != nil {
		return nil, err
	}
	it, ok := iterable.(starlark.Iterable)
	if !ok {
		return nil, fmt.Errorf("sum: %s value is not iterable", iterable.Type())
	}
	iter := it.Iterate()
	defer iter.Done()
	acc := start
	var x starlark.Value
	for iter.Next(&x) {
		var err error
		if acc, err = starlark.Binary(syntax.PLUS, acc, x); err != nil {
			return nil, err
		}
	}
	return acc, nil
}
