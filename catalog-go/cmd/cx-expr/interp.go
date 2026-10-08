// Command cx-expr is an expr-lang/expr launcher implementing the 15.4 contract.
// The program is a single expression; its result is rendered to stdout (strings
// verbatim, everything else as canonical JSON with sorted map keys so the output
// is ordered and deterministic). stdin, argv and a constant now ride the env.
package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/expr-lang/expr"

	"ekaii.fr/commons/catalog-go/internal/launch"
)

func main() { launch.Main(Eval) }

// Eval compiles and runs one expression, writing the rendered result to out; a
// compile or run error is the compact traceback.
func Eval(in launch.Input, out io.Writer) error {
	env := map[string]any{
		"stdin": in.Stdin,
		"argv":  in.Argv,
		"clock": launch.FakeNow(), // fixed time.Time; avoids shadowing expr's now() builtin
	}
	program, err := expr.Compile(in.Code, expr.Env(env))
	if err != nil {
		return err
	}
	v, err := expr.Run(program, env)
	if err != nil {
		return err
	}
	io.WriteString(out, render(v)+"\n")
	return nil
}

// render prints strings verbatim and everything else as canonical JSON
// (encoding/json sorts map keys, so object output is ordered).
func render(v any) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case string:
		return t
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
}
