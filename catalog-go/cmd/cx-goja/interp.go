// Command cx-goja is a goja launcher (ES5.1+) implementing the 15.4 contract.
// Math.random and Date ride a constant clock/rand source so a run is
// deterministic; print()/console.log write to stdout; stdin and argv are
// exposed as globals. Outputs must use ordered structures only (object key
// iteration order is insertion order in ES, never Go map order).
package main

import (
	"io"
	"strings"

	"github.com/dop251/goja"

	"ekaii.fr/commons/catalog-go/internal/launch"
)

func main() { launch.Main(Eval) }

// Eval runs one JavaScript program under goja and returns an *goja.Exception's
// string (the compact traceback) on failure.
func Eval(in launch.Input, out io.Writer) error {
	vm := goja.New()
	vm.SetTimeSource(launch.FakeNow)
	vm.SetRandSource(detRand())

	print := func(call goja.FunctionCall) goja.Value {
		parts := make([]string, len(call.Arguments))
		for i, a := range call.Arguments {
			parts[i] = a.String()
		}
		io.WriteString(out, strings.Join(parts, " ")+"\n")
		return goja.Undefined()
	}
	if err := vm.Set("print", print); err != nil {
		return err
	}
	console := vm.NewObject()
	console.Set("log", print)
	console.Set("error", print)
	if err := vm.Set("console", console); err != nil {
		return err
	}
	if err := vm.Set("stdin", in.Stdin); err != nil {
		return err
	}
	if err := vm.Set("argv", in.Argv); err != nil {
		return err
	}
	if _, err := vm.RunString(in.Code); err != nil {
		return err
	}
	return nil
}

// detRand is a constant-seeded splitmix64 float64 source so Math.random() is
// reproducible across runs and between native and wasip1 builds.
func detRand() goja.RandSource {
	var s uint64 = 0x9e3779b97f4a7c15
	return func() float64 {
		s += 0x9e3779b97f4a7c15
		z := s
		z = (z ^ (z >> 30)) * 0xbf58476d1ce4e5b9
		z = (z ^ (z >> 27)) * 0x94d049bb133111eb
		z ^= z >> 31
		return float64(z>>11) / float64(uint64(1)<<53)
	}
}
