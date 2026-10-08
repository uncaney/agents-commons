// Package launch implements the 15.4 launcher contract shared by the three
// Go-native interpreters (cx-starlark, cx-goja, cx-expr): read stdin fully; a
// payload that starts with '{' is parsed as {"code","stdin","argv"}, otherwise
// the bytes before the first NUL are the code and the bytes after are stdin;
// an exception prints a compact traceback on stdout and exits 1.
package launch

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Input is the parsed launcher payload.
type Input struct {
	Code  string
	Stdin string
	Argv  []string
}

// FakeEpoch is the fixed wall clock the interpreters ride so a run is
// deterministic both natively (tests) and under the wasip1 fake clock
// (2026-01-01T00:00:00Z, matching internal/sandbox). Math.random/Date,
// starlark time.now() and expr's now all resolve to it (constant).
const FakeEpoch int64 = 1767225600

// FakeNow is the constant clock value (UTC).
func FakeNow() time.Time { return time.Unix(FakeEpoch, 0).UTC() }

// Parse applies the 15.4 framing.
func Parse(b []byte) (Input, error) {
	if len(b) > 0 && b[0] == '{' {
		var j struct {
			Code  string   `json:"code"`
			Stdin string   `json:"stdin"`
			Argv  []string `json:"argv"`
		}
		if err := json.Unmarshal(b, &j); err != nil {
			return Input{}, fmt.Errorf("launcher input: bad json: %v", err)
		}
		return Input{Code: j.Code, Stdin: j.Stdin, Argv: j.Argv}, nil
	}
	if i := bytes.IndexByte(b, 0); i >= 0 {
		return Input{Code: string(b[:i]), Stdin: string(b[i+1:])}, nil
	}
	return Input{Code: string(b)}, nil
}

// Eval runs parsed input, writing program output to out. A returned error is
// rendered as the compact traceback.
type Eval func(in Input, out io.Writer) error

// Dispatch parses b, runs eval and returns the process exit code: 0 on
// success, 1 when the input is malformed or the program raises. The traceback
// (err.Error()) is written to out, newline-terminated.
func Dispatch(b []byte, out io.Writer, eval Eval) int {
	in, err := Parse(b)
	if err != nil {
		writeTrace(out, err)
		return 1
	}
	if err := eval(in, out); err != nil {
		writeTrace(out, err)
		return 1
	}
	return 0
}

func writeTrace(out io.Writer, err error) {
	msg := err.Error()
	if !strings.HasSuffix(msg, "\n") {
		msg += "\n"
	}
	io.WriteString(out, msg)
}

// Main is the cmd entry point: read all of stdin, dispatch, exit.
func Main(eval Eval) {
	b, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintln(os.Stdout, "launcher input: "+err.Error())
		os.Exit(1)
	}
	os.Exit(Dispatch(b, os.Stdout, eval))
}
