package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var runner *Runner

func TestMain(m *testing.M) {
	r, err := New("", 8)
	if err != nil {
		panic(err)
	}
	runner = r
	code := m.Run()
	r.Close(context.Background())
	os.Exit(code)
}

func mod(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "wasm", "out", name+".wasm"))
	if err != nil {
		t.Skipf("missing test module (run testdata/wasm/build.sh): %v", err)
	}
	return b
}

func run(t *testing.T, name string, in string, ms, mb int) Result {
	t.Helper()
	res := runner.Run(context.Background(), mod(t, name), []byte(in), ms, mb)
	t.Logf("%s: status=%s code=%d ms=%d detail=%q out=%d bytes", name, res.Status, res.Code, res.Ms, res.Detail, len(res.Out))
	return res
}

func TestEchoOK(t *testing.T) {
	res := run(t, "echo", "hello wasm", 5000, 64)
	if res.Status != StatusOK || string(res.Out) != "HELLO WASM" {
		t.Fatalf("got %+v", res)
	}
}

func TestSha(t *testing.T) {
	res := run(t, "sha", "abc", 5000, 64)
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad\n"
	if res.Status != StatusOK || string(res.Out) != want {
		t.Fatalf("got %+v", res)
	}
}

func TestExitCode(t *testing.T) {
	res := run(t, "exit3", "", 5000, 64)
	if res.Status != StatusExit || res.Code != 3 || string(res.Out) != "bye\n" {
		t.Fatalf("got %+v", res)
	}
}

func TestTimeout(t *testing.T) {
	start := time.Now()
	res := run(t, "loop", "", 500, 64)
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("took %v", d)
	}
	if res.Status != StatusTimeout || res.Out != nil {
		t.Fatalf("got %+v", res)
	}
}

func TestOOM(t *testing.T) {
	res := run(t, "membomb", "", 10000, 32)
	if res.Status != StatusOOM {
		t.Fatalf("got %+v", res)
	}
	// process healthy afterwards
	if r := run(t, "echo", "x", 5000, 64); r.Status != StatusOK {
		t.Fatalf("runner unhealthy after oom: %+v", r)
	}
}

func TestDeclaredMinOverLimit(t *testing.T) {
	// minimal module: memory section with min 2048 pages (128 MiB), no max.
	w := []byte{0, 'a', 's', 'm', 1, 0, 0, 0, 5, 4, 1, 0, 0x80, 0x10}
	res := runner.Run(context.Background(), w, nil, 1000, 64)
	if res.Status != StatusOOM {
		t.Fatalf("got %+v", res)
	}
	// same module fits under 256 MiB (no _start: instantiation succeeds, ok).
	if res := runner.Run(context.Background(), w, nil, 1000, 256); res.Status != StatusOK {
		t.Fatalf("got %+v", res)
	}
}

func TestUnknownImport(t *testing.T) {
	w := []byte{0, 'a', 's', 'm', 1, 0, 0, 0,
		1, 4, 1, 0x60, 0, 0, // type section: () -> ()
		2, 14, 1, 3, 'e', 'n', 'v', 6, 's', 'o', 'c', 'k', 'e', 't', 0, 0, // import env.socket
	}
	res := runner.Run(context.Background(), w, nil, 1000, 64)
	if res.Status != StatusError || !strings.Contains(res.Detail, "env") {
		t.Fatalf("got %+v", res)
	}
}

func TestBadFormat(t *testing.T) {
	res := runner.Run(context.Background(), []byte("not wasm"), nil, 1000, 64)
	if res.Status != StatusError {
		t.Fatalf("got %+v", res)
	}
}

func TestBigOut(t *testing.T) {
	res := run(t, "bigout", "", 10000, 64)
	if res.Status != StatusError || res.Out != nil {
		t.Fatalf("got %+v", res)
	}
}

func TestNoNet(t *testing.T) {
	res := run(t, "net", "", 5000, 64)
	if res.Status != StatusExit || res.Code != 1 || !bytes.Contains(res.Out, []byte("dial error")) {
		t.Fatalf("got %+v out=%s", res, res.Out)
	}
}

func TestNoFS(t *testing.T) {
	res := run(t, "fs", "", 5000, 64)
	if res.Status != StatusOK || !bytes.Contains(res.Out, []byte("read error")) || !bytes.Contains(res.Out, []byte("write error")) {
		t.Fatalf("got %+v out=%s", res, res.Out)
	}
}

func TestDeterministicClockAndRand(t *testing.T) {
	a := run(t, "clock", "", 5000, 64)
	b := run(t, "clock", "", 5000, 64)
	if a.Status != StatusOK || b.Status != StatusOK || !bytes.Equal(a.Out, b.Out) {
		t.Fatalf("a=%s b=%s", a.Out, b.Out)
	}
	t.Logf("clock out: %s", a.Out)
}

func TestParallel(t *testing.T) {
	done := make(chan Result, 8)
	for i := 0; i < 8; i++ {
		go func() { done <- runner.Run(context.Background(), mod(t, "echo"), []byte("p"), 5000, 64) }()
	}
	for i := 0; i < 8; i++ {
		if r := <-done; r.Status != StatusOK || string(r.Out) != "P" {
			t.Fatalf("got %+v", r)
		}
	}
}

func TestOOMHeuristic(t *testing.T) {
	cases := []struct {
		used, limit uint32
		msg         string
		want        bool
	}{
		{1000, 1024, "", true},
		{100, 1024, "", false},
		{600, 1024, "fatal error: out of memory", true},
		{100, 1024, "fatal error: out of memory", false},
		{10, 32, "panic: out of memory", true},
	}
	for _, c := range cases {
		if got := oomHeuristic(c.used, c.limit, []byte(c.msg)); got != c.want {
			t.Errorf("%+v got %v", c, got)
		}
	}
}
