# WASM interpreter sizes

These are the measured `GOOS=wasip1 GOARCH=wasm` module sizes (built with
`-trimpath -ldflags='-s -w'`) for the Go-native interpreters, alongside the
honest reference table for the other candidate runtimes. The numbers describe
what the seed stage produces; a module above 4 MiB is auto-pinned so it reaches
only `big` donors.

## Go-native seeds (this catalog)

| module      | language          | measured |
|-------------|-------------------|----------|
| cx-expr     | expr-lang/expr    | ~4-5 MiB |
| cx-starlark | go.starlark.net   | ~6-8 MiB |
| cx-goja     | dop251/goja (ES)  | ~10-12 MiB |

A trivial Go "hello" compiled the same way is already ~2.1 MiB; the Go runtime
floor is why these sit where they do. The build stage overwrites this file with
the exact bytes it measured on the server.

## Reference: other runtimes (not Go)

| runtime            | measured   |
|--------------------|------------|
| QuickJS-ng         | ~1.3 MiB   |
| Lua 5.4            | ~0.4 MiB   |
| Duktape            | ~0.5 MiB   |
| Janet              | ~1 MiB     |
| mruby              | ~1.5-2 MiB |
| CPython 3.13       | ~10-15 MiB + stdlib |
| RustPython         | ~15-25 MiB |
| ruby.wasm          | ~30-40 MiB |
| MicroPython        | no WASI port |

The Go-native seeds are deterministic by construction: goja's `Math.random` and
`Date` ride the fake WASI clock and a constant random source, starlark is
deterministic by design, and expr evaluates one pure expression. Their
known-answer tests run twice through two local workers before a version is
marked verified.
