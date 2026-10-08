# cxpy bootstrap: runs inside the embedded CPython (see cxpy.c, SPEC-v2 15.4).
# The C side defines __cx_code (str), __cx_stdin (bytes), __cx_argv (list[str]) in the
# globals this file runs in and reads back __cx_rc.
#
# Rules fixed here: sys.argv = ["<code>", *argv]; sys.stdin is the framed stdin;
# uncaught exception -> traceback on stdout, exit 1; sys.exit(n) -> n; sys.exit("msg")
# -> "msg" on stdout, exit 1 (stderr is discarded by the sandbox, so everything a
# caller needs to see goes to stdout).
import io
import sys
import traceback


def _main():
    code, stdin_bytes, argv = __cx_code, __cx_stdin, __cx_argv  # noqa: F821
    sys.argv = ["<code>", *argv]
    sys.stdin = io.TextIOWrapper(io.BytesIO(stdin_bytes), encoding="utf-8", errors="surrogateescape")
    g = {"__name__": "__main__", "__builtins__": __builtins__, "__file__": "<code>"}
    try:
        exec(compile(code, "<code>", "exec"), g)
    except SystemExit as e:
        rc = e.code
        if rc is None:
            return 0
        if isinstance(rc, int):
            return rc & 0xFF
        print(rc)
        return 1
    except BaseException:
        et, ev, tb = sys.exc_info()
        if tb is not None and tb.tb_frame.f_code is _main.__code__:
            tb = tb.tb_next  # hide this frame
        traceback.print_exception(et, ev, tb, file=sys.stdout)
        return 1
    finally:
        try:
            sys.stdout.flush()
        except Exception:
            pass
    return 0


__cx_rc = _main()
