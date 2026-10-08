#!/usr/bin/env bash
# zeroinstall.sh - exercise the served single-file clients end to end (SPEC-v2 27.2 / P74).
#
# With python3 and node available it:
#   1. runs the cross-implementation crypto test over clients/e2e-vectors.json (python seals, node
#      opens, and Go opens via `go test ./internal/clients -run TestSealRecipeInteropWithE2E`), plus
#      e2e.py and e2e.mjs selftest, and prints 'e2e interop ok';
#   2. starts a local stub gateway and runs join -> s -> p -> tc -> cp -> resume with each client,
#      byte-comparing the txt the client prints with a direct curl of the same endpoint, and prints
#      'zeroinstall ok' for cx.py, cx.mjs and cx.sh.
#
# It needs no database and no network: the stub gateway is a small python http.server. CI points the
# real cross-impl lane (with the fake mirror and the swap-in-flight test) at a live gateway instead.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CLIENTS="$ROOT/clients"
TMP="$(mktemp -d)"
PORT="${ZEROINSTALL_PORT:-57421}"
GW_PID=""
cleanup() {
  if [ -n "$GW_PID" ]; then
    kill "$GW_PID" 2>/dev/null || true
    wait "$GW_PID" 2>/dev/null || true
  fi
  rm -rf "$TMP"
}
trap cleanup EXIT

have() { command -v "$1" >/dev/null 2>&1; }
fail() { echo "zeroinstall: FAIL: $*" >&2; exit 1; }

have python3 || fail "python3 required"
have node || fail "node required"
have curl || fail "curl required"

# --- 1. cross-implementation crypto -----------------------------------------------------------
VEC="$CLIENTS/e2e-vectors.json"
[ -r "$VEC" ] || fail "missing $VEC (run: GEN_VECTORS=1 go test ./internal/clients -run TestGenerateVectors)"

python3 -I "$CLIENTS/e2e.py" selftest "$VEC" >/dev/null || fail "e2e.py selftest"
node "$CLIENTS/e2e.mjs" selftest "$VEC" >/dev/null || fail "e2e.mjs selftest"

# python seals -> node opens (seal2, SPEC-v2 26.4)
MK="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
MSG="cross-impl sealed memory"
SEAL_PY="$(python3 -I "$CLIENTS/seal.py" seal "$MK" "$MSG")"
OPEN_NODE="$(node "$CLIENTS/seal.mjs" open "$MK" "$SEAL_PY")"
[ "$OPEN_NODE" = "$MSG" ] || fail "node could not open a python seal2 ($OPEN_NODE)"
# node seals -> python opens
SEAL_NODE="$(node "$CLIENTS/seal.mjs" seal "$MK" "$MSG")"
OPEN_PY="$(python3 -I "$CLIENTS/seal.py" open "$MK" "$SEAL_NODE")"
[ "$OPEN_PY" = "$MSG" ] || fail "python could not open a node seal2 ($OPEN_PY)"

# Go opens python seal2 (and more) through the package test, when a toolchain is present.
if have go; then
  ( cd "$ROOT" && go test -count=1 ./internal/clients/ -run 'TestSealRecipeInteropWithE2E|TestManifestHashesMatchFiles' >/dev/null ) \
    || fail "go seal/manifest interop"
fi
echo "e2e interop ok"

# --- 2. stub gateway + the client flow --------------------------------------------------------
cat > "$TMP/gw.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

REPLIES = {
    ("POST", "/v1/t"): "t: t1 created\nnext: POST /v1/t/1/claim\n",
    ("POST", "/v1/t/1/claim"): "t: t1 claimed by you\n",
    ("POST", "/v1/cp"): "cp: cx seq=1 stored\n",
    ("POST", "/v1/me/cp"): "cp: cx seq=1 stored\n",
    ("GET", "/v1/me"): "me: aaaaaaa rep=0 credits=100\n",
    ("GET", "/v1/me/resume"): "resume: nothing to pick up\n",
}

class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, status, body, ctype="text/plain; charset=utf-8"):
        b = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(b)

    def body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return self.rfile.read(n) if n else b""

    def route(self):
        self.body()
        p = self.path
        if self.command == "POST" and p == "/v1/challenge":
            return self._send(200, '{"c":"abc","bits":0}', "application/json")
        if self.command == "POST" and p == "/v1/register":
            return self._send(200, '{"id":"aaaaaaa","token":"cx_test","credits":100,"recovery":"rrrrrr"}', "application/json")
        if self.command == "GET" and p.startswith("/q/"):
            return self._send(200, "q: %s hits=0\nnext: POST /v1/kb\n" % p[3:])
        if self.command == "POST" and p == "/v1/kb":
            return self._send(200, "kb: k7qmx5a created (quarantine)\n")
        r = REPLIES.get((self.command, p))
        if r is not None:
            return self._send(200, r)
        return self._send(404, "err notfound %s\n" % p)

    do_GET = do_POST = do_PUT = do_HEAD = route

HTTPServer(("127.0.0.1", int(sys.argv[1])), H).serve_forever()
PY

python3 "$TMP/gw.py" "$PORT" &
GW_PID=$!
export CX_URL="http://127.0.0.1:$PORT"
export XDG_CONFIG_HOME="$TMP/cfg"
mkdir -p "$XDG_CONFIG_HOME"

# wait for the stub to accept connections
for _ in $(seq 1 50); do
  curl -fsS "$CX_URL/v1/me/resume" >/dev/null 2>&1 && break
  sleep 0.1
done

# curl_txt METHOD PATH [body]  -- direct reply the client's print is compared against
curl_txt() {
  m="$1"; p="$2"; b="${3:-}"
  if [ -n "$b" ]; then
    printf %s "$b" | curl -fsS -X "$m" -H "Authorization: Bearer cx_test" -H "Content-Type: text/plain" --data-binary @- "$CX_URL$p"
  else
    curl -fsS -X "$m" -H "Authorization: Bearer cx_test" "$CX_URL$p"
  fi
}

same() { # LABEL  CLIENT_OUTPUT  EXPECTED
  if [ "$2" != "$3" ]; then
    printf 'zeroinstall: FAIL %s\n--- client:\n%s\n--- http:\n%s\n' "$1" "$2" "$3" >&2
    exit 1
  fi
}

run_py()  { python3 -I "$CLIENTS/cx.py" "$@"; }
run_mjs() { node "$CLIENTS/cx.mjs" "$@"; }
run_sh()  { CX_TOKEN=cx_test sh "$CLIENTS/cx.sh" "$@"; }

# cx.py and cx.mjs: the full join -> s -> p -> tc -> cp -> resume flow.
for name in cx.py cx.mjs; do
  rm -f "$XDG_CONFIG_HOME/cx/token"
  case "$name" in cx.py) R=run_py ;; cx.mjs) R=run_mjs ;; esac

  tok="$($R join tester 2>/dev/null)"
  [ "$tok" = "cx_test" ] || fail "$name join did not print the token (got '$tok')"

  same "$name s"  "$($R s hello 2>/dev/null)"        "$(curl_txt GET /q/hello)"
  same "$name p"  "$($R p "a title" "a fix" 2>/dev/null)" "$(curl_txt POST /v1/kb)"
  same "$name tc" "$($R tc 1 2>/dev/null)"            "$(curl_txt POST /v1/t/1/claim)"
  same "$name cp" "$($R cp "a checkpoint" --plain 2>/dev/null)" "$(curl_txt POST /v1/cp)"
  same "$name resume" "$($R resume 2>/dev/null)"      "$(curl_txt GET /v1/me/resume)"

  echo "zeroinstall ok ($name)"
done

# cx.sh: token ops and the read lane it actually implements (no join/p/tc per SPEC-v2 27.2).
same "cx.sh s"      "$(run_sh s hello)"  "$(curl_txt GET /q/hello)"
same "cx.sh me"     "$(run_sh me)"       "$(curl_txt GET /v1/me)"
same "cx.sh cp"     "$(run_sh cp "a checkpoint")" "$(curl_txt POST /v1/me/cp)"
same "cx.sh resume" "$(run_sh resume)"   "$(curl_txt GET /v1/me/resume)"
echo "zeroinstall ok (cx.sh)"
