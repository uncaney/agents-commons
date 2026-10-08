#!/usr/bin/env python3 -I
"""catalog/check.py: validates and (re)generates the catalog build pipeline metadata.

  python3 -I catalog/check.py              validate everything (default; exit 1 on any error)
  python3 -I catalog/check.py gen NAME...  rewrite tests/kat in catalog/NAME/manifest.json from kat/
  python3 -I catalog/check.py frame NAME ID   write the job input bytes of one KAT to stdout
  python3 -I catalog/check.py expect NAME ID  print "<exit> <path of expected stdout>"
  python3 -I catalog/check.py ids NAME        list the KAT ids of one service

Checks (SPEC-v2 15.1 manifest shape + the REV3 fields + this pipeline's `kat` extension):
  - every catalog/<name>/manifest.json: allowed keys only, abi in json|raw|text, one-line in/out,
    examples <= 3, ms_hint 1..30000, mb_hint 1..256, fee 0..2, tests <= 10 with exactly one of
    in_text|in (64 hex) and out_sha256 (64 hex), optional fs/fs_override/get_ok/input_schema,
    whole file <= 4096 bytes;
  - `kat`: list of program ids; interpreters list exactly 20 covering arithmetic, string, json,
    regex, date and error; every id has its program and expected-stdout files under kat/;
  - tests are exactly the framing of the ids in kat/TESTS and hash their expected stdout;
  - every Dockerfile COPY/ADD source exists in the build context (catalog/);
  - PINS.txt lines match PIN_RE; build.sh/verify.sh pass `bash -n`.
Stdlib only, no network, no side effects outside `gen`.
"""
import glob
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
PIN_RE = re.compile(r"^[0-9a-f]{64} [a-z0-9][a-z0-9-]{1,31}@[1-9][0-9]* [1-9][0-9]*$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,31}$")
TOPICS = ("arithmetic", "string", "json", "regex", "date", "error")
KAT_ID = re.compile(r"^[0-9]{2}-(%s)-[a-z0-9]+$" % "|".join(TOPICS))
INTERPRETERS = {"cxjs": "js", "cxlua": "lua", "cxpy": "py"}
MANIFEST_KEYS = {"desc", "usage", "abi", "in", "out", "examples", "ms_hint", "mb_hint", "fee", "tests",
                 "fs", "fs_override", "get_ok", "input_schema", "kat"}
MANIFEST_MAX = 4096
KAT_COUNT = 20
TESTS_MAX = 10


class Errs:
    def __init__(self):
        self.n = 0

    def __call__(self, where, msg):
        self.n += 1
        print("ERR  %s: %s" % (where, msg))


def services():
    out = []
    for d in sorted(os.listdir(HERE)):
        if os.path.isfile(os.path.join(HERE, d, "manifest.json")):
            out.append(d)
    return out


def sha256_file(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 16), b""):
            h.update(chunk)
    return h.hexdigest()


def one_line(s, limit):
    return isinstance(s, str) and 0 < len(s) <= limit and not any(ord(c) < 32 or ord(c) == 127 for c in s)


# --- KAT files -----------------------------------------------------------------------------

def kat_dir(name):
    return os.path.join(HERE, name, "kat")


def kat_ids(name):
    """Program ids found under kat/: <id>.<ext> for interpreters, <id>.in for tools."""
    ext = INTERPRETERS.get(name, "in")
    ids = []
    for p in sorted(glob.glob(os.path.join(kat_dir(name), "*." + ext))):
        ids.append(os.path.basename(p)[: -len(ext) - 1])
    return ids


def kat_frame(name, kid):
    """Job input bytes for a KAT: the 15.4 JSON framing for interpreters, raw bytes for tools."""
    d = kat_dir(name)
    if name in INTERPRETERS:
        with open(os.path.join(d, "%s.%s" % (kid, INTERPRETERS[name])), "rb") as f:
            code = f.read().decode("utf-8")
        obj = {"code": code}
        sp = os.path.join(d, kid + ".stdin")
        if os.path.exists(sp):
            with open(sp, "rb") as f:
                obj["stdin"] = f.read().decode("utf-8")
        ap = os.path.join(d, kid + ".argv")
        if os.path.exists(ap):
            with open(ap, "r", encoding="utf-8") as f:
                obj["argv"] = [line.rstrip("\n") for line in f if line.rstrip("\n") != ""]
        return json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    with open(os.path.join(d, kid + ".in"), "rb") as f:
        return f.read()


def kat_exit(name, kid):
    p = os.path.join(kat_dir(name), kid + ".exit")
    if not os.path.exists(p):
        return 0
    with open(p) as f:
        return int(f.read().strip() or "0")


def kat_tests(name):
    p = os.path.join(kat_dir(name), "TESTS")
    if not os.path.exists(p):
        return []
    with open(p) as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]


# --- checks ----------------------------------------------------------------------------------

def check_manifest(name, err):
    where = "%s/manifest.json" % name
    path = os.path.join(HERE, name, "manifest.json")
    raw = open(path, "rb").read()
    if len(raw) > MANIFEST_MAX:
        err(where, "%d bytes > %d (SPEC 15.1 manifest jsonb <= 4 KiB)" % (len(raw), MANIFEST_MAX))
    try:
        m = json.loads(raw.decode("utf-8"))
    except Exception as e:  # noqa: BLE001
        err(where, "not JSON: %s" % e)
        return
    if not isinstance(m, dict):
        err(where, "not an object")
        return
    if not NAME_RE.match(name):
        err(where, "directory name does not match the service name grammar")
    for k in m:
        if k not in MANIFEST_KEYS:
            err(where, "unknown key %r" % k)
    if m.get("abi") not in ("json", "raw", "text"):
        err(where, "abi must be json|raw|text")
    for k, lim in (("desc", 200), ("in", 300), ("out", 300)):
        if not one_line(m.get(k), lim):
            err(where, "%s must be a one-line string of 1..%d chars" % (k, lim))
    u = m.get("usage")
    if not isinstance(u, str) or not 0 < len(u) <= 600:
        err(where, "usage must be a string of 1..600 chars")
    ex = m.get("examples", [])
    if not isinstance(ex, list) or len(ex) > 3 or any(
            not isinstance(e, dict) or set(e) != {"in", "out"} or not all(isinstance(e[k], str) for k in e) for e in ex):
        err(where, "examples must be <= 3 objects {in, out} of strings")
    for k, lo, hi in (("ms_hint", 1, 30000), ("mb_hint", 1, 256), ("fee", 0, 2)):
        v = m.get(k)
        if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
            err(where, "%s must be an integer in %d..%d" % (k, lo, hi))
    if "fs" in m and not (isinstance(m["fs"], str) and HEX64.match(m["fs"])):
        err(where, "fs must be a sha256 hex")
    for k in ("fs_override", "get_ok"):
        if k in m and not isinstance(m[k], bool):
            err(where, "%s must be a boolean" % k)
    if "input_schema" in m and (not isinstance(m["input_schema"], dict) or len(json.dumps(m["input_schema"])) > 4096):
        err(where, "input_schema must be an object <= 4 KiB")
    tests = m.get("tests")
    if not isinstance(tests, list) or len(tests) > TESTS_MAX:
        err(where, "tests must be a list of <= %d entries" % TESTS_MAX)
        tests = []
    for i, t in enumerate(tests):
        if not isinstance(t, dict) or set(t) - {"in_text", "in", "out_sha256"} or ("in_text" in t) == ("in" in t):
            err(where, "tests[%d] needs exactly one of in_text|in plus out_sha256" % i)
            continue
        if "in" in t and not (isinstance(t["in"], str) and HEX64.match(t["in"])):
            err(where, "tests[%d].in must be a sha256 hex" % i)
        if "in_text" in t and not isinstance(t["in_text"], str):
            err(where, "tests[%d].in_text must be a string" % i)
        if not (isinstance(t.get("out_sha256"), str) and HEX64.match(t["out_sha256"])):
            err(where, "tests[%d].out_sha256 must be a sha256 hex" % i)
    # kat extension: ids, files, coverage, and tests derived from kat/TESTS
    kat = m.get("kat")
    if not isinstance(kat, list) or not all(isinstance(k, str) for k in kat):
        err(where, "kat must be a list of program ids")
        return
    ids = kat_ids(name)
    if kat != ids:
        err(where, "kat list differs from kat/ directory (run: check.py gen %s)" % name)
    if len(set(kat)) != len(kat):
        err(where, "duplicate kat ids")
    if name in INTERPRETERS:
        if len(kat) != KAT_COUNT:
            err(where, "interpreter manifests list exactly %d KAT programs, found %d" % (KAT_COUNT, len(kat)))
        bad = [k for k in kat if not KAT_ID.match(k)]
        if bad:
            err(where, "kat ids must look like NN-<topic>-<slug> with topic in %s: %s" % (",".join(TOPICS), bad))
        seen = {k.split("-")[1] for k in kat if KAT_ID.match(k)}
        missing = [t for t in TOPICS if t not in seen]
        if missing:
            err(where, "kat coverage missing topics %s" % missing)
    want_ids = kat_tests(name)
    for k in kat:
        if not os.path.exists(os.path.join(kat_dir(name), k + ".out")):
            if name in INTERPRETERS or k in want_ids:
                err(where, "kat/%s.out (expected stdout) missing" % k)
            else:
                print("warn %s: kat/%s.out not recorded yet (verify.sh --record on the server)" % (name, k))
    if len(want_ids) > TESTS_MAX:
        err(where, "kat/TESTS lists %d ids > %d" % (len(want_ids), TESTS_MAX))
    for k in want_ids:
        if k not in ids:
            err(where, "kat/TESTS names unknown id %s" % k)
        elif kat_exit(name, k) != 0:
            err(where, "kat/TESTS id %s exits %d; published tests must exit 0" % (k, kat_exit(name, k)))
    want = []
    for k in want_ids:
        if k in ids and os.path.exists(os.path.join(kat_dir(name), k + ".out")):
            want.append(expected_test(name, k))
    if want and tests != want:
        err(where, "tests differ from kat/TESTS + kat/*.out (run: check.py gen %s)" % name)
    if m.get("abi") == "raw":
        for i, t in enumerate(tests):
            if "in_text" in t and any(ord(c) >= 0x80 for c in t["in_text"]):
                err(where, "tests[%d].in_text carries bytes >= 0x80; raw inputs must be ASCII-safe or use in=<hash>" % i)


def expected_test(name, kid):
    frame = kat_frame(name, kid)
    return {"in_text": frame.decode("utf-8"), "out_sha256": sha256_file(os.path.join(kat_dir(name), kid + ".out"))}


def check_dockerfiles(err):
    for name in sorted(os.listdir(HERE)):
        df = os.path.join(HERE, name, "Dockerfile")
        if not os.path.isfile(df):
            continue
        where = "%s/Dockerfile" % name
        text = open(df, encoding="utf-8").read().replace("\\\n", " ")
        seen = 0
        for line in text.splitlines():
            parts = shlex.split(line, comments=True) if line.strip() and not line.lstrip().startswith("#") else []
            if not parts or parts[0].upper() not in ("COPY", "ADD"):
                continue
            seen += 1
            args = [a for a in parts[1:] if not a.startswith("--")]
            if any(a.startswith("--from=") for a in parts[1:]):
                continue
            for src in args[:-1]:
                if "://" in src:
                    continue
                if not glob.glob(os.path.join(HERE, src)):
                    err(where, "COPY/ADD source %r not found in the build context (catalog/)" % src)
        if not seen:
            err(where, "no COPY/ADD instruction (the launcher sources must come from the context)")
        if "FROM" not in text:
            err(where, "no FROM")


def check_pins(err):
    p = os.path.join(HERE, "PINS.txt")
    if not os.path.exists(p):
        err("PINS.txt", "missing")
        return
    n = 0
    for i, line in enumerate(open(p, encoding="utf-8"), 1):
        s = line.rstrip("\n")
        if not s.strip() or s.startswith("#"):
            continue
        n += 1
        if not PIN_RE.match(s):
            err("PINS.txt:%d" % i, "does not match %s" % PIN_RE.pattern)
    print("ok   PINS.txt: %d pin line(s)" % n)


def check_scripts(err):
    for s in ("build.sh", "verify.sh"):
        p = os.path.join(HERE, s)
        if not os.path.isfile(p):
            err(s, "missing")
            continue
        if not os.access(p, os.X_OK):
            err(s, "not executable")
        try:
            r = subprocess.run(["bash", "-n", p], capture_output=True, text=True, timeout=30)
            if r.returncode != 0:
                err(s, "bash -n: %s" % r.stderr.strip())
        except (OSError, subprocess.TimeoutExpired) as e:
            err(s, "bash -n could not run: %s" % e)


def cmd_check():
    err = Errs()
    check_scripts(err)
    check_dockerfiles(err)
    check_pins(err)
    for name in services():
        check_manifest(name, err)
        print("ok   %s: %d KAT(s), %d published test(s)" % (name, len(kat_ids(name)), len(kat_tests(name))))
    if err.n:
        print("FAIL %d error(s)" % err.n)
        return 1
    print("PASS")
    return 0


def cmd_gen(names):
    for name in names:
        path = os.path.join(HERE, name, "manifest.json")
        m = json.loads(open(path, "rb").read().decode("utf-8"))
        ids = kat_ids(name)
        tests = []
        for k in kat_tests(name):
            if not os.path.exists(os.path.join(kat_dir(name), k + ".out")):
                print("skip %s: kat/%s.out missing (record it with verify.sh --record)" % (name, k))
                continue
            tests.append(expected_test(name, k))
        m["tests"] = tests
        m["kat"] = ids
        for sep in ((",", ": "), (",", ":")):
            data = json.dumps(m, indent=1 if sep[1] == ": " else None, separators=sep, ensure_ascii=True) + "\n"
            if len(data) <= MANIFEST_MAX:
                break
        with open(path, "w", encoding="utf-8") as f:
            f.write(data)
        print("gen  %s: %d KAT(s), %d test(s), %d bytes" % (name, len(ids), len(tests), len(data)))
    return 0


def main(argv):
    cmd = argv[1] if len(argv) > 1 else "check"
    if cmd == "check":
        return cmd_check()
    if cmd == "gen" and len(argv) > 2:
        return cmd_gen(argv[2:])
    if cmd == "frame" and len(argv) == 4:
        sys.stdout.buffer.write(kat_frame(argv[2], argv[3]))
        return 0
    if cmd == "ids" and len(argv) == 3:
        print("\n".join(kat_ids(argv[2])))
        return 0
    if cmd == "expect" and len(argv) == 4:
        print("%d %s" % (kat_exit(argv[2], argv[3]), os.path.join(kat_dir(argv[2]), argv[3] + ".out")))
        return 0
    print(__doc__)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
