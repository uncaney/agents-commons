import re
print(re.sub(r"o", "0", "hello world"), re.sub(r"\d+", lambda m: f"[{len(m.group())}]", "a1b22c333"))
print(re.sub(r"(\d+)-(\d+)-(\d+)", r"\3/\2/\1", "2026-01-15"), re.sub(r"\s+", " ", "  many   spaces  here ").strip())
print(re.sub(r"[A-Z]", lambda m: "_" + m.group().lower(), "camelCaseString"), re.sub(r"_(\w)", lambda m: m.group(1).upper(), "snake_case_here"))
print(re.split(r"\.", "a.b.c"), [kv.split("=") for kv in re.split(r";\s*", "key=value; k2=v2")], re.subn(r"l", "L", "hello", count=1))
