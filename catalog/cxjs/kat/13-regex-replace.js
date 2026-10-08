print("hello world".replace(/o/g, "0"), "a1b22c333".replace(/\d+/g, d => `[${d.length}]`));
print("2026-01-15".replace(/(\d+)-(\d+)-(\d+)/, "$3/$2/$1"), "  many   spaces  here ".replace(/\s+/g, " ").trim());
print("camelCaseString".replace(/[A-Z]/g, c => "_" + c.toLowerCase()), "snake_case_here".replace(/_(\w)/g, (_, c) => c.toUpperCase()));
print("a.b.c".split(/\./), "key=value; k2=v2".split(/;\s*/).map(kv => kv.split("=")), "x".replace(/y/, "z"));
