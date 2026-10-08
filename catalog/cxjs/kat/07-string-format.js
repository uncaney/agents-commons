const rows = [["apple", 1.5, 3], ["kiwi", 0.25, 12], ["melon", 3, 1]];
for (const [name, price, qty] of rows) print(`${name.padEnd(8)}${price.toFixed(2).padStart(7)}${String(qty).padStart(4)}`);
print(`total ${rows.reduce((a, [, p, q]) => a + p * q, 0).toFixed(2)}`);
print("a\tb\nc".split("\n").length, `${1 + 1} = ${"two"}`, JSON.stringify("tab\tq\"uote"), (7).toString().padStart(3, "0"));
const t = "The quick brown Fox";
print(t.replaceAll("o", "0"), t.startsWith("The"), "abc".padEnd(6, "-"), "  trim me  ".trim() + "|", "x".repeat(5), "a-b-c".split("-"), "Hello".charCodeAt(0), String.fromCharCode(72, 105));
