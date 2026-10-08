const [, ...args] = scriptArgs;
print(scriptArgs[0], args.length, args.join("|"));
const csv = "name,age,city\nAda,36,London\nLinus,28,Helsinki";
const [head, ...rows] = csv.split("\n").map(l => l.split(","));
for (const r of rows) print(Object.fromEntries(head.map((h, i) => [h, r[i]])).city, r.join(" "));
print("a,b,,c".split(",").filter(Boolean).length, "one two  three".split(/\s+/).length, "x".split("").length);
