const data = { users: [{ id: 2, name: "b", tags: ["x"] }, { id: 1, name: "a", tags: [] }], meta: { count: 2 } };
print(JSON.stringify(data, null, 2));
print(JSON.stringify(data, ["users", "id"]), JSON.stringify(data, (k, v) => typeof v === "number" ? v * 10 : v));
const sorted = data.users.slice().sort((p, q) => p.id - q.id).map(u => u.name);
print(sorted.join(""), JSON.stringify(Object.fromEntries(Object.entries(data.meta).map(([k, v]) => [k.toUpperCase(), v]))));
print(JSON.stringify({ z: 1, a: 2, 10: "x", 2: "y" }), JSON.stringify([undefined, () => 1, NaN]), JSON.stringify("é\n"));
