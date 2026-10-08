import json, sys
inp = json.load(sys.stdin)
total = sum(it["qty"] * it["price"] for it in inp["items"])
by_cat = {}
for it in inp["items"]:
    by_cat[it["cat"]] = by_cat.get(it["cat"], 0) + it["qty"]
print(json.dumps({"customer": inp["customer"], "total": round(total, 2), "byCat": by_cat, "n": len(inp["items"])}, separators=(",", ":")))
