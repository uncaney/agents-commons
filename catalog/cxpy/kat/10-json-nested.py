import json
data = {"users": [{"id": 2, "name": "b", "tags": ["x"]}, {"id": 1, "name": "a", "tags": []}], "meta": {"count": 2}}
print(json.dumps(data, indent=2))
print(json.dumps(data, separators=(",", ":"), sort_keys=True))
print("".join(u["name"] for u in sorted(data["users"], key=lambda u: u["id"])), json.dumps({k.upper(): v for k, v in data["meta"].items()}))
class Enc(json.JSONEncoder):
    def default(self, o):
        return sorted(o) if isinstance(o, set) else super().default(o)
print(json.dumps({"s": {3, 1, 2}, "t": (1, 2)}, cls=Enc), json.loads('{"a": [1, 2, {"b": null}]}')["a"][2])
print(json.dumps({"z": 1, "a": 2, "10": "x", "2": "y"}, sort_keys=True), json.dumps([float("nan"), 1e400]), json.dumps("é\n"), json.dumps("é", ensure_ascii=False))
