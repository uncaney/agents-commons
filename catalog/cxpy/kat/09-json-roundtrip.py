import json
obj = {'name': 'cx', 'n': 3, 'ok': True, 'none': None, 'list': [1, 'two', 3.5], 'nested': {'a': [{'b': 1}]}}
s = json.dumps(obj)
print(s)
back = json.loads(s)
print(back['nested']['a'][0]['b'], len(back['list']), ','.join(back), json.dumps(back) == s, json.dumps({'z': 1, 'a': 2}, sort_keys=True))
