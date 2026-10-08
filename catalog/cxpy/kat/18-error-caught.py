import json
for fn in (lambda: json.loads('{bad'), lambda: int('abc'), lambda: 1 / 0, lambda: {}['x']):
    try:
        fn()
    except Exception as e:
        print(type(e).__name__, e)
class AppError(Exception):
    pass
try:
    raise AppError('boom')
except AppError as e:
    print(type(e).__name__, e, e.args)
