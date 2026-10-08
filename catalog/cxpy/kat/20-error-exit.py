import json, sys
try:
    json.loads("{bad json")
except json.JSONDecodeError as e:
    print(type(e).__name__, e.lineno, e.colno)
class AppError(Exception):
    def __init__(self, msg, code):
        super().__init__(msg)
        self.code = code
try:
    raise AppError("boom", 42)
except AppError as e:
    print(type(e).__name__, e, e.code, isinstance(e, Exception), e.args)
def f():
    try:
        return "try"
    finally:
        print("finally")
print(f(), [(-x if x == 2 else x) for x in [1, 2, 3]])
print("partial output")
sys.stdout.write("written before exit\n")
sys.exit(3)
print("not reached")
