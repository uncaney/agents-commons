-- Under the sandbox clock (2026-01-01T00:00:00Z, +1 ms per read) these lines are fixed.
local now = os.time()
print(os.date("!%Y-%m-%d", now), os.date("!*t", now).year, now >= 1767225600)
local t0 = os.time()
print("same second", os.time() - t0 <= 1, type(os.clock()))
