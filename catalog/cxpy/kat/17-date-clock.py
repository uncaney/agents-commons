# Under the sandbox clock (2026-01-01T00:00:00Z, +1 ms per read) these lines are fixed.
import time
from datetime import datetime, timezone
now = datetime.now(timezone.utc)
print(now.date().isoformat(), now.year, time.time() >= 1767225600)
t0 = time.monotonic()
print("monotonic advances", time.monotonic() >= t0, time.gmtime(time.time()).tm_year)
