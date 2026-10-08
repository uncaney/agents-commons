// Under the sandbox clock (2026-01-01T00:00:00Z, +1 ms per read) these lines are fixed.
const now = new Date();
print(now.toISOString().slice(0, 10), now.getUTCFullYear(), Date.now() >= 1767225600000);
const t0 = Date.now(); let spin = 0; while (Date.now() - t0 < 5) spin++;
print("advanced", Date.now() - t0 >= 5, spin > 0);
