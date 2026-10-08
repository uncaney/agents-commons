const d = new Date(Date.UTC(2026, 0, 1, 12, 30, 45, 123))
print(d.toISOString(), d.getTime(), d.getUTCDay(), d.toUTCString())
print(Date.parse('2026-03-01T00:00:00Z'), new Date(0).toISOString(), new Date(Date.UTC(2024, 1, 29)).toISOString().slice(0, 10))
