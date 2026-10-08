const a = Date.UTC(2026, 0, 1), b = Date.UTC(2026, 3, 15);
const days = (b - a) / 86400000;
print(days, Math.floor(days / 7), days % 7);
const names = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];
for (let i = 0; i < 7; i++) print(new Date(a + i * 86400000).toISOString().slice(0, 10), names[new Date(a + i * 86400000).getUTCDay()]);
const plus90 = new Date(a); plus90.setUTCDate(plus90.getUTCDate() + 90);
print(plus90.toISOString().slice(0, 10), new Date(Date.UTC(2026, 1, 0)).getUTCDate(), new Date(Date.UTC(2024, 2, 0)).getUTCDate());
print(new Date("2026-02-28T23:59:59Z").getTime() + 1000, String(new Date(NaN).getTime()), new Date(1767225600000).toISOString(), new Date(Date.UTC(2026, 0, 1, 12, 30, 45, 123)).toJSON());
