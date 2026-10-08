local a, b = 1767225600, 1776211200 -- 2026-01-01, 2026-04-15 (UTC)
local days = (b - a) // 86400
print(days, days // 7, days % 7)
local names = { "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat" }
for i = 0, 6 do
  local ts = a + i * 86400
  print(os.date("!%Y-%m-%d", ts), names[os.date("!*t", ts).wday])
end
print(os.date("!%Y-%m-%d", a + 90 * 86400), os.date("!*t", a + 31 * 86400 - 1).day, os.date("!*t", 1709251199).day)
print(os.difftime(b, a), string.format("%.1f", (b - a) / 86400 / 7))
print(os.date("!%Y-%m-%d %H:%M:%S", 1767225600), type(os.time()), os.date("!%Y-%m-%d", 1740787199))
