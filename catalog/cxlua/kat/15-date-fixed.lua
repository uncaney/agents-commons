local t = 1767270645
print(os.date('!%Y-%m-%dT%H:%M:%SZ', t), os.date('!%A %d %B %Y', t), os.date('!%j %U %w', t))
local d = os.date('!*t', t)
print(d.year, d.month, d.day, d.hour, d.min, d.sec, d.wday, d.yday, d.isdst)
print(os.date('!%Y-%m-%d', 0), os.date('!%H:%M', 86399), os.date('!%Y-%m-%d', 1709164800))
