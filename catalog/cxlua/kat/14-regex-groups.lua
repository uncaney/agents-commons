local y, m, d = ("due 2026-03-09"):match("(%d%d%d%d)-(%d%d)-(%d%d)")
print(y, m, d, ("due 2026-03-09"):find("%d%d%d%d"))
local parts = {}
for k, v in ("a=1, b=22, c=333"):gmatch("(%w)=(%d+)") do parts[#parts + 1] = k .. ":" .. #v end
print(table.concat(parts, " "), ("cost $42"):match("%$(%d+)"), ("a foo b"):find("%f[%w]foo%f[%W]") ~= nil)
print(("f(a(b)c) g(d)"):match("%b()"), ("key = value"):match("^(%w+)%s*=%s*(%w+)$"))
print(("hello"):match("()ll()"), ("THE (quick) fox"):find("%((%a+)%)"))
print(("5550100"):match("^%d%d%d%-%d%d%d%d$") ~= nil, ("Contact: ada@example.com"):find("%+%d+"), ("+44 20"):find("%+%d+"))
