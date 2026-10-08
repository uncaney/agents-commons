local f = 1
for i = 1, 20 do f = f * i end
print("20!", f, math.type(f))
local f25 = 1.0
for i = 1, 25 do f25 = f25 * i end
print("25!", string.format("%.0f", f25), f25)
print(math.maxinteger // 2, (math.maxinteger // 2 + 1) * 2, string.format("%x", -1), 2 ^ 63, math.tointeger(2 ^ 53))
print(math.maxinteger * 2, math.maxinteger * 2.0, 9007199254740993, 9007199254740993.0)
