local a, b = 7, 3
print(a + b, a - b, a * b, a // b, a % b, a ^ b, 7 / 2, -7 // 2, 1 << 10, 0xF0 & 0x3C)
local s = 0
for i = 1, 100 do s = s + i end
print('sum', s, math.type(s), math.type(2.0), math.maxinteger + 1 == math.mininteger)
