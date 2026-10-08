local function level2(x)
  if x > 1 then error("value " .. x .. " out of range") end
  return x
end
local function level1(x) return level2(x * 2) end
print("before")
level1(1)
print("never printed")
