local nums = {}
for line in io.lines() do
  for tok in line:gmatch("%S+") do nums[#nums + 1] = tonumber(tok) end
end
local sum, max = 0, -math.huge
for _, n in ipairs(nums) do sum = sum + n if n > max then max = n end end
table.sort(nums)
print("n", #nums, "sum", sum, "mean", string.format("%.3f", sum / #nums), "max", max)
print("sorted", table.concat(nums, ","))
