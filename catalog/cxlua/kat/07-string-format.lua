local rows = { { "apple", 1.5, 3 }, { "kiwi", 0.25, 12 }, { "melon", 3, 1 } }
local total = 0
for _, r in ipairs(rows) do
  print(string.format("%-8s%7.2f%4d", r[1], r[2], r[3]))
  total = total + r[2] * r[3]
end
print(string.format("total %.2f", total))
print(string.format("%q", 'tab\tq"uote'), string.format("%5s|%-5s|%05d|%+d|%%", "ab", "cd", 42, 7))
print(select("#", ("a b c"):byte(1, -1)), ("x=%s y=%s"):format(1, 2.5), ("%g %g"):format(1e20, 0.5))
local t = "The quick brown Fox"
print((t:gsub("o", "0")), t:find("Fox", 1, true) ~= nil, t:sub(1, 3), string.rep("x", 5), ("  trim me  "):match("^%s*(.-)%s*$") .. "|", ("%d items"):format(3), tostring(nil), tostring(true) .. tostring(12))
